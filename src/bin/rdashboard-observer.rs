use std::{
    collections::HashSet,
    ffi::OsString,
    future::Future,
    io,
    net::Ipv4Addr,
    path::Path,
    process::{Command, Output},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use rdashboard::{
    observer::{
        BoundObserverSocketV1, OBSERVER_SOCKET_PATH, ObserverRejectionCodeV1,
        ObserverRequestHandlerV1, ObserverServerConfig, PROJECT_RESOURCE_SNAPSHOT_SCHEMA_VERSION,
        ProjectResourceSnapshotV1, serve_until,
    },
    unix_time_ms,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const DOCKER: &str = "/usr/bin/docker";
const DOCKER_HOST: &str = "unix:///var/run/docker.sock";
const TIMEOUT: &str = "/usr/bin/timeout";
const DOCKER_COMMAND_TIMEOUT: &str = "1s";
const PROJECT_ID: &str = "rimg";
const ALLOWED_UID_ENV: &str = "RDASHBOARD_OBSERVER_ALLOWED_UID";
const MAX_DOCKER_OUTPUT_BYTES: usize = 16 * 1024;
const MAX_CANDIDATES: usize = 8;
const MAX_CONNECTIONS: usize = 4;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);
const INSPECT_FORMAT: &str = "{{.Id}}|{{.Created}}|{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}|{{with index .NetworkSettings.Networks \"kamal\"}}{{.IPAddress}}{{end}}|{{index .Config.Labels \"service\"}}|{{index .Config.Labels \"role\"}}";
const STATS_FORMAT: &str = "{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.BlockIO}}";
type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate {
    id: String,
    created: String,
    address: Ipv4Addr,
}

#[derive(Debug)]
struct InstalledObserver {
    project_id: rdashboard::domain::ProjectId,
}

impl InstalledObserver {
    fn new() -> Result<Self, ObserverError> {
        Ok(Self {
            project_id: PROJECT_ID
                .parse()
                .map_err(|_| ObserverError::InvalidInternalProjectId)?,
        })
    }
}

impl ObserverRequestHandlerV1 for InstalledObserver {
    fn observe_project_resources(
        &self,
        project_id: &rdashboard::domain::ProjectId,
    ) -> Result<ProjectResourceSnapshotV1, ObserverRejectionCodeV1> {
        if project_id != &self.project_id {
            return Err(ObserverRejectionCodeV1::ProjectNotConfigured);
        }
        let measurements = collect_resources(&DockerCli).map_err(|error| {
            warn!(error = %error, project_id = %project_id, "project resource collection failed");
            ObserverRejectionCodeV1::CollectionUnavailable
        })?;
        let observed_at_ms = unix_time_ms().map_err(|error| {
            warn!(error = %error, "observer clock is unavailable");
            ObserverRejectionCodeV1::InternalFailure
        })?;
        Ok(ProjectResourceSnapshotV1 {
            schema_version: PROJECT_RESOURCE_SNAPSHOT_SCHEMA_VERSION,
            observed_at_ms,
            cpu_percent: measurements.cpu_percent,
            memory_used_bytes: measurements.memory_used_bytes,
            memory_limit_bytes: measurements.memory_limit_bytes,
            network_rx_bytes: measurements.network_rx_bytes,
            network_tx_bytes: measurements.network_tx_bytes,
            block_read_bytes: measurements.block_read_bytes,
            block_write_bytes: measurements.block_write_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ResourceMeasurements {
    cpu_percent: f64,
    memory_used_bytes: u64,
    memory_limit_bytes: u64,
    network_rx_bytes: u64,
    network_tx_bytes: u64,
    block_read_bytes: u64,
    block_write_bytes: u64,
}

#[tokio::main]
async fn main() -> Result<(), DynError> {
    if std::env::args_os().len() != 1 {
        return Err(ObserverError::InvalidInvocation.into());
    }
    init_tracing()?;
    let allowed_uid = configured_allowed_uid(std::env::var_os(ALLOWED_UID_ENV))?;
    let server_config = ObserverServerConfig::new(allowed_uid, MAX_CONNECTIONS, REQUEST_TIMEOUT)?;
    let handler = Arc::new(InstalledObserver::new()?);
    let mut socket = BoundObserverSocketV1::bind(Path::new(OBSERVER_SOCKET_PATH), 0)?;
    let listener = socket.take_listener();
    info!(
        socket = %socket.path().display(),
        allowed_uid,
        "persistent resource observer listening"
    );
    serve_until(listener, handler, server_config, shutdown_signal()?).await?;
    Ok(())
}

fn configured_allowed_uid(value: Option<OsString>) -> Result<u32, ObserverError> {
    let value = value.ok_or(ObserverError::MissingAllowedUid)?;
    let value = value
        .into_string()
        .map_err(|_| ObserverError::InvalidAllowedUid)?;
    let uid = value
        .parse::<u32>()
        .map_err(|_| ObserverError::InvalidAllowedUid)?;
    if uid == 0 || uid == u32::MAX {
        return Err(ObserverError::InvalidAllowedUid);
    }
    Ok(uid)
}

trait DockerClient {
    fn output(&self, arguments: &[String]) -> Result<Output, ObserverError>;
}

struct DockerCli;

impl DockerClient for DockerCli {
    fn output(&self, arguments: &[String]) -> Result<Output, ObserverError> {
        docker_command(arguments)
            .output()
            .map_err(ObserverError::DockerExec)
    }
}

fn docker_command(arguments: &[String]) -> Command {
    let mut command = Command::new(TIMEOUT);
    command
        .arg("--signal=KILL")
        .arg(DOCKER_COMMAND_TIMEOUT)
        .arg(DOCKER)
        .arg("--host")
        .arg(DOCKER_HOST)
        .args(arguments);
    command
}

fn collect_resources(client: &impl DockerClient) -> Result<ResourceMeasurements, ObserverError> {
    let candidate = discover_target(client)?;
    let output = checked_docker_output(
        client,
        &strings(&[
            "stats",
            "--no-stream",
            "--format",
            STATS_FORMAT,
            &candidate.id,
        ]),
    )?;
    parse_resource_stats(&output.stdout)
}

fn discover_target(client: &impl DockerClient) -> Result<Candidate, ObserverError> {
    let output = checked_docker_output(
        client,
        &strings(&[
            "ps",
            "--no-trunc",
            "--filter",
            "label=service=rimg",
            "--filter",
            "label=role=web",
            "--filter",
            "status=running",
            "--format",
            "{{.ID}}",
        ]),
    )?;
    let identifiers = parse_container_ids(&output.stdout)?;
    if identifiers.is_empty() {
        return Err(ObserverError::NoHealthyContainer);
    }
    let mut arguments = strings(&["inspect", "--format", INSPECT_FORMAT]);
    arguments.extend(identifiers.iter().cloned());
    let inspections = checked_docker_output(client, &arguments)?;
    let candidates = parse_inspections(&identifiers, &inspections.stdout)?;
    newest_candidate(candidates).ok_or(ObserverError::NoHealthyContainer)
}

fn checked_docker_output(
    client: &impl DockerClient,
    arguments: &[String],
) -> Result<Output, ObserverError> {
    let output = client.output(arguments)?;
    if output.stdout.len() > MAX_DOCKER_OUTPUT_BYTES
        || output.stderr.len() > MAX_DOCKER_OUTPUT_BYTES
    {
        return Err(ObserverError::DockerOutputTooLarge);
    }
    if !output.status.success() {
        return Err(ObserverError::DockerFailure);
    }
    Ok(output)
}

fn parse_container_ids(stdout: &[u8]) -> Result<Vec<String>, ObserverError> {
    let text = std::str::from_utf8(stdout).map_err(|_| ObserverError::InvalidDockerOutput)?;
    let mut seen = HashSet::new();
    let mut identifiers = Vec::new();
    for line in text.lines() {
        if !valid_container_id(line) || !seen.insert(line) {
            return Err(ObserverError::InvalidDockerOutput);
        }
        identifiers.push(line.to_owned());
        if identifiers.len() > MAX_CANDIDATES {
            return Err(ObserverError::TooManyCandidates);
        }
    }
    Ok(identifiers)
}

fn valid_container_id(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn parse_inspections(
    expected_identifiers: &[String],
    stdout: &[u8],
) -> Result<Vec<Candidate>, ObserverError> {
    let text = std::str::from_utf8(stdout).map_err(|_| ObserverError::InvalidDockerOutput)?;
    let expected = expected_identifiers
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut observed = HashSet::new();
    let mut candidates = Vec::new();
    for line in text.lines() {
        let fields = line.split('|').collect::<Vec<_>>();
        if fields.len() != 7
            || !expected.contains(fields[0])
            || !observed.insert(fields[0])
            || fields[1].is_empty()
            || fields[1].len() > 64
        {
            return Err(ObserverError::InvalidDockerOutput);
        }
        if fields[2] != "true"
            || fields[3] != "healthy"
            || fields[5] != "rimg"
            || fields[6] != "web"
        {
            continue;
        }
        let address =
            Ipv4Addr::from_str(fields[4]).map_err(|_| ObserverError::InvalidDockerOutput)?;
        if !address.is_private() {
            return Err(ObserverError::NonPrivateContainerAddress(address));
        }
        candidates.push(Candidate {
            id: fields[0].to_owned(),
            created: fields[1].to_owned(),
            address,
        });
    }
    if observed.len() != expected.len() {
        return Err(ObserverError::InvalidDockerOutput);
    }
    Ok(candidates)
}

fn newest_candidate(candidates: Vec<Candidate>) -> Option<Candidate> {
    candidates.into_iter().max_by(|left, right| {
        left.created
            .cmp(&right.created)
            .then_with(|| left.id.cmp(&right.id))
    })
}

fn parse_resource_stats(stdout: &[u8]) -> Result<ResourceMeasurements, ObserverError> {
    let text = std::str::from_utf8(stdout).map_err(|_| ObserverError::InvalidDockerOutput)?;
    let mut lines = text.lines();
    let line = lines.next().ok_or(ObserverError::InvalidDockerOutput)?;
    if lines.next().is_some() {
        return Err(ObserverError::InvalidDockerOutput);
    }
    let fields = line.split('|').collect::<Vec<_>>();
    if fields.len() != 4 {
        return Err(ObserverError::InvalidDockerOutput);
    }
    let cpu_percent = parse_percent(fields[0])?;
    let (memory_used_bytes, memory_limit_bytes) = parse_byte_pair(fields[1])?;
    if memory_limit_bytes == 0 || memory_used_bytes > memory_limit_bytes {
        return Err(ObserverError::InvalidDockerOutput);
    }
    let (received_bytes, sent_bytes) = parse_byte_pair(fields[2])?;
    let (read_bytes, written_bytes) = parse_byte_pair(fields[3])?;
    Ok(ResourceMeasurements {
        cpu_percent,
        memory_used_bytes,
        memory_limit_bytes,
        network_rx_bytes: received_bytes,
        network_tx_bytes: sent_bytes,
        block_read_bytes: read_bytes,
        block_write_bytes: written_bytes,
    })
}

fn parse_byte_pair(value: &str) -> Result<(u64, u64), ObserverError> {
    let mut values = value.split('/');
    let first = values.next().ok_or(ObserverError::InvalidDockerOutput)?;
    let second = values.next().ok_or(ObserverError::InvalidDockerOutput)?;
    if values.next().is_some() {
        return Err(ObserverError::InvalidDockerOutput);
    }
    Ok((parse_byte_size(first)?, parse_byte_size(second)?))
}

fn parse_percent(value: &str) -> Result<f64, ObserverError> {
    let parsed = value
        .trim()
        .strip_suffix('%')
        .ok_or(ObserverError::InvalidDockerOutput)?
        .parse::<f64>()
        .map_err(|_| ObserverError::InvalidDockerOutput)?;
    if parsed.is_finite() && (0.0..=100_000.0).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(ObserverError::InvalidDockerOutput)
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn parse_byte_size(value: &str) -> Result<u64, ObserverError> {
    let value = value.trim();
    let suffix_start = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .ok_or(ObserverError::InvalidDockerOutput)?;
    let (number, suffix) = value.split_at(suffix_start);
    if number.is_empty() || number.matches('.').count() > 1 {
        return Err(ObserverError::InvalidDockerOutput);
    }
    let number = number
        .parse::<f64>()
        .map_err(|_| ObserverError::InvalidDockerOutput)?;
    let multiplier = match suffix {
        "B" => 1.0,
        "kB" | "KB" => 1_000.0,
        "MB" => 1_000_000.0,
        "GB" => 1_000_000_000.0,
        "TB" => 1_000_000_000_000.0,
        "PB" => 1_000_000_000_000_000.0,
        "KiB" => 1_024.0,
        "MiB" => 1_048_576.0,
        "GiB" => 1_073_741_824.0,
        "TiB" => 1_099_511_627_776.0,
        "PiB" => 1_125_899_906_842_624.0,
        _ => return Err(ObserverError::InvalidDockerOutput),
    };
    let bytes = number * multiplier;
    if !bytes.is_finite() || bytes < 0.0 || bytes > u64::MAX as f64 {
        return Err(ObserverError::InvalidDockerOutput);
    }
    Ok(bytes.round() as u64)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn init_tracing() -> Result<(), DynError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()?;
    Ok(())
}

fn shutdown_signal() -> io::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
    })
}

#[derive(Debug, thiserror::Error)]
enum ObserverError {
    #[error("rdashboard-observer accepts no arguments")]
    InvalidInvocation,
    #[error("{ALLOWED_UID_ENV} is required")]
    MissingAllowedUid,
    #[error("{ALLOWED_UID_ENV} must identify a non-root Unix account")]
    InvalidAllowedUid,
    #[error("the internal project ID is invalid")]
    InvalidInternalProjectId,
    #[error("the fixed Docker CLI could not be executed: {0}")]
    DockerExec(io::Error),
    #[error("the fixed Docker query failed or exceeded its one-second deadline")]
    DockerFailure,
    #[error("Docker returned more output than the bounded observer contract permits")]
    DockerOutputTooLarge,
    #[error("Docker returned malformed or ambiguous rimg container metadata")]
    InvalidDockerOutput,
    #[error("more rimg containers matched than the bounded observer contract permits")]
    TooManyCandidates,
    #[error("no running healthy rimg web container is attached to the kamal network")]
    NoHealthyContainer,
    #[error("the selected rimg container address is not private: {0}")]
    NonPrivateContainerAddress(Ipv4Addr),
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::VecDeque,
        ffi::OsStr,
        os::unix::process::ExitStatusExt as _,
        process::{ExitStatus, Output},
    };

    use super::*;

    const FIRST_ID: &str = "a111111111111111111111111111111111111111111111111111111111111111";
    const SECOND_ID: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    struct ScriptedDocker {
        steps: RefCell<VecDeque<(Vec<String>, Output)>>,
    }

    impl ScriptedDocker {
        fn new(steps: Vec<(Vec<String>, Output)>) -> Self {
            Self {
                steps: RefCell::new(steps.into()),
            }
        }

        fn assert_complete(&self) {
            assert!(self.steps.borrow().is_empty(), "unused Docker steps remain");
        }
    }

    impl DockerClient for ScriptedDocker {
        fn output(&self, arguments: &[String]) -> Result<Output, ObserverError> {
            let (expected, output) = self
                .steps
                .borrow_mut()
                .pop_front()
                .expect("unexpected Docker invocation");
            assert_eq!(arguments, expected);
            Ok(output)
        }
    }

    fn command_output(status: i32, stdout: impl Into<Vec<u8>>) -> Output {
        Output {
            status: ExitStatus::from_raw(status << 8),
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    fn list_arguments() -> Vec<String> {
        strings(&[
            "ps",
            "--no-trunc",
            "--filter",
            "label=service=rimg",
            "--filter",
            "label=role=web",
            "--filter",
            "status=running",
            "--format",
            "{{.ID}}",
        ])
    }

    #[test]
    fn fixed_docker_command_has_a_hard_subprocess_deadline() {
        let command = docker_command(&strings(&["ps", "--no-trunc"]));
        assert_eq!(command.get_program(), OsStr::new(TIMEOUT));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("--signal=KILL"),
                OsStr::new(DOCKER_COMMAND_TIMEOUT),
                OsStr::new(DOCKER),
                OsStr::new("--host"),
                OsStr::new(DOCKER_HOST),
                OsStr::new("ps"),
                OsStr::new("--no-trunc"),
            ]
        );
    }

    #[test]
    fn collection_uses_one_batched_inspection_and_returns_numeric_evidence() {
        let docker = ScriptedDocker::new(vec![
            (
                list_arguments(),
                command_output(0, format!("{FIRST_ID}\n{SECOND_ID}\n")),
            ),
            (
                {
                    let mut arguments = strings(&["inspect", "--format", INSPECT_FORMAT]);
                    arguments.extend([FIRST_ID.to_owned(), SECOND_ID.to_owned()]);
                    arguments
                },
                command_output(
                    0,
                    format!(
                        "{FIRST_ID}|2026-07-17T00:00:00Z|true|healthy|172.19.0.7|rimg|web\n{SECOND_ID}|2026-07-17T00:01:00Z|true|healthy|172.19.0.8|rimg|web\n"
                    ),
                ),
            ),
            (
                strings(&["stats", "--no-stream", "--format", STATS_FORMAT, SECOND_ID]),
                command_output(
                    0,
                    b"0.25%|21.06MiB / 15.61GiB|2.88MB / 3.87MB|14.6MB / 223MB\n".to_vec(),
                ),
            ),
        ]);

        let resources = collect_resources(&docker).expect("resource evidence");
        assert!((resources.cpu_percent - 0.25).abs() < f64::EPSILON);
        assert_eq!(resources.memory_used_bytes, 22_083_011);
        assert_eq!(resources.memory_limit_bytes, 16_761_109_873);
        assert_eq!(resources.network_tx_bytes, 3_870_000);
        assert_eq!(resources.block_write_bytes, 223_000_000);
        docker.assert_complete();
    }

    #[test]
    fn inspection_requires_exact_ids_health_labels_and_private_addresses() {
        assert!(
            parse_inspections(
                &[FIRST_ID.to_owned()],
                format!("{FIRST_ID}|2026-07-17T00:00:00Z|true|healthy|172.19.0.7|rimg|web\n")
                    .as_bytes(),
            )
            .is_ok()
        );
        for invalid in [
            format!("{FIRST_ID}|2026-07-17T00:00:00Z|true|healthy|8.8.8.8|rimg|web\n"),
            format!("{SECOND_ID}|2026-07-17T00:00:00Z|true|healthy|172.19.0.7|rimg|web\n"),
            format!(
                "{FIRST_ID}|2026-07-17T00:00:00Z|true|healthy|172.19.0.7|rimg|web\n{FIRST_ID}|2026-07-17T00:00:00Z|true|healthy|172.19.0.7|rimg|web\n"
            ),
        ] {
            assert!(parse_inspections(&[FIRST_ID.to_owned()], invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn parsing_rejects_unbounded_or_invalid_docker_measurements() {
        for invalid in [
            b"nan%|1MiB / 2MiB|1MB / 2MB|3MB / 4MB\n".as_slice(),
            b"0%|3MiB / 2MiB|1MB / 2MB|3MB / 4MB\n".as_slice(),
            b"0%|1watts / 2MiB|1MB / 2MB|3MB / 4MB\n".as_slice(),
        ] {
            assert!(parse_resource_stats(invalid).is_err());
        }
        assert_eq!(parse_byte_size("1KiB").expect("binary unit"), 1_024);
        assert_eq!(parse_byte_size("1kB").expect("decimal unit"), 1_000);
        assert!(parse_container_ids(&vec![b'x'; MAX_DOCKER_OUTPUT_BYTES + 1]).is_err());
    }

    #[test]
    fn installed_service_is_persistent_bounded_and_docker_is_observer_only() {
        let observer = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/deploy/systemd/rdashboard-observer.service"
        ));
        let controller = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/deploy/systemd/rdashboard.service"
        ));
        let fixed_environment = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/deploy/systemd/rdashboard-rimg-health.env"
        ));
        assert!(
            observer.contains(
                "ExecStart=/var/lib/rdashboard-bootstrap/current/bin/rdashboard-observer"
            )
        );
        assert!(observer.contains("RuntimeDirectory=rdashboard-observer"));
        assert!(observer.contains("MemoryMax=64M"));
        assert!(observer.contains("TasksMax=32"));
        assert!(observer.contains("Restart=on-failure"));
        assert!(!observer.contains("StandardInput=socket"));
        assert!(!controller.contains("docker.sock"));
        assert!(controller.contains("rdashboard-observer.service"));
        assert!(fixed_environment.contains(&format!(
            "RDASHBOARD_RIMG_RESOURCE_SOCKET={OBSERVER_SOCKET_PATH}"
        )));
    }
}
