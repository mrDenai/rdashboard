#[cfg(unix)]
mod unix {
    use std::{
        collections::HashSet,
        ffi::OsString,
        io,
        net::Ipv4Addr,
        os::unix::process::CommandExt,
        process::{Command, Output},
        str::FromStr,
    };

    const DOCKER: &str = "/usr/bin/docker";
    const DOCKER_HOST: &str = "unix:///var/run/docker.sock";
    const SOCKET_PROXY: &str = "/usr/lib/systemd/systemd-socket-proxyd";
    const RIMG_PORT: u16 = 8080;
    const MAX_DOCKER_OUTPUT_BYTES: usize = 16 * 1024;
    const MAX_CANDIDATES: usize = 32;
    const INSPECT_FORMAT: &str = "{{.Created}}|{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}|{{with index .NetworkSettings.Networks \"kamal\"}}{{.IPAddress}}{{end}}|{{index .Config.Labels \"service\"}}|{{index .Config.Labels \"role\"}}";

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Candidate {
        id: String,
        created: String,
        address: Ipv4Addr,
    }

    pub fn run(arguments: impl Iterator<Item = OsString>) -> Result<(), ProxyError> {
        let arguments = arguments.collect::<Vec<_>>();
        match arguments.as_slice() {
            [] => run_health_proxy(),
            _ => Err(ProxyError::InvalidInvocation),
        }
    }

    fn run_health_proxy() -> Result<(), ProxyError> {
        let candidate = discover_target(&DockerCli)?;
        let error = socket_proxy_command(candidate.address).exec();
        Err(ProxyError::SocketProxyExec(error))
    }

    fn socket_proxy_command(address: Ipv4Addr) -> Command {
        let mut command = Command::new(SOCKET_PROXY);
        command
            .arg("--connections-max=8")
            .arg("--exit-idle-time=1s")
            .arg(format!("{address}:{RIMG_PORT}"));
        command
    }

    trait DockerClient {
        fn output(&self, arguments: &[&str]) -> Result<Output, ProxyError>;
    }

    struct DockerCli;

    impl DockerClient for DockerCli {
        fn output(&self, arguments: &[&str]) -> Result<Output, ProxyError> {
            docker_command(arguments)
                .output()
                .map_err(ProxyError::DockerExec)
        }
    }

    fn discover_target(client: &impl DockerClient) -> Result<Candidate, ProxyError> {
        let output = checked_docker_output(
            client,
            &[
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
            ],
        )?;
        let identifiers = parse_container_ids(&output.stdout)?;
        let mut candidates = Vec::with_capacity(identifiers.len());
        for identifier in identifiers {
            if let Some(inspected) = inspect_candidate(client, &identifier)?
                && let Some(candidate) = parse_inspection(&identifier, &inspected.stdout)?
            {
                candidates.push(candidate);
            }
        }
        newest_candidate(candidates).ok_or(ProxyError::NoHealthyContainer)
    }

    fn inspect_candidate(
        client: &impl DockerClient,
        identifier: &str,
    ) -> Result<Option<Output>, ProxyError> {
        let output = docker_output(client, &["inspect", "--format", INSPECT_FORMAT, identifier])?;
        if output.status.success() {
            return Ok(Some(output));
        }
        if container_still_exists(client, identifier)? {
            return Err(ProxyError::DockerFailure);
        }
        Ok(None)
    }

    fn container_still_exists(
        client: &impl DockerClient,
        identifier: &str,
    ) -> Result<bool, ProxyError> {
        let output = checked_docker_output(
            client,
            &[
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                &format!("id={identifier}"),
                "--format",
                "{{.ID}}",
            ],
        )?;
        let current = parse_container_ids(&output.stdout)?;
        match current.as_slice() {
            [] => Ok(false),
            [current] if current == identifier => Ok(true),
            _ => Err(ProxyError::InvalidDockerOutput),
        }
    }

    fn docker_command(arguments: &[&str]) -> Command {
        let mut command = Command::new(DOCKER);
        command.arg("--host").arg(DOCKER_HOST).args(arguments);
        command
    }

    fn docker_output(client: &impl DockerClient, arguments: &[&str]) -> Result<Output, ProxyError> {
        let output = client.output(arguments)?;
        validate_output_size(&output)?;
        Ok(output)
    }

    fn checked_docker_output(
        client: &impl DockerClient,
        arguments: &[&str],
    ) -> Result<Output, ProxyError> {
        let output = docker_output(client, arguments)?;
        if !output.status.success() {
            return Err(ProxyError::DockerFailure);
        }
        Ok(output)
    }

    fn validate_output_size(output: &Output) -> Result<(), ProxyError> {
        if output.stdout.len() > MAX_DOCKER_OUTPUT_BYTES
            || output.stderr.len() > MAX_DOCKER_OUTPUT_BYTES
        {
            return Err(ProxyError::DockerOutputTooLarge);
        }
        Ok(())
    }

    fn parse_container_ids(stdout: &[u8]) -> Result<Vec<String>, ProxyError> {
        let text = std::str::from_utf8(stdout).map_err(|_| ProxyError::InvalidDockerOutput)?;
        let mut seen = HashSet::new();
        let mut identifiers = Vec::new();
        for line in text.lines() {
            if line.len() != 64
                || !line
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                || !seen.insert(line)
            {
                return Err(ProxyError::InvalidDockerOutput);
            }
            identifiers.push(line.to_owned());
            if identifiers.len() > MAX_CANDIDATES {
                return Err(ProxyError::TooManyCandidates);
            }
        }
        Ok(identifiers)
    }

    fn parse_inspection(identifier: &str, stdout: &[u8]) -> Result<Option<Candidate>, ProxyError> {
        let text = std::str::from_utf8(stdout).map_err(|_| ProxyError::InvalidDockerOutput)?;
        let mut lines = text.lines();
        let line = lines.next().ok_or(ProxyError::InvalidDockerOutput)?;
        if lines.next().is_some() {
            return Err(ProxyError::InvalidDockerOutput);
        }
        let fields = line.split('|').collect::<Vec<_>>();
        if fields.len() != 6 || fields[0].is_empty() || fields[0].len() > 64 {
            return Err(ProxyError::InvalidDockerOutput);
        }
        if fields[1] != "true"
            || fields[2] != "healthy"
            || fields[4] != "rimg"
            || fields[5] != "web"
        {
            return Ok(None);
        }
        let address = Ipv4Addr::from_str(fields[3]).map_err(|_| ProxyError::InvalidDockerOutput)?;
        if !address.is_private() {
            return Err(ProxyError::NonPrivateContainerAddress(address));
        }
        Ok(Some(Candidate {
            id: identifier.to_owned(),
            created: fields[0].to_owned(),
            address,
        }))
    }

    fn newest_candidate(candidates: Vec<Candidate>) -> Option<Candidate> {
        candidates.into_iter().max_by(|left, right| {
            left.created
                .cmp(&right.created)
                .then_with(|| left.id.cmp(&right.id))
        })
    }

    #[derive(Debug, thiserror::Error)]
    pub enum ProxyError {
        #[error("expected no arguments")]
        InvalidInvocation,
        #[error("the fixed Docker CLI could not be executed: {0}")]
        DockerExec(io::Error),
        #[error("the fixed Docker query failed")]
        DockerFailure,
        #[error("Docker returned more output than the bounded proxy contract permits")]
        DockerOutputTooLarge,
        #[error("Docker returned malformed or ambiguous rimg container metadata")]
        InvalidDockerOutput,
        #[error("more rimg containers matched than the bounded proxy contract permits")]
        TooManyCandidates,
        #[error("no running healthy rimg web container is attached to the kamal network")]
        NoHealthyContainer,
        #[error("the selected rimg container address is not private: {0}")]
        NonPrivateContainerAddress(Ipv4Addr),
        #[error("the fixed systemd socket proxy could not be executed: {0}")]
        SocketProxyExec(io::Error),
    }

    #[cfg(test)]
    mod tests {
        use super::{
            Candidate, DockerClient, INSPECT_FORMAT, MAX_DOCKER_OUTPUT_BYTES, ProxyError,
            SOCKET_PROXY, discover_target, newest_candidate, parse_container_ids, parse_inspection,
            socket_proxy_command, validate_output_size,
        };
        use std::{
            cell::RefCell,
            collections::VecDeque,
            ffi::OsStr,
            net::Ipv4Addr,
            os::unix::process::ExitStatusExt,
            process::{ExitStatus, Output},
        };

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
            fn output(&self, arguments: &[&str]) -> Result<Output, super::ProxyError> {
                let (expected, output) = self
                    .steps
                    .borrow_mut()
                    .pop_front()
                    .expect("unexpected Docker invocation");
                assert_eq!(
                    arguments
                        .iter()
                        .map(|argument| (*argument).to_owned())
                        .collect::<Vec<_>>(),
                    expected
                );
                Ok(output)
            }
        }

        fn arguments(values: &[&str]) -> Vec<String> {
            values.iter().map(|value| (*value).to_owned()).collect()
        }

        fn command_output(status: i32, stdout: impl Into<Vec<u8>>) -> Output {
            Output {
                status: ExitStatus::from_raw(status << 8),
                stdout: stdout.into(),
                stderr: Vec::new(),
            }
        }

        fn initial_list_arguments() -> Vec<String> {
            arguments(&[
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
        fn container_ids_are_full_unique_lowercase_digests() {
            let output = format!("{FIRST_ID}\n{SECOND_ID}\n");
            assert_eq!(
                parse_container_ids(output.as_bytes()).expect("valid IDs"),
                [FIRST_ID.to_owned(), SECOND_ID.to_owned()]
            );
            for invalid in [
                "short\n".to_owned(),
                format!("{}\n", FIRST_ID.to_uppercase()),
                format!("{FIRST_ID}\n{FIRST_ID}\n"),
            ] {
                assert!(parse_container_ids(invalid.as_bytes()).is_err());
            }
        }

        #[test]
        fn inspection_requires_revalidated_health_labels_and_private_kamal_address() {
            let valid = b"2026-07-17T00:00:00.000000000Z|true|healthy|172.19.0.7|rimg|web\n";
            assert_eq!(
                parse_inspection(FIRST_ID, valid)
                    .expect("valid metadata")
                    .expect("eligible container")
                    .address,
                Ipv4Addr::new(172, 19, 0, 7)
            );
            for ineligible in [
                b"2026-07-17T00:00:00Z|false|healthy|172.19.0.7|rimg|web\n".as_slice(),
                b"2026-07-17T00:00:00Z|true|starting|172.19.0.7|rimg|web\n".as_slice(),
                b"2026-07-17T00:00:00Z|true|healthy|172.19.0.7|other|web\n".as_slice(),
            ] {
                assert!(
                    parse_inspection(FIRST_ID, ineligible)
                        .expect("well-formed metadata")
                        .is_none()
                );
            }
            assert!(
                parse_inspection(
                    FIRST_ID,
                    b"2026-07-17T00:00:00Z|true|healthy|8.8.8.8|rimg|web\n"
                )
                .is_err()
            );
        }

        #[test]
        fn newest_healthy_candidate_wins_deterministically() {
            let first = Candidate {
                id: FIRST_ID.to_owned(),
                created: "2026-07-17T00:00:00Z".to_owned(),
                address: Ipv4Addr::new(172, 19, 0, 7),
            };
            let second = Candidate {
                id: SECOND_ID.to_owned(),
                created: "2026-07-17T00:01:00Z".to_owned(),
                address: Ipv4Addr::new(172, 19, 0, 8),
            };
            assert_eq!(newest_candidate(vec![first, second.clone()]), Some(second));
        }

        #[test]
        fn discovery_skips_only_a_candidate_confirmed_removed_during_inspection() {
            let docker = ScriptedDocker::new(vec![
                (
                    initial_list_arguments(),
                    command_output(0, format!("{FIRST_ID}\n{SECOND_ID}\n")),
                ),
                (
                    arguments(&["inspect", "--format", INSPECT_FORMAT, FIRST_ID]),
                    command_output(1, Vec::new()),
                ),
                (
                    arguments(&[
                        "ps",
                        "--all",
                        "--no-trunc",
                        "--filter",
                        &format!("id={FIRST_ID}"),
                        "--format",
                        "{{.ID}}",
                    ]),
                    command_output(0, Vec::new()),
                ),
                (
                    arguments(&["inspect", "--format", INSPECT_FORMAT, SECOND_ID]),
                    command_output(
                        0,
                        b"2026-07-17T00:01:00.000000000Z|true|healthy|172.19.0.8|rimg|web\n"
                            .to_vec(),
                    ),
                ),
            ]);

            let candidate = discover_target(&docker).expect("remaining healthy candidate");
            assert_eq!(candidate.id, SECOND_ID);
            assert_eq!(candidate.address, Ipv4Addr::new(172, 19, 0, 8));
            docker.assert_complete();
        }

        #[test]
        fn discovery_does_not_hide_an_inspection_failure_for_an_existing_container() {
            let docker = ScriptedDocker::new(vec![
                (
                    initial_list_arguments(),
                    command_output(0, format!("{FIRST_ID}\n")),
                ),
                (
                    arguments(&["inspect", "--format", INSPECT_FORMAT, FIRST_ID]),
                    command_output(1, Vec::new()),
                ),
                (
                    arguments(&[
                        "ps",
                        "--all",
                        "--no-trunc",
                        "--filter",
                        &format!("id={FIRST_ID}"),
                        "--format",
                        "{{.ID}}",
                    ]),
                    command_output(0, format!("{FIRST_ID}\n")),
                ),
            ]);

            assert!(discover_target(&docker).is_err());
            docker.assert_complete();
        }

        #[test]
        fn discovery_reports_no_healthy_container_for_empty_or_ineligible_results() {
            let empty = ScriptedDocker::new(vec![(
                initial_list_arguments(),
                command_output(0, Vec::new()),
            )]);
            assert!(matches!(
                discover_target(&empty),
                Err(ProxyError::NoHealthyContainer)
            ));
            empty.assert_complete();

            let ineligible = ScriptedDocker::new(vec![
                (
                    initial_list_arguments(),
                    command_output(0, format!("{FIRST_ID}\n")),
                ),
                (
                    arguments(&["inspect", "--format", INSPECT_FORMAT, FIRST_ID]),
                    command_output(
                        0,
                        b"2026-07-17T00:01:00.000000000Z|true|starting|172.19.0.8|rimg|web\n"
                            .to_vec(),
                    ),
                ),
            ]);
            assert!(matches!(
                discover_target(&ineligible),
                Err(ProxyError::NoHealthyContainer)
            ));
            ineligible.assert_complete();
        }

        #[test]
        fn docker_output_and_socket_proxy_command_remain_bounded_and_fixed() {
            let oversized = command_output(0, vec![b'x'; MAX_DOCKER_OUTPUT_BYTES + 1]);
            assert!(validate_output_size(&oversized).is_err());

            let command = socket_proxy_command(Ipv4Addr::new(172, 19, 0, 8));
            assert_eq!(command.get_program(), OsStr::new(SOCKET_PROXY));
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                [
                    OsStr::new("--connections-max=8"),
                    OsStr::new("--exit-idle-time=1s"),
                    OsStr::new("172.19.0.8:8080"),
                ]
            );
        }

        #[test]
        fn installed_units_keep_docker_authority_out_of_the_controller() {
            let controller = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/deploy/systemd/rdashboard.service"
            ));
            let service = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/deploy/systemd/rdashboard-rimg-health.service"
            ));
            let socket = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/deploy/systemd/rdashboard-rimg-health.socket"
            ));
            let fixed_environment = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/deploy/systemd/rdashboard-rimg-health.env"
            ));
            let operator_environment = controller
                .find("EnvironmentFile=-/etc/rdashboard/controller.env")
                .expect("operator environment is optional");
            let fixed_environment_file = controller
                .find("EnvironmentFile=/usr/lib/rdashboard/rdashboard-rimg-health.env")
                .expect("fixed rimg environment is installed");
            assert!(operator_environment < fixed_environment_file);
            assert!(
                fixed_environment
                    .lines()
                    .any(|line| line == "RDASHBOARD_RIMG_BASE_URL=http://127.0.0.1:18080")
            );
            assert!(fixed_environment.lines().any(|line| {
                line == "RDASHBOARD_RIMG_RESOURCE_SOCKET=/run/rdashboard-observer/observer.sock"
            }));
            assert!(!controller.contains("docker.sock"));
            assert!(service.contains(
                "ExecStart=/var/lib/rdashboard-bootstrap/current/bin/rdashboard-rimg-health-proxy"
            ));
            assert!(
                service
                    .lines()
                    .any(|line| line == "StartLimitIntervalSec=0")
            );
            assert!(service.lines().any(|line| line == "CapabilityBoundingSet="));
            assert!(
                socket
                    .lines()
                    .any(|line| line == "ListenStream=127.0.0.1:18080")
            );
        }
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match unix::run(std::env::args_os().skip(1)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rdashboard-rimg-health-proxy: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("rdashboard-rimg-health-proxy is supported only on Unix");
}
