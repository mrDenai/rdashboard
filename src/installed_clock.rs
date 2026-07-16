use std::{
    fs::{self, File},
    io::{self, Read as _},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::{
    backup::TrustedClockEvidenceV1,
    deploy_driver::{DeployClockSourceV1, DeployDriverError},
    domain::EvidenceDigest,
};

const CHRONYC_EXECUTABLE: &str = "/usr/bin/chronyc";
const CHRONYD_SOCKET: &str = "/run/chrony/chronyd.sock";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 4 * 1024;
const MAX_REFERENCE_AGE_MS: i64 = 60 * 60 * 1_000;
const MAX_REFERENCE_FUTURE_SKEW_MS: i64 = 1_000;

#[derive(Clone, Debug)]
pub struct InstalledChronyClockSourceV1 {
    executable: PathBuf,
    socket: PathBuf,
    required_uid: u32,
    timeout: Duration,
}

impl InstalledChronyClockSourceV1 {
    pub fn installed() -> Self {
        Self {
            executable: PathBuf::from(CHRONYC_EXECUTABLE),
            socket: PathBuf::from(CHRONYD_SOCKET),
            required_uid: 0,
            timeout: COMMAND_TIMEOUT,
        }
    }

    fn observe_tracking(
        &self,
        expected_executable_digest: &EvidenceDigest,
        now_ms: i64,
    ) -> Result<TrustedClockEvidenceV1, InstalledClockErrorV1> {
        if now_ms < 0 {
            return Err(InstalledClockErrorV1::InvalidTracking);
        }
        validate_executable(
            &self.executable,
            self.required_uid,
            expected_executable_digest,
        )?;
        let output = run_tracking_command(&self.executable, &self.socket, self.timeout)?;
        validate_executable(
            &self.executable,
            self.required_uid,
            expected_executable_digest,
        )?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(InstalledClockErrorV1::CommandFailed);
        }
        parse_tracking_output(
            &output.stdout,
            expected_executable_digest,
            &self.socket,
            now_ms,
        )
    }
}

impl DeployClockSourceV1 for InstalledChronyClockSourceV1 {
    fn observe(
        &self,
        expected_executable_digest: &EvidenceDigest,
        now_ms: i64,
    ) -> Result<TrustedClockEvidenceV1, DeployDriverError> {
        self.observe_tracking(expected_executable_digest, now_ms)
            .map_err(Into::into)
    }
}

#[derive(Debug)]
struct ChronyCommandOutputV1 {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_tracking_command(
    executable: &Path,
    socket: &Path,
    timeout: Duration,
) -> Result<ChronyCommandOutputV1, InstalledClockErrorV1> {
    let mut child = Command::new(executable)
        .args(["-c", "-n", "-h"])
        .arg(socket)
        .arg("tracking")
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or(InstalledClockErrorV1::CommandFailed)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(InstalledClockErrorV1::CommandFailed)?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => thread::sleep(COMMAND_POLL_INTERVAL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = join_reader(stdout_reader);
                let _ = join_reader(stderr_reader);
                return Err(InstalledClockErrorV1::CommandDeadlineExceeded);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = join_reader(stdout_reader);
                let _ = join_reader(stderr_reader);
                return Err(error.into());
            }
        }
    };
    Ok(ChronyCommandOutputV1 {
        status,
        stdout: join_reader(stdout_reader)?,
        stderr: join_reader(stderr_reader)?,
    })
}

fn read_bounded(pipe: impl io::Read) -> Result<Vec<u8>, InstalledClockErrorV1> {
    let mut bytes = Vec::with_capacity(MAX_COMMAND_OUTPUT_BYTES);
    pipe.take(u64::try_from(MAX_COMMAND_OUTPUT_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_COMMAND_OUTPUT_BYTES {
        Err(InstalledClockErrorV1::CommandOutputTooLarge)
    } else {
        Ok(bytes)
    }
}

fn join_reader(
    reader: thread::JoinHandle<Result<Vec<u8>, InstalledClockErrorV1>>,
) -> Result<Vec<u8>, InstalledClockErrorV1> {
    reader
        .join()
        .map_err(|_| InstalledClockErrorV1::CommandReaderFailed)?
}

fn parse_tracking_output(
    output: &[u8],
    executable_digest: &EvidenceDigest,
    socket: &Path,
    now_ms: i64,
) -> Result<TrustedClockEvidenceV1, InstalledClockErrorV1> {
    if output.is_empty()
        || output.len() > MAX_COMMAND_OUTPUT_BYTES
        || !output.is_ascii()
        || now_ms < 0
    {
        return Err(InstalledClockErrorV1::InvalidTracking);
    }
    let text = std::str::from_utf8(output).map_err(|_| InstalledClockErrorV1::InvalidTracking)?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.is_empty() || line.contains(['\n', '\r']) {
        return Err(InstalledClockErrorV1::InvalidTracking);
    }
    let fields = line.split(',').collect::<Vec<_>>();
    if fields.len() != 14
        || !valid_reference_id(fields[0])
        || !valid_reference_address(fields[1])
        || !(1..=15).contains(&parse_number::<u8>(fields[2])?)
        || fields[13] != "Normal"
    {
        return Err(InstalledClockErrorV1::InvalidTracking);
    }
    let reference_time_ms = decimal_seconds_to_millis(fields[3], false)?;
    let estimated_offset_ms = decimal_seconds_to_millis(fields[4], true)?;
    let _last_offset = parse_finite(fields[5])?;
    let _rms_offset = parse_nonnegative(fields[6])?;
    let _frequency = parse_finite(fields[7])?;
    let _residual_frequency = parse_finite(fields[8])?;
    let _skew = parse_nonnegative(fields[9])?;
    let _root_delay = parse_nonnegative(fields[10])?;
    let _root_dispersion = parse_nonnegative(fields[11])?;
    let update_interval = parse_nonnegative(fields[12])?;
    let age_ms = now_ms
        .checked_sub(reference_time_ms)
        .ok_or(InstalledClockErrorV1::InvalidTracking)?;
    if reference_time_ms <= 0
        || !(-MAX_REFERENCE_FUTURE_SKEW_MS..=MAX_REFERENCE_AGE_MS).contains(&age_ms)
        || update_interval == 0.0
    {
        return Err(InstalledClockErrorV1::InvalidTracking);
    }
    let socket = socket
        .to_str()
        .ok_or(InstalledClockErrorV1::InvalidTracking)?;
    let observation_digest = EvidenceDigest::sha256(serde_jcs::to_vec(&(
        "rdashboard.chrony-tracking-observation.v1",
        executable_digest,
        socket,
        line,
        now_ms,
    ))?);
    TrustedClockEvidenceV1::new(true, estimated_offset_ms, now_ms, observation_digest)
        .map_err(Into::into)
}

fn parse_number<T: std::str::FromStr>(value: &str) -> Result<T, InstalledClockErrorV1> {
    value
        .parse()
        .map_err(|_| InstalledClockErrorV1::InvalidTracking)
}

fn parse_finite(value: &str) -> Result<f64, InstalledClockErrorV1> {
    let value = parse_number::<f64>(value)?;
    if value.is_finite() {
        Ok(value)
    } else {
        Err(InstalledClockErrorV1::InvalidTracking)
    }
}

fn parse_nonnegative(value: &str) -> Result<f64, InstalledClockErrorV1> {
    let value = parse_finite(value)?;
    if value >= 0.0 {
        Ok(value)
    } else {
        Err(InstalledClockErrorV1::InvalidTracking)
    }
}

fn decimal_seconds_to_millis(
    value: &str,
    round_away_from_zero: bool,
) -> Result<i64, InstalledClockErrorV1> {
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |unsigned| (true, unsigned));
    if negative && unsigned.starts_with('+') {
        return Err(InstalledClockErrorV1::InvalidTracking);
    }
    let unsigned = unsigned.strip_prefix('+').unwrap_or(unsigned);
    let (whole, fraction) = unsigned
        .split_once('.')
        .ok_or(InstalledClockErrorV1::InvalidTracking)?;
    if whole.is_empty()
        || fraction.is_empty()
        || fraction.len() > 9
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(InstalledClockErrorV1::InvalidTracking);
    }
    let whole = parse_number::<i128>(whole)?;
    let fraction_scale =
        u32::try_from(9 - fraction.len()).map_err(|_| InstalledClockErrorV1::InvalidTracking)?;
    let fraction = parse_number::<i128>(fraction)?
        .checked_mul(10_i128.pow(fraction_scale))
        .ok_or(InstalledClockErrorV1::InvalidTracking)?;
    let nanoseconds = whole
        .checked_mul(1_000_000_000)
        .and_then(|whole| whole.checked_add(fraction))
        .ok_or(InstalledClockErrorV1::InvalidTracking)?;
    let rounding = if round_away_from_zero && nanoseconds % 1_000_000 != 0 {
        999_999
    } else {
        500_000
    };
    let milliseconds = nanoseconds
        .checked_add(rounding)
        .ok_or(InstalledClockErrorV1::InvalidTracking)?
        / 1_000_000;
    let signed = if negative {
        milliseconds
            .checked_neg()
            .ok_or(InstalledClockErrorV1::InvalidTracking)?
    } else {
        milliseconds
    };
    i64::try_from(signed).map_err(|_| InstalledClockErrorV1::InvalidTracking)
}

fn valid_reference_id(value: &str) -> bool {
    value.len() == 8 && value != "00000000" && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_reference_address(value: &str) -> bool {
    (1..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn validate_executable(
    path: &Path,
    required_uid: u32,
    expected_digest: &EvidenceDigest,
) -> Result<(), InstalledClockErrorV1> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.mode() & 0o022 != 0
        || path_metadata.mode() & 0o111 == 0
        || path_metadata.len() == 0
        || path_metadata.len() > MAX_EXECUTABLE_BYTES
    {
        return Err(InstalledClockErrorV1::UnsafeExecutable);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened_metadata.len())
            .map_err(|_| InstalledClockErrorV1::UnsafeExecutable)?,
    );
    file.take(MAX_EXECUTABLE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_EXECUTABLE_BYTES
        || path_metadata.dev() != opened_metadata.dev()
        || path_metadata.ino() != opened_metadata.ino()
        || path_metadata.len() != opened_metadata.len()
        || final_metadata.file_type().is_symlink()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
        || &EvidenceDigest::sha256(&bytes) != expected_digest
    {
        return Err(InstalledClockErrorV1::UnsafeExecutable);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum InstalledClockErrorV1 {
    #[error("the installed chronyc executable is not the exact stable root-owned binary")]
    UnsafeExecutable,
    #[error("the local chronyc tracking command failed")]
    CommandFailed,
    #[error("the local chronyc tracking command exceeded its deadline")]
    CommandDeadlineExceeded,
    #[error("the local chronyc tracking output exceeded its bound")]
    CommandOutputTooLarge,
    #[error("a chronyc output reader failed")]
    CommandReaderFailed,
    #[error("chronyc did not report a recent synchronized local clock")]
    InvalidTracking,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Backup(#[from] crate::backup::BackupContractError),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::tempdir;

    use super::*;

    const NOW_MS: i64 = 1_700_000_100_000;
    const TRACKING: &str = "C0A87B01,192.168.123.1,2,1700000000.000000,0.001400000,-0.000300000,0.000500000,1.250,-0.010,0.050,0.010000000,0.002000000,64.0,Normal\n";

    #[test]
    fn exact_local_tracking_report_produces_bound_clock_evidence() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let executable = directory.path().join("chronyc");
        let script = format!("#!/bin/sh\nprintf '%s' '{}'\n", TRACKING.trim_end());
        fs::write(&executable, script.as_bytes())
            .unwrap_or_else(|error| panic!("write fake chronyc: {error}"));
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("chmod fake chronyc: {error}"));
        let required_uid = fs::metadata(&executable)
            .unwrap_or_else(|error| panic!("fake chronyc metadata: {error}"))
            .uid();
        let digest = EvidenceDigest::sha256(script.as_bytes());
        let source = InstalledChronyClockSourceV1 {
            executable,
            socket: directory.path().join("chronyd.sock"),
            required_uid,
            timeout: Duration::from_secs(1),
        };

        let evidence = source
            .observe_tracking(&digest, NOW_MS)
            .unwrap_or_else(|error| panic!("clock evidence: {error}"));

        assert!(evidence.synchronized);
        assert_eq!(evidence.estimated_offset_ms, 2);
        assert_eq!(evidence.observed_at_ms, NOW_MS);
        assert_ne!(evidence.observation_digest, digest);
    }

    #[test]
    fn tracking_parser_rejects_unsynchronized_stale_and_ambiguous_reports() {
        let digest = EvidenceDigest::sha256("chronyc");
        let socket = Path::new(CHRONYD_SOCKET);
        for invalid in [
            TRACKING.replace(",Normal\n", ",Not synchronised\n"),
            TRACKING.replace("1700000000.000000", "1699990000.000000"),
            TRACKING.replace(",Normal\n", ",Normal,extra\n"),
            TRACKING.replace("0.001400000", "NaN"),
        ] {
            assert!(matches!(
                parse_tracking_output(invalid.as_bytes(), &digest, socket, NOW_MS),
                Err(InstalledClockErrorV1::InvalidTracking)
            ));
        }
    }
}
