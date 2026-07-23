use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead as _, BufReader, Read as _, Write as _},
    net::{IpAddr, SocketAddr, TcpStream},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr as _,
    time::{Duration, Instant},
};

use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::{
    domain::EvidenceDigest,
    titanium::{
        TitaniumArtifactKindV1, TitaniumRegistryError, TitaniumRegistryV1,
        TitaniumReleaseActivationV1,
    },
};

pub const MANAGED_NATIVE_RELEASE_ROOT: &str = "/var/lib/rdashboard-managed";
pub const MANAGED_NATIVE_POLICY_ROOT: &str = "/etc/rdashboard/native-runtimes";

const POLICY_PURPOSE: &str = "rdashboard.managed-native-runtime-policy.v1";
const JOURNAL_PURPOSE: &str = "rdashboard.managed-native-release-journal.v1";
const SCHEMA_VERSION: u16 = 1;
const MAX_POLICY_BYTES: u64 = 64 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024;
const MAX_HTTP_STATUS_LINE_BYTES: u64 = 512;
const MAX_SYSTEMD_PROPERTY_BYTES: usize = 64 * 1024;
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const NATIVE_RELEASE_RECOVERY_UNIT: &str = "rdashboard-native-release-recovery.service";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedNativeRuntimePolicyV1 {
    purpose: String,
    schema_version: u16,
    pub project_id: String,
    pub target: String,
    pub release_interface: String,
    pub entrypoint: String,
    pub runtime_contract_digest: EvidenceDigest,
    pub systemd_unit: String,
    pub systemd_unit_sha256: EvidenceDigest,
    pub health_url: String,
    pub health_expected_status: u16,
    pub health_timeout_ms: u64,
    pub policy_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedNativeRuntimePolicyInputV1 {
    pub project_id: String,
    pub target: String,
    pub release_interface: String,
    pub entrypoint: String,
    pub runtime_contract_digest: EvidenceDigest,
    pub systemd_unit_sha256: EvidenceDigest,
    pub health_url: String,
    pub health_expected_status: u16,
    pub health_timeout_ms: u64,
}

#[derive(Serialize)]
struct PolicyPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a str,
    target: &'a str,
    release_interface: &'a str,
    entrypoint: &'a str,
    runtime_contract_digest: &'a EvidenceDigest,
    systemd_unit: &'a str,
    systemd_unit_sha256: &'a EvidenceDigest,
    health_url: &'a str,
    health_expected_status: u16,
    health_timeout_ms: u64,
}

impl ManagedNativeRuntimePolicyV1 {
    pub fn load_installed(project_id: &str) -> Result<Self, NativeReleaseError> {
        if !valid_component(project_id) {
            return Err(NativeReleaseError::InvalidPolicy);
        }
        let bytes = read_stable_file(
            &Path::new(MANAGED_NATIVE_POLICY_ROOT).join(format!("{project_id}.jcs")),
            0,
            0o644,
            MAX_POLICY_BYTES,
        )?;
        let value = Self::decode_canonical(&bytes)?;
        if value.project_id != project_id {
            return Err(NativeReleaseError::InvalidPolicy);
        }
        Ok(value)
    }

    pub fn new(input: ManagedNativeRuntimePolicyInputV1) -> Result<Self, NativeReleaseError> {
        let systemd_unit = format!("{}.service", input.project_id);
        let mut value = Self {
            purpose: POLICY_PURPOSE.to_owned(),
            schema_version: SCHEMA_VERSION,
            project_id: input.project_id,
            target: input.target,
            release_interface: input.release_interface,
            entrypoint: input.entrypoint,
            runtime_contract_digest: input.runtime_contract_digest,
            systemd_unit,
            systemd_unit_sha256: input.systemd_unit_sha256,
            health_url: input.health_url,
            health_expected_status: input.health_expected_status,
            health_timeout_ms: input.health_timeout_ms,
            policy_digest: EvidenceDigest::sha256([]),
        };
        value.policy_digest = value.calculate_digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NativeReleaseError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, NativeReleaseError> {
        let value: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&value)? != bytes {
            return Err(NativeReleaseError::NoncanonicalDocument);
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), NativeReleaseError> {
        if self.purpose != POLICY_PURPOSE
            || self.schema_version != SCHEMA_VERSION
            || !valid_component(&self.project_id)
            || !valid_component(&self.target)
            || !valid_component(&self.release_interface)
            || !valid_relative_path(&self.entrypoint)
            || self.systemd_unit != format!("{}.service", self.project_id)
            || !(100..=599).contains(&self.health_expected_status)
            || !(1_000..=120_000).contains(&self.health_timeout_ms)
            || parse_loopback_health_url(&self.health_url).is_err()
            || self.policy_digest != self.calculate_digest()?
        {
            return Err(NativeReleaseError::InvalidPolicy);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, NativeReleaseError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(&PolicyPayload {
            purpose: POLICY_PURPOSE,
            schema_version: SCHEMA_VERSION,
            project_id: &self.project_id,
            target: &self.target,
            release_interface: &self.release_interface,
            entrypoint: &self.entrypoint,
            runtime_contract_digest: &self.runtime_contract_digest,
            systemd_unit: &self.systemd_unit,
            systemd_unit_sha256: &self.systemd_unit_sha256,
            health_url: &self.health_url,
            health_expected_status: self.health_expected_status,
            health_timeout_ms: self.health_timeout_ms,
        })?))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationPhaseV1 {
    Prepared,
    CandidateLinked,
    CandidateRestarted,
    RollbackSwitchPending,
    RollbackLinked,
    RollbackRestarted,
    FirstRejectionPending,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeReleaseJournalV1 {
    purpose: String,
    schema_version: u16,
    project_id: String,
    policy_digest: EvidenceDigest,
    activation: SerializableActivationV1,
    phase: ActivationPhaseV1,
    updated_at_ms: i64,
    document_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SerializableActivationV1 {
    project_id: String,
    candidate_artifact: EvidenceDigest,
    previous_current_artifact: Option<EvidenceDigest>,
}

impl From<&TitaniumReleaseActivationV1> for SerializableActivationV1 {
    fn from(value: &TitaniumReleaseActivationV1) -> Self {
        Self {
            project_id: value.project_id.clone(),
            candidate_artifact: value.candidate_artifact.clone(),
            previous_current_artifact: value.previous_current_artifact.clone(),
        }
    }
}

impl From<&SerializableActivationV1> for TitaniumReleaseActivationV1 {
    fn from(value: &SerializableActivationV1) -> Self {
        Self {
            project_id: value.project_id.clone(),
            candidate_artifact: value.candidate_artifact.clone(),
            previous_current_artifact: value.previous_current_artifact.clone(),
        }
    }
}

#[derive(Serialize)]
struct JournalPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a str,
    policy_digest: &'a EvidenceDigest,
    activation: &'a SerializableActivationV1,
    phase: ActivationPhaseV1,
    updated_at_ms: i64,
}

impl NativeReleaseJournalV1 {
    fn new(
        policy: &ManagedNativeRuntimePolicyV1,
        activation: &TitaniumReleaseActivationV1,
        phase: ActivationPhaseV1,
        updated_at_ms: i64,
    ) -> Result<Self, NativeReleaseError> {
        let mut value = Self {
            purpose: JOURNAL_PURPOSE.to_owned(),
            schema_version: SCHEMA_VERSION,
            project_id: policy.project_id.clone(),
            policy_digest: policy.policy_digest.clone(),
            activation: activation.into(),
            phase,
            updated_at_ms,
            document_digest: EvidenceDigest::sha256([]),
        };
        value.document_digest = value.calculate_digest()?;
        value.validate(policy)?;
        Ok(value)
    }

    fn set_phase(
        &mut self,
        policy: &ManagedNativeRuntimePolicyV1,
        phase: ActivationPhaseV1,
        updated_at_ms: i64,
    ) -> Result<(), NativeReleaseError> {
        if updated_at_ms < self.updated_at_ms {
            return Err(NativeReleaseError::ClockMovedBackwards);
        }
        self.phase = phase;
        self.updated_at_ms = updated_at_ms;
        self.document_digest = self.calculate_digest()?;
        self.validate(policy)
    }

    fn validate(&self, policy: &ManagedNativeRuntimePolicyV1) -> Result<(), NativeReleaseError> {
        if self.purpose != JOURNAL_PURPOSE
            || self.schema_version != SCHEMA_VERSION
            || self.project_id != policy.project_id
            || self.policy_digest != policy.policy_digest
            || self.activation.project_id != policy.project_id
            || self.updated_at_ms < 0
            || self.document_digest != self.calculate_digest()?
        {
            return Err(NativeReleaseError::InvalidJournal);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, NativeReleaseError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &JournalPayload {
                purpose: JOURNAL_PURPOSE,
                schema_version: SCHEMA_VERSION,
                project_id: &self.project_id,
                policy_digest: &self.policy_digest,
                activation: &self.activation,
                phase: self.phase,
                updated_at_ms: self.updated_at_ms,
            },
        )?))
    }

    fn canonical_bytes(
        &self,
        policy: &ManagedNativeRuntimePolicyV1,
    ) -> Result<Vec<u8>, NativeReleaseError> {
        self.validate(policy)?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(
        bytes: &[u8],
        policy: &ManagedNativeRuntimePolicyV1,
    ) -> Result<Self, NativeReleaseError> {
        let value: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&value)? != bytes {
            return Err(NativeReleaseError::NoncanonicalDocument);
        }
        value.validate(policy)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeReleaseOutcomeV1 {
    Activated,
    RolledBack,
    RejectedFirstRelease,
    CandidateDiscarded,
}

pub trait NativeReleaseRuntimeV1 {
    fn restart(&mut self, systemd_unit: &str) -> Result<(), NativeReleaseError>;
    fn stop(&mut self, systemd_unit: &str) -> Result<(), NativeReleaseError>;
    fn healthy(
        &mut self,
        policy: &ManagedNativeRuntimePolicyV1,
    ) -> Result<bool, NativeReleaseError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemdNativeReleaseRuntimeV1;

impl SystemdNativeReleaseRuntimeV1 {
    pub fn verify_installed(
        policy: &ManagedNativeRuntimePolicyV1,
    ) -> Result<(), NativeReleaseError> {
        policy.validate()?;
        let path = Path::new("/etc/systemd/system").join(&policy.systemd_unit);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o644
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > MAX_POLICY_BYTES
        {
            return Err(NativeReleaseError::UnsafeSystemdUnit);
        }
        let file = File::open(&path)?;
        let opened = file.metadata()?;
        let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
        file.take(MAX_POLICY_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)?;
        let after = fs::symlink_metadata(&path)?;
        if !same_file(&metadata, &opened)
            || !same_file(&opened, &after)
            || bytes.len() as u64 != opened.len()
            || EvidenceDigest::sha256(bytes) != policy.systemd_unit_sha256
        {
            return Err(NativeReleaseError::UnsafeSystemdUnit);
        }
        for property in ["After", "Requires"] {
            let output = Command::new(SYSTEMCTL)
                .args([
                    "show",
                    "--property",
                    property,
                    "--value",
                    "--",
                    &policy.systemd_unit,
                ])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()?;
            if !output.status.success()
                || output.stdout.len() > MAX_SYSTEMD_PROPERTY_BYTES
                || !systemd_property_contains_unit(&output.stdout, NATIVE_RELEASE_RECOVERY_UNIT)
            {
                return Err(NativeReleaseError::UnsafeSystemdUnit);
            }
        }
        Ok(())
    }

    fn systemctl(action: &str, unit: &str) -> Result<(), NativeReleaseError> {
        let status = Command::new(SYSTEMCTL)
            .args([action, "--", unit])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(NativeReleaseError::SystemdRejected)
        }
    }
}

impl NativeReleaseRuntimeV1 for SystemdNativeReleaseRuntimeV1 {
    fn restart(&mut self, systemd_unit: &str) -> Result<(), NativeReleaseError> {
        Self::systemctl("restart", systemd_unit)
    }

    fn stop(&mut self, systemd_unit: &str) -> Result<(), NativeReleaseError> {
        Self::systemctl("stop", systemd_unit)
    }

    fn healthy(
        &mut self,
        policy: &ManagedNativeRuntimePolicyV1,
    ) -> Result<bool, NativeReleaseError> {
        let deadline = Instant::now() + Duration::from_millis(policy.health_timeout_ms);
        loop {
            match probe_health(policy) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(NativeReleaseError::Io(error)) if transient_health_error(&error) => {}
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

pub struct NativeReleaseActivatorV1<'a> {
    registry: &'a TitaniumRegistryV1,
    policy: ManagedNativeRuntimePolicyV1,
    root: PathBuf,
    expected_owner_uid: u32,
}

impl<'a> NativeReleaseActivatorV1<'a> {
    pub fn initialize_installed_project(
        policy: &ManagedNativeRuntimePolicyV1,
    ) -> Result<(), NativeReleaseError> {
        policy.validate()?;
        let runtime_root = Path::new(MANAGED_NATIVE_RELEASE_ROOT);
        validate_directory(runtime_root, 0, 0o755)?;
        let project_root = runtime_root.join(&policy.project_id);
        ensure_directory(&project_root, 0, 0o700)?;
        ensure_directory(&project_root.join("views"), 0, 0o700)?;
        ensure_regular_file(&project_root.join("activation.lock"), 0, 0o600)?;
        File::open(&project_root)?.sync_all()?;
        File::open(runtime_root)?.sync_all()?;
        Ok(())
    }

    pub fn installed_project_ids() -> Result<Vec<String>, NativeReleaseError> {
        let root = Path::new(MANAGED_NATIVE_RELEASE_ROOT);
        validate_directory(root, 0, 0o755)?;
        let mut projects = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let project_id = entry
                .file_name()
                .into_string()
                .map_err(|_| NativeReleaseError::UnsafeRuntimeRoot)?;
            if !valid_component(&project_id) {
                return Err(NativeReleaseError::UnsafeRuntimeRoot);
            }
            validate_directory(&entry.path(), 0, 0o700)?;
            projects.push(project_id);
        }
        projects.sort();
        Ok(projects)
    }

    pub fn open_installed(
        registry: &'a TitaniumRegistryV1,
        policy: ManagedNativeRuntimePolicyV1,
    ) -> Result<Self, NativeReleaseError> {
        Self::open(registry, policy, Path::new(MANAGED_NATIVE_RELEASE_ROOT), 0)
    }

    pub fn open(
        registry: &'a TitaniumRegistryV1,
        policy: ManagedNativeRuntimePolicyV1,
        runtime_root: &Path,
        expected_owner_uid: u32,
    ) -> Result<Self, NativeReleaseError> {
        policy.validate()?;
        validate_directory(runtime_root, expected_owner_uid, 0o755)?;
        let root = runtime_root.join(&policy.project_id);
        validate_directory(&root, expected_owner_uid, 0o700)?;
        validate_directory(&root.join("views"), expected_owner_uid, 0o700)?;
        validate_regular_file(&root.join("activation.lock"), expected_owner_uid, 0o600)?;
        Ok(Self {
            registry,
            policy,
            root,
            expected_owner_uid,
        })
    }

    pub fn activate<R: NativeReleaseRuntimeV1>(
        &self,
        candidate_artifact: &EvidenceDigest,
        runtime: &mut R,
        now_ms: i64,
    ) -> Result<NativeReleaseOutcomeV1, NativeReleaseError> {
        if now_ms < 0 {
            return Err(NativeReleaseError::ClockMovedBackwards);
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.root.join("activation.lock"))?;
        lock.lock_exclusive()?;
        self.validate_release(candidate_artifact)?;
        let journal_path = self.root.join("activation.jcs");
        let mut journal = match fs::symlink_metadata(&journal_path) {
            Ok(_) => {
                let existing = self.read_journal()?;
                if existing.activation.candidate_artifact != *candidate_artifact {
                    return Err(NativeReleaseError::ActivationInProgress);
                }
                self.prepare_journal_views(&existing)?;
                self.validate_current_link_for_journal(&existing)?;
                existing
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let activation = self
                    .registry
                    .begin_release_activation(&self.policy.project_id, candidate_artifact)?;
                let journal = NativeReleaseJournalV1::new(
                    &self.policy,
                    &activation,
                    ActivationPhaseV1::Prepared,
                    now_ms,
                )?;
                self.write_journal(&journal)?;
                self.prepare_journal_views(&journal)?;
                self.validate_current_link(&[
                    activation.previous_current_artifact.as_ref(),
                    Some(candidate_artifact),
                ])?;
                journal
            }
            Err(error) => return Err(error.into()),
        };
        self.resume(&mut journal, runtime, now_ms)
    }

    pub fn recover<R: NativeReleaseRuntimeV1>(
        &self,
        runtime: &mut R,
        now_ms: i64,
    ) -> Result<Option<NativeReleaseOutcomeV1>, NativeReleaseError> {
        if now_ms < 0 {
            return Err(NativeReleaseError::ClockMovedBackwards);
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.root.join("activation.lock"))?;
        lock.lock_exclusive()?;
        match fs::symlink_metadata(self.root.join("activation.jcs")) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(recovery) = self.registry.release_recovery(&self.policy.project_id)?
                else {
                    return Ok(None);
                };
                self.validate_release(&recovery.candidate_artifact)?;
                let committed =
                    recovery.current_artifact.as_ref() == Some(&recovery.candidate_artifact);
                if committed {
                    self.prepare_release_view(&recovery.candidate_artifact)?;
                    self.validate_current_link(&[Some(&recovery.candidate_artifact)])?;
                } else {
                    self.validate_current_link(&[recovery.current_artifact.as_ref()])?;
                }
                let activation = TitaniumReleaseActivationV1 {
                    project_id: self.policy.project_id.clone(),
                    candidate_artifact: recovery.candidate_artifact,
                    previous_current_artifact: if committed {
                        None
                    } else {
                        recovery.current_artifact
                    },
                };
                self.registry
                    .finalize_release_activation(&activation, committed)?;
                return Ok(Some(if committed {
                    NativeReleaseOutcomeV1::Activated
                } else {
                    NativeReleaseOutcomeV1::CandidateDiscarded
                }));
            }
            Err(error) => return Err(error.into()),
        }
        let mut journal = self.read_journal()?;
        self.validate_release(&journal.activation.candidate_artifact)?;
        self.prepare_journal_views(&journal)?;
        self.validate_current_link_for_journal(&journal)?;
        self.resume(&mut journal, runtime, now_ms).map(Some)
    }

    pub fn collect_unreferenced_views(&self) -> Result<u64, NativeReleaseError> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.root.join("activation.lock"))?;
        lock.lock_exclusive()?;
        match fs::symlink_metadata(self.root.join("activation.jcs")) {
            Ok(_) => return Err(NativeReleaseError::ActivationInProgress),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let current = self.registry.release_root_artifact(
            crate::titanium::TitaniumRootKindV1::CurrentRelease,
            &self.policy.project_id,
        )?;
        let last_known_good = self.registry.release_root_artifact(
            crate::titanium::TitaniumRootKindV1::LastKnownGoodRelease,
            &self.policy.project_id,
        )?;
        self.validate_current_link(&[current.as_ref()])?;
        let keep = [current, last_known_good]
            .into_iter()
            .flatten()
            .collect::<std::collections::BTreeSet<_>>();
        for artifact in &keep {
            self.prepare_release_view(artifact)?;
        }
        let views = self.root.join("views");
        let mut removed = 0_u64;
        for entry in fs::read_dir(&views)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| NativeReleaseError::UnsafeReleaseView)?;
            if name.starts_with(".stage-") {
                validate_staging_view_name(&name)?;
                remove_release_view(&entry.path(), self.expected_owner_uid)?;
                removed = removed.saturating_add(1);
                continue;
            }
            let digest = EvidenceDigest::from_str(&name)
                .map_err(|_| NativeReleaseError::UnsafeReleaseView)?;
            if !keep.contains(&digest) {
                validate_release_view_shape(&entry.path(), self.expected_owner_uid)?;
                remove_release_view(&entry.path(), self.expected_owner_uid)?;
                removed = removed.saturating_add(1);
            }
        }
        File::open(&views)?.sync_all()?;
        Ok(removed)
    }

    fn resume<R: NativeReleaseRuntimeV1>(
        &self,
        journal: &mut NativeReleaseJournalV1,
        runtime: &mut R,
        now_ms: i64,
    ) -> Result<NativeReleaseOutcomeV1, NativeReleaseError> {
        let activation = TitaniumReleaseActivationV1::from(&journal.activation);
        let candidate = self.release_view_path(&activation.candidate_artifact);
        let previous = activation
            .previous_current_artifact
            .as_ref()
            .map(|digest| self.release_view_path(digest));

        if journal.phase == ActivationPhaseV1::Prepared {
            self.switch_current_link(&candidate)?;
            self.advance(journal, ActivationPhaseV1::CandidateLinked, now_ms)?;
        }
        if journal.phase == ActivationPhaseV1::CandidateLinked {
            runtime.restart(&self.policy.systemd_unit)?;
            self.advance(journal, ActivationPhaseV1::CandidateRestarted, now_ms)?;
        }
        if journal.phase == ActivationPhaseV1::CandidateRestarted {
            if runtime.healthy(&self.policy)? {
                self.registry.commit_release_activation(&activation)?;
                self.remove_journal()?;
                self.registry
                    .finalize_release_activation(&activation, true)?;
                return Ok(NativeReleaseOutcomeV1::Activated);
            }
            if previous.is_some() {
                self.advance(journal, ActivationPhaseV1::RollbackSwitchPending, now_ms)?;
            } else {
                self.advance(journal, ActivationPhaseV1::FirstRejectionPending, now_ms)?;
            }
        }
        if journal.phase == ActivationPhaseV1::RollbackSwitchPending {
            let previous = previous
                .as_ref()
                .ok_or(NativeReleaseError::InvalidJournal)?;
            self.switch_current_link(previous)?;
            self.advance(journal, ActivationPhaseV1::RollbackLinked, now_ms)?;
        }
        if journal.phase == ActivationPhaseV1::RollbackLinked {
            runtime.restart(&self.policy.systemd_unit)?;
            self.advance(journal, ActivationPhaseV1::RollbackRestarted, now_ms)?;
        }
        if journal.phase == ActivationPhaseV1::RollbackRestarted {
            if !runtime.healthy(&self.policy)? {
                return Err(NativeReleaseError::RollbackUnhealthy);
            }
            self.registry.abort_release_activation(&activation)?;
            self.remove_journal()?;
            self.registry
                .finalize_release_activation(&activation, false)?;
            return Ok(NativeReleaseOutcomeV1::RolledBack);
        }
        if journal.phase == ActivationPhaseV1::FirstRejectionPending {
            if previous.is_some() {
                return Err(NativeReleaseError::InvalidJournal);
            }
            runtime.stop(&self.policy.systemd_unit)?;
            self.remove_current_link()?;
            self.registry.abort_release_activation(&activation)?;
            self.remove_journal()?;
            self.registry
                .finalize_release_activation(&activation, false)?;
            return Ok(NativeReleaseOutcomeV1::RejectedFirstRelease);
        }
        Err(NativeReleaseError::InvalidJournal)
    }

    fn validate_release(&self, artifact: &EvidenceDigest) -> Result<(), NativeReleaseError> {
        let descriptor = self.registry.release_descriptor(
            artifact,
            &self.policy.project_id,
            &self.policy.target,
            &self.policy.release_interface,
        )?;
        if descriptor.entrypoint != self.policy.entrypoint
            || descriptor.runtime_contract_digest != self.policy.runtime_contract_digest
        {
            return Err(NativeReleaseError::ReleasePolicyMismatch);
        }
        Ok(())
    }

    fn prepare_journal_views(
        &self,
        journal: &NativeReleaseJournalV1,
    ) -> Result<(), NativeReleaseError> {
        self.prepare_release_view(&journal.activation.candidate_artifact)?;
        if let Some(previous) = journal.activation.previous_current_artifact.as_ref() {
            self.prepare_release_view(previous)?;
        }
        Ok(())
    }

    fn prepare_release_view(&self, artifact: &EvidenceDigest) -> Result<(), NativeReleaseError> {
        self.validate_release(artifact)?;
        let release_payload = self
            .registry
            .artifact_payload_path(artifact, TitaniumArtifactKindV1::Release)?;
        let runtime_payloads = self.registry.release_runtime_payloads(
            artifact,
            &self.policy.project_id,
            &self.policy.target,
            &self.policy.release_interface,
        )?;
        let final_path = self.release_view_path(artifact);
        match fs::symlink_metadata(&final_path) {
            Ok(_) => {
                return self.validate_release_view(
                    &final_path,
                    &release_payload,
                    &runtime_payloads,
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let staging = self
            .root
            .join("views")
            .join(format!(".stage-{}", Uuid::new_v4().simple()));
        let result = (|| {
            fs::create_dir(&staging)?;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
            let runtime = staging.join("runtime");
            fs::create_dir(&runtime)?;
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
            std::os::unix::fs::symlink(&release_payload, staging.join("release"))?;
            for (mount, payload) in &runtime_payloads {
                std::os::unix::fs::symlink(payload, runtime.join(mount))?;
            }
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o555))?;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o555))?;
            File::open(&runtime)?.sync_all()?;
            File::open(&staging)?.sync_all()?;
            match fs::rename(&staging, &final_path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            File::open(self.root.join("views"))?.sync_all()?;
            self.validate_release_view(&final_path, &release_payload, &runtime_payloads)
        })();
        if staging.exists() {
            let _ = fs::set_permissions(&staging, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    fn validate_release_view(
        &self,
        view: &Path,
        release_payload: &Path,
        runtime_payloads: &[(String, PathBuf)],
    ) -> Result<(), NativeReleaseError> {
        validate_directory(view, self.expected_owner_uid, 0o555)?;
        validate_directory(&view.join("runtime"), self.expected_owner_uid, 0o555)?;
        validate_exact_symlink(
            &view.join("release"),
            release_payload,
            self.expected_owner_uid,
        )?;
        let mut actual = fs::read_dir(view)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        actual.sort();
        let expected_entries = ["release", "runtime"]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        if actual != expected_entries {
            return Err(NativeReleaseError::UnsafeReleaseView);
        }
        let mut runtime_names = fs::read_dir(view.join("runtime"))?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        runtime_names.sort();
        let expected_names = runtime_payloads
            .iter()
            .map(|(mount, _)| mount.into())
            .collect::<Vec<std::ffi::OsString>>();
        if runtime_names != expected_names {
            return Err(NativeReleaseError::UnsafeReleaseView);
        }
        for (mount, payload) in runtime_payloads {
            validate_exact_symlink(
                &view.join("runtime").join(mount),
                payload,
                self.expected_owner_uid,
            )?;
        }
        Ok(())
    }

    fn release_view_path(&self, artifact: &EvidenceDigest) -> PathBuf {
        self.root.join("views").join(artifact.as_str())
    }

    fn validate_current_link_for_journal(
        &self,
        journal: &NativeReleaseJournalV1,
    ) -> Result<(), NativeReleaseError> {
        let activation = TitaniumReleaseActivationV1::from(&journal.activation);
        match journal.phase {
            ActivationPhaseV1::Prepared => self.validate_current_link(&[
                activation.previous_current_artifact.as_ref(),
                Some(&activation.candidate_artifact),
            ]),
            ActivationPhaseV1::CandidateLinked | ActivationPhaseV1::CandidateRestarted => {
                self.validate_current_link(&[Some(&activation.candidate_artifact)])
            }
            ActivationPhaseV1::RollbackLinked | ActivationPhaseV1::RollbackRestarted => {
                self.validate_current_link(&[activation.previous_current_artifact.as_ref()])
            }
            ActivationPhaseV1::RollbackSwitchPending => self.validate_current_link(&[
                Some(&activation.candidate_artifact),
                activation.previous_current_artifact.as_ref(),
            ]),
            ActivationPhaseV1::FirstRejectionPending => {
                if activation.previous_current_artifact.is_some() {
                    return Err(NativeReleaseError::InvalidJournal);
                }
                self.validate_current_link(&[Some(&activation.candidate_artifact), None])
            }
        }
    }

    fn validate_current_link(
        &self,
        allowed: &[Option<&EvidenceDigest>],
    ) -> Result<(), NativeReleaseError> {
        if allowed.is_empty() {
            return Err(NativeReleaseError::ReleaseStateDiverged);
        }
        let actual = match fs::symlink_metadata(self.root.join("current")) {
            Ok(metadata) => {
                if !metadata.file_type().is_symlink() {
                    return Err(NativeReleaseError::UnsafeReleaseLink);
                }
                Some(fs::read_link(self.root.join("current"))?)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let matches_allowed = allowed.iter().any(|allowed| {
            actual
                == allowed
                    .as_ref()
                    .map(|digest| self.release_view_path(digest))
        });
        if !matches_allowed {
            return Err(NativeReleaseError::ReleaseStateDiverged);
        }
        Ok(())
    }

    fn advance(
        &self,
        journal: &mut NativeReleaseJournalV1,
        phase: ActivationPhaseV1,
        now_ms: i64,
    ) -> Result<(), NativeReleaseError> {
        journal.set_phase(&self.policy, phase, now_ms)?;
        self.write_journal(journal)
    }

    fn switch_current_link(&self, target: &Path) -> Result<(), NativeReleaseError> {
        if !target.is_absolute() {
            return Err(NativeReleaseError::UnsafeReleaseLink);
        }
        let temporary = self
            .root
            .join(format!(".current.{}.tmp", Uuid::new_v4().simple()));
        std::os::unix::fs::symlink(target, &temporary)?;
        fs::rename(&temporary, self.root.join("current"))?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    fn remove_current_link(&self) -> Result<(), NativeReleaseError> {
        match fs::remove_file(self.root.join("current")) {
            Ok(()) => File::open(&self.root)?.sync_all().map_err(Into::into),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn read_journal(&self) -> Result<NativeReleaseJournalV1, NativeReleaseError> {
        let bytes = read_stable_file(
            &self.root.join("activation.jcs"),
            self.expected_owner_uid,
            0o600,
            MAX_JOURNAL_BYTES,
        )?;
        NativeReleaseJournalV1::decode_canonical(&bytes, &self.policy)
    }

    fn write_journal(&self, journal: &NativeReleaseJournalV1) -> Result<(), NativeReleaseError> {
        write_atomic_file(
            &self.root.join("activation.jcs"),
            &journal.canonical_bytes(&self.policy)?,
            0o600,
        )
    }

    fn remove_journal(&self) -> Result<(), NativeReleaseError> {
        match fs::remove_file(self.root.join("activation.jcs")) {
            Ok(()) => File::open(&self.root)?.sync_all().map_err(Into::into),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn probe_health(policy: &ManagedNativeRuntimePolicyV1) -> Result<bool, NativeReleaseError> {
    let (address, authority, path) = parse_loopback_health_url(&policy.health_url)?;
    let timeout = Duration::from_millis(policy.health_timeout_ms.min(2_000));
    let mut stream = match TcpStream::connect_timeout(&address, timeout) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::TimedOut
            ) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error.into()),
    };
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()?;
    let mut line = Vec::new();
    BufReader::new(stream)
        .take(MAX_HTTP_STATUS_LINE_BYTES)
        .read_until(b'\n', &mut line)?;
    if !line.ends_with(b"\r\n") {
        return Err(NativeReleaseError::InvalidHealthResponse);
    }
    line.truncate(line.len().saturating_sub(2));
    let line = std::str::from_utf8(&line).map_err(|_| NativeReleaseError::InvalidHealthResponse)?;
    let mut parts = line.split(' ');
    let version = parts.next();
    let status = parts.next().and_then(|value| value.parse::<u16>().ok());
    if !matches!(version, Some("HTTP/1.0" | "HTTP/1.1")) || status.is_none() {
        return Err(NativeReleaseError::InvalidHealthResponse);
    }
    Ok(status == Some(policy.health_expected_status))
}

fn parse_loopback_health_url(
    value: &str,
) -> Result<(SocketAddr, String, String), NativeReleaseError> {
    let parsed = Url::parse(value).map_err(|_| NativeReleaseError::InvalidPolicy)?;
    if parsed.scheme() != "http"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(NativeReleaseError::InvalidPolicy);
    }
    let host = parsed.host_str().ok_or(NativeReleaseError::InvalidPolicy)?;
    let address = host
        .parse::<IpAddr>()
        .map_err(|_| NativeReleaseError::InvalidPolicy)?;
    if !address.is_loopback() {
        return Err(NativeReleaseError::InvalidPolicy);
    }
    let port = parsed.port().ok_or(NativeReleaseError::InvalidPolicy)?;
    let path = parsed.path();
    if path.is_empty() || !path.starts_with('/') {
        return Err(NativeReleaseError::InvalidPolicy);
    }
    let authority = match address {
        IpAddr::V4(_) => format!("{host}:{port}"),
        IpAddr::V6(_) => format!("[{host}]:{port}"),
    };
    Ok((SocketAddr::new(address, port), authority, path.to_owned()))
}

fn transient_health_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::WouldBlock
    )
}

fn systemd_property_contains_unit(value: &[u8], expected: &str) -> bool {
    std::str::from_utf8(value)
        .is_ok_and(|value| value.split_ascii_whitespace().any(|unit| unit == expected))
}

fn write_atomic_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), NativeReleaseError> {
    let parent = path.parent().ok_or(NativeReleaseError::UnsafeRuntimeRoot)?;
    let temporary = parent.join(format!(".journal.{}.tmp", Uuid::new_v4().simple()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_stable_file(
    path: &Path,
    expected_uid: u32,
    mode: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, NativeReleaseError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.uid() != expected_uid
        || before.mode() & 0o7777 != mode
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > maximum_bytes
    {
        return Err(NativeReleaseError::UnsafeRuntimeRoot);
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    if !same_file(&before, &opened)
        || !same_file(&opened, &after)
        || bytes.len() as u64 != opened.len()
    {
        return Err(NativeReleaseError::ConcurrentChange);
    }
    Ok(bytes)
}

fn validate_directory(path: &Path, expected_uid: u32, mode: u32) -> Result<(), NativeReleaseError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != mode
    {
        return Err(NativeReleaseError::UnsafeRuntimeRoot);
    }
    Ok(())
}

fn validate_regular_file(
    path: &Path,
    expected_uid: u32,
    mode: u32,
) -> Result<(), NativeReleaseError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != 1
    {
        return Err(NativeReleaseError::UnsafeRuntimeRoot);
    }
    Ok(())
}

fn ensure_directory(path: &Path, expected_uid: u32, mode: u32) -> Result<(), NativeReleaseError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_directory(path, expected_uid, mode),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(mode);
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            validate_directory(path, expected_uid, mode)
        }
        Err(error) => Err(error.into()),
    }
}

fn ensure_regular_file(
    path: &Path,
    expected_uid: u32,
    mode: u32,
) -> Result<(), NativeReleaseError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_regular_file(path, expected_uid, mode),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(mode);
            match options.open(path) {
                Ok(file) => file.sync_all()?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            validate_regular_file(path, expected_uid, mode)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_exact_symlink(
    path: &Path,
    expected_target: &Path,
    expected_uid: u32,
) -> Result<(), NativeReleaseError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || fs::read_link(path)? != expected_target
    {
        return Err(NativeReleaseError::UnsafeReleaseView);
    }
    Ok(())
}

fn validate_staging_view_name(name: &str) -> Result<(), NativeReleaseError> {
    let suffix = name
        .strip_prefix(".stage-")
        .ok_or(NativeReleaseError::UnsafeReleaseView)?;
    if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(NativeReleaseError::UnsafeReleaseView);
    }
    Ok(())
}

fn validate_release_view_shape(path: &Path, expected_uid: u32) -> Result<(), NativeReleaseError> {
    validate_directory(path, expected_uid, 0o555)?;
    validate_directory(&path.join("runtime"), expected_uid, 0o555)?;
    let release = fs::symlink_metadata(path.join("release"))?;
    if !release.file_type().is_symlink() || release.uid() != expected_uid {
        return Err(NativeReleaseError::UnsafeReleaseView);
    }
    for entry in fs::read_dir(path.join("runtime"))? {
        let metadata = fs::symlink_metadata(entry?.path())?;
        if !metadata.file_type().is_symlink() || metadata.uid() != expected_uid {
            return Err(NativeReleaseError::UnsafeReleaseView);
        }
    }
    Ok(())
}

fn remove_release_view(path: &Path, expected_uid: u32) -> Result<(), NativeReleaseError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
    {
        return Err(NativeReleaseError::UnsafeReleaseView);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let runtime = path.join("runtime");
    if let Ok(metadata) = fs::symlink_metadata(&runtime) {
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || metadata.uid() != expected_uid
        {
            return Err(NativeReleaseError::UnsafeReleaseView);
        }
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
    }
    fs::remove_dir_all(path)?;
    Ok(())
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

fn valid_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= 4_096
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[derive(Debug, thiserror::Error)]
pub enum NativeReleaseError {
    #[error("managed native release I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("managed native release JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("managed native runtime policy is invalid")]
    InvalidPolicy,
    #[error("managed native release journal is invalid")]
    InvalidJournal,
    #[error("managed native release document is not canonical")]
    NoncanonicalDocument,
    #[error("managed native runtime root is unsafe")]
    UnsafeRuntimeRoot,
    #[error("installed systemd unit is unsafe or differs from policy")]
    UnsafeSystemdUnit,
    #[error("managed native release does not match installed runtime policy")]
    ReleasePolicyMismatch,
    #[error("managed native release link target is unsafe")]
    UnsafeReleaseLink,
    #[error("managed native release view is unsafe")]
    UnsafeReleaseView,
    #[error("another native release activation is unfinished")]
    ActivationInProgress,
    #[error("systemd rejected the managed native release operation")]
    SystemdRejected,
    #[error("managed native release rollback did not recover health")]
    RollbackUnhealthy,
    #[error("managed native health response is malformed")]
    InvalidHealthResponse,
    #[error("managed native release state changed concurrently")]
    ConcurrentChange,
    #[error("managed native runtime link and Titanium release roots diverged")]
    ReleaseStateDiverged,
    #[error("the monotonic operation timestamp moved backwards")]
    ClockMovedBackwards,
    #[error(transparent)]
    Titanium(#[from] TitaniumRegistryError),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn systemd_dependency_matching_requires_an_exact_unit_token() {
        assert!(systemd_property_contains_unit(
            b"network.target rdashboard-native-release-recovery.service\n",
            NATIVE_RELEASE_RECOVERY_UNIT
        ));
        assert!(!systemd_property_contains_unit(
            b"rdashboard-native-release-recovery.service.disabled\n",
            NATIVE_RELEASE_RECOVERY_UNIT
        ));
    }
    use crate::titanium::{
        TITANIUM_RELEASE_DESCRIPTOR_FILE, TitaniumAcquisitionClassV1, TitaniumArtifactSpecV1,
        TitaniumReleaseDescriptorV1, TitaniumReleaseRuntimeArtifactV1, TitaniumRootKindV1,
    };

    #[derive(Default)]
    struct FakeRuntime {
        candidate_healthy: bool,
        previous_healthy: bool,
        restarts: usize,
        stops: usize,
    }

    impl NativeReleaseRuntimeV1 for FakeRuntime {
        fn restart(&mut self, _systemd_unit: &str) -> Result<(), NativeReleaseError> {
            self.restarts += 1;
            Ok(())
        }

        fn stop(&mut self, _systemd_unit: &str) -> Result<(), NativeReleaseError> {
            self.stops += 1;
            Ok(())
        }

        fn healthy(
            &mut self,
            _policy: &ManagedNativeRuntimePolicyV1,
        ) -> Result<bool, NativeReleaseError> {
            Ok(if self.restarts <= 1 {
                self.candidate_healthy
            } else {
                self.previous_healthy
            })
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        TitaniumRegistryV1,
        ManagedNativeRuntimePolicyV1,
        u32,
    ) {
        let directory = tempdir().expect("temporary directory");
        let registry_root = directory.path().join("titanium");
        fs::create_dir(&registry_root).expect("registry root");
        fs::set_permissions(&registry_root, fs::Permissions::from_mode(0o755))
            .expect("registry mode");
        let owner = fs::metadata(&registry_root)
            .expect("registry metadata")
            .uid();
        let registry = TitaniumRegistryV1::open_for_owner(&registry_root, owner).expect("registry");
        let policy = ManagedNativeRuntimePolicyV1::new(ManagedNativeRuntimePolicyInputV1 {
            project_id: "rimg".to_owned(),
            target: "linux-x86_64".to_owned(),
            release_interface: "native-service-v1".to_owned(),
            entrypoint: "bin/rimg".to_owned(),
            runtime_contract_digest: EvidenceDigest::sha256("runtime"),
            systemd_unit_sha256: EvidenceDigest::sha256("unit"),
            health_url: "http://127.0.0.1:8080/health/ready".to_owned(),
            health_expected_status: 204,
            health_timeout_ms: 5_000,
        })
        .expect("policy");
        (directory, registry, policy, owner)
    }

    fn runtime_root(directory: &tempfile::TempDir, owner: u32) -> PathBuf {
        let root = directory.path().join("managed");
        fs::create_dir(&root).expect("managed root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("managed mode");
        let project = root.join("rimg");
        fs::create_dir(&project).expect("project root");
        fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).expect("project mode");
        let views = project.join("views");
        fs::create_dir(&views).expect("views root");
        fs::set_permissions(&views, fs::Permissions::from_mode(0o700)).expect("views mode");
        let lock = project.join("activation.lock");
        fs::write(&lock, []).expect("activation lock");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).expect("lock mode");
        assert_eq!(fs::metadata(root).expect("root metadata").uid(), owner);
        project.parent().expect("managed parent").to_owned()
    }

    fn release(
        directory: &tempfile::TempDir,
        registry: &TitaniumRegistryV1,
        name: &str,
        bytes: &[u8],
    ) -> EvidenceDigest {
        let source = directory.path().join(name);
        fs::create_dir(&source).expect("release source");
        fs::create_dir(source.join("bin")).expect("release bin");
        let executable = source.join("bin/rimg");
        fs::write(&executable, bytes).expect("release executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("executable mode");
        let descriptor = TitaniumReleaseDescriptorV1::new(
            "rimg".to_owned(),
            "native-service-v1".to_owned(),
            "linux-x86_64".to_owned(),
            "bin/rimg".to_owned(),
            EvidenceDigest::sha256("runtime"),
            Vec::new(),
        )
        .expect("descriptor");
        fs::write(
            source.join(TITANIUM_RELEASE_DESCRIPTOR_FILE),
            descriptor.canonical_bytes().expect("descriptor bytes"),
        )
        .expect("write descriptor");
        registry
            .publish_candidate_release(
                &source,
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::Release,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![],
                    provenance_digest: EvidenceDigest::sha256(name),
                },
            )
            .expect("publish release")
            .artifact_digest
    }

    fn release_with_runtime(
        directory: &tempfile::TempDir,
        registry: &TitaniumRegistryV1,
    ) -> (EvidenceDigest, EvidenceDigest) {
        let runtime_source = directory.path().join("runtime-library");
        fs::create_dir(&runtime_source).expect("runtime source");
        fs::write(runtime_source.join("librimg.so"), b"runtime").expect("runtime library");
        let runtime = registry
            .publish_rooted_tree_artifact(
                &runtime_source,
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::RuntimeLibrary,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![],
                    provenance_digest: EvidenceDigest::sha256("runtime provenance"),
                },
                TitaniumRootKindV1::WarmAction,
                "runtime-library".to_owned(),
            )
            .expect("publish runtime");
        let source = directory.path().join("release-with-runtime");
        fs::create_dir(&source).expect("release source");
        fs::create_dir(source.join("bin")).expect("release bin");
        let executable = source.join("bin/rimg");
        fs::write(&executable, b"release").expect("release executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("executable mode");
        let descriptor = TitaniumReleaseDescriptorV1::new(
            "rimg".to_owned(),
            "native-service-v1".to_owned(),
            "linux-x86_64".to_owned(),
            "bin/rimg".to_owned(),
            EvidenceDigest::sha256("runtime"),
            vec![TitaniumReleaseRuntimeArtifactV1 {
                mount: "native".to_owned(),
                artifact_digest: runtime.artifact_digest.clone(),
            }],
        )
        .expect("descriptor");
        fs::write(
            source.join(TITANIUM_RELEASE_DESCRIPTOR_FILE),
            descriptor.canonical_bytes().expect("descriptor bytes"),
        )
        .expect("write descriptor");
        let release = registry
            .publish_candidate_release(
                &source,
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::Release,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![runtime.artifact_digest.clone()],
                    provenance_digest: EvidenceDigest::sha256("release provenance"),
                },
            )
            .expect("publish release");
        (release.artifact_digest, runtime.artifact_digest)
    }

    #[test]
    fn healthy_candidate_switches_current_and_commits_registry_root() {
        let (directory, registry, policy, owner) = fixture();
        let managed = runtime_root(&directory, owner);
        let candidate = release(&directory, &registry, "release-a", b"a");
        let activator =
            NativeReleaseActivatorV1::open(&registry, policy, &managed, owner).expect("activator");
        let mut runtime = FakeRuntime {
            candidate_healthy: true,
            ..FakeRuntime::default()
        };
        assert_eq!(
            activator
                .activate(&candidate, &mut runtime, 10)
                .expect("activate"),
            NativeReleaseOutcomeV1::Activated
        );
        assert_eq!(runtime.restarts, 1);
        assert_eq!(runtime.stops, 0);
        assert!(!managed.join("rimg/activation.jcs").exists());
        assert_eq!(
            fs::read_link(managed.join("rimg/current")).expect("current link"),
            managed.join("rimg/views").join(candidate.as_str())
        );
    }

    #[test]
    fn unhealthy_candidate_restores_and_proves_the_previous_release() {
        let (directory, registry, policy, owner) = fixture();
        let managed = runtime_root(&directory, owner);
        let first = release(&directory, &registry, "release-a", b"a");
        let second = release(&directory, &registry, "release-b", b"b");
        let activator =
            NativeReleaseActivatorV1::open(&registry, policy, &managed, owner).expect("activator");
        activator
            .activate(
                &first,
                &mut FakeRuntime {
                    candidate_healthy: true,
                    ..FakeRuntime::default()
                },
                10,
            )
            .expect("first activation");
        let mut runtime = FakeRuntime {
            candidate_healthy: false,
            previous_healthy: true,
            ..FakeRuntime::default()
        };
        assert_eq!(
            activator
                .activate(&second, &mut runtime, 20)
                .expect("rollback"),
            NativeReleaseOutcomeV1::RolledBack
        );
        assert_eq!(runtime.restarts, 2);
        assert_eq!(
            fs::read_link(managed.join("rimg/current")).expect("restored current"),
            managed.join("rimg/views").join(first.as_str())
        );
    }

    #[test]
    fn unhealthy_first_release_stops_cleanly_without_committing_current() {
        let (directory, registry, policy, owner) = fixture();
        let managed = runtime_root(&directory, owner);
        let candidate = release(&directory, &registry, "release-a", b"a");
        let activator =
            NativeReleaseActivatorV1::open(&registry, policy, &managed, owner).expect("activator");
        let mut runtime = FakeRuntime::default();
        assert_eq!(
            activator
                .activate(&candidate, &mut runtime, 10)
                .expect("reject first release"),
            NativeReleaseOutcomeV1::RejectedFirstRelease
        );
        assert_eq!(runtime.stops, 1);
        assert!(!managed.join("rimg/current").exists());
    }

    #[test]
    fn activation_view_reuses_exact_runtime_artifact_without_copying_it_into_release() {
        let (directory, registry, policy, owner) = fixture();
        let managed = runtime_root(&directory, owner);
        let (candidate, runtime) = release_with_runtime(&directory, &registry);
        let activator =
            NativeReleaseActivatorV1::open(&registry, policy, &managed, owner).expect("activator");
        activator
            .activate(
                &candidate,
                &mut FakeRuntime {
                    candidate_healthy: true,
                    ..FakeRuntime::default()
                },
                10,
            )
            .expect("activation");
        let view = managed.join("rimg/views").join(candidate.as_str());
        assert_eq!(
            fs::read_link(view.join("runtime/native")).expect("runtime link"),
            registry
                .artifact_payload_path(&runtime, TitaniumArtifactKindV1::RuntimeLibrary)
                .expect("runtime payload")
        );
        assert!(!view.join("release/librimg.so").exists());
    }

    #[test]
    fn interrupted_restart_recovers_the_same_journaled_candidate() {
        struct RestartFailure;
        impl NativeReleaseRuntimeV1 for RestartFailure {
            fn restart(&mut self, _systemd_unit: &str) -> Result<(), NativeReleaseError> {
                Err(NativeReleaseError::SystemdRejected)
            }

            fn stop(&mut self, _systemd_unit: &str) -> Result<(), NativeReleaseError> {
                Ok(())
            }

            fn healthy(
                &mut self,
                _policy: &ManagedNativeRuntimePolicyV1,
            ) -> Result<bool, NativeReleaseError> {
                Ok(false)
            }
        }

        let (directory, registry, policy, owner) = fixture();
        let managed = runtime_root(&directory, owner);
        let candidate = release(&directory, &registry, "release-a", b"a");
        let activator =
            NativeReleaseActivatorV1::open(&registry, policy, &managed, owner).expect("activator");
        assert!(matches!(
            activator.activate(&candidate, &mut RestartFailure, 10),
            Err(NativeReleaseError::SystemdRejected)
        ));
        assert!(managed.join("rimg/activation.jcs").is_file());
        assert_eq!(
            activator
                .recover(
                    &mut FakeRuntime {
                        candidate_healthy: true,
                        ..FakeRuntime::default()
                    },
                    20,
                )
                .expect("recovery"),
            Some(NativeReleaseOutcomeV1::Activated)
        );
        assert!(!managed.join("rimg/activation.jcs").exists());
    }

    #[test]
    fn recovery_rejects_a_candidate_phase_when_the_current_link_is_missing() {
        let (directory, registry, policy, owner) = fixture();
        let managed = runtime_root(&directory, owner);
        let candidate = release(&directory, &registry, "release-a", b"a");
        let activator = NativeReleaseActivatorV1::open(&registry, policy.clone(), &managed, owner)
            .expect("activator");
        let activation = registry
            .begin_release_activation("rimg", &candidate)
            .expect("begin activation");
        let journal = NativeReleaseJournalV1::new(
            &policy,
            &activation,
            ActivationPhaseV1::CandidateLinked,
            10,
        )
        .expect("candidate-linked journal");
        activator
            .prepare_journal_views(&journal)
            .expect("prepare candidate view");
        activator.write_journal(&journal).expect("write journal");

        assert!(matches!(
            activator.recover(&mut FakeRuntime::default(), 20),
            Err(NativeReleaseError::ReleaseStateDiverged)
        ));
    }

    #[test]
    fn rollback_recovery_accepts_a_switch_completed_before_the_next_journal_write() {
        let (directory, registry, policy, owner) = fixture();
        let managed = runtime_root(&directory, owner);
        let first = release(&directory, &registry, "release-a", b"a");
        let second = release(&directory, &registry, "release-b", b"b");
        let activator = NativeReleaseActivatorV1::open(&registry, policy.clone(), &managed, owner)
            .expect("activator");
        activator
            .activate(
                &first,
                &mut FakeRuntime {
                    candidate_healthy: true,
                    ..FakeRuntime::default()
                },
                10,
            )
            .expect("first activation");
        let activation = registry
            .begin_release_activation("rimg", &second)
            .expect("begin second activation");
        let journal = NativeReleaseJournalV1::new(
            &policy,
            &activation,
            ActivationPhaseV1::RollbackSwitchPending,
            20,
        )
        .expect("rollback-pending journal");
        activator
            .prepare_journal_views(&journal)
            .expect("prepare release views");
        activator.write_journal(&journal).expect("write journal");
        activator
            .switch_current_link(&activator.release_view_path(&first))
            .expect("complete switch before crash");

        assert_eq!(
            activator
                .recover(
                    &mut FakeRuntime {
                        candidate_healthy: true,
                        ..FakeRuntime::default()
                    },
                    30,
                )
                .expect("recover rollback"),
            Some(NativeReleaseOutcomeV1::RolledBack)
        );
        assert_eq!(
            fs::read_link(managed.join("rimg/current")).expect("restored current"),
            managed.join("rimg/views").join(first.as_str())
        );
    }

    #[test]
    fn first_rejection_recovers_after_current_was_removed_before_journal_cleanup() {
        let (directory, registry, policy, owner) = fixture();
        let managed = runtime_root(&directory, owner);
        let candidate = release(&directory, &registry, "release-a", b"a");
        let activator = NativeReleaseActivatorV1::open(&registry, policy.clone(), &managed, owner)
            .expect("activator");
        let activation = registry
            .begin_release_activation("rimg", &candidate)
            .expect("begin activation");
        let journal = NativeReleaseJournalV1::new(
            &policy,
            &activation,
            ActivationPhaseV1::FirstRejectionPending,
            10,
        )
        .expect("first-rejection journal");
        activator
            .prepare_journal_views(&journal)
            .expect("prepare candidate view");
        activator
            .switch_current_link(&activator.release_view_path(&candidate))
            .expect("switch candidate link");
        activator.write_journal(&journal).expect("write journal");
        activator
            .remove_current_link()
            .expect("remove current before crash");
        let mut runtime = FakeRuntime::default();

        assert_eq!(
            activator
                .recover(&mut runtime, 20)
                .expect("recover first rejection"),
            Some(NativeReleaseOutcomeV1::RejectedFirstRelease)
        );
        assert_eq!(runtime.stops, 1);
        assert!(!managed.join("rimg/current").exists());
        assert!(
            registry
                .release_recovery("rimg")
                .expect("recovery root")
                .is_none()
        );
    }

    #[test]
    fn recovery_finishes_registry_roots_after_the_activation_journal_was_removed() {
        let (directory, registry, policy, owner) = fixture();
        let managed = runtime_root(&directory, owner);
        let candidate = release(&directory, &registry, "release-a", b"a");
        let activator =
            NativeReleaseActivatorV1::open(&registry, policy, &managed, owner).expect("activator");
        let activation = registry
            .begin_release_activation("rimg", &candidate)
            .expect("begin activation");
        activator
            .prepare_release_view(&candidate)
            .expect("prepare candidate view");
        activator
            .switch_current_link(&activator.release_view_path(&candidate))
            .expect("switch candidate link");
        registry
            .commit_release_activation(&activation)
            .expect("commit registry roots");

        assert_eq!(
            activator
                .recover(&mut FakeRuntime::default(), 20)
                .expect("finish root recovery"),
            Some(NativeReleaseOutcomeV1::Activated)
        );
        assert!(
            registry
                .release_recovery("rimg")
                .expect("recovery root")
                .is_none()
        );
        assert!(matches!(
            registry.read_root(TitaniumRootKindV1::CandidateRelease, candidate.as_str()),
            Err(TitaniumRegistryError::Io(error)) if error.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn recovery_discards_a_candidate_when_activation_never_reached_the_link() {
        let (directory, registry, policy, owner) = fixture();
        let managed = runtime_root(&directory, owner);
        let candidate = release(&directory, &registry, "release-a", b"a");
        let activator =
            NativeReleaseActivatorV1::open(&registry, policy, &managed, owner).expect("activator");
        registry
            .begin_release_activation("rimg", &candidate)
            .expect("begin activation");

        assert_eq!(
            activator
                .recover(&mut FakeRuntime::default(), 20)
                .expect("discard candidate"),
            Some(NativeReleaseOutcomeV1::CandidateDiscarded)
        );
        assert!(!managed.join("rimg/current").exists());
        assert!(
            registry
                .release_recovery("rimg")
                .expect("recovery root")
                .is_none()
        );
    }

    #[test]
    fn view_collection_preserves_only_current_and_last_known_good() {
        let (directory, registry, policy, owner) = fixture();
        let managed = runtime_root(&directory, owner);
        let activator =
            NativeReleaseActivatorV1::open(&registry, policy, &managed, owner).expect("activator");
        let releases = [
            release(&directory, &registry, "release-a", b"a"),
            release(&directory, &registry, "release-b", b"b"),
            release(&directory, &registry, "release-c", b"c"),
        ];
        for (index, release) in releases.iter().enumerate() {
            activator
                .activate(
                    release,
                    &mut FakeRuntime {
                        candidate_healthy: true,
                        ..FakeRuntime::default()
                    },
                    i64::try_from(index + 1).expect("timestamp"),
                )
                .expect("activate release");
        }
        assert_eq!(activator.collect_unreferenced_views().expect("collect"), 1);
        assert!(
            !managed
                .join("rimg/views")
                .join(releases[0].as_str())
                .exists()
        );
        assert!(
            managed
                .join("rimg/views")
                .join(releases[1].as_str())
                .is_dir()
        );
        assert!(
            managed
                .join("rimg/views")
                .join(releases[2].as_str())
                .is_dir()
        );
    }
}
