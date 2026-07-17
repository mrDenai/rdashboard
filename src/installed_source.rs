use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroize as _;

use crate::{
    build_source::BUILD_SOURCE_EXPORT_ROOT,
    domain::{
        EvidenceDigest, GitCommitId, InstalledPolicyIdentity, ProjectId, ReleaseClass, RemoteUrl,
    },
    source::{
        GitSourceProjectConfig, GitSshTransportConfig, InstalledSourceProjectPolicy,
        SourceAttestationError, SourceAttestationVerifier, SourceProjectState, SourceSnapshot,
    },
    source_socket::{SOURCE_SOCKET_PATH, SourceServerConfigV1},
};

pub const SOURCE_CONFIG_PATH: &str = "/etc/rdashboard/source.json";
pub const SOURCE_STATE_DIRECTORY: &str = "/var/lib/rdashboard-source";
pub const SOURCE_REPOSITORY_ROOT: &str = "/var/lib/rdashboard-source/repositories";
pub const SOURCE_DATABASE_PATH: &str = "/var/lib/rdashboard-source/source.sqlite";
pub const SOURCE_ATTESTATION_CREDENTIAL_PATH: &str =
    "/run/credentials/rdashboard-source.service/source-attestation-seed";
pub const SOURCE_GIT_SSH_CREDENTIAL_DIRECTORY: &str = "/run/credentials/rdashboard-source.service";

const SOURCE_CONFIG_SCHEMA_VERSION: u16 = 3;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_GIT_SSH_CREDENTIAL_BYTES: u64 = 64 * 1024;
const MIN_RECONCILE_INTERVAL_MS: u64 = 10_000;
const MAX_RECONCILE_INTERVAL_MS: u64 = 10 * 60 * 1_000;
const MIN_ATTESTATION_TTL_MS: u64 = 10_000;
const MAX_ATTESTATION_TTL_MS: u64 = 60 * 60 * 1_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledSourceGitSshV1 {
    pub private_key_credential: String,
    pub private_key_sha256: EvidenceDigest,
    pub known_hosts_credential: String,
    pub known_hosts_sha256: EvidenceDigest,
}

impl InstalledSourceGitSshV1 {
    pub fn new(
        project_id: &ProjectId,
        private_key_sha256: EvidenceDigest,
        known_hosts_sha256: EvidenceDigest,
    ) -> Self {
        Self {
            private_key_credential: format!("source-git-{project_id}-private-key"),
            private_key_sha256,
            known_hosts_credential: format!("source-git-{project_id}-known-hosts"),
            known_hosts_sha256,
        }
    }

    fn validate(&self, project_id: &ProjectId) -> Result<(), InstalledSourceError> {
        if self.private_key_credential != format!("source-git-{project_id}-private-key")
            || self.known_hosts_credential != format!("source-git-{project_id}-known-hosts")
        {
            return Err(InstalledSourceError::InvalidConfig);
        }
        Ok(())
    }

    fn transport(&self) -> GitSshTransportConfig {
        GitSshTransportConfig {
            private_key_path: Path::new(SOURCE_GIT_SSH_CREDENTIAL_DIRECTORY)
                .join(&self.private_key_credential),
            known_hosts_path: Path::new(SOURCE_GIT_SSH_CREDENTIAL_DIRECTORY)
                .join(&self.known_hosts_credential),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledSourceProjectV1 {
    pub project_id: ProjectId,
    pub remote_url: RemoteUrl,
    pub repository_identity: EvidenceDigest,
    pub git_ssh: Option<InstalledSourceGitSshV1>,
    pub installed_policy: InstalledPolicyIdentity,
    pub auto_deploy: bool,
    pub maximum_attempts: u32,
    pub release_class: ReleaseClass,
}

impl InstalledSourceProjectV1 {
    pub fn new(
        project_id: ProjectId,
        remote_url: RemoteUrl,
        git_ssh: Option<InstalledSourceGitSshV1>,
        installed_policy: InstalledPolicyIdentity,
        auto_deploy: bool,
        maximum_attempts: u32,
        release_class: ReleaseClass,
    ) -> Result<Self, InstalledSourceError> {
        let repository_identity = GitSourceProjectConfig {
            project_id: project_id.clone(),
            remote_url: remote_url.clone(),
            ssh_transport: None,
        }
        .repository_identity();
        let project = Self {
            project_id,
            remote_url,
            repository_identity,
            git_ssh,
            installed_policy,
            auto_deploy,
            maximum_attempts,
            release_class,
        };
        project.validate()?;
        Ok(project)
    }

    fn validate(&self) -> Result<(), InstalledSourceError> {
        let repository = GitSourceProjectConfig {
            project_id: self.project_id.clone(),
            remote_url: self.remote_url.clone(),
            ssh_transport: None,
        };
        if self.repository_identity != repository.repository_identity()
            || remote_uses_ssh(&self.remote_url) != self.git_ssh.is_some()
            || self
                .git_ssh
                .as_ref()
                .is_some_and(|git_ssh| git_ssh.validate(&self.project_id).is_err())
            || self.installed_policy.version == 0
            || !(1..=10).contains(&self.maximum_attempts)
            || self.release_class == ReleaseClass::Rollback
        {
            return Err(InstalledSourceError::InvalidConfig);
        }
        Ok(())
    }

    pub fn repository_config(&self) -> GitSourceProjectConfig {
        GitSourceProjectConfig {
            project_id: self.project_id.clone(),
            remote_url: self.remote_url.clone(),
            ssh_transport: self
                .git_ssh
                .as_ref()
                .map(InstalledSourceGitSshV1::transport),
        }
    }

    pub fn source_policy(&self) -> InstalledSourceProjectPolicy {
        InstalledSourceProjectPolicy {
            project_id: self.project_id.clone(),
            repository_identity: self.repository_identity.clone(),
            installed_policy: self.installed_policy.clone(),
            auto_deploy: self.auto_deploy,
            maximum_attempts: self.maximum_attempts,
            release_class: self.release_class,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledSourceConfigV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub source_uid: u32,
    pub build_reader_gid: u32,
    pub executor_uid: u32,
    pub socket_path: PathBuf,
    pub state_directory: PathBuf,
    pub repository_root: PathBuf,
    pub build_source_export_root: PathBuf,
    pub database_path: PathBuf,
    pub max_connections: u16,
    pub request_timeout_ms: u64,
    pub reconcile_interval_ms: u64,
    pub attestation_ttl_ms: u64,
    pub attestation_key_id: String,
    pub attestation_public_key: String,
    pub projects: Vec<InstalledSourceProjectV1>,
    pub document_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledSourceConfigInputV1 {
    pub source_uid: u32,
    pub build_reader_gid: u32,
    pub max_connections: u16,
    pub request_timeout_ms: u64,
    pub reconcile_interval_ms: u64,
    pub attestation_ttl_ms: u64,
    pub attestation_key_id: String,
    pub attestation_public_key: String,
    pub projects: Vec<InstalledSourceProjectV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInstalledSourceHeadV1 {
    pub project_id: ProjectId,
    pub head: GitCommitId,
    pub sequence: u64,
    pub attestation_digest: EvidenceDigest,
    pub installed_policy: InstalledPolicyIdentity,
    pub repository_identity: EvidenceDigest,
    pub accepted_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Serialize)]
struct InstalledSourceConfigPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    source_uid: u32,
    build_reader_gid: u32,
    executor_uid: u32,
    socket_path: &'a Path,
    state_directory: &'a Path,
    repository_root: &'a Path,
    build_source_export_root: &'a Path,
    database_path: &'a Path,
    max_connections: u16,
    request_timeout_ms: u64,
    reconcile_interval_ms: u64,
    attestation_ttl_ms: u64,
    attestation_key_id: &'a str,
    attestation_public_key: &'a str,
    projects: &'a [InstalledSourceProjectV1],
}

impl InstalledSourceConfigV1 {
    pub fn new(input: InstalledSourceConfigInputV1) -> Result<Self, InstalledSourceError> {
        let mut config = Self {
            purpose: "rdashboard.installed-source-config.v3".to_owned(),
            schema_version: SOURCE_CONFIG_SCHEMA_VERSION,
            source_uid: input.source_uid,
            build_reader_gid: input.build_reader_gid,
            executor_uid: 0,
            socket_path: PathBuf::from(SOURCE_SOCKET_PATH),
            state_directory: PathBuf::from(SOURCE_STATE_DIRECTORY),
            repository_root: PathBuf::from(SOURCE_REPOSITORY_ROOT),
            build_source_export_root: PathBuf::from(BUILD_SOURCE_EXPORT_ROOT),
            database_path: PathBuf::from(SOURCE_DATABASE_PATH),
            max_connections: input.max_connections,
            request_timeout_ms: input.request_timeout_ms,
            reconcile_interval_ms: input.reconcile_interval_ms,
            attestation_ttl_ms: input.attestation_ttl_ms,
            attestation_key_id: input.attestation_key_id,
            attestation_public_key: input.attestation_public_key,
            projects: input.projects,
            document_digest: EvidenceDigest::sha256([]),
        };
        config.document_digest = config.calculate_digest()?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), InstalledSourceError> {
        if self.purpose != "rdashboard.installed-source-config.v3"
            || self.schema_version != SOURCE_CONFIG_SCHEMA_VERSION
            || self.source_uid == 0
            || self.source_uid == u32::MAX
            || self.build_reader_gid == 0
            || self.build_reader_gid == u32::MAX
            || self.executor_uid != 0
            || self.socket_path != Path::new(SOURCE_SOCKET_PATH)
            || self.state_directory != Path::new(SOURCE_STATE_DIRECTORY)
            || self.repository_root != Path::new(SOURCE_REPOSITORY_ROOT)
            || self.build_source_export_root != Path::new(BUILD_SOURCE_EXPORT_ROOT)
            || self.database_path != Path::new(SOURCE_DATABASE_PATH)
            || !(1..=64).contains(&self.max_connections)
            || !(100..=30_000).contains(&self.request_timeout_ms)
            || !(MIN_RECONCILE_INTERVAL_MS..=MAX_RECONCILE_INTERVAL_MS)
                .contains(&self.reconcile_interval_ms)
            || !(MIN_ATTESTATION_TTL_MS..=MAX_ATTESTATION_TTL_MS).contains(&self.attestation_ttl_ms)
            || !valid_key_id(&self.attestation_key_id)
            || decode_public_key(&self.attestation_public_key).is_err()
            || self.projects.is_empty()
            || self.document_digest != self.calculate_digest()?
        {
            return Err(InstalledSourceError::InvalidConfig);
        }
        let mut projects = BTreeSet::new();
        for project in &self.projects {
            project.validate()?;
            if !projects.insert(project.project_id.to_string()) {
                return Err(InstalledSourceError::InvalidConfig);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, InstalledSourceError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &InstalledSourceConfigPayload {
                purpose: "rdashboard.installed-source-config.v3",
                schema_version: SOURCE_CONFIG_SCHEMA_VERSION,
                source_uid: self.source_uid,
                build_reader_gid: self.build_reader_gid,
                executor_uid: self.executor_uid,
                socket_path: &self.socket_path,
                state_directory: &self.state_directory,
                repository_root: &self.repository_root,
                build_source_export_root: &self.build_source_export_root,
                database_path: &self.database_path,
                max_connections: self.max_connections,
                request_timeout_ms: self.request_timeout_ms,
                reconcile_interval_ms: self.reconcile_interval_ms,
                attestation_ttl_ms: self.attestation_ttl_ms,
                attestation_key_id: &self.attestation_key_id,
                attestation_public_key: &self.attestation_public_key,
                projects: &self.projects,
            },
        )?))
    }

    pub fn server_config(&self) -> Result<SourceServerConfigV1, InstalledSourceError> {
        self.validate()?;
        Ok(SourceServerConfigV1::new(
            self.executor_uid,
            usize::from(self.max_connections),
            Duration::from_millis(self.request_timeout_ms),
        )?)
    }

    pub const fn reconcile_interval(&self) -> Duration {
        Duration::from_millis(self.reconcile_interval_ms)
    }

    pub fn attestation_ttl_ms(&self) -> Result<i64, InstalledSourceError> {
        i64::try_from(self.attestation_ttl_ms).map_err(|_| InstalledSourceError::InvalidConfig)
    }

    pub fn repository_configs(&self) -> Vec<GitSourceProjectConfig> {
        self.projects
            .iter()
            .map(InstalledSourceProjectV1::repository_config)
            .collect()
    }

    pub fn source_policies(&self) -> Vec<InstalledSourceProjectPolicy> {
        self.projects
            .iter()
            .map(InstalledSourceProjectV1::source_policy)
            .collect()
    }

    pub fn project_ids(&self) -> Vec<ProjectId> {
        self.projects
            .iter()
            .map(|project| project.project_id.clone())
            .collect()
    }

    pub fn verify_snapshot(
        &self,
        snapshot: &SourceSnapshot,
        expected_target: &GitCommitId,
        now_ms: i64,
    ) -> Result<VerifiedInstalledSourceHeadV1, InstalledSourceError> {
        self.validate()?;
        if now_ms < 0 {
            return Err(InstalledSourceError::InvalidSourceSnapshot);
        }
        let project = self
            .projects
            .iter()
            .find(|project| project.project_id == snapshot.project_id)
            .ok_or(InstalledSourceError::InvalidSourceSnapshot)?;
        let signed = snapshot
            .attestation
            .as_ref()
            .ok_or(InstalledSourceError::InvalidSourceSnapshot)?;
        let attestation_digest = snapshot
            .attestation_digest
            .as_ref()
            .ok_or(InstalledSourceError::InvalidSourceSnapshot)?;
        let verifier = SourceAttestationVerifier::new(std::collections::BTreeMap::from([(
            self.attestation_key_id.clone(),
            decode_public_key(&self.attestation_public_key)?,
        )]))?;
        let payload = verifier.verify(signed, now_ms)?;
        if snapshot.state != SourceProjectState::Ready
            || snapshot.head.as_ref() != Some(expected_target)
            || snapshot.sequence == 0
            || snapshot.sequence != payload.sequence
            || snapshot.head.as_ref() != Some(&payload.head)
            || snapshot.blocked_sha.as_ref() == Some(expected_target)
            || snapshot
                .reconcile_paused_until_ms
                .is_some_and(|until_ms| now_ms < until_ms)
            || snapshot.divergent_candidate.is_some()
            || snapshot.divergence_channel.is_some()
            || snapshot.divergence_evidence_digest.is_some()
            || signed.digest()? != *attestation_digest
            || payload.project_id != project.project_id
            || payload.repository_identity != project.repository_identity
            || payload.installed_policy != project.installed_policy
        {
            return Err(InstalledSourceError::InvalidSourceSnapshot);
        }
        Ok(VerifiedInstalledSourceHeadV1 {
            project_id: payload.project_id.clone(),
            head: payload.head.clone(),
            sequence: payload.sequence,
            attestation_digest: attestation_digest.clone(),
            installed_policy: payload.installed_policy.clone(),
            repository_identity: payload.repository_identity.clone(),
            accepted_at_ms: payload.accepted_at_ms,
            expires_at_ms: payload.expires_at_ms,
        })
    }
}

pub fn load_installed_source_config() -> Result<InstalledSourceConfigV1, InstalledSourceError> {
    load_installed_source_config_from(Path::new(SOURCE_CONFIG_PATH))
}

pub(crate) fn load_installed_source_config_from(
    path: &Path,
) -> Result<InstalledSourceConfigV1, InstalledSourceError> {
    load_installed_source_config_from_owner(path, 0)
}

fn load_installed_source_config_from_owner(
    path: &Path,
    required_uid: u32,
) -> Result<InstalledSourceConfigV1, InstalledSourceError> {
    let bytes = read_stable_config(path, required_uid)?;
    let config: InstalledSourceConfigV1 = serde_json::from_slice(&bytes)?;
    if serde_jcs::to_vec(&config)? != bytes {
        return Err(InstalledSourceError::NoncanonicalConfig);
    }
    config.validate()?;
    Ok(config)
}

pub fn load_source_signing_key(
    config: &InstalledSourceConfigV1,
) -> Result<SigningKey, InstalledSourceError> {
    load_source_signing_key_from(Path::new(SOURCE_ATTESTATION_CREDENTIAL_PATH), config)
}

pub(crate) fn load_source_signing_key_from(
    path: &Path,
    config: &InstalledSourceConfigV1,
) -> Result<SigningKey, InstalledSourceError> {
    config.validate()?;
    let path_metadata = fs::symlink_metadata(path)?;
    let credential_uid = path_metadata.uid();
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || credential_uid != 0 && credential_uid != config.source_uid
        || path_metadata.permissions().mode() & 0o077 != 0
        || path_metadata.len() != 32
    {
        return Err(InstalledSourceError::UnsafeCredential);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != 32
    {
        return Err(InstalledSourceError::UnsafeCredential);
    }
    let mut seed = Vec::with_capacity(32);
    file.take(33).read_to_end(&mut seed)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if seed.len() != 32
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
    {
        seed.zeroize();
        return Err(InstalledSourceError::UnsafeCredential);
    }
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&seed);
    seed.zeroize();
    let signing_key = SigningKey::from_bytes(&bytes);
    bytes.zeroize();
    if signing_key.verifying_key() != decode_public_key(&config.attestation_public_key)? {
        return Err(InstalledSourceError::CredentialKeyMismatch);
    }
    Ok(signing_key)
}

pub fn validate_source_git_ssh_credentials(
    config: &InstalledSourceConfigV1,
) -> Result<(), InstalledSourceError> {
    validate_source_git_ssh_credentials_from(config, Path::new(SOURCE_GIT_SSH_CREDENTIAL_DIRECTORY))
}

fn validate_source_git_ssh_credentials_from(
    config: &InstalledSourceConfigV1,
    credential_directory: &Path,
) -> Result<(), InstalledSourceError> {
    config.validate()?;
    for project in &config.projects {
        let Some(git_ssh) = &project.git_ssh else {
            continue;
        };
        let expected_hosts = BTreeSet::from([ssh_known_host(&project.remote_url)?]);
        let private_key_path = credential_directory.join(&git_ssh.private_key_credential);
        let known_hosts_path = credential_directory.join(&git_ssh.known_hosts_credential);
        let mut private_key = read_stable_git_credential(&private_key_path, config.source_uid)?;
        let known_hosts = read_stable_git_credential(&known_hosts_path, config.source_uid)?;
        let valid = EvidenceDigest::sha256(&private_key) == git_ssh.private_key_sha256
            && EvidenceDigest::sha256(&known_hosts) == git_ssh.known_hosts_sha256
            && valid_openssh_private_key(&private_key)
            && valid_known_hosts(&known_hosts, &expected_hosts);
        private_key.zeroize();
        if !valid {
            return Err(InstalledSourceError::GitCredentialMismatch);
        }
    }
    Ok(())
}

fn read_stable_git_credential(
    path: &Path,
    source_uid: u32,
) -> Result<Vec<u8>, InstalledSourceError> {
    let path_metadata = fs::symlink_metadata(path)?;
    let credential_uid = path_metadata.uid();
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || credential_uid != 0 && credential_uid != source_uid
        || path_metadata.permissions().mode() & 0o077 != 0
        || path_metadata.len() == 0
        || path_metadata.len() > MAX_GIT_SSH_CREDENTIAL_BYTES
    {
        return Err(InstalledSourceError::UnsafeGitCredential);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(InstalledSourceError::UnsafeGitCredential);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(MAX_GIT_SSH_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
        || bytes.len() != usize::try_from(opened_metadata.len()).unwrap_or(usize::MAX)
    {
        bytes.zeroize();
        return Err(InstalledSourceError::UnsafeGitCredential);
    }
    Ok(bytes)
}

fn valid_openssh_private_key(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    if text.contains('\r') || !text.ends_with('\n') {
        return false;
    }
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() < 3
        || lines.first() != Some(&"-----BEGIN OPENSSH PRIVATE KEY-----")
        || lines.last() != Some(&"-----END OPENSSH PRIVATE KEY-----")
        || lines[1..lines.len() - 1]
            .iter()
            .any(|line| line.is_empty() || line.len() > 80)
    {
        return false;
    }
    let encoded = lines[1..lines.len() - 1].concat();
    let Ok(mut decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let valid = decoded.starts_with(b"openssh-key-v1\0");
    decoded.zeroize();
    valid
}

fn valid_known_hosts(bytes: &[u8], expected_hosts: &BTreeSet<String>) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    if text.contains(['\0', '\r']) || !text.ends_with('\n') {
        return false;
    }
    let mut present_hosts = BTreeSet::new();
    for line in text.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 3
            || fields[0].starts_with(['@', '|'])
            || fields[0]
                .bytes()
                .any(|byte| matches!(byte, b'!' | b'*' | b'?'))
            || !matches!(fields[1], "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ssh-rsa")
            || base64::engine::general_purpose::STANDARD
                .decode(fields[2])
                .is_err()
        {
            return false;
        }
        present_hosts.extend(fields[0].split(',').map(str::to_owned));
    }
    !present_hosts.is_empty() && expected_hosts.is_subset(&present_hosts)
}

fn remote_uses_ssh(remote: &RemoteUrl) -> bool {
    Url::parse(remote.as_str()).is_ok_and(|url| url.scheme() == "ssh")
}

fn ssh_known_host(remote: &RemoteUrl) -> Result<String, InstalledSourceError> {
    let url = Url::parse(remote.as_str()).map_err(|_| InstalledSourceError::InvalidConfig)?;
    if url.scheme() != "ssh" {
        return Err(InstalledSourceError::InvalidConfig);
    }
    let host = url.host_str().ok_or(InstalledSourceError::InvalidConfig)?;
    let port = url.port().unwrap_or(22);
    if port == 22 && !host.contains(':') {
        Ok(host.to_owned())
    } else {
        Ok(format!("[{host}]:{port}"))
    }
}

fn read_stable_config(path: &Path, required_uid: u32) -> Result<Vec<u8>, InstalledSourceError> {
    let parent = path.parent().ok_or(InstalledSourceError::UnsafeConfig)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    let path_metadata = fs::symlink_metadata(path)?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != required_uid
        || parent_metadata.permissions().mode() & 0o022 != 0
        || path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.permissions().mode() & 0o022 != 0
        || path_metadata.len() == 0
        || path_metadata.len() > MAX_CONFIG_BYTES
    {
        return Err(InstalledSourceError::UnsafeConfig);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(InstalledSourceError::UnsafeConfig);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
        || bytes.len() != usize::try_from(opened_metadata.len()).unwrap_or(usize::MAX)
    {
        return Err(InstalledSourceError::UnsafeConfig);
    }
    Ok(bytes)
}

fn decode_public_key(value: &str) -> Result<VerifyingKey, InstalledSourceError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| InstalledSourceError::InvalidConfig)?;
    let bytes = decoded
        .try_into()
        .map_err(|_| InstalledSourceError::InvalidConfig)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| InstalledSourceError::InvalidConfig)?;
    if key.is_weak() {
        return Err(InstalledSourceError::InvalidConfig);
    }
    Ok(key)
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Debug, thiserror::Error)]
pub enum InstalledSourceError {
    #[error("installed source configuration is invalid")]
    InvalidConfig,
    #[error("installed source configuration is not a stable root-owned file")]
    UnsafeConfig,
    #[error("installed source configuration is not canonical JCS")]
    NoncanonicalConfig,
    #[error("source attestation credential is not a safe exact seed")]
    UnsafeCredential,
    #[error("source attestation seed does not match the installed public key")]
    CredentialKeyMismatch,
    #[error("source Git SSH credential is not a safe exact private file")]
    UnsafeGitCredential,
    #[error("source Git SSH key or pinned host file does not match installed configuration")]
    GitCredentialMismatch,
    #[error("source snapshot is not a current installed-policy-bound accepted head")]
    InvalidSourceSnapshot,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Socket(#[from] crate::source_socket::SourceSocketError),
    #[error(transparent)]
    Attestation(#[from] SourceAttestationError),
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        str::FromStr as _,
    };

    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    use super::*;
    use crate::source::{DeterministicSourceRepository, DurableSourceBroker, SourceStore};

    fn config_with_remote(
        source_uid: u32,
        signing_key: &SigningKey,
        remote_url: &str,
        git_ssh: Option<InstalledSourceGitSshV1>,
    ) -> InstalledSourceConfigV1 {
        let project_id = ProjectId::from_str("rimg").expect("project");
        let project = InstalledSourceProjectV1::new(
            project_id,
            RemoteUrl::from_str(remote_url).expect("remote"),
            git_ssh,
            InstalledPolicyIdentity {
                digest: EvidenceDigest::sha256("owner policy"),
                version: 7,
            },
            true,
            3,
            ReleaseClass::StatefulCompatible,
        )
        .expect("source project");
        InstalledSourceConfigV1::new(InstalledSourceConfigInputV1 {
            source_uid,
            build_reader_gid: 77,
            max_connections: 16,
            request_timeout_ms: 2_000,
            reconcile_interval_ms: 30_000,
            attestation_ttl_ms: 60_000,
            attestation_key_id: "source-2026-01".to_owned(),
            attestation_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            projects: vec![project],
        })
        .expect("source config")
    }

    fn config(source_uid: u32, signing_key: &SigningKey) -> InstalledSourceConfigV1 {
        config_with_remote(
            source_uid,
            signing_key,
            "https://github.com/example/rimg.git",
            None,
        )
    }

    fn fake_openssh_private_key() -> Vec<u8> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"openssh-key-v1\0fixture");
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{encoded}\n-----END OPENSSH PRIVATE KEY-----\n"
        )
        .into_bytes()
    }

    #[test]
    fn installed_source_config_is_canonical_policy_bound_and_tamper_evident() {
        let directory = tempdir().expect("tempdir");
        let uid = fs::metadata(directory.path()).expect("metadata").uid();
        let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
        let installed = config(uid, &signing_key);
        let path = directory.path().join("source.json");
        fs::write(
            &path,
            serde_jcs::to_vec(&installed).expect("canonical config"),
        )
        .expect("write config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        assert_eq!(
            load_installed_source_config_from_owner(&path, uid).expect("load config"),
            installed
        );

        let mut tampered = installed.clone();
        tampered.projects[0].maximum_attempts += 1;
        assert!(matches!(
            tampered.validate(),
            Err(InstalledSourceError::InvalidConfig)
        ));

        let mut weak_identity_key = [0_u8; 32];
        weak_identity_key[0] = 1;
        assert!(matches!(
            decode_public_key(&URL_SAFE_NO_PAD.encode(weak_identity_key)),
            Err(InstalledSourceError::InvalidConfig)
        ));
    }

    #[test]
    fn source_seed_is_exact_private_zeroized_input_bound_to_installed_public_key() {
        let directory = tempdir().expect("tempdir");
        let uid = fs::metadata(directory.path()).expect("metadata").uid();
        let signing_key = SigningKey::from_bytes(&[23_u8; 32]);
        let installed = config(uid, &signing_key);
        let credential = directory.path().join("source-attestation-seed");
        fs::write(&credential, signing_key.to_bytes()).expect("write seed");
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).expect("permissions");
        assert_eq!(
            load_source_signing_key_from(&credential, &installed)
                .expect("load signing key")
                .verifying_key(),
            signing_key.verifying_key()
        );

        let mismatched = config(uid, &SigningKey::from_bytes(&[29_u8; 32]));
        assert!(matches!(
            load_source_signing_key_from(&credential, &mismatched),
            Err(InstalledSourceError::CredentialKeyMismatch)
        ));
    }

    #[test]
    fn source_git_ssh_credentials_are_exact_private_and_host_pinned() {
        let directory = tempdir().expect("tempdir");
        let uid = fs::metadata(directory.path()).expect("metadata").uid();
        let signing_key = SigningKey::from_bytes(&[37_u8; 32]);
        let private_key = fake_openssh_private_key();
        let known_hosts = b"github.com ssh-ed25519 aG9zdGtleQ==\n";
        let installed = config_with_remote(
            uid,
            &signing_key,
            "ssh://git@github.com/mrDenai/rimg.git",
            Some(InstalledSourceGitSshV1::new(
                &ProjectId::from_str("rimg").expect("project"),
                EvidenceDigest::sha256(&private_key),
                EvidenceDigest::sha256(known_hosts),
            )),
        );
        let private_key_path = directory.path().join("source-git-rimg-private-key");
        let known_hosts_path = directory.path().join("source-git-rimg-known-hosts");
        fs::write(&private_key_path, &private_key).expect("write private key");
        fs::write(&known_hosts_path, known_hosts).expect("write known hosts");
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
            .expect("private key permissions");
        fs::set_permissions(&known_hosts_path, fs::Permissions::from_mode(0o600))
            .expect("known hosts permissions");

        validate_source_git_ssh_credentials_from(&installed, directory.path())
            .expect("validate Git SSH credentials");

        fs::write(
            &known_hosts_path,
            b"attacker.example ssh-ed25519 aG9zdGtleQ==\n",
        )
        .expect("replace known hosts");
        assert!(matches!(
            validate_source_git_ssh_credentials_from(&installed, directory.path()),
            Err(InstalledSourceError::GitCredentialMismatch)
        ));

        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o640))
            .expect("make private key unsafe");
        assert!(matches!(
            validate_source_git_ssh_credentials_from(&installed, directory.path()),
            Err(InstalledSourceError::UnsafeGitCredential)
        ));
    }

    #[test]
    fn source_git_ssh_configuration_cannot_be_partial_or_attached_to_https() {
        let directory = tempdir().expect("tempdir");
        let uid = fs::metadata(directory.path()).expect("metadata").uid();
        let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
        let project_id = ProjectId::from_str("rimg").expect("project");
        let git_ssh = InstalledSourceGitSshV1::new(
            &project_id,
            EvidenceDigest::sha256("private key"),
            EvidenceDigest::sha256("known hosts"),
        );
        for (remote, transport) in [
            ("ssh://git@github.com/mrDenai/rimg.git", None),
            ("https://github.com/mrDenai/rimg.git", Some(git_ssh.clone())),
        ] {
            assert!(matches!(
                InstalledSourceProjectV1::new(
                    project_id.clone(),
                    RemoteUrl::from_str(remote).expect("remote"),
                    transport,
                    InstalledPolicyIdentity {
                        digest: EvidenceDigest::sha256("owner policy"),
                        version: 7,
                    },
                    true,
                    3,
                    ReleaseClass::StatefulCompatible,
                ),
                Err(InstalledSourceError::InvalidConfig)
            ));
        }

        let mut valid = config_with_remote(
            uid,
            &signing_key,
            "ssh://git@github.com/mrDenai/rimg.git",
            Some(git_ssh),
        );
        valid.projects[0]
            .git_ssh
            .as_mut()
            .expect("SSH transport")
            .private_key_credential = "source-git-other-private-key".to_owned();
        assert!(matches!(
            valid.validate(),
            Err(InstalledSourceError::InvalidConfig)
        ));
    }

    #[test]
    fn source_service_can_write_only_its_external_export_store() {
        let unit = include_str!("../deploy/systemd/rdashboard-source.service");
        assert!(unit.lines().any(|line| line == "ProtectSystem=strict"));
        assert_eq!(
            unit.lines()
                .filter(|line| line.starts_with("ReadWritePaths="))
                .collect::<Vec<_>>(),
            ["ReadWritePaths=/var/lib/rdashboard-build/source-exports"]
        );
        assert_eq!(
            unit.lines()
                .filter(|line| line.starts_with("LoadCredential="))
                .collect::<Vec<_>>(),
            [
                "LoadCredential=source-attestation-seed:/etc/rdashboard/credentials/source-attestation-seed"
            ]
        );
        let git_ssh_drop_in = include_str!("../deploy/systemd/rdashboard-source-git-ssh.conf");
        assert_eq!(
            git_ssh_drop_in
                .lines()
                .filter(|line| line.starts_with("LoadCredential="))
                .collect::<Vec<_>>(),
            [
                "LoadCredential=source-git-rimg-private-key:/etc/rdashboard/credentials/source-git-rimg-private-key",
                "LoadCredential=source-git-rimg-known-hosts:/etc/rdashboard/credentials/source-git-rimg-known-hosts",
            ]
        );
    }

    #[test]
    fn candidate_output_directories_inherit_the_reader_group() {
        let tmpfiles = include_str!("../deploy/systemd/rdashboard-tmpfiles.conf");
        for path in [
            "/var/lib/rdashboard-build/release-bundles",
            "/var/lib/rdashboard-build/release-bundles/rimg",
            "/var/lib/rdashboard-build/attestations",
            "/var/lib/rdashboard-build/attestations/rimg",
        ] {
            let expected = format!("d {path} 2750 rdashboard-build rdashboard-build-readers -");
            assert!(tmpfiles.lines().any(|line| line == expected));
        }
    }

    #[test]
    fn installed_source_snapshot_verification_is_signature_policy_and_control_bound() {
        let directory = tempdir().expect("tempdir");
        let uid = fs::metadata(directory.path()).expect("metadata").uid();
        let signing_key = SigningKey::from_bytes(&[31_u8; 32]);
        let installed = config(uid, &signing_key);
        let project_id = installed.projects[0].project_id.clone();
        let repository = DeterministicSourceRepository::default();
        repository
            .set_repository_identity(
                &project_id,
                installed.projects[0].repository_identity.clone(),
            )
            .expect("repository identity");
        let head =
            GitCommitId::from_str("0123456789abcdef0123456789abcdef01234567").expect("commit");
        repository
            .insert_commit(&project_id, &head, None)
            .expect("insert commit");
        let broker = DurableSourceBroker::new(
            SourceStore::open(directory.path().join("source.sqlite")).expect("source store"),
            repository,
            installed.attestation_key_id.clone(),
            signing_key,
            installed.attestation_ttl_ms().expect("attestation TTL"),
            installed.source_policies(),
            100,
        )
        .expect("source broker");
        broker
            .process_direct_push(
                &project_id,
                "installed-snapshot",
                "refs/heads/main",
                None,
                head.clone(),
                101,
            )
            .expect("accept head");
        let snapshot = broker.store().snapshot(&project_id).expect("snapshot");

        let verified = installed
            .verify_snapshot(&snapshot, &head, 102)
            .expect("verify installed source snapshot");
        assert_eq!(verified.head, head);
        assert_eq!(verified.sequence, 1);
        assert_eq!(
            verified.installed_policy,
            installed.projects[0].installed_policy
        );

        let mut paused = snapshot.clone();
        paused.reconcile_paused_until_ms = Some(200);
        assert!(matches!(
            installed.verify_snapshot(&paused, &verified.head, 102),
            Err(InstalledSourceError::InvalidSourceSnapshot)
        ));

        let mut substituted = snapshot;
        substituted.sequence += 1;
        assert!(matches!(
            installed.verify_snapshot(&substituted, &verified.head, 102),
            Err(InstalledSourceError::InvalidSourceSnapshot)
        ));
    }
}
