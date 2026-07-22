use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    str::FromStr,
    sync::{
        Arc, Mutex, TryLockError,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::domain::{EvidenceDigest, GIB, GitCommitId, ProjectId, RemoteUrl};
use url::Url;

use super::{CommitRelationship, SourceError, SourceRepository};

const SYSTEM_GIT: &str = "/usr/bin/git";
#[cfg(unix)]
const SYSTEM_KILL: &str = "/usr/bin/kill";
const ACCEPTED_REF: &str = "refs/heads/rdashboard-accepted/main";
const FETCHED_MAIN_REF: &str = "refs/remotes/rdashboard/main";
const LOCAL_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const FETCH_TIMEOUT: Duration = Duration::from_mins(1);
const RECONCILIATION_FETCH_TIMEOUT: Duration = Duration::from_secs(2);
const CAPTURE_LIMIT: usize = 64 * 1024;
const MAX_EXPORT_TREE_ENTRIES: usize = 100_000;
const MAX_EXPORT_TREE_ENTRY_BYTES: usize = 64 * 1024;
const ERROR_DETAIL_CHAR_LIMIT: usize = 512;
const PACK_KEEP_MESSAGE_LIMIT: usize = 256;
const MAX_CANONICAL_CONFIG_BYTES: u64 = 64 * 1024;
const FETCH_STAGING_DIRECTORY: &str = ".rdashboard-fetch-staging";
const STAGING_INITIALIZATION_MARKER: &str = ".rdashboard-init-v1";
const STAGED_MAIN_REF: &str = "refs/heads/rdashboard-staged/main";
const STAGED_FETCHED_HAVE_REF: &str = "refs/rdashboard-haves/fetched-main";
const STAGED_ACCEPTED_HAVE_REF: &str = "refs/rdashboard-haves/accepted-main";
const DEFAULT_FETCH_MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_FETCH_MAX_STAGING_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_FETCH_EMERGENCY_BYTES: u64 = 4 * GIB;
const DEFAULT_FETCH_EMERGENCY_PERCENT: u64 = 5;
const OWNER_ONLY_SHARED_REPOSITORY: &str = "core.sharedRepository=0600";
const SOURCE_CREDENTIAL_DIRECTORY: &str = "/run/credentials/rdashboard-source.service";
type GitVersion = (u64, u64);
const MINIMUM_DURABLE_FILES_GIT_VERSION: GitVersion = (2, 36);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExportTreeMetrics {
    file_count: u64,
    total_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct FetchLimits {
    max_file_bytes: u64,
    max_staging_bytes: u64,
    emergency_bytes: u64,
    emergency_percent: u64,
}

impl FetchLimits {
    const PRODUCTION: Self = Self {
        max_file_bytes: DEFAULT_FETCH_MAX_FILE_BYTES,
        max_staging_bytes: DEFAULT_FETCH_MAX_STAGING_BYTES,
        emergency_bytes: DEFAULT_FETCH_EMERGENCY_BYTES,
        emergency_percent: DEFAULT_FETCH_EMERGENCY_PERCENT,
    };

    #[cfg(test)]
    const TEST: Self = Self {
        max_file_bytes: 16 * 1024 * 1024,
        max_staging_bytes: 32 * 1024 * 1024,
        emergency_bytes: 16 * 1024 * 1024,
        emergency_percent: 0,
    };

    fn validate(self) -> Result<Self, SourceError> {
        if self.max_file_bytes == 0
            || self.max_staging_bytes == 0
            || self.max_file_bytes > self.max_staging_bytes
            || self.emergency_percent > 100
        {
            return Err(SourceError::Repository(
                "Git fetch disk limits are internally inconsistent".to_owned(),
            ));
        }
        self.preflight_required_bytes(self.emergency_bytes)?;
        Ok(self)
    }

    fn emergency_reserve_bytes(self, path: &Path) -> Result<u64, SourceError> {
        let filesystem_bytes = fs2::total_space(path)
            .map_err(|error| repository_io_error("measure Git fetch filesystem size", &error))?;
        let percentage_bytes = filesystem_bytes
            .saturating_mul(self.emergency_percent)
            .div_ceil(100);
        Ok(self.emergency_bytes.max(percentage_bytes))
    }

    fn preflight_required_bytes(self, emergency_bytes: u64) -> Result<u64, SourceError> {
        self.max_staging_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(emergency_bytes))
            .ok_or_else(|| SourceError::Repository("Git fetch disk limits overflowed".to_owned()))
    }

    fn staging_minimum_available_bytes(self, emergency_bytes: u64) -> Result<u64, SourceError> {
        self.max_staging_bytes
            .checked_add(emergency_bytes)
            .ok_or_else(|| SourceError::Repository("Git fetch disk limits overflowed".to_owned()))
    }
}

#[derive(Clone, Debug)]
pub struct GitSourceProjectConfig {
    pub project_id: ProjectId,
    pub remote_url: RemoteUrl,
    pub ssh_transport: Option<GitSshTransportConfig>,
}

impl GitSourceProjectConfig {
    pub fn repository_identity(&self) -> EvidenceDigest {
        network_repository_identity(&self.remote_url)
    }
}

#[derive(Clone, Debug)]
pub struct GitSshTransportConfig {
    pub private_key_path: PathBuf,
    pub known_hosts_path: PathBuf,
}

impl GitSshTransportConfig {
    fn validate(&self) -> Result<(), SourceError> {
        for path in [&self.private_key_path, &self.known_hosts_path] {
            if path.parent() != Some(Path::new(SOURCE_CREDENTIAL_DIRECTORY))
                || path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_none_or(|name| {
                        name.is_empty()
                            || name.len() > 96
                            || !name.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                            })
                    })
            {
                return Err(SourceError::InvalidInstalledPolicy);
            }
        }
        if self.private_key_path == self.known_hosts_path {
            return Err(SourceError::InvalidInstalledPolicy);
        }
        Ok(())
    }

    fn command(&self) -> Result<String, SourceError> {
        self.validate()?;
        let private_key = self
            .private_key_path
            .to_str()
            .ok_or(SourceError::InvalidInstalledPolicy)?;
        let known_hosts = self
            .known_hosts_path
            .to_str()
            .ok_or(SourceError::InvalidInstalledPolicy)?;
        Ok(format!(
            "/usr/bin/ssh -i {private_key} -oIdentitiesOnly=yes -oIdentityAgent=none -oBatchMode=yes -oStrictHostKeyChecking=yes -oUserKnownHostsFile={known_hosts} -oGlobalKnownHostsFile=/dev/null -oUpdateHostKeys=no -oCheckHostIP=no -oPreferredAuthentications=publickey -oPasswordAuthentication=no -oKbdInteractiveAuthentication=no -oConnectTimeout=15 -oConnectionAttempts=1 -oServerAliveInterval=10"
        ))
    }
}

#[derive(Clone, Debug)]
pub struct GitSourceRepository {
    git_executable: PathBuf,
    git_version: GitVersion,
    projects: Arc<BTreeMap<String, InstalledGitProject>>,
    fetch_lock: Arc<Mutex<()>>,
    foreground_fetch_waiters: Arc<AtomicUsize>,
    priority_fetch_projects: Arc<BTreeMap<String, Arc<AtomicBool>>>,
    priority_fetch_project_count: Arc<AtomicUsize>,
    fetch_priority_generation: Arc<AtomicU64>,
    fetch_limits: FetchLimits,
}

#[derive(Clone, Debug)]
struct InstalledGitProject {
    repository_root: PathBuf,
    repository_path: PathBuf,
    remote: GitRemote,
    ssh_command: Option<String>,
    repository_identity: EvidenceDigest,
    command_lock: Arc<Mutex<()>>,
    #[cfg(unix)]
    filesystem_identity: RepositoryFilesystemIdentity,
    #[cfg(unix)]
    configuration_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PromotedPackGuard {
    pack_hash: String,
    keep_message: String,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RepositoryFilesystemIdentity {
    root_device: u64,
    root_inode: u64,
    repository_device: u64,
    repository_inode: u64,
    owner_uid: u32,
}

#[cfg(unix)]
impl RepositoryFilesystemIdentity {
    fn require_shared_filesystem(self) -> Result<Self, SourceError> {
        if self.root_device != self.repository_device {
            return Err(SourceError::Repository(
                "canonical Git repository and fetch staging root must share one filesystem so bounded promotion can enforce the emergency disk reserve"
                    .to_owned(),
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug)]
enum GitRemote {
    Network(RemoteUrl),
    #[cfg(test)]
    Local(PathBuf),
}

impl GitRemote {
    fn argument(&self) -> OsString {
        match self {
            Self::Network(url) => OsString::from(url.as_str()),
            #[cfg(test)]
            Self::Local(path) => path.as_os_str().to_owned(),
        }
    }

    const fn allows_file_protocol(&self) -> bool {
        match self {
            Self::Network(_) => false,
            #[cfg(test)]
            Self::Local(_) => true,
        }
    }

    fn repository_identity(&self) -> EvidenceDigest {
        match self {
            Self::Network(url) => network_repository_identity(url),
            #[cfg(test)]
            Self::Local(path) => EvidenceDigest::sha256(format!(
                "rdashboard.test-local-repository.v1\0{}",
                path.display()
            )),
        }
    }
}

impl GitSourceRepository {
    pub fn open(
        repository_root: impl AsRef<Path>,
        projects: impl IntoIterator<Item = GitSourceProjectConfig>,
    ) -> Result<Self, SourceError> {
        let projects = projects
            .into_iter()
            .map(|project| {
                (
                    project.project_id,
                    GitRemote::Network(project.remote_url),
                    project.ssh_transport,
                )
            })
            .collect::<Vec<_>>();
        Self::open_with_transport(repository_root.as_ref(), projects, FetchLimits::PRODUCTION)
    }

    #[cfg(test)]
    fn open_with_remotes(
        repository_root: &Path,
        projects: Vec<(ProjectId, GitRemote)>,
    ) -> Result<Self, SourceError> {
        Self::open_with_remotes_and_limits(repository_root, projects, FetchLimits::PRODUCTION)
    }

    #[cfg(test)]
    fn open_with_remotes_and_limits(
        repository_root: &Path,
        projects: Vec<(ProjectId, GitRemote)>,
        fetch_limits: FetchLimits,
    ) -> Result<Self, SourceError> {
        Self::open_with_transport(
            repository_root,
            projects
                .into_iter()
                .map(|(project_id, remote)| (project_id, remote, None))
                .collect(),
            fetch_limits,
        )
    }

    fn open_with_transport(
        repository_root: &Path,
        projects: Vec<(ProjectId, GitRemote, Option<GitSshTransportConfig>)>,
        fetch_limits: FetchLimits,
    ) -> Result<Self, SourceError> {
        let root = validate_repository_root(repository_root)?;
        let (git_executable, git_version) = validate_git_executable()?;
        let fetch_limits = fetch_limits.validate()?;
        #[cfg(unix)]
        validate_process_kill_executable()?;
        let mut installed = BTreeMap::new();
        for (project_id, remote, ssh_transport) in projects {
            let remote_uses_ssh = match &remote {
                GitRemote::Network(remote) => {
                    Url::parse(remote.as_str()).is_ok_and(|url| url.scheme() == "ssh")
                }
                #[cfg(test)]
                GitRemote::Local(_) => false,
            };
            if remote_uses_ssh != ssh_transport.is_some() {
                return Err(SourceError::InvalidInstalledPolicy);
            }
            if let Some(transport) = &ssh_transport {
                transport.validate()?;
            }
            let ssh_command = ssh_transport
                .as_ref()
                .map(GitSshTransportConfig::command)
                .transpose()?;
            let key = project_id.to_string();
            let repository_path = validate_project_repository(&root, &project_id)?;
            #[cfg(unix)]
            let filesystem_identity = validate_repository_permissions(&root, &repository_path)?;
            #[cfg(unix)]
            let configuration_digest = canonical_repository_configuration_digest(
                &repository_path,
                filesystem_identity.owner_uid,
            )?;
            let repository_identity = remote.repository_identity();
            if installed
                .insert(
                    key,
                    InstalledGitProject {
                        repository_root: root.clone(),
                        repository_path,
                        remote,
                        ssh_command,
                        repository_identity,
                        command_lock: Arc::new(Mutex::new(())),
                        #[cfg(unix)]
                        filesystem_identity,
                        #[cfg(unix)]
                        configuration_digest,
                    },
                )
                .is_some()
            {
                return Err(SourceError::DuplicateInstalledProject);
            }
        }
        if installed.is_empty() {
            return Err(SourceError::InvalidInstalledPolicy);
        }
        let priority_fetch_projects = installed
            .keys()
            .map(|project_id| (project_id.clone(), Arc::new(AtomicBool::new(false))))
            .collect();
        let repository = Self {
            git_executable,
            git_version,
            projects: Arc::new(installed),
            fetch_lock: Arc::new(Mutex::new(())),
            foreground_fetch_waiters: Arc::new(AtomicUsize::new(0)),
            priority_fetch_projects: Arc::new(priority_fetch_projects),
            priority_fetch_project_count: Arc::new(AtomicUsize::new(0)),
            fetch_priority_generation: Arc::new(AtomicU64::new(0)),
            fetch_limits,
        };
        repository.verify_bare_repositories()?;
        Ok(repository)
    }

    #[cfg(test)]
    fn open_local(
        repository_root: &Path,
        project_id: ProjectId,
        remote_path: PathBuf,
    ) -> Result<Self, SourceError> {
        Self::open_local_with_limits(repository_root, project_id, remote_path, FetchLimits::TEST)
    }

    #[cfg(test)]
    fn open_local_with_limits(
        repository_root: &Path,
        project_id: ProjectId,
        remote_path: PathBuf,
        fetch_limits: FetchLimits,
    ) -> Result<Self, SourceError> {
        Self::open_with_remotes_and_limits(
            repository_root,
            vec![(project_id, GitRemote::Local(remote_path))],
            fetch_limits,
        )
    }

    fn verify_bare_repositories(&self) -> Result<(), SourceError> {
        for project in self.projects.values() {
            let _guard = project
                .command_lock
                .lock()
                .map_err(|_| SourceError::LockPoisoned)?;
            self.verify_local_config_is_self_contained(project)?;
            self.verify_ref_storage(project)?;
            let output = self.run_git(
                project,
                "verify bare repository",
                os_args(&["rev-parse", "--is-bare-repository"]),
                None,
                LOCAL_COMMAND_TIMEOUT,
            )?;
            require_success("verify bare repository", &output)?;
            if parse_stdout("verify bare repository", &output)? != "true" {
                return Err(SourceError::Repository(
                    "installed canonical repository is not bare".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn verify_ref_storage(&self, project: &InstalledGitProject) -> Result<(), SourceError> {
        let output = self.run_git(
            project,
            "inspect repository ref storage",
            os_args(&[
                "config",
                "--local",
                "--no-includes",
                "--get",
                "extensions.refStorage",
            ]),
            None,
            LOCAL_COMMAND_TIMEOUT,
        )?;
        let storage = match output.status.code() {
            Some(0) => parse_stdout("inspect repository ref storage", &output)?,
            Some(1) => "files",
            _ => return Err(command_failure("inspect repository ref storage", &output)),
        };
        require_durable_ref_storage(self.git_version, storage)
    }

    fn verify_local_config_is_self_contained(
        &self,
        project: &InstalledGitProject,
    ) -> Result<(), SourceError> {
        let output = self.run_git(
            project,
            "inspect repository-local Git configuration keys",
            os_args(&[
                "config",
                "--local",
                "--no-includes",
                "--name-only",
                "--list",
            ]),
            None,
            LOCAL_COMMAND_TIMEOUT,
        )?;
        require_success("inspect repository-local Git configuration keys", &output)?;
        for key in parse_stdout("inspect repository-local Git configuration keys", &output)?
            .lines()
            .map(str::to_ascii_lowercase)
        {
            let is_conditional_include = key.starts_with("includeif.")
                && key.rsplit('.').next().is_some_and(|name| name == "path");
            if key == "include.path" || is_conditional_include {
                return Err(SourceError::Repository(
                    "canonical Git repository configuration includes are forbidden".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn project(&self, project_id: &ProjectId) -> Result<&InstalledGitProject, SourceError> {
        self.projects
            .get(project_id.as_str())
            .ok_or_else(|| SourceError::UnknownProject(project_id.to_string()))
    }

    /// Writes the exact accepted tree as a deterministic tar stream without exposing the bare
    /// repository to the build identity.
    pub fn export_accepted_tree(
        &self,
        project_id: &ProjectId,
        expected_head: &GitCommitId,
        output: &File,
    ) -> Result<(), SourceError> {
        let project = self.project(project_id)?;
        let _guard = project
            .command_lock
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?;
        validate_installed_repository(project)?;
        if self.read_ref(project, ACCEPTED_REF)?.as_ref() != Some(expected_head) {
            return Err(SourceError::Repository(
                "accepted source head changed before immutable export".to_owned(),
            ));
        }
        self.validate_exportable_tree(project, expected_head)?;
        let mut command = Command::new(&self.git_executable);
        configure_git_command(&mut command, project);
        command.args([
            OsString::from("archive"),
            OsString::from("--format=tar"),
            OsString::from(expected_head.as_str()),
        ]);
        run_command_to_file(
            command,
            "export accepted source tree",
            output.try_clone().map_err(|error| {
                repository_io_error("clone immutable source export descriptor", &error)
            })?,
            FETCH_TIMEOUT,
        )?;
        validate_installed_repository(project)?;
        if self.read_ref(project, ACCEPTED_REF)?.as_ref() != Some(expected_head) {
            return Err(SourceError::Repository(
                "accepted source head changed during immutable export".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_exportable_tree(
        &self,
        project: &InstalledGitProject,
        expected_head: &GitCommitId,
    ) -> Result<ExportTreeMetrics, SourceError> {
        let mut command = Command::new(&self.git_executable);
        configure_git_command(&mut command, project);
        command.args([
            OsString::from("ls-tree"),
            OsString::from("-r"),
            OsString::from("-z"),
            OsString::from("-l"),
            OsString::from("--full-tree"),
            OsString::from(expected_head.as_str()),
        ]);
        let metrics = run_export_tree_inspection(
            command,
            "inspect immutable export tree",
            LOCAL_COMMAND_TIMEOUT,
        )?;
        if metrics.file_count == 0 {
            return Err(SourceError::Repository(
                "immutable export tree is empty".to_owned(),
            ));
        }
        Ok(metrics)
    }

    fn read_ref(
        &self,
        project: &InstalledGitProject,
        reference: &str,
    ) -> Result<Option<GitCommitId>, SourceError> {
        let output = self.run_git(
            project,
            "read canonical ref",
            vec![
                OsString::from("for-each-ref"),
                OsString::from("--format=%(objectname)"),
                OsString::from(reference),
            ],
            None,
            LOCAL_COMMAND_TIMEOUT,
        )?;
        require_success("read canonical ref", &output)?;
        let value = parse_stdout("read canonical ref", &output)?;
        if value.is_empty() {
            Ok(None)
        } else {
            GitCommitId::from_str(value)
                .map(Some)
                .map_err(|_| SourceError::Repository("canonical ref is not a commit ID".to_owned()))
        }
    }

    fn contains_commit_locked(
        &self,
        project: &InstalledGitProject,
        commit: &GitCommitId,
    ) -> Result<bool, SourceError> {
        let input = format!("{commit}\n").into_bytes();
        let output = self.run_git(
            project,
            "inspect commit object",
            os_args(&["cat-file", "--batch-check=%(objecttype)"]),
            Some(&input),
            LOCAL_COMMAND_TIMEOUT,
        )?;
        require_success("inspect commit object", &output)?;
        let object_type = parse_stdout("inspect commit object", &output)?;
        if object_type == "commit" {
            Ok(true)
        } else if object_type
            .strip_suffix(" missing")
            .is_some_and(|missing| missing == commit.as_str())
        {
            Ok(false)
        } else {
            Err(SourceError::Repository(
                "source object exists but is not a commit".to_owned(),
            ))
        }
    }

    fn is_ancestor(
        &self,
        project: &InstalledGitProject,
        ancestor: &GitCommitId,
        descendant: &GitCommitId,
    ) -> Result<bool, SourceError> {
        let output = self.run_git(
            project,
            "compare commit ancestry",
            vec![
                OsString::from("merge-base"),
                OsString::from("--is-ancestor"),
                OsString::from(ancestor.as_str()),
                OsString::from(descendant.as_str()),
            ],
            None,
            LOCAL_COMMAND_TIMEOUT,
        )?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(command_failure("compare commit ancestry", &output)),
        }
    }

    fn run_git(
        &self,
        project: &InstalledGitProject,
        operation: &'static str,
        arguments: Vec<OsString>,
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<GitCommandOutput, SourceError> {
        validate_installed_repository(project)?;
        let mut command = Command::new(&self.git_executable);
        configure_git_command(&mut command, project);
        command.args(arguments);
        run_command(command, operation, input, timeout)
    }

    fn run_staging_git(
        &self,
        project: &InstalledGitProject,
        git_directory: &Path,
        operation: &'static str,
        arguments: Vec<OsString>,
        timeout: Duration,
        disk_guard: Option<&CommandDiskGuard<'_>>,
    ) -> Result<GitCommandOutput, SourceError> {
        let mut command = Command::new(&self.git_executable);
        configure_git_command_for_directory(
            &mut command,
            git_directory,
            project.remote.allows_file_protocol(),
            project.ssh_command.as_deref(),
        );
        configure_staging_object_directories(&mut command, project, git_directory)?;
        command.args(arguments);
        run_command_guarded(command, operation, CommandInput::Null, timeout, disk_guard)
    }

    fn read_staging_ref(
        &self,
        project: &InstalledGitProject,
        git_directory: &Path,
        reference: &str,
    ) -> Result<Option<GitCommitId>, SourceError> {
        let output = self.run_staging_git(
            project,
            git_directory,
            "read staged ref",
            vec![
                OsString::from("for-each-ref"),
                OsString::from("--format=%(objectname)"),
                OsString::from(reference),
            ],
            LOCAL_COMMAND_TIMEOUT,
            None,
        )?;
        require_success("read staged ref", &output)?;
        let value = parse_stdout("read staged ref", &output)?;
        if value.is_empty() {
            Ok(None)
        } else {
            GitCommitId::from_str(value)
                .map(Some)
                .map_err(|_| SourceError::Repository("staged ref is not a commit ID".to_owned()))
        }
    }

    fn seed_staging_negotiation_refs(
        &self,
        project: &InstalledGitProject,
        staging_path: &Path,
        disk_guard: &CommandDiskGuard<'_>,
    ) -> Result<(), SourceError> {
        for (canonical_ref, staged_ref) in [
            (FETCHED_MAIN_REF, STAGED_FETCHED_HAVE_REF),
            (ACCEPTED_REF, STAGED_ACCEPTED_HAVE_REF),
        ] {
            let Some(commit) = self.read_ref(project, canonical_ref)? else {
                continue;
            };
            let output = self.run_staging_git(
                project,
                staging_path,
                "seed bounded fetch negotiation",
                vec![
                    OsString::from("update-ref"),
                    OsString::from("--no-deref"),
                    OsString::from(staged_ref),
                    OsString::from(commit.as_str()),
                    OsString::new(),
                ],
                LOCAL_COMMAND_TIMEOUT,
                Some(disk_guard),
            )?;
            require_success("seed bounded fetch negotiation", &output)?;
        }
        Ok(())
    }

    fn repository_object_format(
        &self,
        project: &InstalledGitProject,
    ) -> Result<&'static str, SourceError> {
        let output = self.run_git(
            project,
            "inspect repository object format",
            os_args(&["rev-parse", "--show-object-format"]),
            None,
            LOCAL_COMMAND_TIMEOUT,
        )?;
        require_success("inspect repository object format", &output)?;
        match parse_stdout("inspect repository object format", &output)? {
            "sha1" => Ok("sha1"),
            "sha256" => Ok("sha256"),
            _ => Err(SourceError::Repository(
                "canonical repository uses an unsupported object format".to_owned(),
            )),
        }
    }

    fn initialize_staging_repository(
        &self,
        project: &InstalledGitProject,
        staging_path: &Path,
        object_format: &str,
    ) -> Result<(), SourceError> {
        create_private_directory(staging_path)?;
        let mut command = Command::new(&self.git_executable);
        configure_git_environment(&mut command, project.ssh_command.as_deref());
        command.env("GIT_DEFAULT_REF_FORMAT", "files");
        command.args([
            OsString::from("--no-pager"),
            OsString::from("-c"),
            OsString::from("credential.helper="),
            OsString::from("-c"),
            OsString::from("core.hooksPath=/dev/null"),
            OsString::from("init"),
            OsString::from("--bare"),
            OsString::from("--shared=0600"),
            OsString::from("--initial-branch=main"),
            OsString::from(format!("--object-format={object_format}")),
            staging_path.as_os_str().to_owned(),
        ]);
        let output = run_command(
            command,
            "initialize fetch staging repository",
            None,
            LOCAL_COMMAND_TIMEOUT,
        )?;
        require_success("initialize fetch staging repository", &output)?;
        sync_staging_initialization_file(
            project,
            &staging_path.join("config"),
            "sync fetch staging configuration",
        )?;
        sync_staging_initialization_file(
            project,
            &staging_path.join("HEAD"),
            "sync fetch staging HEAD",
        )?;
        sync_directory(staging_path)?;
        write_staging_initialization_marker(project, staging_path)?;
        sync_directory(staging_path)?;
        let staging_root = staging_path
            .parent()
            .ok_or(SourceError::InvalidCanonicalRepositoryPath)?;
        sync_directory(staging_root)
    }

    fn fetch_staged_main(
        &self,
        project: &InstalledGitProject,
        staging_path: &Path,
        disk_guard: &CommandDiskGuard<'_>,
        fetch_timeout: Duration,
    ) -> Result<GitCommitId, SourceError> {
        self.seed_staging_negotiation_refs(project, staging_path, disk_guard)?;
        let output = self.run_staging_git(
            project,
            staging_path,
            "fetch bounded remote main",
            vec![
                OsString::from("-c"),
                OsString::from("fetch.unpackLimit=1"),
                OsString::from("-c"),
                OsString::from("transfer.unpackLimit=1"),
                OsString::from("-c"),
                OsString::from("fetch.fsckObjects=true"),
                OsString::from("-c"),
                OsString::from("transfer.fsckObjects=true"),
                OsString::from("-c"),
                OsString::from("gc.auto=0"),
                OsString::from("-c"),
                OsString::from("maintenance.auto=false"),
                OsString::from("-c"),
                OsString::from("pack.writeReverseIndex=false"),
                OsString::from("-c"),
                OsString::from("core.fsync=reference"),
                OsString::from("-c"),
                OsString::from("core.fsyncMethod=fsync"),
                OsString::from("fetch"),
                OsString::from("--quiet"),
                OsString::from("--no-tags"),
                OsString::from("--no-recurse-submodules"),
                OsString::from("--no-write-fetch-head"),
                OsString::from("--force"),
                project.remote.argument(),
                OsString::from(format!("+refs/heads/main:{STAGED_MAIN_REF}")),
            ],
            fetch_timeout,
            Some(disk_guard),
        )?;
        require_success("fetch bounded remote main", &output)?;
        validate_staging_identity(staging_path, disk_guard.staging_identity)?;
        inspect_staging_tree(staging_path, self.fetch_limits, false)?;
        let candidate = self
            .read_staging_ref(project, staging_path, STAGED_MAIN_REF)?
            .ok_or_else(|| {
                SourceError::Repository(
                    "bounded remote main did not resolve to a staged commit".to_owned(),
                )
            })?;
        let input = format!("{candidate}\n").into_bytes();
        let output = {
            let mut command = Command::new(&self.git_executable);
            configure_git_command_for_directory(
                &mut command,
                staging_path,
                project.remote.allows_file_protocol(),
                project.ssh_command.as_deref(),
            );
            configure_staging_object_directories(&mut command, project, staging_path)?;
            command.args(os_args(&["cat-file", "--batch-check=%(objecttype)"]));
            run_command(
                command,
                "inspect staged commit object",
                Some(&input),
                LOCAL_COMMAND_TIMEOUT,
            )?
        };
        require_success("inspect staged commit object", &output)?;
        if parse_stdout("inspect staged commit object", &output)? != "commit" {
            return Err(SourceError::Repository(
                "bounded remote main is not a commit object".to_owned(),
            ));
        }
        Ok(candidate)
    }

    fn promote_staged_pack(
        &self,
        project: &InstalledGitProject,
        staging_path: &Path,
        candidate: &GitCommitId,
        emergency_reserve_bytes: u64,
    ) -> Result<Option<PromotedPackGuard>, SourceError> {
        let pack_path = staged_pack(staging_path, self.fetch_limits)?;
        validate_installed_repository(project)?;
        let Some(pack_path) = pack_path else {
            if self.contains_commit_locked(project, candidate)? {
                return Ok(None);
            }
            return Err(SourceError::Repository(
                "bounded Git fetch produced no pack for a missing commit".to_owned(),
            ));
        };
        require_available_bytes(
            &project.repository_root,
            emergency_reserve_bytes,
            "promote bounded Git fetch",
        )?;
        let pack_file =
            open_verified_staged_pack(&pack_path, self.fetch_limits.max_file_bytes, staging_path)?;
        let promotion_guard = CommandDiskGuard {
            free_space_path: &project.repository_root,
            minimum_available_bytes: emergency_reserve_bytes,
            staging_path: None,
            staging_identity: None,
            fetch_limits: self.fetch_limits,
            foreground_fetch_waiters: None,
            priority_fetch_project_count: None,
            fetch_priority_generation: None,
        };
        let keep_message = promoted_pack_keep_message(project, candidate);
        let mut command = Command::new(&self.git_executable);
        configure_git_command(&mut command, project);
        command.args([
            OsString::from("-c"),
            OsString::from("gc.auto=0"),
            OsString::from("-c"),
            OsString::from("maintenance.auto=false"),
            OsString::from("-c"),
            OsString::from("pack.writeReverseIndex=false"),
            OsString::from("-c"),
            OsString::from(OWNER_ONLY_SHARED_REPOSITORY),
            OsString::from("-c"),
            OsString::from("core.fsync=pack,pack-metadata"),
            OsString::from("-c"),
            OsString::from("core.fsyncMethod=fsync"),
            OsString::from("index-pack"),
            OsString::from("--stdin"),
            OsString::from("--fix-thin"),
            OsString::from("--strict"),
            OsString::from(format!("--keep={keep_message}")),
            OsString::from(format!(
                "--max-input-size={}",
                self.fetch_limits.max_file_bytes
            )),
        ]);
        let output = run_command_guarded(
            command,
            "promote bounded Git pack",
            CommandInput::File(pack_file),
            FETCH_TIMEOUT,
            Some(&promotion_guard),
        )?;
        require_success("promote bounded Git pack", &output)?;
        let promoted_pack_guard =
            promoted_pack_guard_from_output(project, candidate, keep_message, &output)?;
        validate_installed_repository(project)?;
        if !self.contains_commit_locked(project, candidate)? {
            return Err(SourceError::Repository(
                "promoted Git pack does not contain the staged commit".to_owned(),
            ));
        }
        Ok(Some(promoted_pack_guard))
    }

    fn update_fetched_main_ref(
        &self,
        project: &InstalledGitProject,
        candidate: &GitCommitId,
    ) -> Result<(), SourceError> {
        let current = self.read_ref(project, FETCHED_MAIN_REF)?;
        if current.as_ref() == Some(candidate) {
            return Ok(());
        }
        let old_value = current.map_or_else(OsString::new, |commit| commit.as_str().into());
        let output = self.run_git(
            project,
            "publish bounded fetched head",
            durable_update_ref_arguments(FETCHED_MAIN_REF, candidate, old_value),
            None,
            LOCAL_COMMAND_TIMEOUT,
        )?;
        if output.status.success() {
            validate_installed_repository(project)
        } else {
            Err(command_failure("publish bounded fetched head", &output))
        }
    }

    fn reconcile_stale_staging_directories(
        &self,
        active_project: &InstalledGitProject,
        staging_root: &Path,
    ) -> Result<(), SourceError> {
        validate_staging_root(active_project, staging_root)?;
        for entry in fs::read_dir(staging_root)
            .map_err(|error| repository_io_error("enumerate stale Git fetch staging", &error))?
        {
            let entry = entry
                .map_err(|error| repository_io_error("inspect stale Git fetch staging", &error))?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                SourceError::Repository("Git fetch staging entry is not UTF-8".to_owned())
            })?;
            let project_name = name.strip_suffix(".git").ok_or_else(|| {
                SourceError::Repository("unexpected entry in Git fetch staging root".to_owned())
            })?;
            let project_id = ProjectId::from_str(project_name).map_err(|_| {
                SourceError::Repository(
                    "invalid project entry in Git fetch staging root".to_owned(),
                )
            })?;
            let Some(stale_project) = self.projects.get(project_id.as_str()) else {
                return Err(SourceError::Repository(format!(
                    "Git fetch staging for unconfigured project {project_id} was retained for explicit retirement reconciliation"
                )));
            };
            if std::ptr::eq(stale_project, active_project) {
                self.reconcile_interrupted_fetch(stale_project, &entry.path())?;
                continue;
            }
            let _guard = stale_project
                .command_lock
                .lock()
                .map_err(|_| SourceError::LockPoisoned)?;
            validate_installed_repository(stale_project)?;
            self.reconcile_interrupted_fetch(stale_project, &entry.path())?;
        }
        Ok(())
    }

    fn reconcile_interrupted_fetch(
        &self,
        project: &InstalledGitProject,
        staging_path: &Path,
    ) -> Result<(), SourceError> {
        validate_new_staging_repository(project, staging_path)?;
        if !staging_initialization_complete(project, staging_path)? {
            return remove_staging_directory(project, staging_path);
        }
        inspect_staging_tree(staging_path, self.fetch_limits, false)?;
        if !staging_repository_initialized(staging_path)? {
            return Err(SourceError::Repository(
                "initialized Git fetch staging lost its durable repository skeleton and was retained for explicit reconciliation"
                    .to_owned(),
            ));
        }
        let Some(candidate) = self.read_staging_ref(project, staging_path, STAGED_MAIN_REF)? else {
            return remove_staging_directory(project, staging_path);
        };
        let current = self.read_ref(project, FETCHED_MAIN_REF)?;
        let mut promoted_pack_guard = find_promoted_pack_guard(project, &candidate)?;
        let staged_pack = staged_pack(staging_path, self.fetch_limits);
        let mut contains_candidate = self.contains_commit_locked(project, &candidate)?;

        if promoted_pack_guard.is_some() {
            if !contains_candidate {
                return Err(SourceError::Repository(
                    "interrupted Git promotion retained its keep marker but the candidate object is unavailable"
                        .to_owned(),
                ));
            }
        } else if current.as_ref() != Some(&candidate) {
            match staged_pack {
                Ok(Some(_)) => {
                    let emergency_reserve_bytes = self
                        .fetch_limits
                        .emergency_reserve_bytes(&project.repository_root)?;
                    promoted_pack_guard = self.promote_staged_pack(
                        project,
                        staging_path,
                        &candidate,
                        emergency_reserve_bytes,
                    )?;
                    if promoted_pack_guard.is_none() {
                        return Err(SourceError::Repository(
                            "interrupted Git promotion did not recreate its exact keep marker"
                                .to_owned(),
                        ));
                    }
                    contains_candidate = true;
                }
                Ok(None) if !contains_candidate => {
                    return remove_staging_directory(project, staging_path);
                }
                Ok(None) => {}
                Err(staging_error) if contains_candidate => {
                    return Err(SourceError::Repository(format!(
                        "interrupted Git promotion has no exact keep marker and its staged pack cannot be replayed: {staging_error}"
                    )));
                }
                Err(_) => return remove_staging_directory(project, staging_path),
            }
        }
        if !contains_candidate {
            return Err(SourceError::Repository(
                "durable fetched ref points to an unavailable canonical commit".to_owned(),
            ));
        }
        self.update_fetched_main_ref(project, &candidate)?;
        if let Some(promoted_pack_guard) = promoted_pack_guard.as_ref() {
            release_promoted_pack_guard(project, promoted_pack_guard)?;
        }
        remove_staging_directory(project, staging_path)
    }

    fn reconcile_orphaned_promoted_pack_guards(
        &self,
        project: &InstalledGitProject,
    ) -> Result<(), SourceError> {
        let promoted_pack_guards = find_project_promoted_pack_guards(project)?;
        if promoted_pack_guards.is_empty() {
            return Ok(());
        }
        let current = self.read_ref(project, FETCHED_MAIN_REF)?;
        for (candidate, promoted_pack_guard) in promoted_pack_guards {
            if current.as_ref() != Some(&candidate)
                || !self.contains_commit_locked(project, &candidate)?
            {
                return Err(SourceError::Repository(format!(
                    "orphaned Git keep marker for candidate {candidate} was retained for explicit reconciliation"
                )));
            }
            release_promoted_pack_guard(project, &promoted_pack_guard)?;
        }
        Ok(())
    }

    fn fetch_remote_main_locked(
        &self,
        project_id: &ProjectId,
        project: &InstalledGitProject,
        fetch_timeout: Duration,
        background_generation: Option<u64>,
    ) -> Result<GitCommitId, SourceError> {
        let _guard = project
            .command_lock
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?;
        self.require_current_background_priority(background_generation)?;
        validate_installed_repository(project)?;
        let staging_root = prepare_staging_root(project)?;
        self.reconcile_stale_staging_directories(project, &staging_root)?;
        self.require_current_background_priority(background_generation)?;
        self.reconcile_orphaned_promoted_pack_guards(project)?;
        cleanup_canonical_pack_temporaries(project)?;
        self.require_current_background_priority(background_generation)?;
        let emergency_reserve_bytes = self
            .fetch_limits
            .emergency_reserve_bytes(&project.repository_root)?;
        require_available_bytes(
            &project.repository_root,
            self.fetch_limits
                .preflight_required_bytes(emergency_reserve_bytes)?,
            "start bounded Git fetch",
        )?;
        let staging_path = staging_root.join(format!("{project_id}.git"));
        let object_format = self.repository_object_format(project)?;
        let mut promotion_started = false;
        let result = (|| {
            self.initialize_staging_repository(project, &staging_path, object_format)?;
            let staging_identity = validate_new_staging_repository(project, &staging_path)?;
            let staging_guard = CommandDiskGuard {
                free_space_path: &project.repository_root,
                minimum_available_bytes: self
                    .fetch_limits
                    .staging_minimum_available_bytes(emergency_reserve_bytes)?,
                staging_path: Some(&staging_path),
                staging_identity: Some(staging_identity),
                fetch_limits: self.fetch_limits,
                foreground_fetch_waiters: background_generation
                    .map(|_| self.foreground_fetch_waiters.as_ref()),
                priority_fetch_project_count: background_generation
                    .map(|_| self.priority_fetch_project_count.as_ref()),
                fetch_priority_generation: background_generation
                    .map(|generation| (self.fetch_priority_generation.as_ref(), generation)),
            };
            let candidate =
                self.fetch_staged_main(project, &staging_path, &staging_guard, fetch_timeout)?;
            promotion_started = true;
            let promoted_pack_guard = self.promote_staged_pack(
                project,
                &staging_path,
                &candidate,
                emergency_reserve_bytes,
            )?;
            Ok((candidate, promoted_pack_guard))
        })();
        let (candidate, promoted_pack_guard) = if promotion_started {
            result?
        } else {
            reconcile_failed_fetch(project, &staging_path, result)?
        };
        // The staging ref is the recovery token for a promoted pack. Publish the
        // canonical ref before removing it so a failed ref update can be retried.
        self.update_fetched_main_ref(project, &candidate)?;
        if let Some(promoted_pack_guard) = promoted_pack_guard.as_ref() {
            release_promoted_pack_guard(project, promoted_pack_guard)?;
        }
        remove_staging_directory(project, &staging_path)?;
        Ok(candidate)
    }

    fn require_current_background_priority(
        &self,
        expected_generation: Option<u64>,
    ) -> Result<(), SourceError> {
        let Some(expected_generation) = expected_generation else {
            return Ok(());
        };
        if self.foreground_fetch_waiters.load(Ordering::Acquire) > 0
            || self.priority_fetch_project_count.load(Ordering::Acquire) > 0
            || self.fetch_priority_generation.load(Ordering::Acquire) != expected_generation
        {
            return Err(SourceError::ReconciliationDeferred);
        }
        Ok(())
    }

    fn priority_fetch_project(&self, project_id: &ProjectId) -> Result<&AtomicBool, SourceError> {
        self.priority_fetch_projects
            .get(project_id.as_str())
            .map(Arc::as_ref)
            .ok_or_else(|| SourceError::UnknownProject(project_id.to_string()))
    }
}

impl SourceRepository for GitSourceRepository {
    fn repository_identity(&self, project_id: &ProjectId) -> Result<EvidenceDigest, SourceError> {
        Ok(self.project(project_id)?.repository_identity.clone())
    }

    fn fetch_remote_main(&self, project_id: &ProjectId) -> Result<GitCommitId, SourceError> {
        let project = self.project(project_id)?;
        self.foreground_fetch_waiters.fetch_add(1, Ordering::AcqRel);
        let fetch_guard = self.fetch_lock.lock();
        self.foreground_fetch_waiters.fetch_sub(1, Ordering::AcqRel);
        let _fetch_guard = fetch_guard.map_err(|_| SourceError::LockPoisoned)?;
        self.fetch_remote_main_locked(project_id, project, FETCH_TIMEOUT, None)
    }

    fn fetch_remote_main_reconciliation(
        &self,
        project_id: &ProjectId,
    ) -> Result<GitCommitId, SourceError> {
        let priority_generation = self.fetch_priority_generation.load(Ordering::Acquire);
        if self.foreground_fetch_waiters.load(Ordering::Acquire) > 0
            || self.priority_fetch_project_count.load(Ordering::Acquire) > 0
        {
            return Err(SourceError::ReconciliationDeferred);
        }
        let _fetch_guard = match self.fetch_lock.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(SourceError::ReconciliationDeferred),
            Err(TryLockError::Poisoned(_)) => return Err(SourceError::LockPoisoned),
        };
        if self.foreground_fetch_waiters.load(Ordering::Acquire) > 0
            || self.priority_fetch_project_count.load(Ordering::Acquire) > 0
        {
            return Err(SourceError::ReconciliationDeferred);
        }
        if self.fetch_priority_generation.load(Ordering::Acquire) != priority_generation {
            return Err(SourceError::ReconciliationDeferred);
        }
        let project = self.project(project_id)?;
        self.fetch_remote_main_locked(
            project_id,
            project,
            RECONCILIATION_FETCH_TIMEOUT,
            Some(priority_generation),
        )
    }

    fn notify_priority_fetch(&self, project_id: &ProjectId) -> Result<(), SourceError> {
        let priority = self.priority_fetch_project(project_id)?;
        if !priority.swap(true, Ordering::AcqRel) {
            self.priority_fetch_project_count
                .fetch_add(1, Ordering::AcqRel);
        }
        self.fetch_priority_generation
            .fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn clear_priority_fetch(&self, project_id: &ProjectId) -> Result<(), SourceError> {
        let priority = self.priority_fetch_project(project_id)?;
        if priority.swap(false, Ordering::AcqRel) {
            self.priority_fetch_project_count
                .fetch_sub(1, Ordering::AcqRel);
        }
        Ok(())
    }

    fn contains_commit(
        &self,
        project_id: &ProjectId,
        commit: &GitCommitId,
    ) -> Result<bool, SourceError> {
        let project = self.project(project_id)?;
        let _guard = project
            .command_lock
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?;
        self.contains_commit_locked(project, commit)
    }

    fn relationship(
        &self,
        project_id: &ProjectId,
        current: &GitCommitId,
        candidate: &GitCommitId,
    ) -> Result<CommitRelationship, SourceError> {
        if current == candidate {
            return Ok(CommitRelationship::Same);
        }
        let project = self.project(project_id)?;
        let _guard = project
            .command_lock
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?;
        if !self.contains_commit_locked(project, current)?
            || !self.contains_commit_locked(project, candidate)?
        {
            return Err(SourceError::Repository(
                "cannot compare commits missing from the canonical repository".to_owned(),
            ));
        }
        let current_is_ancestor = self.is_ancestor(project, current, candidate)?;
        let candidate_is_ancestor = self.is_ancestor(project, candidate, current)?;
        match (current_is_ancestor, candidate_is_ancestor) {
            (true, false) => Ok(CommitRelationship::FastForward),
            (false, true) => Ok(CommitRelationship::Rewind),
            (false, false) => Ok(CommitRelationship::Diverged),
            (true, true) => Err(SourceError::Repository(
                "Git reported a cyclic commit relationship".to_owned(),
            )),
        }
    }

    fn accepted_head(&self, project_id: &ProjectId) -> Result<Option<GitCommitId>, SourceError> {
        let project = self.project(project_id)?;
        let _guard = project
            .command_lock
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?;
        self.read_ref(project, ACCEPTED_REF)
    }

    fn compare_and_swap_accepted_head(
        &self,
        project_id: &ProjectId,
        expected: Option<&GitCommitId>,
        candidate: &GitCommitId,
    ) -> Result<bool, SourceError> {
        let project = self.project(project_id)?;
        let _guard = project
            .command_lock
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?;
        if !self.contains_commit_locked(project, candidate)? {
            return Err(SourceError::Repository(
                "accepted candidate is missing from the canonical repository".to_owned(),
            ));
        }
        if self.read_ref(project, ACCEPTED_REF)?.as_ref() != expected {
            return Ok(false);
        }
        let old_value = expected.map_or_else(OsString::new, |commit| commit.as_str().into());
        let output = self.run_git(
            project,
            "advance accepted head",
            durable_update_ref_arguments(ACCEPTED_REF, candidate, old_value),
            None,
            LOCAL_COMMAND_TIMEOUT,
        )?;
        if output.status.success() {
            validate_installed_repository(project)?;
            return Ok(true);
        }
        if self.read_ref(project, ACCEPTED_REF)?.as_ref() == expected {
            Err(command_failure("advance accepted head", &output))
        } else {
            Ok(false)
        }
    }

    fn accepted_tree_metrics(
        &self,
        project_id: &ProjectId,
        head: &GitCommitId,
    ) -> Result<(u64, u64), SourceError> {
        let project = self.project(project_id)?;
        let _guard = project
            .command_lock
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?;
        validate_installed_repository(project)?;
        if self.read_ref(project, ACCEPTED_REF)?.as_ref() != Some(head) {
            return Err(SourceError::Repository(
                "accepted source head changed before tree measurement".to_owned(),
            ));
        }
        let metrics = self.validate_exportable_tree(project, head)?;
        validate_installed_repository(project)?;
        if self.read_ref(project, ACCEPTED_REF)?.as_ref() != Some(head) {
            return Err(SourceError::Repository(
                "accepted source head changed during tree measurement".to_owned(),
            ));
        }
        Ok((metrics.file_count, metrics.total_bytes))
    }
}

fn validate_git_executable() -> Result<(PathBuf, GitVersion), SourceError> {
    let executable = fs::canonicalize(SYSTEM_GIT)
        .map_err(|error| repository_io_error("resolve system Git", &error))?;
    if !executable.is_file() {
        return Err(SourceError::Repository(
            "the fixed system Git executable is not a regular file".to_owned(),
        ));
    }
    let mut command = Command::new(&executable);
    configure_git_environment(&mut command, None);
    let output = command
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| repository_io_error("inspect system Git version", &error))?;
    if !output.status.success() || output.stdout.len() > CAPTURE_LIMIT {
        return Err(SourceError::Repository(
            "the fixed system Git executable did not report a bounded version".to_owned(),
        ));
    }
    let version = std::str::from_utf8(&output.stdout).map_err(|_| {
        SourceError::Repository("the fixed system Git version is not UTF-8".to_owned())
    })?;
    let version = require_durable_git_version(version)?;
    Ok((executable, version))
}

fn require_durable_git_version(version_output: &str) -> Result<GitVersion, SourceError> {
    let version = version_output
        .trim()
        .strip_prefix("git version ")
        .and_then(|value| value.split_ascii_whitespace().next())
        .ok_or_else(|| {
            SourceError::Repository("the fixed system Git version is malformed".to_owned())
        })?;
    let mut components = version.split('.');
    let major = components
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    let minor = components
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    let Some(version) = major.zip(minor) else {
        return Err(SourceError::Repository(
            "the fixed system Git version is malformed".to_owned(),
        ));
    };
    if version < MINIMUM_DURABLE_FILES_GIT_VERSION {
        return Err(SourceError::Repository(format!(
            "Git {}.{} or newer is required for durable pack, metadata and reference fsync",
            MINIMUM_DURABLE_FILES_GIT_VERSION.0, MINIMUM_DURABLE_FILES_GIT_VERSION.1
        )));
    }
    Ok(version)
}

fn require_durable_ref_storage(
    git_version: GitVersion,
    ref_storage: &str,
) -> Result<(), SourceError> {
    match ref_storage {
        "files" if git_version >= MINIMUM_DURABLE_FILES_GIT_VERSION => Ok(()),
        _ => Err(SourceError::Repository(
            "canonical Git repository must use the files ref storage backend".to_owned(),
        )),
    }
}

#[cfg(unix)]
fn validate_process_kill_executable() -> Result<(), SourceError> {
    let executable = Path::new(SYSTEM_KILL);
    if !executable.is_file() {
        return Err(SourceError::Repository(
            "the fixed process-group kill executable is not a regular file".to_owned(),
        ));
    }
    Ok(())
}

fn network_repository_identity(remote_url: &RemoteUrl) -> EvidenceDigest {
    EvidenceDigest::sha256(format!(
        "rdashboard.git-repository.v1\0{}\0refs/heads/main",
        remote_url.as_str()
    ))
}

fn validate_repository_root(path: &Path) -> Result<PathBuf, SourceError> {
    if !path.is_absolute() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| repository_io_error("resolve repository root", &error))?;
    if canonical != path || !canonical.is_dir() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    Ok(canonical)
}

fn validate_project_repository(
    root: &Path,
    project_id: &ProjectId,
) -> Result<PathBuf, SourceError> {
    let expected = root.join(format!("{project_id}.git"));
    let canonical = fs::canonicalize(&expected)
        .map_err(|error| repository_io_error("resolve canonical repository", &error))?;
    if canonical != expected || !canonical.is_dir() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    Ok(canonical)
}

#[cfg(unix)]
fn validate_repository_permissions(
    root: &Path,
    repository: &Path,
) -> Result<RepositoryFilesystemIdentity, SourceError> {
    let root_metadata = fs::metadata(root)
        .map_err(|error| repository_io_error("inspect repository root", &error))?;
    let repository_metadata = fs::metadata(repository)
        .map_err(|error| repository_io_error("inspect canonical repository", &error))?;
    if root_metadata.uid() != repository_metadata.uid()
        || root_metadata.mode() & 0o077 != 0
        || repository_metadata.mode() & 0o077 != 0
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    validate_critical_repository_entries(repository, root_metadata.uid())?;
    RepositoryFilesystemIdentity {
        root_device: root_metadata.dev(),
        root_inode: root_metadata.ino(),
        repository_device: repository_metadata.dev(),
        repository_inode: repository_metadata.ino(),
        owner_uid: root_metadata.uid(),
    }
    .require_shared_filesystem()
}

#[cfg(unix)]
fn validate_critical_repository_entries(
    repository: &Path,
    owner_uid: u32,
) -> Result<(), SourceError> {
    for unsupported_entry in [
        "reftable",
        "commondir",
        "gitdir",
        "config.worktree",
        "worktrees",
    ] {
        match fs::symlink_metadata(repository.join(unsupported_entry)) {
            Ok(_) => return Err(SourceError::InvalidCanonicalRepositoryPath),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(repository_io_error(
                    "inspect unsupported canonical Git repository entry",
                    &error,
                ));
            }
        }
    }
    for (relative, expected_directory) in [
        ("objects", true),
        ("refs", true),
        ("config", false),
        ("HEAD", false),
    ] {
        let path = repository.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| repository_io_error("inspect canonical repository entry", &error))?;
        let expected_type = if expected_directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        };
        if metadata.file_type().is_symlink()
            || !expected_type
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
    }
    validate_files_ref_storage(&repository.join("refs"), owner_uid)?;
    validate_optional_repository_file(
        &repository.join("packed-refs"),
        owner_uid,
        "inspect canonical packed refs",
    )?;
    validate_canonical_object_storage(&repository.join("objects"), owner_uid)?;
    Ok(())
}

#[cfg(unix)]
fn validate_files_ref_storage(refs_path: &Path, owner_uid: u32) -> Result<(), SourceError> {
    let mut pending_directories = vec![refs_path.to_path_buf()];
    while let Some(directory) = pending_directories.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| repository_io_error("enumerate canonical files refs", &error))?
        {
            let entry = entry
                .map_err(|error| repository_io_error("inspect canonical files ref", &error))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| repository_io_error("inspect canonical files ref", &error))?;
            if metadata.file_type().is_symlink()
                || metadata.uid() != owner_uid
                || metadata.mode() & 0o022 != 0
            {
                return Err(SourceError::InvalidCanonicalRepositoryPath);
            }
            if metadata.is_dir() {
                pending_directories.push(entry.path());
            } else if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(SourceError::InvalidCanonicalRepositoryPath);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_optional_repository_file(
    path: &Path,
    owner_uid: u32,
    operation: &'static str,
) -> Result<(), SourceError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(repository_io_error(operation, &error)),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_canonical_object_storage(
    objects_path: &Path,
    owner_uid: u32,
) -> Result<(), SourceError> {
    let mut saw_info = false;
    let mut saw_pack = false;
    for entry in fs::read_dir(objects_path)
        .map_err(|error| repository_io_error("enumerate canonical Git objects", &error))?
    {
        let entry = entry
            .map_err(|error| repository_io_error("inspect canonical Git object entry", &error))?;
        let name = entry.file_name();
        if name != "info" && name != "pack" {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| repository_io_error("inspect canonical Git object entry", &error))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
        if name == "info" {
            saw_info = true;
            if fs::read_dir(entry.path())
                .map_err(|error| {
                    repository_io_error("inspect canonical Git object metadata", &error)
                })?
                .next()
                .transpose()
                .map_err(|error| {
                    repository_io_error("inspect canonical Git object metadata", &error)
                })?
                .is_some()
            {
                return Err(SourceError::InvalidCanonicalRepositoryPath);
            }
            continue;
        }
        saw_pack = true;
        for artifact in fs::read_dir(entry.path()).map_err(|error| {
            repository_io_error("enumerate canonical Git pack artifacts", &error)
        })? {
            let artifact = artifact.map_err(|error| {
                repository_io_error("inspect canonical Git pack artifact", &error)
            })?;
            let metadata = fs::symlink_metadata(artifact.path()).map_err(|error| {
                repository_io_error("inspect canonical Git pack artifact", &error)
            })?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != owner_uid
                || metadata.nlink() != 1
                || metadata.mode() & 0o022 != 0
            {
                return Err(SourceError::InvalidCanonicalRepositoryPath);
            }
        }
    }
    if saw_info && saw_pack {
        Ok(())
    } else {
        Err(SourceError::InvalidCanonicalRepositoryPath)
    }
}

#[cfg(unix)]
fn canonical_repository_configuration_digest(
    repository: &Path,
    owner_uid: u32,
) -> Result<EvidenceDigest, SourceError> {
    let config_path = repository.join("config");
    let path_metadata = fs::symlink_metadata(&config_path)
        .map_err(|error| repository_io_error("inspect canonical Git configuration", &error))?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.uid() != owner_uid
        || path_metadata.nlink() != 1
        || path_metadata.mode() & 0o022 != 0
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let config = File::open(&config_path)
        .map_err(|error| repository_io_error("open canonical Git configuration", &error))?;
    let file_metadata = config
        .metadata()
        .map_err(|error| repository_io_error("inspect canonical Git configuration", &error))?;
    if !file_metadata.is_file()
        || path_metadata.dev() != file_metadata.dev()
        || path_metadata.ino() != file_metadata.ino()
        || file_metadata.uid() != owner_uid
        || file_metadata.nlink() != 1
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let mut bytes = Vec::new();
    config
        .take(MAX_CANONICAL_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| repository_io_error("read canonical Git configuration", &error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CANONICAL_CONFIG_BYTES {
        return Err(SourceError::Repository(format!(
            "canonical Git configuration exceeded {MAX_CANONICAL_CONFIG_BYTES} bytes"
        )));
    }
    let mut evidence = b"rdashboard.canonical-git-config.v1\0".to_vec();
    evidence.extend_from_slice(&bytes);
    Ok(EvidenceDigest::sha256(evidence))
}

fn validate_installed_repository(project: &InstalledGitProject) -> Result<(), SourceError> {
    let canonical_root = fs::canonicalize(&project.repository_root)
        .map_err(|error| repository_io_error("revalidate repository root", &error))?;
    let canonical_repository = fs::canonicalize(&project.repository_path)
        .map_err(|error| repository_io_error("revalidate canonical repository", &error))?;
    if canonical_root != project.repository_root || canonical_repository != project.repository_path
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    #[cfg(unix)]
    {
        if validate_repository_permissions(&canonical_root, &canonical_repository)?
            != project.filesystem_identity
            || canonical_repository_configuration_digest(
                &canonical_repository,
                project.filesystem_identity.owner_uid,
            )? != project.configuration_digest
        {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StagingFilesystemIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    owner_uid: u32,
}

struct CommandDiskGuard<'a> {
    free_space_path: &'a Path,
    minimum_available_bytes: u64,
    staging_path: Option<&'a Path>,
    staging_identity: Option<StagingFilesystemIdentity>,
    fetch_limits: FetchLimits,
    foreground_fetch_waiters: Option<&'a AtomicUsize>,
    priority_fetch_project_count: Option<&'a AtomicUsize>,
    fetch_priority_generation: Option<(&'a AtomicU64, u64)>,
}

impl CommandDiskGuard<'_> {
    fn check(&self) -> Result<(), SourceError> {
        if self
            .foreground_fetch_waiters
            .is_some_and(|waiters| waiters.load(Ordering::Acquire) > 0)
            || self
                .priority_fetch_project_count
                .is_some_and(|pending| pending.load(Ordering::Acquire) > 0)
            || self
                .fetch_priority_generation
                .is_some_and(|(generation, expected)| {
                    generation.load(Ordering::Acquire) != expected
                })
        {
            return Err(SourceError::ReconciliationDeferred);
        }
        require_available_bytes(
            self.free_space_path,
            self.minimum_available_bytes,
            "continue bounded Git operation",
        )?;
        if let Some(staging_path) = self.staging_path {
            validate_staging_identity(staging_path, self.staging_identity)?;
            inspect_staging_tree(staging_path, self.fetch_limits, true)?;
        }
        Ok(())
    }
}

fn prepare_staging_root(project: &InstalledGitProject) -> Result<PathBuf, SourceError> {
    let staging_root = project.repository_root.join(FETCH_STAGING_DIRECTORY);
    if staging_root
        .try_exists()
        .map_err(|error| repository_io_error("inspect Git fetch staging root", &error))?
    {
        validate_staging_root(project, &staging_root)?;
    } else {
        create_private_directory(&staging_root)?;
        validate_staging_root(project, &staging_root)?;
        sync_directory(&project.repository_root)?;
    }
    Ok(staging_root)
}

fn validate_staging_root(
    project: &InstalledGitProject,
    staging_root: &Path,
) -> Result<(), SourceError> {
    let canonical = fs::canonicalize(staging_root)
        .map_err(|error| repository_io_error("resolve Git fetch staging root", &error))?;
    if canonical != staging_root || staging_root.parent() != Some(&project.repository_root) {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let metadata = fs::symlink_metadata(staging_root)
        .map_err(|error| repository_io_error("inspect Git fetch staging root", &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    #[cfg(unix)]
    {
        if metadata.uid() != project.filesystem_identity.owner_uid
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
    }
    Ok(())
}

fn remove_staging_directory(
    project: &InstalledGitProject,
    staging_path: &Path,
) -> Result<(), SourceError> {
    let staging_root = project.repository_root.join(FETCH_STAGING_DIRECTORY);
    validate_staging_root(project, &staging_root)?;
    if staging_path.parent() != Some(staging_root.as_path()) {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let metadata = fs::symlink_metadata(staging_path)
        .map_err(|error| repository_io_error("inspect Git fetch staging repository", &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    #[cfg(unix)]
    if metadata.uid() != project.filesystem_identity.owner_uid || metadata.mode() & 0o022 != 0 {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    fs::remove_dir_all(staging_path)
        .map_err(|error| repository_io_error("remove Git fetch staging repository", &error))?;
    sync_directory(&staging_root)
}

fn create_private_directory(path: &Path) -> Result<(), SourceError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|error| repository_io_error("create Git fetch staging directory", &error))
}

fn sync_staging_initialization_file(
    project: &InstalledGitProject,
    path: &Path,
    operation: &'static str,
) -> Result<(), SourceError> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|error| repository_io_error(operation, &error))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let file = File::options()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| repository_io_error(operation, &error))?;
    let file_metadata = file
        .metadata()
        .map_err(|error| repository_io_error(operation, &error))?;
    if !file_metadata.is_file() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    #[cfg(unix)]
    if path_metadata.dev() != file_metadata.dev()
        || path_metadata.ino() != file_metadata.ino()
        || path_metadata.uid() != project.filesystem_identity.owner_uid
        || file_metadata.uid() != project.filesystem_identity.owner_uid
        || path_metadata.nlink() != 1
        || file_metadata.nlink() != 1
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    #[cfg(unix)]
    {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| repository_io_error(operation, &error))?;
        let secured_path_metadata =
            fs::symlink_metadata(path).map_err(|error| repository_io_error(operation, &error))?;
        let secured_file_metadata = file
            .metadata()
            .map_err(|error| repository_io_error(operation, &error))?;
        if secured_path_metadata.file_type().is_symlink()
            || secured_path_metadata.dev() != file_metadata.dev()
            || secured_path_metadata.ino() != file_metadata.ino()
            || secured_file_metadata.dev() != file_metadata.dev()
            || secured_file_metadata.ino() != file_metadata.ino()
            || secured_path_metadata.mode() & 0o777 != 0o600
            || secured_file_metadata.mode() & 0o777 != 0o600
        {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
    }
    file.sync_all()
        .map_err(|error| repository_io_error(operation, &error))
}

fn staging_initialization_marker(project: &InstalledGitProject) -> Vec<u8> {
    format!(
        "rdashboard-fetch-init-v1:{}\n",
        project.repository_identity.as_str()
    )
    .into_bytes()
}

fn write_staging_initialization_marker(
    project: &InstalledGitProject,
    staging_path: &Path,
) -> Result<(), SourceError> {
    let marker_path = staging_path.join(STAGING_INITIALIZATION_MARKER);
    let mut marker = File::options()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .map_err(|error| {
            repository_io_error("create fetch staging initialization marker", &error)
        })?;
    #[cfg(unix)]
    marker
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            repository_io_error("secure fetch staging initialization marker", &error)
        })?;
    marker
        .write_all(&staging_initialization_marker(project))
        .map_err(|error| {
            repository_io_error("write fetch staging initialization marker", &error)
        })?;
    marker
        .sync_all()
        .map_err(|error| repository_io_error("sync fetch staging initialization marker", &error))?;
    if !staging_initialization_complete(project, staging_path)? {
        return Err(SourceError::Repository(
            "fetch staging initialization marker was not durably reconstructed".to_owned(),
        ));
    }
    Ok(())
}

fn staging_initialization_complete(
    project: &InstalledGitProject,
    staging_path: &Path,
) -> Result<bool, SourceError> {
    let marker_path = staging_path.join(STAGING_INITIALIZATION_MARKER);
    let path_metadata = match fs::symlink_metadata(&marker_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(repository_io_error(
                "inspect fetch staging initialization marker",
                &error,
            ));
        }
    };
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Ok(false);
    }
    let expected = staging_initialization_marker(project);
    let maximum_bytes = u64::try_from(expected.len().saturating_add(1)).map_err(|_| {
        SourceError::Repository("fetch staging initialization marker size overflowed".to_owned())
    })?;
    let marker = File::open(&marker_path)
        .map_err(|error| repository_io_error("open fetch staging initialization marker", &error))?;
    let file_metadata = marker.metadata().map_err(|error| {
        repository_io_error("inspect fetch staging initialization marker", &error)
    })?;
    if !file_metadata.is_file() {
        return Ok(false);
    }
    #[cfg(unix)]
    if path_metadata.dev() != file_metadata.dev()
        || path_metadata.ino() != file_metadata.ino()
        || path_metadata.uid() != project.filesystem_identity.owner_uid
        || file_metadata.uid() != project.filesystem_identity.owner_uid
        || path_metadata.nlink() != 1
        || file_metadata.nlink() != 1
        || path_metadata.mode() & 0o777 != 0o600
        || file_metadata.mode() & 0o777 != 0o600
    {
        return Ok(false);
    }
    let mut contents = Vec::with_capacity(expected.len());
    marker
        .take(maximum_bytes)
        .read_to_end(&mut contents)
        .map_err(|error| repository_io_error("read fetch staging initialization marker", &error))?;
    Ok(contents == expected)
}

fn staging_repository_initialized(staging_path: &Path) -> Result<bool, SourceError> {
    for (relative_path, expected_directory) in [
        ("HEAD", false),
        ("config", false),
        ("objects", true),
        ("refs", true),
    ] {
        let path = staging_path.join(relative_path);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(repository_io_error(
                    "inspect fetch staging repository skeleton",
                    &error,
                ));
            }
        };
        if metadata.file_type().is_symlink()
            || (expected_directory && !metadata.is_dir())
            || (!expected_directory && !metadata.is_file())
        {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
    }
    Ok(true)
}

fn validate_new_staging_repository(
    project: &InstalledGitProject,
    staging_path: &Path,
) -> Result<StagingFilesystemIdentity, SourceError> {
    let staging_root = project.repository_root.join(FETCH_STAGING_DIRECTORY);
    if staging_path.parent() != Some(staging_root.as_path())
        || fs::canonicalize(staging_path)
            .map_err(|error| repository_io_error("resolve Git fetch staging repository", &error))?
            != staging_path
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let metadata = fs::symlink_metadata(staging_path)
        .map_err(|error| repository_io_error("inspect Git fetch staging repository", &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    #[cfg(unix)]
    {
        if metadata.uid() != project.filesystem_identity.owner_uid || metadata.mode() & 0o022 != 0 {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
        Ok(StagingFilesystemIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(StagingFilesystemIdentity {})
    }
}

fn validate_staging_identity(
    staging_path: &Path,
    expected: Option<StagingFilesystemIdentity>,
) -> Result<(), SourceError> {
    let expected = expected.ok_or_else(|| {
        SourceError::Repository("Git fetch staging identity is missing".to_owned())
    })?;
    let canonical = fs::canonicalize(staging_path)
        .map_err(|error| repository_io_error("revalidate Git fetch staging path", &error))?;
    if canonical != staging_path {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let metadata = fs::symlink_metadata(staging_path)
        .map_err(|error| repository_io_error("revalidate Git fetch staging repository", &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    #[cfg(unix)]
    if metadata.dev() != expected.device
        || metadata.ino() != expected.inode
        || metadata.uid() != expected.owner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    #[cfg(not(unix))]
    let _ = expected;
    Ok(())
}

fn inspect_staging_tree(
    staging_path: &Path,
    limits: FetchLimits,
    tolerate_disappearing_entries: bool,
) -> Result<u64, SourceError> {
    let root_metadata = fs::symlink_metadata(staging_path)
        .map_err(|error| repository_io_error("inspect Git fetch staging tree", &error))?;
    #[cfg(unix)]
    let expected_owner = Some(root_metadata.uid());
    #[cfg(not(unix))]
    let expected_owner = {
        let _ = root_metadata;
        None
    };
    let mut total_bytes = 0_u64;
    inspect_staging_entry(
        staging_path,
        limits,
        tolerate_disappearing_entries,
        expected_owner,
        &mut total_bytes,
    )?;
    Ok(total_bytes)
}

fn inspect_staging_entry(
    path: &Path,
    limits: FetchLimits,
    tolerate_disappearing_entries: bool,
    expected_owner: Option<u32>,
    total_bytes: &mut u64,
) -> Result<(), SourceError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if tolerate_disappearing_entries && error.kind() == io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(error) => {
            return Err(repository_io_error(
                "inspect Git fetch staging entry",
                &error,
            ));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(SourceError::Repository(
            "Git fetch staging contains a symbolic link".to_owned(),
        ));
    }
    #[cfg(unix)]
    if Some(metadata.uid()) != expected_owner || metadata.mode() & 0o022 != 0 {
        return Err(SourceError::Repository(
            "Git fetch staging ownership or permissions changed".to_owned(),
        ));
    }
    #[cfg(not(unix))]
    let _ = expected_owner;
    if metadata.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error)
                if tolerate_disappearing_entries && error.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(());
            }
            Err(error) => {
                return Err(repository_io_error(
                    "enumerate Git fetch staging tree",
                    &error,
                ));
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error)
                    if tolerate_disappearing_entries && error.kind() == io::ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(error) => {
                    return Err(repository_io_error(
                        "inspect Git fetch staging child",
                        &error,
                    ));
                }
            };
            inspect_staging_entry(
                &entry.path(),
                limits,
                tolerate_disappearing_entries,
                expected_owner,
                total_bytes,
            )?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(SourceError::Repository(
            "Git fetch staging contains a special file".to_owned(),
        ));
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err(SourceError::Repository(
            "Git fetch staging contains a hard-linked file".to_owned(),
        ));
    }
    if metadata.len() > limits.max_file_bytes {
        return Err(SourceError::Repository(format!(
            "Git fetch staging file exceeded the {} byte per-file limit",
            limits.max_file_bytes
        )));
    }
    *total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
        SourceError::Repository("Git fetch staging byte count overflowed".to_owned())
    })?;
    if *total_bytes > limits.max_staging_bytes {
        return Err(SourceError::Repository(format!(
            "Git fetch staging exceeded the {} byte aggregate limit",
            limits.max_staging_bytes
        )));
    }
    Ok(())
}

fn staged_pack(staging_path: &Path, limits: FetchLimits) -> Result<Option<PathBuf>, SourceError> {
    inspect_staging_tree(staging_path, limits, false)?;
    let objects_path = staging_path.join("objects");
    for entry in fs::read_dir(&objects_path)
        .map_err(|error| repository_io_error("inspect staged Git objects", &error))?
    {
        let entry = entry.map_err(|error| repository_io_error("inspect staged object", &error))?;
        let name = entry.file_name();
        if name != "info" && name != "pack" {
            return Err(SourceError::Repository(
                "bounded Git fetch produced loose or unexpected objects".to_owned(),
            ));
        }
    }
    let info_path = objects_path.join("info");
    if fs::read_dir(&info_path)
        .map_err(|error| repository_io_error("inspect staged object metadata", &error))?
        .next()
        .transpose()
        .map_err(|error| repository_io_error("inspect staged object metadata", &error))?
        .is_some()
    {
        return Err(SourceError::Repository(
            "bounded Git fetch produced unexpected object metadata".to_owned(),
        ));
    }
    let pack_directory = objects_path.join("pack");
    let mut pack_stem = None;
    let mut index_stem = None;
    for entry in fs::read_dir(&pack_directory)
        .map_err(|error| repository_io_error("inspect staged Git pack", &error))?
    {
        let entry =
            entry.map_err(|error| repository_io_error("inspect staged pack entry", &error))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            SourceError::Repository("staged Git pack name is not UTF-8".to_owned())
        })?;
        if let Some(stem) = name.strip_suffix(".pack") {
            if !valid_pack_stem(stem) || pack_stem.replace(stem.to_owned()).is_some() {
                return Err(SourceError::Repository(
                    "bounded Git fetch produced an invalid pack set".to_owned(),
                ));
            }
        } else if let Some(stem) = name.strip_suffix(".idx") {
            if !valid_pack_stem(stem) || index_stem.replace(stem.to_owned()).is_some() {
                return Err(SourceError::Repository(
                    "bounded Git fetch produced an invalid pack index set".to_owned(),
                ));
            }
        } else {
            return Err(SourceError::Repository(
                "bounded Git fetch produced an unexpected pack artifact".to_owned(),
            ));
        }
    }
    if pack_stem.is_none() && index_stem.is_none() {
        return Ok(None);
    }
    let pack_stem = pack_stem.ok_or_else(|| {
        SourceError::Repository("bounded Git fetch produced a pack index without a pack".to_owned())
    })?;
    if index_stem.as_deref() != Some(pack_stem.as_str()) {
        return Err(SourceError::Repository(
            "bounded Git fetch pack and index do not match".to_owned(),
        ));
    }
    Ok(Some(pack_directory.join(format!("{pack_stem}.pack"))))
}

fn valid_pack_stem(stem: &str) -> bool {
    let Some(hash) = stem.strip_prefix("pack-") else {
        return false;
    };
    matches!(hash.len(), 40 | 64)
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn durable_update_ref_arguments(
    reference: &str,
    candidate: &GitCommitId,
    old_value: OsString,
) -> Vec<OsString> {
    vec![
        OsString::from("-c"),
        OsString::from(OWNER_ONLY_SHARED_REPOSITORY),
        OsString::from("-c"),
        OsString::from("core.fsync=reference"),
        OsString::from("-c"),
        OsString::from("core.fsyncMethod=fsync"),
        OsString::from("update-ref"),
        OsString::from("--no-deref"),
        OsString::from(reference),
        OsString::from(candidate.as_str()),
        old_value,
    ]
}

fn promoted_pack_keep_message(project: &InstalledGitProject, candidate: &GitCommitId) -> String {
    format!(
        "rdashboard-fetch-v1:{}:{}",
        project.repository_identity.as_str(),
        candidate.as_str()
    )
}

fn promoted_pack_guard_from_output(
    project: &InstalledGitProject,
    candidate: &GitCommitId,
    keep_message: String,
    output: &GitCommandOutput,
) -> Result<PromotedPackGuard, SourceError> {
    let pack_hash = parse_stdout("promote bounded Git pack", output)?
        .strip_prefix("keep\t")
        .ok_or_else(|| {
            SourceError::Repository(
                "Git pack promotion did not report its exact keep marker".to_owned(),
            )
        })?;
    let pack_stem = format!("pack-{pack_hash}");
    if pack_hash.len() != candidate.as_str().len() || !valid_pack_stem(&pack_stem) {
        return Err(SourceError::Repository(
            "Git pack promotion reported an invalid pack identity".to_owned(),
        ));
    }
    let guard = PromotedPackGuard {
        pack_hash: pack_hash.to_owned(),
        keep_message,
    };
    validate_promoted_pack_guard(project, &guard)?;
    Ok(guard)
}

fn find_promoted_pack_guard(
    project: &InstalledGitProject,
    candidate: &GitCommitId,
) -> Result<Option<PromotedPackGuard>, SourceError> {
    let mut matching_guard = None;
    for (guard_candidate, guard) in find_project_promoted_pack_guards(project)? {
        if guard_candidate != *candidate {
            continue;
        }
        if matching_guard.replace(guard).is_some() {
            return Err(SourceError::Repository(
                "interrupted Git promotion has multiple exact keep markers".to_owned(),
            ));
        }
    }
    Ok(matching_guard)
}

fn find_project_promoted_pack_guards(
    project: &InstalledGitProject,
) -> Result<Vec<(GitCommitId, PromotedPackGuard)>, SourceError> {
    let pack_directory = canonical_pack_directory(project)?;
    let keep_prefix = format!(
        "rdashboard-fetch-v1:{}:",
        project.repository_identity.as_str()
    );
    let mut promoted_pack_guards = Vec::new();
    for entry in fs::read_dir(&pack_directory)
        .map_err(|error| repository_io_error("enumerate canonical Git pack guards", &error))?
    {
        let entry = entry
            .map_err(|error| repository_io_error("inspect canonical Git pack guard", &error))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            SourceError::Repository("canonical Git pack entry is not UTF-8".to_owned())
        })?;
        let Some(pack_stem) = name.strip_suffix(".keep") else {
            continue;
        };
        if !valid_pack_stem(pack_stem) {
            continue;
        }
        let mut keep_file = open_verified_canonical_pack_artifact(
            project,
            &entry.path(),
            "open canonical Git keep marker",
        )?;
        let Some(keep_message) = read_keep_file_message(&mut keep_file)? else {
            continue;
        };
        let Some(candidate) = keep_message.strip_prefix(keep_prefix.as_bytes()) else {
            continue;
        };
        let candidate = std::str::from_utf8(candidate).map_err(|_| {
            SourceError::Repository(
                "canonical Git keep marker has a non-UTF-8 candidate identity".to_owned(),
            )
        })?;
        let candidate = GitCommitId::from_str(candidate).map_err(|_| {
            SourceError::Repository(
                "canonical Git keep marker has an invalid candidate identity".to_owned(),
            )
        })?;
        let guard = PromotedPackGuard {
            pack_hash: pack_stem
                .strip_prefix("pack-")
                .expect("validated Git pack stem has its fixed prefix")
                .to_owned(),
            keep_message: String::from_utf8(keep_message).map_err(|_| {
                SourceError::Repository(
                    "canonical Git keep marker has a non-UTF-8 operation identity".to_owned(),
                )
            })?,
        };
        validate_promoted_pack_guard(project, &guard)?;
        promoted_pack_guards.push((candidate, guard));
    }
    Ok(promoted_pack_guards)
}

fn validate_promoted_pack_guard(
    project: &InstalledGitProject,
    guard: &PromotedPackGuard,
) -> Result<(), SourceError> {
    let pack_directory = canonical_pack_directory(project)?;
    let stem = format!("pack-{}", guard.pack_hash);
    if !valid_pack_stem(&stem) {
        return Err(SourceError::Repository(
            "canonical Git keep marker has an invalid pack identity".to_owned(),
        ));
    }
    let pack_path = pack_directory.join(format!("{stem}.pack"));
    let index_path = pack_directory.join(format!("{stem}.idx"));
    let keep_path = pack_directory.join(format!("{stem}.keep"));
    let pack_file = open_verified_canonical_pack_artifact(
        project,
        &pack_path,
        "open promoted canonical Git pack",
    )?;
    let index_file = open_verified_canonical_pack_artifact(
        project,
        &index_path,
        "open promoted canonical Git pack index",
    )?;
    let mut keep_file = open_verified_canonical_pack_artifact(
        project,
        &keep_path,
        "open promoted canonical Git keep marker",
    )?;
    if !keep_file_has_message(&mut keep_file, &guard.keep_message)? {
        return Err(SourceError::Repository(
            "canonical Git keep marker is not bound to the pending promotion".to_owned(),
        ));
    }
    pack_file
        .sync_all()
        .map_err(|error| repository_io_error("sync promoted canonical Git pack", &error))?;
    index_file
        .sync_all()
        .map_err(|error| repository_io_error("sync promoted canonical Git pack index", &error))?;
    keep_file
        .sync_all()
        .map_err(|error| repository_io_error("sync promoted canonical Git keep marker", &error))?;
    sync_directory(&pack_directory)
}

fn release_promoted_pack_guard(
    project: &InstalledGitProject,
    guard: &PromotedPackGuard,
) -> Result<(), SourceError> {
    validate_promoted_pack_guard(project, guard)?;
    let pack_directory = canonical_pack_directory(project)?;
    let keep_path = pack_directory.join(format!("pack-{}.keep", guard.pack_hash));
    fs::remove_file(&keep_path)
        .map_err(|error| repository_io_error("release canonical Git keep marker", &error))?;
    sync_directory(&pack_directory)
}

fn keep_file_has_message(file: &mut File, keep_message: &str) -> Result<bool, SourceError> {
    Ok(read_keep_file_message(file)?.as_deref() == Some(keep_message.as_bytes()))
}

fn read_keep_file_message(file: &mut File) -> Result<Option<Vec<u8>>, SourceError> {
    let read_limit = PACK_KEEP_MESSAGE_LIMIT
        .checked_add(2)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| SourceError::Repository("Git keep marker size overflowed".to_owned()))?;
    let mut contents = Vec::with_capacity(PACK_KEEP_MESSAGE_LIMIT + 1);
    file.take(read_limit)
        .read_to_end(&mut contents)
        .map_err(|error| repository_io_error("read canonical Git keep marker", &error))?;
    if contents.len() > PACK_KEEP_MESSAGE_LIMIT + 1 || contents.last() != Some(&b'\n') {
        return Ok(None);
    }
    contents.pop();
    if contents.contains(&b'\n') {
        return Ok(None);
    }
    Ok(Some(contents))
}

fn canonical_pack_directory(project: &InstalledGitProject) -> Result<PathBuf, SourceError> {
    validate_installed_repository(project)?;
    let pack_directory = project.repository_path.join("objects/pack");
    if fs::canonicalize(&pack_directory)
        .map_err(|error| repository_io_error("resolve canonical Git pack directory", &error))?
        != pack_directory
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let directory_metadata = fs::symlink_metadata(&pack_directory)
        .map_err(|error| repository_io_error("inspect canonical Git pack directory", &error))?;
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    #[cfg(unix)]
    if directory_metadata.uid() != project.filesystem_identity.owner_uid
        || directory_metadata.mode() & 0o022 != 0
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    Ok(pack_directory)
}

fn open_verified_canonical_pack_artifact(
    project: &InstalledGitProject,
    path: &Path,
    operation: &'static str,
) -> Result<File, SourceError> {
    let pack_directory = canonical_pack_directory(project)?;
    if path.parent() != Some(pack_directory.as_path())
        || fs::canonicalize(path).map_err(|error| repository_io_error(operation, &error))? != path
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let path_metadata =
        fs::symlink_metadata(path).map_err(|error| repository_io_error(operation, &error))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let file = File::open(path).map_err(|error| repository_io_error(operation, &error))?;
    let file_metadata = file
        .metadata()
        .map_err(|error| repository_io_error(operation, &error))?;
    if !file_metadata.is_file() {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    #[cfg(unix)]
    if path_metadata.dev() != file_metadata.dev()
        || path_metadata.ino() != file_metadata.ino()
        || path_metadata.uid() != project.filesystem_identity.owner_uid
        || file_metadata.uid() != project.filesystem_identity.owner_uid
        || path_metadata.nlink() != 1
        || file_metadata.nlink() != 1
        || path_metadata.mode() & 0o022 != 0
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    Ok(file)
}

fn open_verified_staged_pack(
    pack_path: &Path,
    max_file_bytes: u64,
    staging_path: &Path,
) -> Result<File, SourceError> {
    let canonical_staging = fs::canonicalize(staging_path)
        .map_err(|error| repository_io_error("resolve staged Git repository", &error))?;
    let canonical_pack = fs::canonicalize(pack_path)
        .map_err(|error| repository_io_error("resolve staged Git pack", &error))?;
    if canonical_staging != staging_path
        || canonical_pack != pack_path
        || !canonical_pack.starts_with(canonical_staging.join("objects/pack"))
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let path_metadata = fs::symlink_metadata(pack_path)
        .map_err(|error| repository_io_error("inspect staged Git pack", &error))?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.len() > max_file_bytes
    {
        return Err(SourceError::Repository(
            "staged Git pack failed its file contract".to_owned(),
        ));
    }
    let file = File::open(pack_path)
        .map_err(|error| repository_io_error("open staged Git pack", &error))?;
    let file_metadata = file
        .metadata()
        .map_err(|error| repository_io_error("reinspect staged Git pack", &error))?;
    if !file_metadata.is_file() || file_metadata.len() > max_file_bytes {
        return Err(SourceError::Repository(
            "staged Git pack failed its open-file contract".to_owned(),
        ));
    }
    #[cfg(unix)]
    if path_metadata.dev() != file_metadata.dev()
        || path_metadata.ino() != file_metadata.ino()
        || path_metadata.uid() != file_metadata.uid()
        || path_metadata.nlink() != 1
        || file_metadata.nlink() != 1
        || path_metadata.mode() & 0o022 != 0
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    Ok(file)
}

fn cleanup_canonical_pack_temporaries(project: &InstalledGitProject) -> Result<(), SourceError> {
    let pack_directory = canonical_pack_directory(project)?;
    let mut removed = false;
    for entry in fs::read_dir(&pack_directory)
        .map_err(|error| repository_io_error("enumerate canonical Git pack directory", &error))?
    {
        let entry = entry
            .map_err(|error| repository_io_error("inspect canonical Git pack entry", &error))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            SourceError::Repository("canonical Git pack entry is not UTF-8".to_owned())
        })?;
        if !name.starts_with("tmp_pack_") && !name.starts_with("tmp_idx_") {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| repository_io_error("inspect temporary Git pack", &error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
        #[cfg(unix)]
        if metadata.uid() != project.filesystem_identity.owner_uid
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
        {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
        fs::remove_file(entry.path())
            .map_err(|error| repository_io_error("remove temporary Git pack", &error))?;
        removed = true;
    }
    if removed {
        sync_directory(&pack_directory)?;
    }
    Ok(())
}

fn reconcile_failed_fetch<T>(
    project: &InstalledGitProject,
    staging_path: &Path,
    result: Result<T, SourceError>,
) -> Result<T, SourceError> {
    let operation_error = match result {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    let cleanup_result = staging_path
        .try_exists()
        .map_err(|error| repository_io_error("inspect failed fetch staging repository", &error))
        .and_then(|exists| {
            if exists {
                remove_staging_directory(project, staging_path)
            } else {
                Ok(())
            }
        });
    match cleanup_result {
        Ok(()) => Err(operation_error),
        Err(cleanup_error) => Err(SourceError::Repository(format!(
            "{operation_error}; failed to clean fetch staging: {cleanup_error}"
        ))),
    }
}

fn require_available_bytes(
    path: &Path,
    required_bytes: u64,
    operation: &'static str,
) -> Result<(), SourceError> {
    let available = fs2::available_space(path)
        .map_err(|error| repository_io_error("measure Git fetch free space", &error))?;
    if available < required_bytes {
        return Err(SourceError::Repository(format!(
            "Git operation {operation} requires {required_bytes} available bytes but only {available} remain"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), SourceError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| repository_io_error("sync Git repository directory", &error))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), SourceError> {
    Ok(())
}

fn configure_git_command(command: &mut Command, project: &InstalledGitProject) {
    configure_git_command_for_directory(
        command,
        &project.repository_path,
        project.remote.allows_file_protocol(),
        project.ssh_command.as_deref(),
    );
}

fn configure_git_command_for_directory(
    command: &mut Command,
    git_directory: &Path,
    allow_file_protocol: bool,
    ssh_command: Option<&str>,
) {
    command
        .arg("--no-pager")
        .arg("--git-dir")
        .arg(git_directory)
        .args(["-c", "credential.helper="])
        .args(["-c", "credential.interactive=never"])
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(["-c", "protocol.allow=never"])
        .args(["-c", "protocol.https.allow=always"])
        .args(["-c", "protocol.ssh.allow=always"]);
    if allow_file_protocol {
        command.args(["-c", "protocol.file.allow=always"]);
    }
    configure_git_environment(command, ssh_command);
}

fn configure_staging_object_directories(
    command: &mut Command,
    project: &InstalledGitProject,
    staging_path: &Path,
) -> Result<(), SourceError> {
    validate_installed_repository(project)?;
    let canonical_objects = project.repository_path.join("objects");
    let staging_objects = staging_path.join("objects");
    for (path, operation) in [
        (&canonical_objects, "resolve canonical Git objects"),
        (&staging_objects, "resolve staged Git objects"),
    ] {
        if fs::canonicalize(path).map_err(|error| repository_io_error(operation, &error))?
            != path.as_path()
        {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|error| repository_io_error(operation, &error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
        #[cfg(unix)]
        if metadata.uid() != project.filesystem_identity.owner_uid || metadata.mode() & 0o022 != 0 {
            return Err(SourceError::InvalidCanonicalRepositoryPath);
        }
    }
    let alternate_objects = std::env::join_paths([canonical_objects.as_path()])
        .map_err(|_| SourceError::InvalidCanonicalRepositoryPath)?;
    command
        .env("GIT_OBJECT_DIRECTORY", staging_objects)
        .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", alternate_objects)
        .env("GIT_OPTIONAL_LOCKS", "0");
    Ok(())
}

fn configure_git_environment(command: &mut Command, ssh_command: Option<&str>) {
    command
        .env_clear()
        .env("HOME", "/nonexistent")
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0");
    if let Some(ssh_command) = ssh_command {
        command
            .env("GIT_SSH_VARIANT", "ssh")
            .env("GIT_SSH_COMMAND", ssh_command);
    }
}

#[derive(Debug)]
struct GitCommandOutput {
    status: ExitStatus,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
}

#[derive(Debug)]
struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

enum CommandInput<'a> {
    Null,
    Bytes(&'a [u8]),
    File(File),
}

fn run_command(
    command: Command,
    operation: &'static str,
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<GitCommandOutput, SourceError> {
    let input = input.map_or(CommandInput::Null, CommandInput::Bytes);
    run_command_guarded(command, operation, input, timeout, None)
}

fn run_command_guarded(
    mut command: Command,
    operation: &'static str,
    input: CommandInput<'_>,
    timeout: Duration,
    disk_guard: Option<&CommandDiskGuard<'_>>,
) -> Result<GitCommandOutput, SourceError> {
    if let Some(guard) = disk_guard {
        guard.check()?;
    }
    let byte_input = match input {
        CommandInput::Null => {
            command.stdin(Stdio::null());
            None
        }
        CommandInput::Bytes(bytes) => {
            command.stdin(Stdio::piped());
            Some(bytes)
        }
        CommandInput::File(file) => {
            command.stdin(Stdio::from(file));
            None
        }
    };
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    configure_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| repository_io_error(operation, &error))?;
    if let Some(input) = byte_input {
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| SourceError::Repository("Git stdin was not available".to_owned()))?
            .write_all(input);
        if let Err(error) = write_result {
            terminate_process_tree(&mut child);
            return Err(repository_io_error(operation, &error));
        }
    }
    let stdout = spawn_output_reader(
        child
            .stdout
            .take()
            .ok_or_else(|| SourceError::Repository("Git stdout was not available".to_owned()))?,
    );
    let stderr = spawn_output_reader(
        child
            .stderr
            .take()
            .ok_or_else(|| SourceError::Repository("Git stderr was not available".to_owned()))?,
    );
    let status = wait_for_child(&mut child, operation, timeout, disk_guard);
    match status {
        Ok(status) => Ok(GitCommandOutput {
            status,
            stdout: join_output_reader(stdout, operation)?,
            stderr: join_output_reader(stderr, operation)?,
        }),
        Err(error) => {
            let _ = join_output_reader(stdout, operation);
            let _ = join_output_reader(stderr, operation);
            Err(error)
        }
    }
}

fn run_command_to_file(
    mut command: Command,
    operation: &'static str,
    output: File,
    timeout: Duration,
) -> Result<(), SourceError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(output))
        .stderr(Stdio::piped());
    configure_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| repository_io_error(operation, &error))?;
    let stderr = spawn_output_reader(
        child
            .stderr
            .take()
            .ok_or_else(|| SourceError::Repository("Git stderr was not available".to_owned()))?,
    );
    let status = wait_for_child(&mut child, operation, timeout, None);
    let stderr = join_output_reader(stderr, operation)?;
    let status = status?;
    if status.success() {
        Ok(())
    } else {
        Err(command_failure(
            operation,
            &GitCommandOutput {
                status,
                stdout: CapturedOutput {
                    bytes: Vec::new(),
                    truncated: false,
                },
                stderr,
            },
        ))
    }
}

fn run_export_tree_inspection(
    mut command: Command,
    operation: &'static str,
    timeout: Duration,
) -> Result<ExportTreeMetrics, SourceError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| repository_io_error(operation, &error))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SourceError::Repository("Git stdout was not available".to_owned()))?;
    let tree_reader = thread::spawn(move || validate_export_tree_stream(stdout));
    let stderr = spawn_output_reader(
        child
            .stderr
            .take()
            .ok_or_else(|| SourceError::Repository("Git stderr was not available".to_owned()))?,
    );
    let status = wait_for_child(&mut child, operation, timeout, None);
    let tree_result = tree_reader
        .join()
        .map_err(|_| SourceError::Repository("Git export tree reader failed".to_owned()))?;
    let stderr = join_output_reader(stderr, operation)?;
    let status = status?;
    let entries = tree_result?;
    if status.success() {
        Ok(entries)
    } else {
        Err(command_failure(
            operation,
            &GitCommandOutput {
                status,
                stdout: CapturedOutput {
                    bytes: Vec::new(),
                    truncated: false,
                },
                stderr,
            },
        ))
    }
}

fn validate_export_tree_stream(reader: impl Read) -> Result<ExportTreeMetrics, SourceError> {
    let mut reader = BufReader::new(reader);
    let mut record = Vec::with_capacity(512);
    let mut file_count = 0_u64;
    let mut total_bytes = 0_u64;
    while read_bounded_nul_record(&mut reader, &mut record)? {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| {
                SourceError::Repository("immutable export tree entry was malformed".to_owned())
            })?;
        let metadata = &record[..tab];
        let path = &record[tab + 1..];
        let fields = metadata
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        if fields.len() != 4
            || !matches!(fields[2].len(), 40 | 64)
            || !fields[2]
                .iter()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(SourceError::Repository(
                "immutable export tree entry was malformed".to_owned(),
            ));
        }
        let has_archive_attributes = path
            .split(|byte| *byte == b'/')
            .any(|component| component == b".gitattributes");
        if fields[1] != b"blob"
            || !matches!(fields[0], b"100644" | b"100755")
            || path.is_empty()
            || has_archive_attributes
        {
            return Err(SourceError::Repository(
                "immutable export contains a non-regular entry or archive attributes".to_owned(),
            ));
        }
        let size = std::str::from_utf8(fields[3])
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                SourceError::Repository("immutable export tree entry size was malformed".to_owned())
            })?;
        file_count = file_count.checked_add(1).ok_or_else(|| {
            SourceError::Repository("immutable export entry count overflowed".to_owned())
        })?;
        total_bytes = total_bytes.checked_add(size).ok_or_else(|| {
            SourceError::Repository("immutable export logical size overflowed".to_owned())
        })?;
        if file_count > u64::try_from(MAX_EXPORT_TREE_ENTRIES).unwrap_or(u64::MAX) {
            return Err(SourceError::Repository(
                "immutable export exceeds the source file count limit".to_owned(),
            ));
        }
    }
    Ok(ExportTreeMetrics {
        file_count,
        total_bytes,
    })
}

fn read_bounded_nul_record(
    reader: &mut impl BufRead,
    record: &mut Vec<u8>,
) -> Result<bool, SourceError> {
    record.clear();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|error| repository_io_error("inspect immutable export tree output", &error))?;
        if available.is_empty() {
            if record.is_empty() {
                return Ok(false);
            }
            return Err(SourceError::Repository(
                "immutable export tree ended with a partial entry".to_owned(),
            ));
        }
        let delimiter = available.iter().position(|byte| *byte == 0);
        let retained = delimiter.unwrap_or(available.len());
        if record.len().saturating_add(retained) > MAX_EXPORT_TREE_ENTRY_BYTES {
            return Err(SourceError::Repository(
                "immutable export tree entry exceeded the path inspection limit".to_owned(),
            ));
        }
        record.extend_from_slice(&available[..retained]);
        reader.consume(retained + usize::from(delimiter.is_some()));
        if delimiter.is_some() {
            return Ok(true);
        }
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

fn wait_for_child(
    child: &mut std::process::Child,
    operation: &'static str,
    timeout: Duration,
    disk_guard: Option<&CommandDiskGuard<'_>>,
) -> Result<ExitStatus, SourceError> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| repository_io_error(operation, &error))?
        {
            if let Some(guard) = disk_guard
                && let Err(error) = guard.check()
            {
                terminate_process_tree(child);
                return Err(error);
            }
            terminate_remaining_process_group(child.id());
            return Ok(status);
        }
        if let Some(guard) = disk_guard
            && let Err(error) = guard.check()
        {
            terminate_process_tree(child);
            return Err(error);
        }
        if started.elapsed() >= timeout {
            terminate_process_tree(child);
            return Err(SourceError::Repository(format!(
                "Git operation {operation} exceeded its deadline"
            )));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn terminate_process_tree(child: &mut std::process::Child) {
    terminate_remaining_process_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn terminate_remaining_process_group(process_group_id: u32) {
    let _ = Command::new(SYSTEM_KILL)
        .args(["-KILL", "--"])
        .arg(format!("-{process_group_id}"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(not(unix))]
fn terminate_remaining_process_group(_process_group_id: u32) {}

fn spawn_output_reader(
    reader: impl Read + Send + 'static,
) -> thread::JoinHandle<Result<CapturedOutput, io::Error>> {
    thread::spawn(move || capture_output(reader))
}

fn capture_output(mut reader: impl Read) -> Result<CapturedOutput, io::Error> {
    let mut bytes = Vec::with_capacity(CAPTURE_LIMIT.min(8 * 1024));
    let mut truncated = false;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = CAPTURE_LIMIT.saturating_sub(bytes.len());
        let retained = remaining.min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained != read;
    }
    Ok(CapturedOutput { bytes, truncated })
}

fn join_output_reader(
    reader: thread::JoinHandle<Result<CapturedOutput, io::Error>>,
    operation: &'static str,
) -> Result<CapturedOutput, SourceError> {
    reader
        .join()
        .map_err(|_| SourceError::Repository(format!("Git {operation} output reader failed")))?
        .map_err(|error| repository_io_error(operation, &error))
}

fn require_success(operation: &'static str, output: &GitCommandOutput) -> Result<(), SourceError> {
    if output.status.success() {
        Ok(())
    } else {
        Err(command_failure(operation, output))
    }
}

fn parse_stdout<'a>(
    operation: &'static str,
    output: &'a GitCommandOutput,
) -> Result<&'a str, SourceError> {
    if output.stdout.truncated {
        return Err(SourceError::Repository(format!(
            "Git {operation} output exceeded the capture limit"
        )));
    }
    std::str::from_utf8(&output.stdout.bytes)
        .map(str::trim)
        .map_err(|_| SourceError::Repository(format!("Git {operation} output was not UTF-8")))
}

fn command_failure(operation: &'static str, output: &GitCommandOutput) -> SourceError {
    let raw = String::from_utf8_lossy(&output.stderr.bytes);
    let mut detail = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let detail_was_long = detail.chars().count() > ERROR_DETAIL_CHAR_LIMIT;
    detail = detail.chars().take(ERROR_DETAIL_CHAR_LIMIT).collect();
    if output.stderr.truncated || detail_was_long {
        detail.push_str(" [truncated]");
    }
    if detail.is_empty() {
        "no diagnostic output".clone_into(&mut detail);
    }
    SourceError::Repository(format!("Git {operation} failed: {detail}"))
}

fn repository_io_error(operation: &'static str, error: &io::Error) -> SourceError {
    SourceError::Repository(format!("Git {operation} failed with I/O error: {error}"))
}

fn os_args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(|value| OsString::from(*value)).collect()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs::OpenOptions,
        io::{Read as _, Seek as _, SeekFrom},
        process::Command,
        str::FromStr,
        sync::mpsc,
        time::Instant,
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use sha2::{Digest as _, Sha256};
    use tempfile::{TempDir, tempdir};

    use super::*;

    const MAX_SMALL_FETCH_STORAGE_GROWTH: u64 = 64 * 1024;

    #[test]
    fn production_fetch_reserve_fits_the_bounded_single_vps_contract() {
        let limits = FetchLimits::PRODUCTION;
        assert_eq!(limits.max_staging_bytes, GIB);
        assert_eq!(limits.emergency_bytes, 4 * GIB);
        assert_eq!(limits.emergency_percent, 5);
        assert_eq!(
            limits
                .preflight_required_bytes(limits.emergency_bytes)
                .expect("bounded production preflight"),
            6 * GIB
        );
    }

    #[test]
    fn source_git_ssh_environment_is_fixed_identity_only_and_host_pinned() {
        let mut command = Command::new(SYSTEM_GIT);
        let ssh_command = GitSshTransportConfig {
            private_key_path: PathBuf::from(
                "/run/credentials/rdashboard-source.service/source-git-rimg-private-key",
            ),
            known_hosts_path: PathBuf::from(
                "/run/credentials/rdashboard-source.service/source-git-rimg-known-hosts",
            ),
        }
        .command()
        .expect("fixed SSH command");
        configure_git_environment(&mut command, Some(&ssh_command));
        let environment = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment.get("HOME"),
            Some(&Some("/nonexistent".to_owned()))
        );
        assert_eq!(
            environment.get("GIT_TERMINAL_PROMPT"),
            Some(&Some("0".to_owned()))
        );
        assert_eq!(
            environment.get("GIT_SSH_VARIANT"),
            Some(&Some("ssh".to_owned()))
        );
        assert!(!environment.contains_key("SSH_AUTH_SOCK"));

        let ssh = environment
            .get("GIT_SSH_COMMAND")
            .and_then(Option::as_deref)
            .expect("fixed SSH command");
        for required in [
            "-i /run/credentials/rdashboard-source.service/source-git-rimg-private-key",
            "-oIdentitiesOnly=yes",
            "-oIdentityAgent=none",
            "-oBatchMode=yes",
            "-oStrictHostKeyChecking=yes",
            "-oUserKnownHostsFile=/run/credentials/rdashboard-source.service/source-git-rimg-known-hosts",
            "-oGlobalKnownHostsFile=/dev/null",
            "-oUpdateHostKeys=no",
            "-oCheckHostIP=no",
            "-oPreferredAuthentications=publickey",
            "-oPasswordAuthentication=no",
            "-oKbdInteractiveAuthentication=no",
        ] {
            assert!(
                ssh.contains(required),
                "missing SSH restriction: {required}"
            );
        }

        let mut https_command = Command::new(SYSTEM_GIT);
        configure_git_environment(&mut https_command, None);
        let https_environment = https_command
            .get_envs()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        assert!(!https_environment.contains("GIT_SSH_COMMAND"));
        assert!(!https_environment.contains("GIT_SSH_VARIANT"));
    }

    #[test]
    fn export_tree_inspection_streams_large_and_unusual_path_sets() {
        let mut listing = Vec::new();
        for index in 0..2_000 {
            listing.extend_from_slice(
                format!(
                    "100644 blob 0000000000000000000000000000000000000000 {index}\tdirectory/file-{index:04}.txt\0"
                )
                .as_bytes(),
            );
        }
        listing.extend_from_slice(
            b"100755 blob 0000000000000000000000000000000000000000 7\tdirectory/line\nbreak\0",
        );
        assert!(listing.len() > CAPTURE_LIMIT);
        assert_eq!(
            validate_export_tree_stream(listing.as_slice())
                .unwrap_or_else(|error| panic!("validate export tree: {error}")),
            ExportTreeMetrics {
                file_count: 2_001,
                total_bytes: (0_u64..2_000).sum::<u64>() + 7,
            }
        );
    }

    #[test]
    fn export_tree_inspection_rejects_archive_attributes_and_nonregular_entries() {
        for listing in [
            b"100644 blob 0000000000000000000000000000000000000000 1\tdirectory/.gitattributes\0"
                .as_slice(),
            b"120000 blob 0000000000000000000000000000000000000000 1\tlinked-source\0".as_slice(),
            b"160000 commit 0000000000000000000000000000000000000000 -\tnested-repository\0"
                .as_slice(),
        ] {
            assert!(matches!(
                validate_export_tree_stream(listing),
                Err(SourceError::Repository(detail))
                    if detail.contains("non-regular entry or archive attributes")
            ));
        }
    }

    struct GitFixture {
        _directory: TempDir,
        repository: GitSourceRepository,
        project_id: ProjectId,
        worktree: PathBuf,
        remote: PathBuf,
    }

    #[test]
    fn durable_git_version_floor_rejects_unsupported_or_ambiguous_versions() {
        for supported in [
            "git version 2.36.0\n",
            "git version 2.55.1.windows.1\n",
            "git version 3.0.0\n",
        ] {
            require_durable_git_version(supported)
                .unwrap_or_else(|error| panic!("supported Git version {supported:?}: {error}"));
        }
        for unsupported in [
            "git version 2.35.9\n",
            "git version 1.99.0\n",
            "git version two.55.0\n",
            "2.55.0\n",
        ] {
            assert!(
                require_durable_git_version(unsupported).is_err(),
                "unsupported Git version was accepted: {unsupported:?}"
            );
        }
        require_durable_ref_storage((2, 36), "files")
            .unwrap_or_else(|error| panic!("Git 2.36 files refs: {error}"));
        assert!(require_durable_ref_storage((2, 55), "reftable").is_err());
        assert!(require_durable_ref_storage((2, 55), "unknown").is_err());
    }

    #[test]
    fn fetch_staging_repository_pins_files_ref_storage() {
        let fixture = git_fixture();
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let staging_root = prepare_staging_root(project)
            .unwrap_or_else(|error| panic!("prepare staging root: {error}"));
        let staging_path = staging_root.join(format!("{}.git", fixture.project_id));
        fixture
            .repository
            .initialize_staging_repository(project, &staging_path, "sha1")
            .unwrap_or_else(|error| panic!("initialize staging repository: {error}"));

        let config = fs::read_to_string(staging_path.join("config"))
            .unwrap_or_else(|error| panic!("read staging config: {error}"));
        assert!(!config.to_ascii_lowercase().contains("refstorage"));
        assert!(
            config
                .lines()
                .any(|line| line.trim() == "sharedrepository = 0600")
        );
        assert!(!staging_path.join("reftable").exists());
        assert!(staging_path.join("refs").is_dir());
        assert!(
            staging_initialization_complete(project, &staging_path)
                .unwrap_or_else(|error| panic!("validate staging marker: {error}"))
        );
        #[cfg(unix)]
        for relative_path in ["config", "HEAD"] {
            let path = staging_path.join(relative_path);
            assert_eq!(
                fs::metadata(&path)
                    .unwrap_or_else(|error| panic!("inspect {relative_path}: {error}"))
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
                .unwrap_or_else(|error| panic!("make {relative_path} permissive: {error}"));
            sync_staging_initialization_file(project, &path, "resync staging fixture")
                .unwrap_or_else(|error| panic!("secure {relative_path}: {error}"));
            assert_eq!(
                fs::metadata(&path)
                    .unwrap_or_else(|error| panic!("reinspect {relative_path}: {error}"))
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn real_git_adapter_fetches_compares_and_advances_with_cas() {
        let fixture = git_fixture();
        let first = commit_file(&fixture.worktree, "first", "first");
        push_main(&fixture.worktree, &fixture.remote, false);
        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("fetch first: {error}")),
            first
        );
        assert!(
            fixture
                .repository
                .compare_and_swap_accepted_head(&fixture.project_id, None, &first)
                .unwrap_or_else(|error| panic!("accept first: {error}"))
        );

        let second = commit_file(&fixture.worktree, "second", "second");
        push_main(&fixture.worktree, &fixture.remote, false);
        let fetched = fixture
            .repository
            .fetch_remote_main(&fixture.project_id)
            .unwrap_or_else(|error| panic!("fetch second: {error}"));
        assert_eq!(fetched, second);
        assert_eq!(
            fixture
                .repository
                .relationship(&fixture.project_id, &first, &second)
                .unwrap_or_else(|error| panic!("fast-forward relationship: {error}")),
            CommitRelationship::FastForward
        );
        assert!(
            !fixture
                .repository
                .compare_and_swap_accepted_head(&fixture.project_id, None, &second)
                .unwrap_or_else(|error| panic!("stale CAS: {error}"))
        );
        assert!(
            fixture
                .repository
                .compare_and_swap_accepted_head(&fixture.project_id, Some(&first), &second)
                .unwrap_or_else(|error| panic!("advance second: {error}"))
        );
        assert_eq!(
            fixture
                .repository
                .accepted_head(&fixture.project_id)
                .unwrap_or_else(|error| panic!("accepted head: {error}")),
            Some(second.clone())
        );
        assert_eq!(
            fixture
                .repository
                .accepted_tree_metrics(&fixture.project_id, &second)
                .unwrap_or_else(|error| panic!("measure accepted tree: {error}")),
            (1, u64::try_from("second".len()).unwrap_or(u64::MAX))
        );
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        assert_eq!(
            find_promoted_pack_guard(project, &second)
                .unwrap_or_else(|error| panic!("inspect released pack guard: {error}")),
            None
        );
        let archive_path = fixture
            .worktree
            .parent()
            .unwrap_or_else(|| panic!("fixture parent"))
            .join("accepted.tar");
        let mut archive = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&archive_path)
            .unwrap_or_else(|error| panic!("create source archive: {error}"));
        fixture
            .repository
            .export_accepted_tree(&fixture.project_id, &second, &archive)
            .unwrap_or_else(|error| panic!("export accepted tree: {error}"));
        archive
            .seek(SeekFrom::Start(0))
            .unwrap_or_else(|error| panic!("rewind source archive: {error}"));
        let mut tar_bytes = Vec::new();
        archive
            .read_to_end(&mut tar_bytes)
            .unwrap_or_else(|error| panic!("read source archive: {error}"));
        assert!(
            tar_bytes
                .windows(b"fixture.txt".len())
                .any(|window| window == b"fixture.txt")
        );
    }

    #[test]
    fn unrelated_binary_pack_keep_marker_is_ignored_and_retained() {
        let fixture = git_fixture();
        let first = commit_file(&fixture.worktree, "first", "first");
        push_main(&fixture.worktree, &fixture.remote, false);
        fixture
            .repository
            .fetch_remote_main(&fixture.project_id)
            .unwrap_or_else(|error| panic!("fetch first: {error}"));
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let unrelated_keep = project
            .repository_path
            .join("objects/pack/pack-ffffffffffffffffffffffffffffffffffffffff.keep");
        fs::write(&unrelated_keep, [0xff, b'\n'])
            .unwrap_or_else(|error| panic!("write unrelated binary keep: {error}"));
        make_file_private(&unrelated_keep);

        let second = commit_file(&fixture.worktree, "second", "second");
        push_main(&fixture.worktree, &fixture.remote, false);
        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("fetch with unrelated binary keep: {error}")),
            second
        );
        assert!(unrelated_keep.is_file());
        assert!(
            fixture
                .repository
                .contains_commit_locked(project, &first)
                .unwrap_or_else(|error| panic!("inspect first commit: {error}"))
        );
    }

    #[test]
    fn incremental_fetch_storage_tracks_new_objects_instead_of_repacking_full_history() {
        let fixture = git_fixture();
        let baseline_payload = deterministic_noise(16_384);
        let baseline = commit_bytes(&fixture.worktree, &baseline_payload, "large baseline");
        push_main(&fixture.worktree, &fixture.remote, false);
        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("fetch large baseline: {error}")),
            baseline
        );
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let baseline_storage = canonical_pack_storage_bytes(project);
        let baseline_payload_bytes = u64::try_from(baseline_payload.len())
            .unwrap_or_else(|error| panic!("baseline payload size: {error}"));
        assert!(baseline_storage > baseline_payload_bytes / 2);

        let mut previous_storage = baseline_storage;
        for index in 0..4 {
            let fixture_name = format!("incremental-{index}.txt");
            let contents = format!("incremental object {index}");
            let message = format!("incremental {index}");
            let candidate = commit_path(
                &fixture.worktree,
                &fixture_name,
                contents.as_bytes(),
                &message,
            );
            push_main(&fixture.worktree, &fixture.remote, false);
            assert_eq!(
                fixture
                    .repository
                    .fetch_remote_main(&fixture.project_id)
                    .unwrap_or_else(|error| panic!("fetch incremental {index}: {error}")),
                candidate
            );
            let current_storage = canonical_pack_storage_bytes(project);
            let growth = current_storage
                .checked_sub(previous_storage)
                .unwrap_or_else(|| panic!("canonical pack storage shrank during fetch {index}"));
            assert!(
                growth > 0,
                "incremental fetch {index} stored no new objects"
            );
            assert!(
                growth < MAX_SMALL_FETCH_STORAGE_GROWTH,
                "incremental fetch {index} added {growth} bytes after a {baseline_storage} byte baseline"
            );
            previous_storage = current_storage;
        }
        assert!(previous_storage - baseline_storage < baseline_storage);
    }

    #[test]
    fn divergent_fetch_storage_transfers_only_objects_after_the_common_ancestor() {
        let fixture = git_fixture();
        let baseline_payload = deterministic_noise(16_384);
        let common = commit_bytes(
            &fixture.worktree,
            &baseline_payload,
            "large common ancestor",
        );
        push_main(&fixture.worktree, &fixture.remote, false);
        fixture
            .repository
            .fetch_remote_main(&fixture.project_id)
            .unwrap_or_else(|error| panic!("fetch common ancestor: {error}"));
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let baseline_storage = canonical_pack_storage_bytes(project);

        let forward = commit_path(
            &fixture.worktree,
            "forward.txt",
            b"forward branch object",
            "forward branch",
        );
        push_main(&fixture.worktree, &fixture.remote, false);
        fixture
            .repository
            .fetch_remote_main(&fixture.project_id)
            .unwrap_or_else(|error| panic!("fetch forward branch: {error}"));

        reset_hard(&fixture.worktree, &common);
        let divergent = commit_path(
            &fixture.worktree,
            "divergent.txt",
            b"divergent branch object",
            "divergent branch",
        );
        push_main(&fixture.worktree, &fixture.remote, true);
        let before_divergence = canonical_pack_storage_bytes(project);
        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("fetch divergent branch: {error}")),
            divergent
        );
        let divergence_growth = canonical_pack_storage_bytes(project)
            .checked_sub(before_divergence)
            .unwrap_or_else(|| panic!("canonical pack storage shrank during divergent fetch"));
        assert!(divergence_growth > 0);
        assert!(
            divergence_growth < MAX_SMALL_FETCH_STORAGE_GROWTH,
            "divergent fetch added {divergence_growth} bytes after a {baseline_storage} byte baseline"
        );
        assert_eq!(
            fixture
                .repository
                .relationship(&fixture.project_id, &forward, &divergent)
                .unwrap_or_else(|error| panic!("divergent relationship: {error}")),
            CommitRelationship::Diverged
        );
    }

    #[test]
    fn unchanged_fetch_reuses_canonical_objects_without_writing_another_pack() {
        let fixture = git_fixture();
        let candidate = commit_file(&fixture.worktree, "first", "first");
        push_main(&fixture.worktree, &fixture.remote, false);
        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("fetch initial head: {error}")),
            candidate
        );
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let before = canonical_pack_storage_bytes(project);
        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("refetch unchanged head: {error}")),
            candidate
        );
        assert_eq!(canonical_pack_storage_bytes(project), before);
    }

    #[test]
    fn oversized_fetch_does_not_publish_canonical_objects_or_ref() {
        let fixture = git_fixture_with_limits(FetchLimits {
            max_file_bytes: 32 * 1024,
            max_staging_bytes: 512 * 1024,
            emergency_bytes: 0,
            emergency_percent: 0,
        });
        let mut contents = Vec::with_capacity(256 * 1024);
        for counter in 0_u64..8192 {
            contents.extend_from_slice(&Sha256::digest(counter.to_le_bytes()));
        }
        let candidate = commit_bytes(&fixture.worktree, &contents, "oversized");
        push_main(&fixture.worktree, &fixture.remote, false);

        let error = fixture
            .repository
            .fetch_remote_main(&fixture.project_id)
            .expect_err("oversized fetch must fail closed");
        assert!(
            matches!(
                &error,
                SourceError::Repository(message) if message.contains("per-file limit")
            ),
            "unexpected oversized fetch error: {error}"
        );
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        assert_eq!(
            fixture
                .repository
                .read_ref(project, FETCHED_MAIN_REF)
                .unwrap_or_else(|error| panic!("read failed fetched ref: {error}")),
            None
        );
        assert!(
            !fixture
                .repository
                .contains_commit(&fixture.project_id, &candidate)
                .unwrap_or_else(|error| panic!("inspect rejected commit: {error}"))
        );
        assert_directory_empty(&project.repository_path.join("objects/pack"));
        assert_directory_empty(&project.repository_path.join("objects/info"));
        assert_directory_empty(&project.repository_root.join(FETCH_STAGING_DIRECTORY));
    }

    #[test]
    fn next_fetch_cleans_interrupted_staging_and_pack_temporaries() {
        let fixture = git_fixture();
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let staging_root = prepare_staging_root(project)
            .unwrap_or_else(|error| panic!("prepare stale staging root: {error}"));
        let stale_staging = staging_root.join(format!("{}.git", fixture.project_id));
        create_private_directory(&stale_staging)
            .unwrap_or_else(|error| panic!("create stale staging: {error}"));
        fs::write(stale_staging.join("partial.pack"), b"interrupted")
            .unwrap_or_else(|error| panic!("write stale staging: {error}"));
        let temporary_pack = project
            .repository_path
            .join("objects/pack/tmp_pack_interrupted");
        fs::write(&temporary_pack, b"interrupted")
            .unwrap_or_else(|error| panic!("write temporary pack: {error}"));
        make_file_private(&temporary_pack);
        let candidate = commit_file(&fixture.worktree, "first", "first");
        push_main(&fixture.worktree, &fixture.remote, false);

        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("fetch after interrupted operation: {error}")),
            candidate
        );
        assert!(!temporary_pack.exists());
        assert_directory_empty(&staging_root);
    }

    #[cfg(unix)]
    #[test]
    fn missing_initialization_marker_discards_a_permissive_torn_skeleton_before_scanning() {
        let fixture = git_fixture();
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let staging_root = prepare_staging_root(project)
            .unwrap_or_else(|error| panic!("prepare stale staging root: {error}"));
        let stale_staging = staging_root.join(format!("{}.git", fixture.project_id));
        create_private_directory(&stale_staging)
            .unwrap_or_else(|error| panic!("create stale staging: {error}"));
        run_test_git(
            Command::new(SYSTEM_GIT)
                .arg("init")
                .arg("--bare")
                .arg("--initial-branch=main")
                .arg(&stale_staging),
        );
        for relative_path in ["config", "HEAD"] {
            fs::set_permissions(
                stale_staging.join(relative_path),
                fs::Permissions::from_mode(0o666),
            )
            .unwrap_or_else(|error| panic!("make torn {relative_path} permissive: {error}"));
        }
        assert!(!stale_staging.join(STAGING_INITIALIZATION_MARKER).exists());

        let candidate = commit_file(&fixture.worktree, "first", "first");
        push_main(&fixture.worktree, &fixture.remote, false);
        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("fetch after torn initialization: {error}")),
            candidate
        );
        assert_directory_empty(&staging_root);
    }

    #[test]
    fn next_fetch_reconciles_a_promoted_pack_before_ref_publication() {
        let fixture = git_fixture();
        let (candidate, staging_root, _staging_path, promoted_pack_guard) =
            promote_without_publishing_fetched_ref(&fixture);
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let keep_path = project
            .repository_path
            .join("objects/pack")
            .join(format!("pack-{}.keep", promoted_pack_guard.pack_hash));
        assert!(keep_path.is_file());
        assert_eq!(
            find_promoted_pack_guard(project, &candidate)
                .unwrap_or_else(|error| panic!("find interrupted pack guard: {error}")),
            Some(promoted_pack_guard)
        );
        assert_eq!(
            fixture
                .repository
                .read_ref(project, FETCHED_MAIN_REF)
                .unwrap_or_else(|error| panic!("read unpublished fetched ref: {error}")),
            None
        );

        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("reconcile interrupted promotion: {error}")),
            candidate
        );
        assert_eq!(
            fixture
                .repository
                .read_ref(project, FETCHED_MAIN_REF)
                .unwrap_or_else(|error| panic!("read reconciled fetched ref: {error}")),
            Some(candidate)
        );
        assert!(!keep_path.exists());
        assert_directory_empty(&staging_root);
    }

    #[test]
    fn interrupted_promotion_recreates_a_missing_exact_keep_marker() {
        let fixture = git_fixture();
        let (candidate, staging_root, _staging_path, promoted_pack_guard) =
            promote_without_publishing_fetched_ref(&fixture);
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let pack_directory = project.repository_path.join("objects/pack");
        let keep_path = pack_directory.join(format!("pack-{}.keep", promoted_pack_guard.pack_hash));
        fs::remove_file(&keep_path)
            .unwrap_or_else(|error| panic!("remove interrupted pack guard: {error}"));
        sync_directory(&pack_directory)
            .unwrap_or_else(|error| panic!("sync missing pack guard: {error}"));

        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("replay promotion without keep marker: {error}")),
            candidate.clone()
        );
        assert_eq!(
            fixture
                .repository
                .read_ref(project, FETCHED_MAIN_REF)
                .unwrap_or_else(|error| panic!("read replayed fetched ref: {error}")),
            Some(candidate)
        );
        assert!(!keep_path.exists());
        assert_directory_empty(&staging_root);
    }

    #[test]
    fn interrupted_promotion_recovers_with_a_missing_staged_pack_index() {
        let fixture = git_fixture();
        let (candidate, staging_root, staging_path, promoted_pack_guard) =
            promote_without_publishing_fetched_ref(&fixture);
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let staged_pack = staged_pack(&staging_path, fixture.repository.fetch_limits)
            .unwrap_or_else(|error| panic!("inspect staged pack before corruption: {error}"))
            .unwrap_or_else(|| panic!("interrupted promotion has no staged pack"));
        let staged_index = staged_pack.with_extension("idx");
        fs::remove_file(&staged_index)
            .unwrap_or_else(|error| panic!("remove staged pack index: {error}"));
        sync_directory(
            staged_index
                .parent()
                .unwrap_or_else(|| panic!("staged index has no parent")),
        )
        .unwrap_or_else(|error| panic!("sync missing staged pack index: {error}"));
        let keep_path = project
            .repository_path
            .join("objects/pack")
            .join(format!("pack-{}.keep", promoted_pack_guard.pack_hash));

        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("recover without staged pack index: {error}")),
            candidate.clone()
        );
        assert_eq!(
            fixture
                .repository
                .read_ref(project, FETCHED_MAIN_REF)
                .unwrap_or_else(|error| panic!("read recovered fetched ref: {error}")),
            Some(candidate)
        );
        assert!(!keep_path.exists());
        assert_directory_empty(&staging_root);
    }

    #[test]
    fn orphaned_pack_guard_is_released_only_after_its_durable_ref_exists() {
        let fixture = git_fixture();
        let (candidate, staging_root, staging_path, promoted_pack_guard) =
            promote_without_publishing_fetched_ref(&fixture);
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        fixture
            .repository
            .update_fetched_main_ref(project, &candidate)
            .unwrap_or_else(|error| panic!("publish fetched ref before token loss: {error}"));
        remove_staging_directory(project, &staging_path)
            .unwrap_or_else(|error| panic!("simulate staging token loss: {error}"));
        let keep_path = project
            .repository_path
            .join("objects/pack")
            .join(format!("pack-{}.keep", promoted_pack_guard.pack_hash));
        assert!(keep_path.is_file());

        assert_eq!(
            fixture
                .repository
                .fetch_remote_main(&fixture.project_id)
                .unwrap_or_else(|error| panic!("reconcile orphaned pack guard: {error}")),
            candidate
        );
        assert!(!keep_path.exists());
        assert_directory_empty(&staging_root);
    }

    #[test]
    fn staging_for_an_unconfigured_project_is_retained_for_explicit_retirement() {
        let fixture = git_fixture();
        let (_candidate, staging_root, staging_path, promoted_pack_guard) =
            promote_without_publishing_fetched_ref(&fixture);
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let retired_staging_path = staging_root.join("retired.git");
        fs::rename(&staging_path, &retired_staging_path)
            .unwrap_or_else(|error| panic!("rename retired project staging: {error}"));
        sync_directory(&staging_root)
            .unwrap_or_else(|error| panic!("sync retired project staging: {error}"));
        let keep_path = project
            .repository_path
            .join("objects/pack")
            .join(format!("pack-{}.keep", promoted_pack_guard.pack_hash));

        let error = fixture
            .repository
            .fetch_remote_main(&fixture.project_id)
            .expect_err("unconfigured project staging must not be discarded");
        assert!(
            matches!(
                &error,
                SourceError::Repository(message)
                    if message.contains("unconfigured project retired")
            ),
            "unexpected retired staging error: {error}"
        );
        assert!(retired_staging_path.is_dir());
        assert!(keep_path.is_file());
    }

    #[test]
    fn staging_tree_enforces_the_aggregate_limit() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        let first = directory.path().join("first");
        fs::write(&first, [0_u8; 8])
            .unwrap_or_else(|error| panic!("write first bounded file: {error}"));
        make_file_private(&first);
        let second = directory.path().join("second");
        fs::write(&second, [0_u8; 8])
            .unwrap_or_else(|error| panic!("write second bounded file: {error}"));
        make_file_private(&second);
        let error = inspect_staging_tree(
            directory.path(),
            FetchLimits {
                max_file_bytes: 8,
                max_staging_bytes: 15,
                emergency_bytes: 0,
                emergency_percent: 0,
            },
            false,
        )
        .expect_err("aggregate staging limit must be enforced");
        assert!(
            matches!(
                &error,
                SourceError::Repository(message) if message.contains("aggregate limit")
            ),
            "unexpected aggregate limit error: {error}"
        );
    }

    #[test]
    fn real_git_adapter_distinguishes_rewind_divergence_and_missing_objects() {
        let fixture = git_fixture();
        let first = commit_file(&fixture.worktree, "first", "first");
        let second = commit_file(&fixture.worktree, "second", "second");
        push_main(&fixture.worktree, &fixture.remote, false);
        fixture
            .repository
            .fetch_remote_main(&fixture.project_id)
            .unwrap_or_else(|error| panic!("fetch second: {error}"));

        reset_hard(&fixture.worktree, &first);
        push_main(&fixture.worktree, &fixture.remote, true);
        let rewound = fixture
            .repository
            .fetch_remote_main(&fixture.project_id)
            .unwrap_or_else(|error| panic!("fetch rewind: {error}"));
        assert_eq!(rewound, first);
        assert_eq!(
            fixture
                .repository
                .relationship(&fixture.project_id, &second, &first)
                .unwrap_or_else(|error| panic!("rewind relationship: {error}")),
            CommitRelationship::Rewind
        );

        let divergent = commit_file(&fixture.worktree, "divergent", "divergent");
        push_main(&fixture.worktree, &fixture.remote, true);
        fixture
            .repository
            .fetch_remote_main(&fixture.project_id)
            .unwrap_or_else(|error| panic!("fetch divergent: {error}"));
        assert_eq!(
            fixture
                .repository
                .relationship(&fixture.project_id, &second, &divergent)
                .unwrap_or_else(|error| panic!("divergent relationship: {error}")),
            CommitRelationship::Diverged
        );
        let missing = GitCommitId::from_str(&"f".repeat(40))
            .unwrap_or_else(|error| panic!("missing commit fixture: {error}"));
        assert!(
            !fixture
                .repository
                .contains_commit(&fixture.project_id, &missing)
                .unwrap_or_else(|error| panic!("inspect missing commit: {error}"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_repository_root_rejects_symlink_aliases() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        let real_root = directory.path().join("repositories");
        fs::create_dir(&real_root).unwrap_or_else(|error| panic!("repository root: {error}"));
        init_bare(&real_root.join("rimg.git"));
        let alias = directory.path().join("repository-alias");
        std::os::unix::fs::symlink(&real_root, &alias)
            .unwrap_or_else(|error| panic!("repository symlink: {error}"));
        let project_id =
            ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project fixture: {error}"));
        assert!(matches!(
            GitSourceRepository::open_local(
                &alias,
                project_id,
                directory.path().join("remote.git")
            ),
            Err(SourceError::InvalidCanonicalRepositoryPath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn repository_identity_rejects_a_cross_filesystem_canonical_repository() {
        let identity = RepositoryFilesystemIdentity {
            root_device: 17,
            root_inode: 101,
            repository_device: 29,
            repository_inode: 202,
            owner_uid: 1_000,
        };

        let error = identity
            .require_shared_filesystem()
            .expect_err("cross-filesystem repository must fail closed");
        assert!(matches!(
            error,
            SourceError::Repository(message)
                if message.contains("must share one filesystem")
                    && message.contains("emergency disk reserve")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_repository_permissions_and_inode_are_revalidated_for_every_command() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        let repository_root = directory.path().join("repositories");
        fs::create_dir(&repository_root).unwrap_or_else(|error| panic!("repository root: {error}"));
        make_directory_private(&repository_root);
        let repository_path = repository_root.join("rimg.git");
        init_bare(&repository_path);
        let project_id =
            ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project fixture: {error}"));

        fs::set_permissions(&repository_root, fs::Permissions::from_mode(0o777))
            .unwrap_or_else(|error| panic!("make root writable: {error}"));
        assert!(matches!(
            GitSourceRepository::open_local(
                &repository_root,
                project_id.clone(),
                directory.path().join("remote.git")
            ),
            Err(SourceError::InvalidCanonicalRepositoryPath)
        ));
        fs::set_permissions(&repository_root, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("restore root permissions: {error}"));
        fs::set_permissions(
            repository_path.join("config"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap_or_else(|error| panic!("make config writable: {error}"));
        assert!(matches!(
            GitSourceRepository::open_local(
                &repository_root,
                project_id.clone(),
                directory.path().join("remote.git")
            ),
            Err(SourceError::InvalidCanonicalRepositoryPath)
        ));
        fs::set_permissions(
            repository_path.join("config"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap_or_else(|error| panic!("restore config permissions: {error}"));

        let repository = GitSourceRepository::open_local(
            &repository_root,
            project_id.clone(),
            directory.path().join("remote.git"),
        )
        .unwrap_or_else(|error| panic!("open canonical repository: {error}"));
        fs::rename(&repository_path, repository_root.join("replaced-rimg.git"))
            .unwrap_or_else(|error| panic!("move original repository: {error}"));
        init_bare(&repository_path);
        assert!(matches!(
            repository.accepted_head(&project_id),
            Err(SourceError::InvalidCanonicalRepositoryPath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_mutation_files_are_owner_only_and_revalidated() {
        let fixture = git_fixture();
        let candidate = commit_file(&fixture.worktree, "first", "first");
        push_main(&fixture.worktree, &fixture.remote, false);
        fixture
            .repository
            .fetch_remote_main(&fixture.project_id)
            .unwrap_or_else(|error| panic!("fetch candidate: {error}"));
        fixture
            .repository
            .compare_and_swap_accepted_head(&fixture.project_id, None, &candidate)
            .unwrap_or_else(|error| panic!("accept candidate: {error}"));
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        assert_owner_only_directory(&project.repository_root);
        assert_owner_only_directory(&project.repository_path);
        let fetched_ref = project.repository_path.join(FETCHED_MAIN_REF);
        let accepted_ref = project.repository_path.join(ACCEPTED_REF);
        assert_owner_only_regular_file(&fetched_ref);
        assert_owner_only_regular_file(&accepted_ref);
        let pack_path = fs::read_dir(project.repository_path.join("objects/pack"))
            .unwrap_or_else(|error| panic!("read canonical packs: {error}"))
            .map(|entry| {
                entry
                    .unwrap_or_else(|error| panic!("read canonical pack entry: {error}"))
                    .path()
            })
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "pack")
            })
            .unwrap_or_else(|| panic!("canonical promoted pack is missing"));
        assert_owner_only_regular_file(&pack_path);

        fs::set_permissions(&fetched_ref, fs::Permissions::from_mode(0o660))
            .unwrap_or_else(|error| panic!("make fetched ref group writable: {error}"));
        assert!(matches!(
            fixture.repository.accepted_head(&fixture.project_id),
            Err(SourceError::InvalidCanonicalRepositoryPath)
        ));
        fs::set_permissions(&fetched_ref, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("restore fetched ref permissions: {error}"));
        fs::set_permissions(&pack_path, fs::Permissions::from_mode(0o660))
            .unwrap_or_else(|error| panic!("make canonical pack group writable: {error}"));
        assert!(matches!(
            fixture.repository.accepted_head(&fixture.project_id),
            Err(SourceError::InvalidCanonicalRepositoryPath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_object_storage_rejects_external_alternates() {
        let fixture = git_fixture();
        let alternates = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"))
            .repository_path
            .join("objects/info/alternates");
        fs::write(&alternates, b"/tmp/untrusted-objects\n")
            .unwrap_or_else(|error| panic!("write canonical alternate: {error}"));
        make_file_private(&alternates);

        assert!(matches!(
            fixture.repository.accepted_head(&fixture.project_id),
            Err(SourceError::InvalidCanonicalRepositoryPath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_repository_rejects_reftable_storage_before_git_commands() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        let repository_root = directory.path().join("repositories");
        fs::create_dir(&repository_root).unwrap_or_else(|error| panic!("repository root: {error}"));
        make_directory_private(&repository_root);
        let repository_path = repository_root.join("rimg.git");
        init_bare(&repository_path);
        let outside = directory.path().join("outside-reftable");
        fs::create_dir(&outside).unwrap_or_else(|error| panic!("outside reftable: {error}"));
        std::os::unix::fs::symlink(&outside, repository_path.join("reftable"))
            .unwrap_or_else(|error| panic!("reftable symlink: {error}"));
        let project_id =
            ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project fixture: {error}"));

        assert!(matches!(
            GitSourceRepository::open_local(
                &repository_root,
                project_id,
                directory.path().join("remote.git")
            ),
            Err(SourceError::InvalidCanonicalRepositoryPath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_repository_rejects_common_dir_redirects_before_git_commands() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        let repository_root = directory.path().join("repositories");
        fs::create_dir(&repository_root).unwrap_or_else(|error| panic!("repository root: {error}"));
        make_directory_private(&repository_root);
        let repository_path = repository_root.join("rimg.git");
        init_bare(&repository_path);
        let common_dir = repository_path.join("commondir");
        fs::write(&common_dir, b"../external-common.git\n")
            .unwrap_or_else(|error| panic!("write common-dir redirect: {error}"));
        make_file_private(&common_dir);
        let project_id =
            ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project fixture: {error}"));

        assert!(matches!(
            GitSourceRepository::open_local(
                &repository_root,
                project_id,
                directory.path().join("remote.git")
            ),
            Err(SourceError::InvalidCanonicalRepositoryPath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_repository_rejects_local_config_includes() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        let repository_root = directory.path().join("repositories");
        fs::create_dir(&repository_root).unwrap_or_else(|error| panic!("repository root: {error}"));
        make_directory_private(&repository_root);
        let repository_path = repository_root.join("rimg.git");
        init_bare(&repository_path);
        let included_config = directory.path().join("included.conf");
        fs::write(&included_config, b"[core]\n\tbare = true\n")
            .unwrap_or_else(|error| panic!("write included config: {error}"));
        let mut config = File::options()
            .append(true)
            .open(repository_path.join("config"))
            .unwrap_or_else(|error| panic!("open canonical config: {error}"));
        writeln!(
            config,
            "\n[include]\n\tpath = {}",
            included_config.display()
        )
        .unwrap_or_else(|error| panic!("append canonical config include: {error}"));
        drop(config);
        let project_id =
            ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project fixture: {error}"));

        let error = GitSourceRepository::open_local(
            &repository_root,
            project_id,
            directory.path().join("remote.git"),
        )
        .expect_err("repository-local include must fail closed");
        assert!(
            matches!(error, SourceError::Repository(message) if message.contains("configuration includes are forbidden"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_repository_configuration_is_immutable_after_open() {
        let fixture = git_fixture();
        let config_path = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"))
            .repository_path
            .join("config");
        let mut config = File::options()
            .append(true)
            .open(&config_path)
            .unwrap_or_else(|error| panic!("open canonical config: {error}"));
        writeln!(config, "# configuration drift")
            .unwrap_or_else(|error| panic!("mutate canonical config: {error}"));
        drop(config);

        assert!(matches!(
            fixture.repository.accepted_head(&fixture.project_id),
            Err(SourceError::InvalidCanonicalRepositoryPath)
        ));
    }

    #[test]
    fn project_command_locks_do_not_serialize_unrelated_repositories() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        let repository_root = directory.path().join("repositories");
        fs::create_dir(&repository_root).unwrap_or_else(|error| panic!("repository root: {error}"));
        make_directory_private(&repository_root);
        let first = ProjectId::from_str("rimg")
            .unwrap_or_else(|error| panic!("first project fixture: {error}"));
        let second = ProjectId::from_str("keyroom")
            .unwrap_or_else(|error| panic!("second project fixture: {error}"));
        init_bare(&repository_root.join("rimg.git"));
        init_bare(&repository_root.join("keyroom.git"));
        let repository = GitSourceRepository::open_with_remotes(
            &repository_root,
            vec![
                (
                    first.clone(),
                    GitRemote::Local(directory.path().join("one.git")),
                ),
                (
                    second.clone(),
                    GitRemote::Local(directory.path().join("two.git")),
                ),
            ],
        )
        .unwrap_or_else(|error| panic!("open project repositories: {error}"));
        let first_project = repository
            .project(&first)
            .unwrap_or_else(|error| panic!("first installed project: {error}"));
        let first_guard = first_project
            .command_lock
            .lock()
            .unwrap_or_else(|_| panic!("first command lock"));
        let (sender, receiver) = mpsc::channel();
        let concurrent_repository = repository.clone();
        let worker = thread::spawn(move || {
            let result = concurrent_repository.accepted_head(&second);
            let _ = sender.send(result);
        });
        let concurrent_result = receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("unrelated project was serialized: {error}"));
        assert_eq!(
            concurrent_result.unwrap_or_else(|error| panic!("read second project: {error}")),
            None
        );
        drop(first_guard);
        worker
            .join()
            .unwrap_or_else(|_| panic!("join project lock worker"));
    }

    #[test]
    fn background_fetch_does_not_queue_ahead_of_waiting_webhook_work() {
        let fixture = git_fixture();
        let held_fetch = fixture
            .repository
            .fetch_lock
            .lock()
            .unwrap_or_else(|_| panic!("hold global fetch lock"));
        let foreground_repository = fixture.repository.clone();
        let foreground_project = fixture.project_id.clone();
        let foreground =
            thread::spawn(move || foreground_repository.fetch_remote_main(&foreground_project));
        for _ in 0..100 {
            if fixture
                .repository
                .foreground_fetch_waiters
                .load(Ordering::Acquire)
                == 1
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fixture
                .repository
                .foreground_fetch_waiters
                .load(Ordering::Acquire),
            1,
            "foreground webhook fetch did not register its priority"
        );
        let started = Instant::now();
        assert!(matches!(
            fixture
                .repository
                .fetch_remote_main_reconciliation(&fixture.project_id),
            Err(SourceError::ReconciliationDeferred)
        ));
        assert!(started.elapsed() < Duration::from_millis(100));

        drop(held_fetch);
        let _ = foreground
            .join()
            .unwrap_or_else(|_| panic!("join foreground fetch"));
    }

    #[test]
    fn durable_priority_signal_blocks_background_fetch_until_cleared() {
        let fixture = git_fixture();
        fixture
            .repository
            .notify_priority_fetch(&fixture.project_id)
            .unwrap_or_else(|error| panic!("signal priority fetch: {error}"));
        fixture
            .repository
            .notify_priority_fetch(&fixture.project_id)
            .unwrap_or_else(|error| panic!("repeat priority signal: {error}"));
        assert_eq!(
            fixture
                .repository
                .priority_fetch_project_count
                .load(Ordering::Acquire),
            1,
            "duplicate delivery wake-ups must not inflate the pending-project count"
        );
        assert!(matches!(
            fixture
                .repository
                .fetch_remote_main_reconciliation(&fixture.project_id),
            Err(SourceError::ReconciliationDeferred)
        ));

        fixture
            .repository
            .clear_priority_fetch(&fixture.project_id)
            .unwrap_or_else(|error| panic!("clear priority fetch: {error}"));
        assert_eq!(
            fixture
                .repository
                .priority_fetch_project_count
                .load(Ordering::Acquire),
            0
        );
        let result = fixture
            .repository
            .fetch_remote_main_reconciliation(&fixture.project_id);
        assert!(
            !matches!(result, Err(SourceError::ReconciliationDeferred)),
            "clearing the durable priority signal must re-enable background fetch admission"
        );
    }

    #[cfg(unix)]
    #[test]
    fn durable_webhook_signal_interrupts_an_active_background_fetch_command() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        let priority_generation = Arc::new(AtomicU64::new(0));
        let guard = CommandDiskGuard {
            free_space_path: directory.path(),
            minimum_available_bytes: 0,
            staging_path: None,
            staging_identity: None,
            fetch_limits: FetchLimits::TEST,
            foreground_fetch_waiters: None,
            priority_fetch_project_count: None,
            fetch_priority_generation: Some((priority_generation.as_ref(), 0)),
        };
        let signal = Arc::clone(&priority_generation);
        let notifier = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            signal.fetch_add(1, Ordering::AcqRel);
        });
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 3 & wait"]);
        let started = Instant::now();
        assert!(matches!(
            run_command_guarded(
                command,
                "test background fetch priority",
                CommandInput::Null,
                Duration::from_secs(3),
                Some(&guard),
            ),
            Err(SourceError::ReconciliationDeferred)
        ));
        notifier
            .join()
            .unwrap_or_else(|_| panic!("join foreground notifier"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn command_deadline_terminates_descendants_and_drains_their_output_pipes() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 3 & wait"]);
        let started = Instant::now();
        assert!(matches!(
            run_command(
                command,
                "test descendant deadline",
                None,
                Duration::from_millis(50)
            ),
            Err(SourceError::Repository(message)) if message.contains("exceeded its deadline")
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    fn git_fixture() -> GitFixture {
        git_fixture_with_limits(FetchLimits::TEST)
    }

    fn git_fixture_with_limits(fetch_limits: FetchLimits) -> GitFixture {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        let repository_root = directory.path().join("repositories");
        let remote = directory.path().join("remote.git");
        let worktree = directory.path().join("worktree");
        fs::create_dir(&repository_root).unwrap_or_else(|error| panic!("repository root: {error}"));
        make_directory_private(&repository_root);
        init_bare(&remote);
        init_bare(&repository_root.join("rimg.git"));
        run_test_git(
            Command::new(SYSTEM_GIT)
                .arg("init")
                .arg("--initial-branch=main")
                .arg(&worktree),
        );
        let project_id =
            ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project fixture: {error}"));
        let repository = GitSourceRepository::open_local_with_limits(
            &repository_root,
            project_id.clone(),
            remote.clone(),
            fetch_limits,
        )
        .unwrap_or_else(|error| panic!("open Git source repository: {error}"));
        GitFixture {
            _directory: directory,
            repository,
            project_id,
            worktree,
            remote,
        }
    }

    fn promote_without_publishing_fetched_ref(
        fixture: &GitFixture,
    ) -> (GitCommitId, PathBuf, PathBuf, PromotedPackGuard) {
        let candidate = commit_file(&fixture.worktree, "first", "first");
        push_main(&fixture.worktree, &fixture.remote, false);
        let project = fixture
            .repository
            .project(&fixture.project_id)
            .unwrap_or_else(|error| panic!("installed project: {error}"));
        let staging_root = prepare_staging_root(project)
            .unwrap_or_else(|error| panic!("prepare staging root: {error}"));
        let staging_path = staging_root.join(format!("{}.git", fixture.project_id));
        let object_format = fixture
            .repository
            .repository_object_format(project)
            .unwrap_or_else(|error| panic!("read object format: {error}"));
        fixture
            .repository
            .initialize_staging_repository(project, &staging_path, object_format)
            .unwrap_or_else(|error| panic!("initialize interrupted staging: {error}"));
        let staging_identity = validate_new_staging_repository(project, &staging_path)
            .unwrap_or_else(|error| panic!("validate interrupted staging: {error}"));
        let emergency_reserve_bytes = fixture
            .repository
            .fetch_limits
            .emergency_reserve_bytes(&project.repository_root)
            .unwrap_or_else(|error| panic!("measure emergency reserve: {error}"));
        let staging_guard = CommandDiskGuard {
            free_space_path: &project.repository_root,
            minimum_available_bytes: fixture
                .repository
                .fetch_limits
                .staging_minimum_available_bytes(emergency_reserve_bytes)
                .unwrap_or_else(|error| panic!("calculate staging reserve: {error}")),
            staging_path: Some(&staging_path),
            staging_identity: Some(staging_identity),
            fetch_limits: fixture.repository.fetch_limits,
            foreground_fetch_waiters: None,
            priority_fetch_project_count: None,
            fetch_priority_generation: None,
        };
        let staged_candidate = fixture
            .repository
            .fetch_staged_main(project, &staging_path, &staging_guard, FETCH_TIMEOUT)
            .unwrap_or_else(|error| panic!("stage interrupted fetch: {error}"));
        assert!(
            !fixture
                .repository
                .contains_commit_locked(project, &staged_candidate)
                .unwrap_or_else(|error| panic!("inspect unpromoted candidate: {error}")),
            "staging fetch wrote into the canonical object database before promotion"
        );
        assert_directory_empty(&project.repository_path.join("objects/pack"));
        assert_directory_empty(&project.repository_path.join("objects/info"));
        let promoted_pack_guard = fixture
            .repository
            .promote_staged_pack(
                project,
                &staging_path,
                &staged_candidate,
                emergency_reserve_bytes,
            )
            .unwrap_or_else(|error| panic!("promote interrupted fetch: {error}"))
            .unwrap_or_else(|| panic!("new staged candidate did not produce a promoted pack"));
        assert_eq!(staged_candidate, candidate);
        (candidate, staging_root, staging_path, promoted_pack_guard)
    }

    fn init_bare(path: &Path) {
        run_test_git(
            Command::new(SYSTEM_GIT)
                .arg("init")
                .arg("--bare")
                .arg("--initial-branch=main")
                .arg(path),
        );
        make_directory_private(path);
    }

    fn commit_file(worktree: &Path, contents: &str, message: &str) -> GitCommitId {
        commit_path(worktree, "fixture.txt", contents.as_bytes(), message)
    }

    fn commit_bytes(worktree: &Path, contents: &[u8], message: &str) -> GitCommitId {
        commit_path(worktree, "fixture.bin", contents, message)
    }

    fn deterministic_noise(blocks: u64) -> Vec<u8> {
        let mut contents = Vec::new();
        for counter in 0..blocks {
            contents.extend_from_slice(&Sha256::digest(counter.to_le_bytes()));
        }
        contents
    }

    fn canonical_pack_storage_bytes(project: &InstalledGitProject) -> u64 {
        let pack_directory = project.repository_path.join("objects/pack");
        let mut total = 0_u64;
        for entry in fs::read_dir(&pack_directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", pack_directory.display()))
        {
            let entry = entry.unwrap_or_else(|error| panic!("read canonical pack entry: {error}"));
            let metadata = entry
                .metadata()
                .unwrap_or_else(|error| panic!("inspect {}: {error}", entry.path().display()));
            if metadata.is_file() {
                total = total
                    .checked_add(metadata.len())
                    .unwrap_or_else(|| panic!("canonical pack storage overflowed"));
            }
        }
        total
    }

    fn commit_path(
        worktree: &Path,
        fixture_name: &str,
        contents: &[u8],
        message: &str,
    ) -> GitCommitId {
        fs::write(worktree.join(fixture_name), contents)
            .unwrap_or_else(|error| panic!("write Git fixture: {error}"));
        run_test_git(
            Command::new(SYSTEM_GIT)
                .arg("-C")
                .arg(worktree)
                .args(["add", fixture_name]),
        );
        run_test_git(
            Command::new(SYSTEM_GIT)
                .arg("-C")
                .arg(worktree)
                .args(["commit", "--quiet", "-m", message]),
        );
        let head = run_test_git(
            Command::new(SYSTEM_GIT)
                .arg("-C")
                .arg(worktree)
                .args(["rev-parse", "HEAD"]),
        );
        GitCommitId::from_str(head.trim())
            .unwrap_or_else(|error| panic!("Git fixture commit: {error}"))
    }

    fn assert_directory_empty(path: &Path) {
        let first_entry = fs::read_dir(path)
            .unwrap_or_else(|error| panic!("read directory {}: {error}", path.display()))
            .next()
            .transpose()
            .unwrap_or_else(|error| panic!("read entry in {}: {error}", path.display()));
        assert!(
            first_entry.is_none(),
            "directory is not empty: {}",
            path.display()
        );
    }

    #[cfg(unix)]
    fn assert_owner_only_regular_file(path: &Path) {
        let metadata = fs::symlink_metadata(path)
            .unwrap_or_else(|error| panic!("inspect {}: {error}", path.display()));
        assert!(metadata.is_file(), "{} is not a file", path.display());
        assert_eq!(
            metadata.permissions().mode() & 0o077,
            0,
            "{} is accessible outside its owner",
            path.display()
        );
    }

    #[cfg(unix)]
    fn assert_owner_only_directory(path: &Path) {
        let metadata = fs::symlink_metadata(path)
            .unwrap_or_else(|error| panic!("inspect {}: {error}", path.display()));
        assert!(metadata.is_dir(), "{} is not a directory", path.display());
        assert_eq!(
            metadata.permissions().mode() & 0o077,
            0,
            "{} is accessible outside its owner",
            path.display()
        );
    }

    fn make_file_private(path: &Path) {
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("make {} private: {error}", path.display()));
        #[cfg(not(unix))]
        let _ = path;
    }

    fn make_directory_private(path: &Path) {
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("make {} private: {error}", path.display()));
        #[cfg(not(unix))]
        let _ = path;
    }

    fn push_main(worktree: &Path, remote: &Path, force: bool) {
        let mut command = Command::new(SYSTEM_GIT);
        command.arg("-C").arg(worktree).arg("push").arg("--quiet");
        if force {
            command.arg("--force");
        }
        command.arg(remote).arg("HEAD:refs/heads/main");
        run_test_git(&mut command);
    }

    fn reset_hard(worktree: &Path, commit: &GitCommitId) {
        run_test_git(Command::new(SYSTEM_GIT).arg("-C").arg(worktree).args([
            "reset",
            "--hard",
            "--quiet",
            commit.as_str(),
        ]));
    }

    fn run_test_git(command: &mut Command) -> String {
        let output = command
            .env("GIT_AUTHOR_NAME", "rdashboard test")
            .env("GIT_AUTHOR_EMAIL", "rdashboard@example.invalid")
            .env("GIT_COMMITTER_NAME", "rdashboard test")
            .env("GIT_COMMITTER_EMAIL", "rdashboard@example.invalid")
            .output()
            .unwrap_or_else(|error| panic!("run fixture Git: {error}"));
        assert!(
            output.status.success(),
            "fixture Git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap_or_else(|error| panic!("fixture Git stdout: {error}"))
    }
}
