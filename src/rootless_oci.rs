use std::{
    fmt::Write as _,
    fs::{self, File},
    io::{self, Read as _},
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::UnixStream,
    },
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    build_storage::{
        BUILD_STORAGE_MIN_FREE_BYTES, SHARED_BUILD_STORAGE_MIN_BYTES, SHARED_BUILD_STORAGE_ROOT,
    },
    domain::{EvidenceDigest, valid_workflow_identity},
};

pub const ROOTLESS_OCI_POLICY_SCHEMA_VERSION: u16 = 1;
pub const BUILDKIT_STATE_ROOT: &str = "/var/lib/rdashboard-build/buildkit";
pub const BUILDKIT_RUNTIME_ROOT: &str = "/run/rdashboard-buildkit";
pub const BUILDKIT_SOCKET_PATH: &str = "/run/rdashboard-buildkit/buildkitd.sock";
pub const BUILDKIT_CONFIG_PATH: &str = "/etc/rdashboard/buildkitd.toml";
pub const BUILDKITD_EXECUTABLE: &str = "/usr/libexec/rdashboard/buildkitd";
pub const BUILDCTL_EXECUTABLE: &str = "/usr/libexec/rdashboard/buildctl";
pub const ROOTLESSKIT_EXECUTABLE: &str = "/usr/libexec/rdashboard/rootlesskit";
pub const BUILDKIT_RUNTIME_EXECUTABLE: &str = "/usr/libexec/rdashboard/runc";

const NEWUIDMAP_EXECUTABLE: &str = "/usr/bin/newuidmap";
const NEWGIDMAP_EXECUTABLE: &str = "/usr/bin/newgidmap";
const SUBUID_PATH: &str = "/etc/subuid";
const SUBGID_PATH: &str = "/etc/subgid";
const USER_NAMESPACE_LIMIT_PATH: &str = "/proc/sys/user/max_user_namespaces";
const UNPRIVILEGED_USER_NAMESPACE_PATH: &str = "/proc/sys/kernel/unprivileged_userns_clone";
const APPARMOR_USER_NAMESPACE_PATH: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
const MIN_SUBORDINATE_IDS: u64 = 65_536;
const MIN_SUBORDINATE_ID_START: u64 = 65_536;
const MAX_TOOL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_SUBID_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootlessOciRuntimePolicyV1 {
    pub schema_version: u16,
    pub daemon_uid: u32,
    pub daemon_user: String,
    pub buildkitd_sha256: EvidenceDigest,
    pub buildctl_sha256: EvidenceDigest,
    pub rootlesskit_sha256: EvidenceDigest,
    pub runtime_sha256: EvidenceDigest,
    pub buildkit_config_sha256: EvidenceDigest,
    pub max_parallelism: u16,
}

impl RootlessOciRuntimePolicyV1 {
    pub fn validate(&self, worker_uid: u32, job_account_uid: u32) -> Result<(), RootlessOciError> {
        if self.schema_version != ROOTLESS_OCI_POLICY_SCHEMA_VERSION
            || self.daemon_uid == 0
            || self.daemon_uid == u32::MAX
            || self.daemon_uid == worker_uid
            || self.daemon_uid == job_account_uid
            || !valid_workflow_identity(&self.daemon_user)
            || self.max_parallelism != 1
        {
            return Err(RootlessOciError::InvalidPolicy);
        }
        Ok(())
    }

    pub fn verify_installed(
        &self,
        worker_uid: u32,
        job_account_uid: u32,
        shared_group_gid: u32,
    ) -> Result<(), RootlessOciError> {
        self.verify_layout(
            worker_uid,
            job_account_uid,
            shared_group_gid,
            &InstalledLayout::system(),
        )
    }

    fn verify_layout(
        &self,
        worker_uid: u32,
        job_account_uid: u32,
        shared_group_gid: u32,
        layout: &InstalledLayout,
    ) -> Result<(), RootlessOciError> {
        self.validate(worker_uid, job_account_uid)?;
        verify_tool(
            &layout.buildkitd,
            "buildkitd",
            layout.trusted_uid,
            &self.buildkitd_sha256,
        )?;
        verify_tool(
            &layout.buildctl,
            "buildctl",
            layout.trusted_uid,
            &self.buildctl_sha256,
        )?;
        verify_tool(
            &layout.rootlesskit,
            "rootlesskit",
            layout.trusted_uid,
            &self.rootlesskit_sha256,
        )?;
        verify_tool(
            &layout.runtime,
            "runc",
            layout.trusted_uid,
            &self.runtime_sha256,
        )?;
        verify_mapping_helper(&layout.newuidmap, "newuidmap", layout.trusted_uid)?;
        verify_mapping_helper(&layout.newgidmap, "newgidmap", layout.trusted_uid)?;

        let config = read_stable_regular(
            &layout.config,
            layout.trusted_uid,
            0o644,
            MAX_CONFIG_BYTES,
            StableFileKind::Config,
        )?;
        if EvidenceDigest::sha256(&config) != self.buildkit_config_sha256 {
            return Err(RootlessOciError::ConfigDigestMismatch);
        }
        verify_buildkit_config(&config, self.max_parallelism)?;

        let subordinate_users = read_stable_regular(
            &layout.subuid,
            layout.trusted_uid,
            0o644,
            MAX_SUBID_BYTES,
            StableFileKind::Subuid,
        )?;
        let subordinate_groups = read_stable_regular(
            &layout.subgid,
            layout.trusted_uid,
            0o644,
            MAX_SUBID_BYTES,
            StableFileKind::Subgid,
        )?;
        verify_subordinate_ids(&subordinate_users, &self.daemon_user, self.daemon_uid)
            .map_err(|error| error.into_runtime_error("subuid"))?;
        verify_subordinate_ids(&subordinate_groups, &self.daemon_user, self.daemon_uid)
            .map_err(|error| error.into_runtime_error("subgid"))?;

        if read_kernel_switch(&layout.max_user_namespaces)? == 0 {
            return Err(RootlessOciError::UserNamespacesDisabled);
        }
        if layout.unprivileged_userns.try_exists()?
            && read_kernel_switch(&layout.unprivileged_userns)? != 1
        {
            return Err(RootlessOciError::UserNamespacesDisabled);
        }
        if layout.apparmor_userns.try_exists()? && read_kernel_switch(&layout.apparmor_userns)? != 0
        {
            return Err(RootlessOciError::ApparmorBlocksUserNamespaces);
        }

        verify_shared_storage_boundary(layout, self.daemon_uid, shared_group_gid)?;

        verify_directory(
            &layout.runtime_root,
            self.daemon_uid,
            shared_group_gid,
            0o750,
            DirectoryKind::Runtime,
        )?;
        layout
            .socket_probe
            .verify(&layout.socket, self.daemon_uid, shared_group_gid)?;
        Ok(())
    }
}

fn verify_shared_storage_boundary(
    layout: &InstalledLayout,
    daemon_uid: u32,
    shared_group_gid: u32,
) -> Result<(), RootlessOciError> {
    verify_directory(
        &layout.state_root,
        daemon_uid,
        shared_group_gid,
        0o700,
        DirectoryKind::State,
    )?;
    let boundary = layout.boundary_probe.inspect(&layout.state_root)?;
    let state_metadata = fs::metadata(&layout.state_root)?;
    let storage_metadata = fs::metadata(&layout.storage_root)?;
    if state_metadata.dev() != storage_metadata.dev()
        || boundary.total_bytes < SHARED_BUILD_STORAGE_MIN_BYTES
        || boundary.total_inodes == 0
        || boundary.available_bytes > boundary.total_bytes
        || boundary.available_inodes > boundary.total_inodes
    {
        return Err(RootlessOciError::InvalidStateBoundary);
    }
    if boundary.root_available_bytes < BUILD_STORAGE_MIN_FREE_BYTES {
        return Err(RootlessOciError::RootEmergencyReserveViolated);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootlessOciFailureV1 {
    pub purpose: &'static str,
    pub schema_version: u16,
    pub ready: bool,
    pub reason_code: &'static str,
    pub summary: String,
    pub remediation: &'static str,
}

impl RootlessOciFailureV1 {
    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        String::from_utf8(serde_jcs::to_vec(self)?).map_err(|error| {
            serde_json::Error::io(io::Error::new(io::ErrorKind::InvalidData, error))
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RootlessOciError {
    #[error("rootless OCI runtime policy is invalid")]
    InvalidPolicy,
    #[error("installed rootless OCI tool {0} is missing or unsafe")]
    UnsafeTool(&'static str),
    #[error("installed rootless OCI tool {0} does not match its pinned SHA-256")]
    ToolDigestMismatch(&'static str),
    #[error("installed rootless ID mapping helper {0} is missing or unsafe")]
    UnsafeMappingHelper(&'static str),
    #[error("installed BuildKit configuration is missing or unsafe")]
    UnsafeConfig,
    #[error("installed BuildKit configuration does not match its pinned SHA-256")]
    ConfigDigestMismatch,
    #[error("installed BuildKit configuration violates the fixed rootless boundary")]
    InvalidConfig,
    #[error("installed {0} file is missing or unsafe")]
    UnsafeSubordinateIdFile(&'static str),
    #[error("installed {0} file contains an unsafe subordinate-ID layout")]
    UnsafeSubordinateIdLayout(&'static str),
    #[error("installed {0} file does not grant the rootless daemon at least 65536 IDs")]
    InsufficientSubordinateIds(&'static str),
    #[error("unprivileged user namespaces are disabled")]
    UserNamespacesDisabled,
    #[error("AppArmor blocks unprivileged user namespaces")]
    ApparmorBlocksUserNamespaces,
    #[error("rootless BuildKit state root is missing or unsafe")]
    UnsafeStateRoot,
    #[error("rootless BuildKit state is outside the fixed shared build domain")]
    InvalidStateBoundary,
    #[error("the host filesystem has less than the required 20 GiB recovery reserve")]
    RootEmergencyReserveViolated,
    #[error("rootless BuildKit runtime root is missing or unsafe")]
    UnsafeRuntimeRoot,
    #[error("rootless BuildKit Unix socket is missing or unsafe")]
    UnsafeSocket,
    #[error("rootless BuildKit Unix socket is not accepting connections")]
    SocketUnavailable,
    #[error("rootless OCI readiness inspection failed: {0}")]
    Io(#[from] io::Error),
    #[error("rootless OCI readiness TOML failed: {0}")]
    Toml(#[from] toml::de::Error),
}

impl RootlessOciError {
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidPolicy => "rootless_oci_policy_invalid",
            Self::UnsafeTool(_) => "rootless_oci_tool_unsafe",
            Self::ToolDigestMismatch(_) => "rootless_oci_tool_digest_mismatch",
            Self::UnsafeMappingHelper(_) => "rootless_oci_mapping_helper_unsafe",
            Self::UnsafeConfig => "rootless_oci_config_unsafe",
            Self::ConfigDigestMismatch => "rootless_oci_config_digest_mismatch",
            Self::InvalidConfig => "rootless_oci_config_invalid",
            Self::UnsafeSubordinateIdFile(_) => "rootless_oci_subid_file_unsafe",
            Self::UnsafeSubordinateIdLayout(_) => "rootless_oci_subid_layout_unsafe",
            Self::InsufficientSubordinateIds(_) => "rootless_oci_subid_range_missing",
            Self::UserNamespacesDisabled => "rootless_oci_userns_disabled",
            Self::ApparmorBlocksUserNamespaces => "rootless_oci_apparmor_userns_blocked",
            Self::UnsafeStateRoot => "rootless_oci_state_root_unsafe",
            Self::InvalidStateBoundary => "rootless_oci_state_boundary_invalid",
            Self::RootEmergencyReserveViolated => "rootless_oci_root_reserve_violated",
            Self::UnsafeRuntimeRoot => "rootless_oci_runtime_root_unsafe",
            Self::UnsafeSocket => "rootless_oci_socket_unsafe",
            Self::SocketUnavailable => "rootless_oci_socket_unavailable",
            Self::Io(_) => "rootless_oci_probe_io_failed",
            Self::Toml(_) => "rootless_oci_config_toml_invalid",
        }
    }

    pub const fn remediation(&self) -> &'static str {
        match self {
            Self::InvalidPolicy => {
                "install a reviewed launcher policy with distinct worker, build and BuildKit identities"
            }
            Self::UnsafeTool(_) | Self::ToolDigestMismatch(_) => {
                "install the reviewed root-owned BuildKit tool bundle and update only the root-owned pinned digests"
            }
            Self::UnsafeMappingHelper(_) => {
                "install root-owned setuid newuidmap/newgidmap helpers; do not grant capabilities to repository jobs"
            }
            Self::UnsafeConfig
            | Self::ConfigDigestMismatch
            | Self::InvalidConfig
            | Self::Toml(_) => {
                "install the fixed offline rootless buildkitd.toml and bind its exact digest in launcher policy"
            }
            Self::UnsafeSubordinateIdFile(_) => {
                "restore the root-owned subordinate-ID file with its fixed mode before enabling rootless BuildKit"
            }
            Self::UnsafeSubordinateIdLayout(_) => {
                "move every host subordinate-ID range above 65535 and remove all overlaps before enabling rootless BuildKit"
            }
            Self::InsufficientSubordinateIds(_) => {
                "assign a non-overlapping subordinate UID and GID range of at least 65536 IDs to the BuildKit user"
            }
            Self::UserNamespacesDisabled => {
                "enable a positive user.max_user_namespaces and, when present, kernel.unprivileged_userns_clone=1"
            }
            Self::ApparmorBlocksUserNamespaces => {
                "review the host AppArmor user-namespace policy before enabling rootless BuildKit"
            }
            Self::UnsafeStateRoot | Self::InvalidStateBoundary => {
                "restore the fixed shared build directory and its ownership on the host filesystem"
            }
            Self::RootEmergencyReserveViolated => {
                "run ownership-based garbage collection without lowering the 20 GiB recovery reserve"
            }
            Self::UnsafeRuntimeRoot | Self::UnsafeSocket | Self::SocketUnavailable => {
                "start the reviewed rdashboard-buildkit service and verify its peer-restricted Unix socket"
            }
            Self::Io(_) => {
                "inspect the reported host filesystem error and rerun the read-only readiness probe"
            }
        }
    }

    pub fn failure(&self) -> RootlessOciFailureV1 {
        RootlessOciFailureV1 {
            purpose: "rdashboard.rootless-oci-readiness.v1",
            schema_version: 1,
            ready: false,
            reason_code: self.reason_code(),
            summary: self.to_string(),
            remediation: self.remediation(),
        }
    }
}

#[derive(Debug)]
struct InstalledLayout {
    buildkitd: PathBuf,
    buildctl: PathBuf,
    rootlesskit: PathBuf,
    runtime: PathBuf,
    newuidmap: PathBuf,
    newgidmap: PathBuf,
    config: PathBuf,
    subuid: PathBuf,
    subgid: PathBuf,
    max_user_namespaces: PathBuf,
    unprivileged_userns: PathBuf,
    apparmor_userns: PathBuf,
    storage_root: PathBuf,
    state_root: PathBuf,
    runtime_root: PathBuf,
    socket: PathBuf,
    trusted_uid: u32,
    boundary_probe: Box<dyn FilesystemBoundaryProbe>,
    socket_probe: Box<dyn SocketProbe>,
}

impl InstalledLayout {
    fn system() -> Self {
        Self {
            buildkitd: BUILDKITD_EXECUTABLE.into(),
            buildctl: BUILDCTL_EXECUTABLE.into(),
            rootlesskit: ROOTLESSKIT_EXECUTABLE.into(),
            runtime: BUILDKIT_RUNTIME_EXECUTABLE.into(),
            newuidmap: NEWUIDMAP_EXECUTABLE.into(),
            newgidmap: NEWGIDMAP_EXECUTABLE.into(),
            config: BUILDKIT_CONFIG_PATH.into(),
            subuid: SUBUID_PATH.into(),
            subgid: SUBGID_PATH.into(),
            max_user_namespaces: USER_NAMESPACE_LIMIT_PATH.into(),
            unprivileged_userns: UNPRIVILEGED_USER_NAMESPACE_PATH.into(),
            apparmor_userns: APPARMOR_USER_NAMESPACE_PATH.into(),
            storage_root: SHARED_BUILD_STORAGE_ROOT.into(),
            state_root: BUILDKIT_STATE_ROOT.into(),
            runtime_root: BUILDKIT_RUNTIME_ROOT.into(),
            socket: BUILDKIT_SOCKET_PATH.into(),
            trusted_uid: 0,
            boundary_probe: Box::new(SystemFilesystemBoundaryProbe),
            socket_probe: Box::new(SystemSocketProbe),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct FilesystemBoundarySnapshot {
    total_bytes: u64,
    available_bytes: u64,
    total_inodes: u64,
    available_inodes: u64,
    root_available_bytes: u64,
}

trait FilesystemBoundaryProbe: std::fmt::Debug + Send + Sync {
    fn inspect(&self, root: &Path) -> Result<FilesystemBoundarySnapshot, RootlessOciError>;
}

trait SocketProbe: std::fmt::Debug + Send + Sync {
    fn verify(
        &self,
        path: &Path,
        socket_owner_uid: u32,
        client_group_gid: u32,
    ) -> Result<(), RootlessOciError>;
}

#[derive(Debug)]
struct SystemSocketProbe;

impl SocketProbe for SystemSocketProbe {
    fn verify(
        &self,
        path: &Path,
        socket_owner_uid: u32,
        client_group_gid: u32,
    ) -> Result<(), RootlessOciError> {
        verify_socket(path, socket_owner_uid, client_group_gid)
    }
}

#[derive(Debug)]
struct SystemFilesystemBoundaryProbe;

impl FilesystemBoundaryProbe for SystemFilesystemBoundaryProbe {
    fn inspect(&self, root: &Path) -> Result<FilesystemBoundarySnapshot, RootlessOciError> {
        let state_root = File::open(root)?;
        let state = rustix::fs::fstatvfs(&state_root).map_err(io::Error::from)?;
        let fragment_size = if state.f_frsize == 0 {
            state.f_bsize
        } else {
            state.f_frsize
        };
        let host_root = fs2::statvfs("/")?;
        Ok(FilesystemBoundarySnapshot {
            total_bytes: state.f_blocks.saturating_mul(fragment_size),
            available_bytes: state.f_bavail.saturating_mul(fragment_size),
            total_inodes: state.f_files,
            available_inodes: state.f_favail,
            root_available_bytes: host_root.available_space(),
        })
    }
}

#[derive(Clone, Copy)]
enum StableFileKind {
    Config,
    Subuid,
    Subgid,
}

impl StableFileKind {
    const fn error(self) -> RootlessOciError {
        match self {
            Self::Config => RootlessOciError::UnsafeConfig,
            Self::Subuid => RootlessOciError::UnsafeSubordinateIdFile("subuid"),
            Self::Subgid => RootlessOciError::UnsafeSubordinateIdFile("subgid"),
        }
    }
}

#[derive(Clone, Copy)]
enum DirectoryKind {
    State,
    Runtime,
}

impl DirectoryKind {
    const fn error(self) -> RootlessOciError {
        match self {
            Self::State => RootlessOciError::UnsafeStateRoot,
            Self::Runtime => RootlessOciError::UnsafeRuntimeRoot,
        }
    }
}

fn verify_tool(
    path: &Path,
    name: &'static str,
    trusted_uid: u32,
    expected_digest: &EvidenceDigest,
) -> Result<(), RootlessOciError> {
    verify_trusted_parent(path, trusted_uid).map_err(|()| RootlessOciError::UnsafeTool(name))?;
    let metadata = fs::symlink_metadata(path).map_err(|_| RootlessOciError::UnsafeTool(name))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != trusted_uid
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_TOOL_BYTES
        || !matches!(metadata.permissions().mode() & 0o7777, 0o555 | 0o755)
    {
        return Err(RootlessOciError::UnsafeTool(name));
    }
    let mut file = File::open(path).map_err(|_| RootlessOciError::UnsafeTool(name))?;
    let opened = file
        .metadata()
        .map_err(|_| RootlessOciError::UnsafeTool(name))?;
    if !same_file(&metadata, &opened) {
        return Err(RootlessOciError::UnsafeTool(name));
    }
    let mut hasher = Sha256::new();
    let copied =
        io::copy(&mut file, &mut hasher).map_err(|_| RootlessOciError::UnsafeTool(name))?;
    let after = fs::symlink_metadata(path).map_err(|_| RootlessOciError::UnsafeTool(name))?;
    if copied != opened.len() || !same_file(&opened, &after) {
        return Err(RootlessOciError::UnsafeTool(name));
    }
    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut digest, "{byte:02x}").expect("writing SHA-256 to String cannot fail");
    }
    if digest != expected_digest.as_str() {
        return Err(RootlessOciError::ToolDigestMismatch(name));
    }
    Ok(())
}

fn verify_mapping_helper(
    path: &Path,
    name: &'static str,
    trusted_uid: u32,
) -> Result<(), RootlessOciError> {
    verify_trusted_parent(path, trusted_uid)
        .map_err(|()| RootlessOciError::UnsafeMappingHelper(name))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RootlessOciError::UnsafeMappingHelper(name))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != trusted_uid
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.permissions().mode() & 0o7777 != 0o4755
    {
        return Err(RootlessOciError::UnsafeMappingHelper(name));
    }
    Ok(())
}

fn read_stable_regular(
    path: &Path,
    expected_uid: u32,
    expected_mode: u32,
    maximum_bytes: u64,
    kind: StableFileKind,
) -> Result<Vec<u8>, RootlessOciError> {
    verify_trusted_parent(path, expected_uid).map_err(|()| kind.error())?;
    let metadata = fs::symlink_metadata(path).map_err(|_| kind.error())?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != expected_mode
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(kind.error());
    }
    let file = File::open(path).map_err(|_| kind.error())?;
    let opened = file.metadata().map_err(|_| kind.error())?;
    if !same_file(&metadata, &opened) {
        return Err(kind.error());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| kind.error())?;
    let after = fs::symlink_metadata(path).map_err(|_| kind.error())?;
    if !same_file(&opened, &after)
        || bytes.len() != usize::try_from(opened.len()).unwrap_or(usize::MAX)
    {
        return Err(kind.error());
    }
    Ok(bytes)
}

fn verify_trusted_parent(path: &Path, expected_uid: u32) -> Result<(), ()> {
    let parent = path.parent().ok_or(())?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| ())?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(());
    }
    Ok(())
}

fn verify_directory(
    path: &Path,
    owner_uid: u32,
    shared_group_gid: u32,
    expected_mode: u32,
    kind: DirectoryKind,
) -> Result<(), RootlessOciError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| kind.error())?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != shared_group_gid
        || metadata.permissions().mode() & 0o7777 != expected_mode
    {
        return Err(kind.error());
    }
    Ok(())
}

fn verify_socket(
    path: &Path,
    socket_owner_uid: u32,
    client_group_gid: u32,
) -> Result<(), RootlessOciError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RootlessOciError::UnsafeSocket)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != socket_owner_uid
        || metadata.gid() != client_group_gid
        || metadata.permissions().mode() & 0o7777 != 0o660
    {
        return Err(RootlessOciError::UnsafeSocket);
    }
    if UnixStream::connect(path).is_err() {
        return Err(RootlessOciError::SocketUnavailable);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubordinateIdError {
    UnsafeLayout,
    MissingDaemonRange,
}

impl SubordinateIdError {
    const fn into_runtime_error(self, kind: &'static str) -> RootlessOciError {
        match self {
            Self::UnsafeLayout => RootlessOciError::UnsafeSubordinateIdLayout(kind),
            Self::MissingDaemonRange => RootlessOciError::InsufficientSubordinateIds(kind),
        }
    }
}

fn verify_subordinate_ids(
    bytes: &[u8],
    daemon_user: &str,
    daemon_uid: u32,
) -> Result<(), SubordinateIdError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SubordinateIdError::UnsafeLayout)?;
    let numeric_uid = daemon_uid.to_string();
    let mut total = 0_u64;
    let mut ranges = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let identity = fields.next().ok_or(SubordinateIdError::UnsafeLayout)?;
        let start = fields
            .next()
            .ok_or(SubordinateIdError::UnsafeLayout)?
            .parse::<u64>()
            .map_err(|_| SubordinateIdError::UnsafeLayout)?;
        let count = fields
            .next()
            .ok_or(SubordinateIdError::UnsafeLayout)?
            .parse::<u64>()
            .map_err(|_| SubordinateIdError::UnsafeLayout)?;
        let end = start
            .checked_add(count)
            .ok_or(SubordinateIdError::UnsafeLayout)?;
        if fields.next().is_some()
            || count == 0
            // Every entry is checked: a setuid mapping helper must never be able to map a reserved
            // host UID/GID through an unrelated account's subordinate range.
            || start < MIN_SUBORDINATE_ID_START
            || end > u64::from(u32::MAX) + 1
        {
            return Err(SubordinateIdError::UnsafeLayout);
        }
        ranges.push((start, end));
        if identity == daemon_user || identity == numeric_uid {
            total = total
                .checked_add(count)
                .ok_or(SubordinateIdError::UnsafeLayout)?;
        }
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(SubordinateIdError::UnsafeLayout);
    }
    if total < MIN_SUBORDINATE_IDS {
        return Err(SubordinateIdError::MissingDaemonRange);
    }
    Ok(())
}

fn read_kernel_switch(path: &Path) -> Result<u64, RootlessOciError> {
    let value = fs::read_to_string(path)?;
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error).into())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildkitConfig {
    root: String,
    #[serde(rename = "insecure-entitlements")]
    insecure_entitlements: Vec<String>,
    grpc: BuildkitGrpcConfig,
    cdi: BuildkitCdiConfig,
    history: BuildkitHistoryConfig,
    worker: BuildkitWorkerConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildkitGrpcConfig {
    address: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildkitCdiConfig {
    disabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildkitHistoryConfig {
    #[serde(rename = "maxAge")]
    max_age: u64,
    #[serde(rename = "maxEntries")]
    max_entries: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildkitWorkerConfig {
    oci: BuildkitOciWorkerConfig,
    containerd: BuildkitDisabledWorkerConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildkitDisabledWorkerConfig {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
// This mirrors BuildKit's external TOML shape; each switch is checked against the fixed policy.
#[allow(clippy::struct_excessive_bools)]
struct BuildkitOciWorkerConfig {
    enabled: bool,
    platforms: Vec<String>,
    snapshotter: String,
    rootless: bool,
    #[serde(rename = "noProcessSandbox")]
    no_process_sandbox: bool,
    gc: bool,
    #[serde(rename = "reservedSpace")]
    reserved_space: String,
    #[serde(rename = "maxUsedSpace")]
    max_used_space: String,
    #[serde(rename = "minFreeSpace")]
    min_free_space: String,
    binary: String,
    #[serde(rename = "max-parallelism")]
    max_parallelism: u16,
    #[serde(rename = "cniPoolSize")]
    cni_pool_size: u16,
    gcpolicy: Vec<BuildkitGcPolicy>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct BuildkitGcPolicy {
    #[serde(default)]
    all: bool,
    #[serde(default, rename = "keepDuration")]
    keep_duration: Option<String>,
    #[serde(default)]
    filters: Vec<String>,
    #[serde(rename = "reservedSpace")]
    reserved_space: String,
    #[serde(rename = "maxUsedSpace")]
    max_used_space: String,
    #[serde(rename = "minFreeSpace")]
    min_free_space: String,
}

fn verify_buildkit_config(bytes: &[u8], max_parallelism: u16) -> Result<(), RootlessOciError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "BuildKit config is not UTF-8"))?;
    let config: BuildkitConfig = toml::from_str(text)?;
    let expected_gc = vec![
        BuildkitGcPolicy {
            all: false,
            keep_duration: Some("24h".to_owned()),
            filters: vec![
                "type==source.local".to_owned(),
                "type==exec.cachemount".to_owned(),
            ],
            reserved_space: "256MB".to_owned(),
            max_used_space: "512MB".to_owned(),
            min_free_space: "4GB".to_owned(),
        },
        BuildkitGcPolicy {
            all: true,
            keep_duration: None,
            filters: Vec::new(),
            reserved_space: "256MB".to_owned(),
            max_used_space: "1536MB".to_owned(),
            min_free_space: "4GB".to_owned(),
        },
    ];
    if config.root != BUILDKIT_STATE_ROOT
        || !config.insecure_entitlements.is_empty()
        || config.grpc.address != [format!("unix://{BUILDKIT_SOCKET_PATH}")]
        || !config.cdi.disabled
        || config.history.max_age != 86_400
        || config.history.max_entries != 32
        || config.worker.containerd.enabled
        || !config.worker.oci.enabled
        || config.worker.oci.platforms != ["linux/amd64"]
        || config.worker.oci.snapshotter != "overlayfs"
        || !config.worker.oci.rootless
        || config.worker.oci.no_process_sandbox
        || !config.worker.oci.gc
        || config.worker.oci.reserved_space != "256MB"
        || config.worker.oci.max_used_space != "1536MB"
        || config.worker.oci.min_free_space != "4GB"
        || config.worker.oci.binary != BUILDKIT_RUNTIME_EXECUTABLE
        || config.worker.oci.max_parallelism != max_parallelism
        || config.worker.oci.cni_pool_size != 0
        || config.worker.oci.gcpolicy != expected_gc
    {
        return Err(RootlessOciError::InvalidConfig);
    }
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
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::tempdir;

    use super::*;

    #[derive(Clone, Debug)]
    struct FixedBoundaryProbe {
        snapshot: FilesystemBoundarySnapshot,
    }

    impl FilesystemBoundaryProbe for FixedBoundaryProbe {
        fn inspect(&self, _root: &Path) -> Result<FilesystemBoundarySnapshot, RootlessOciError> {
            Ok(self.snapshot)
        }
    }

    #[derive(Clone, Debug)]
    struct FixedSocketProbe {
        ready: bool,
    }

    impl SocketProbe for FixedSocketProbe {
        fn verify(
            &self,
            _path: &Path,
            _socket_owner_uid: u32,
            _client_group_gid: u32,
        ) -> Result<(), RootlessOciError> {
            if self.ready {
                Ok(())
            } else {
                Err(RootlessOciError::UnsafeSocket)
            }
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        layout: InstalledLayout,
        policy: RootlessOciRuntimePolicyV1,
        worker_uid: u32,
        job_account_uid: u32,
        shared_group_gid: u32,
    }

    fn create_tool(root: &Path, name: &str, body: &[u8]) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, body).expect("write tool");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("tool mode");
        path
    }

    fn create_installed_layout(root: &Path, trusted_uid: u32) -> (InstalledLayout, Vec<u8>) {
        let buildkitd = create_tool(root, "buildkitd", b"buildkitd");
        let buildctl = create_tool(root, "buildctl", b"buildctl");
        let rootlesskit = create_tool(root, "rootlesskit", b"rootlesskit");
        let runtime = create_tool(root, "runc", b"runc");
        let uid_mapping_helper = create_tool(root, "newuidmap", b"newuidmap");
        let gid_mapping_helper = create_tool(root, "newgidmap", b"newgidmap");
        fs::set_permissions(&uid_mapping_helper, fs::Permissions::from_mode(0o4755))
            .expect("newuidmap mode");
        fs::set_permissions(&gid_mapping_helper, fs::Permissions::from_mode(0o4755))
            .expect("newgidmap mode");

        let config = root.join("buildkitd.toml");
        let config_bytes = buildkit_config_fixture();
        fs::write(&config, &config_bytes).expect("write config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).expect("config mode");
        let subordinate_users_path = root.join("subuid");
        let subordinate_groups_path = root.join("subgid");
        for path in [&subordinate_users_path, &subordinate_groups_path] {
            fs::write(path, "rdashboard-buildkit:100000:65536\n").expect("write subid");
            fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("subid mode");
        }
        let max_user_namespaces = root.join("max_user_namespaces");
        let unprivileged_userns = root.join("unprivileged_userns_clone");
        let apparmor_userns = root.join("apparmor_restrict_unprivileged_userns");
        fs::write(&max_user_namespaces, b"65536\n").expect("max user namespaces");
        fs::write(&unprivileged_userns, b"1\n").expect("user namespace switch");
        fs::write(&apparmor_userns, b"0\n").expect("AppArmor switch");
        let storage_root = root.join("storage");
        let state_root = storage_root.join("buildkit");
        let runtime_root = root.join("run");
        fs::create_dir(&storage_root).expect("storage root");
        fs::create_dir(&state_root).expect("state root");
        fs::create_dir(&runtime_root).expect("runtime root");
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).expect("state mode");
        fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o750))
            .expect("runtime mode");
        let socket = runtime_root.join("buildkitd.sock");

        let layout = InstalledLayout {
            buildkitd,
            buildctl,
            rootlesskit,
            runtime,
            newuidmap: uid_mapping_helper,
            newgidmap: gid_mapping_helper,
            config,
            subuid: subordinate_users_path,
            subgid: subordinate_groups_path,
            max_user_namespaces,
            unprivileged_userns,
            apparmor_userns,
            storage_root,
            state_root,
            runtime_root,
            socket,
            trusted_uid,
            boundary_probe: Box::new(FixedBoundaryProbe {
                snapshot: FilesystemBoundarySnapshot {
                    total_bytes: 64 * 1024 * 1024 * 1024,
                    available_bytes: 32 * 1024 * 1024 * 1024,
                    total_inodes: 100_000,
                    available_inodes: 100_000,
                    root_available_bytes: 32 * 1024 * 1024 * 1024,
                },
            }),
            socket_probe: Box::new(FixedSocketProbe { ready: true }),
        };
        (layout, config_bytes)
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempdir().expect("temporary directory");
            let root = directory.path();
            let trusted_uid = fs::metadata(root).expect("root metadata").uid();
            let shared_group_gid = fs::metadata(root).expect("root metadata").gid();
            assert_ne!(trusted_uid, 0, "tests require an unprivileged owner");
            assert_ne!(shared_group_gid, 0, "tests require an unprivileged group");
            let worker_uid = trusted_uid.checked_add(1).expect("worker UID");
            let job_account_uid = trusted_uid.checked_add(2).expect("build UID");
            let daemon_uid = trusted_uid;
            let (layout, config_bytes) = create_installed_layout(root, trusted_uid);
            let policy = RootlessOciRuntimePolicyV1 {
                schema_version: ROOTLESS_OCI_POLICY_SCHEMA_VERSION,
                daemon_uid,
                daemon_user: "rdashboard-buildkit".to_owned(),
                buildkitd_sha256: EvidenceDigest::sha256(b"buildkitd"),
                buildctl_sha256: EvidenceDigest::sha256(b"buildctl"),
                rootlesskit_sha256: EvidenceDigest::sha256(b"rootlesskit"),
                runtime_sha256: EvidenceDigest::sha256(b"runc"),
                buildkit_config_sha256: EvidenceDigest::sha256(&config_bytes),
                max_parallelism: 1,
            };
            Self {
                _directory: directory,
                layout,
                policy,
                worker_uid,
                job_account_uid,
                shared_group_gid,
            }
        }

        fn verify(&self) -> Result<(), RootlessOciError> {
            self.policy.verify_layout(
                self.worker_uid,
                self.job_account_uid,
                self.shared_group_gid,
                &self.layout,
            )
        }
    }

    fn buildkit_config_fixture() -> Vec<u8> {
        include_bytes!("../deploy/systemd/rdashboard-buildkitd.toml").to_vec()
    }

    #[test]
    fn complete_rootless_runtime_is_required_before_activation() {
        let fixture = Fixture::new();
        fixture.verify().expect("complete runtime");

        fs::write(&fixture.layout.buildctl, b"substituted").expect("replace buildctl");
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::ToolDigestMismatch("buildctl"))
        ));
    }

    #[test]
    fn policy_requires_a_separate_single_parallelism_daemon() {
        let mut fixture = Fixture::new();
        fixture.policy.daemon_uid = fixture.job_account_uid;
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::InvalidPolicy)
        ));

        let mut fixture = Fixture::new();
        fixture.policy.daemon_user = "../buildkit".to_owned();
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::InvalidPolicy)
        ));

        let mut fixture = Fixture::new();
        fixture.policy.daemon_uid = fixture.layout.trusted_uid;
        fixture.policy.max_parallelism = 2;
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::InvalidPolicy)
        ));
    }

    #[test]
    fn unsafe_buildkit_features_and_shared_storage_regressions_fail_closed() {
        let mut fixture = Fixture::new();
        let unsafe_config = String::from_utf8(buildkit_config_fixture())
            .expect("UTF-8 config")
            .replace(
                "insecure-entitlements = []",
                "insecure-entitlements = [\"network.host\"]",
            );
        fs::write(&fixture.layout.config, unsafe_config.as_bytes()).expect("unsafe config");
        fixture.policy.buildkit_config_sha256 = EvidenceDigest::sha256(unsafe_config.as_bytes());
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::InvalidConfig)
        ));

        let mut fixture = Fixture::new();
        fixture.layout.boundary_probe = Box::new(FixedBoundaryProbe {
            snapshot: FilesystemBoundarySnapshot {
                total_bytes: 64 * 1024 * 1024 * 1024,
                available_bytes: 65 * 1024 * 1024 * 1024,
                total_inodes: 100_000,
                available_inodes: 100_000,
                root_available_bytes: 32 * 1024 * 1024 * 1024,
            },
        });
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::InvalidStateBoundary)
        ));

        let mut fixture = Fixture::new();
        fixture.layout.boundary_probe = Box::new(FixedBoundaryProbe {
            snapshot: FilesystemBoundarySnapshot {
                total_bytes: 64 * 1024 * 1024 * 1024,
                available_bytes: 32 * 1024 * 1024 * 1024,
                total_inodes: 100_000,
                available_inodes: 100_000,
                root_available_bytes: 19 * 1024 * 1024 * 1024,
            },
        });
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::RootEmergencyReserveViolated)
        ));
    }

    #[test]
    fn subordinate_ids_kernel_policy_and_live_socket_are_mandatory() {
        let fixture = Fixture::new();
        fs::write(
            &fixture.layout.subuid,
            b"rdashboard-buildkit:100000:65535\n",
        )
        .expect("short subuid");
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::InsufficientSubordinateIds("subuid"))
        ));

        let fixture = Fixture::new();
        fs::write(
            &fixture.layout.subuid,
            b"legacy-runtime:1000:100\nrdashboard-buildkit:100000:65536\n",
        )
        .expect("low unrelated subuid");
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::UnsafeSubordinateIdLayout("subuid"))
        ));

        let fixture = Fixture::new();
        fs::write(
            &fixture.layout.subuid,
            b"rdashboard-buildkit:100000:65536\nother:120000:65536\n",
        )
        .expect("overlapping subuid");
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::UnsafeSubordinateIdLayout("subuid"))
        ));

        let fixture = Fixture::new();
        fs::write(&fixture.layout.apparmor_userns, b"1\n").expect("block user namespaces");
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::ApparmorBlocksUserNamespaces)
        ));

        let mut fixture = Fixture::new();
        fixture.layout.socket_probe = Box::new(FixedSocketProbe { ready: false });
        assert!(matches!(
            fixture.verify(),
            Err(RootlessOciError::UnsafeSocket)
        ));

        let fixture = Fixture::new();
        fs::remove_file(&fixture.layout.unprivileged_userns)
            .expect("remove optional userns switch");
        fs::remove_file(&fixture.layout.apparmor_userns).expect("remove optional AppArmor switch");
        fixture
            .verify()
            .expect("missing optional kernel switches are accepted");
    }

    #[test]
    fn readiness_failure_is_canonical_and_actionable() {
        let failure = RootlessOciError::UnsafeTool("buildctl").failure();
        let encoded = failure.canonical_json().expect("canonical failure");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).expect("failure JSON")["reason_code"],
            "rootless_oci_tool_unsafe"
        );
        assert!(encoded.contains("install the reviewed root-owned BuildKit tool bundle"));

        let layout_failure = RootlessOciError::UnsafeSubordinateIdLayout("subuid").failure();
        assert_eq!(
            layout_failure.reason_code,
            "rootless_oci_subid_layout_unsafe"
        );
        assert!(layout_failure.remediation.contains("above 65535"));
    }
}
