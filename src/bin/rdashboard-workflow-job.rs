use std::{
    fs::{self, DirBuilder},
    io,
    os::unix::{
        fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
        process::CommandExt as _,
    },
    path::{Path, PathBuf},
    process::Command,
};

const WORKSPACE_ROOT: &str = "/workspace";
const JOB_ROOT: &str = "/job";

fn main() -> Result<(), WorkflowJobError> {
    let mut arguments = std::env::args_os();
    let _executable = arguments.next();
    let adapter = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(WorkflowJobError::InvalidInvocation)?;
    if arguments.next().is_some() {
        return Err(WorkflowJobError::InvalidInvocation);
    }
    validate_job_root(Path::new(JOB_ROOT))?;
    for directory in ["tmp", "target", "cargo-home", "ccache", "ccache-tmp"] {
        create_private_job_directory(&Path::new(JOB_ROOT).join(directory))?;
    }
    let script = match adapter.as_str() {
        "bare-bin-ci-v1" => Path::new(WORKSPACE_ROOT).join("bin/ci"),
        "native-release-build-v1" => Path::new(WORKSPACE_ROOT).join("bin/build-release"),
        "oci-release-build-v1" => Path::new(WORKSPACE_ROOT).join("bin/build-oci-release"),
        _ => return Err(WorkflowJobError::UnsupportedAdapter),
    };
    validate_fixed_script(&script)?;
    let error = Command::new(&script).exec();
    Err(WorkflowJobError::Exec {
        path: script,
        source: error,
    })
}

fn validate_job_root(path: &Path) -> Result<(), WorkflowJobError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.uid() == 0
        || metadata.gid() == 0
    {
        return Err(WorkflowJobError::UnsafeJobRoot);
    }
    Ok(())
}

fn create_private_job_directory(path: &Path) -> Result<(), WorkflowJobError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.uid() == 0
        || metadata.gid() == 0
    {
        return Err(WorkflowJobError::UnsafeJobDirectory);
    }
    Ok(())
}

fn validate_fixed_script(path: &Path) -> Result<(), WorkflowJobError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| WorkflowJobError::Script {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.len() == 0
    {
        return Err(WorkflowJobError::UnsafeScript(path.to_owned()));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum WorkflowJobError {
    #[error("workflow job accepts exactly one fixed adapter ID")]
    InvalidInvocation,
    #[error("workflow job adapter is not installed")]
    UnsupportedAdapter,
    #[error("workflow job scratch root is unsafe")]
    UnsafeJobRoot,
    #[error("workflow job scratch directory is unsafe")]
    UnsafeJobDirectory,
    #[error("workflow job script {0} is unsafe")]
    UnsafeScript(PathBuf),
    #[error("workflow job script {path} could not be inspected: {source}")]
    Script { path: PathBuf, source: io::Error },
    #[error("workflow job script {path} could not be executed: {source}")]
    Exec { path: PathBuf, source: io::Error },
    #[error("workflow job filesystem operation failed: {0}")]
    Io(#[from] io::Error),
}
