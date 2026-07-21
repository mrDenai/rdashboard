use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write as _},
    os::unix::{
        fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        process::CommandExt as _,
    },
    path::{Path, PathBuf},
    process::Command,
};

use rdashboard::cargo_prefetch::{
    CARGO_DEPENDENCY_MANIFEST_FILE, CARGO_VENDOR_DIRECTORY, CargoDependencyManifestV1,
    CargoPrefetchError,
};

const PREPARED_ROOT: &str = "/prepared";
const PREPARED_SOURCE_ROOT: &str = "/prepared/source";
const DEPENDENCY_ROOT: &str = "/dependencies";
#[cfg(test)]
const PREPARED_RUN_COMPOSITION_FILE: &str = ".rdashboard-prepared-run.jcs";
const JOB_ROOT: &str = "/job";
const WORKSPACE_ROOT: &str = "/job/workspace";
const CARGO_HOME_ROOT: &str = "/job/cargo-home";
const CARGO_VENDOR_CONFIG: &[u8] = b"[source.crates-io]\nreplace-with = \"rdashboard_vendor\"\n\n[source.rdashboard_vendor]\ndirectory = \"/dependencies/vendor\"\n\n[net]\noffline = true\n";
const MAX_DEPENDENCY_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_WORKSPACE_FILES: u64 = 100_000;
const MAX_WORKSPACE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

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
    validate_read_only_root(Path::new(PREPARED_ROOT))?;
    validate_read_only_root(Path::new(PREPARED_SOURCE_ROOT))?;
    validate_read_only_root(Path::new(DEPENDENCY_ROOT))?;
    for directory in [
        "tmp",
        "target",
        "cargo-home",
        "ccache",
        "ccache-tmp",
        "workspace",
    ] {
        create_private_job_directory(&Path::new(JOB_ROOT).join(directory))?;
    }
    copy_prepared_workspace(Path::new(PREPARED_SOURCE_ROOT), Path::new(WORKSPACE_ROOT))?;
    let cargo_vendor =
        configure_cargo_dependency(Path::new(DEPENDENCY_ROOT), Path::new(CARGO_HOME_ROOT))?;
    std::env::set_current_dir(WORKSPACE_ROOT)?;
    let script = match adapter.as_str() {
        "bare-bin-ci-v1" => Path::new(WORKSPACE_ROOT).join("bin/ci"),
        "native-release-build-v1" => Path::new(WORKSPACE_ROOT).join("bin/build-release"),
        "oci-release-build-v1" => Path::new(WORKSPACE_ROOT).join("bin/build-oci-release"),
        _ => return Err(WorkflowJobError::UnsupportedAdapter),
    };
    validate_fixed_script(&script)?;
    let mut command = Command::new(&script);
    if cargo_vendor {
        command
            .env("CARGO_SOURCE_CRATES_IO_REPLACE_WITH", "rdashboard_vendor")
            .env(
                "CARGO_SOURCE_RDASHBOARD_VENDOR_DIRECTORY",
                "/dependencies/vendor",
            )
            .env("CARGO_NET_OFFLINE", "true");
    }
    let error = command.exec();
    Err(WorkflowJobError::Exec {
        path: script,
        source: error,
    })
}

fn configure_cargo_dependency(
    dependency_root: &Path,
    cargo_home: &Path,
) -> Result<bool, WorkflowJobError> {
    let manifest_path = dependency_root.join(CARGO_DEPENDENCY_MANIFEST_FILE);
    let vendor_path = dependency_root.join(CARGO_VENDOR_DIRECTORY);
    let manifest_metadata = match fs::symlink_metadata(&manifest_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if fs::symlink_metadata(&vendor_path).is_ok() {
                return Err(WorkflowJobError::UnsafeDependencyInput);
            }
            return Ok(false);
        }
        Err(error) => return Err(error.into()),
    };
    if manifest_metadata.file_type().is_symlink()
        || !manifest_metadata.file_type().is_file()
        || manifest_metadata.nlink() != 1
        || manifest_metadata.permissions().mode() & 0o7777 != 0o444
        || manifest_metadata.len() == 0
        || manifest_metadata.len() > MAX_DEPENDENCY_MANIFEST_BYTES
    {
        return Err(WorkflowJobError::UnsafeDependencyInput);
    }
    let manifest_bytes = fs::read(&manifest_path)?;
    if u64::try_from(manifest_bytes.len()).ok() != Some(manifest_metadata.len()) {
        return Err(WorkflowJobError::UnsafeDependencyInput);
    }
    CargoDependencyManifestV1::decode_canonical(&manifest_bytes)?;
    validate_read_only_root(&vendor_path).map_err(|_| WorkflowJobError::UnsafeDependencyInput)?;

    let config_path = cargo_home.join("config.toml");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut config = options.open(config_path)?;
    config.write_all(CARGO_VENDOR_CONFIG)?;
    config.flush()?;
    Ok(true)
}

fn validate_read_only_root(path: &Path) -> Result<(), WorkflowJobError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o555
    {
        return Err(WorkflowJobError::UnsafePreparedRoot(path.to_owned()));
    }
    Ok(())
}

fn copy_prepared_workspace(source: &Path, destination: &Path) -> Result<(), WorkflowJobError> {
    if fs::read_dir(destination)?.next().is_some() {
        return Err(WorkflowJobError::UnsafeJobDirectory);
    }
    let mut pending = vec![(source.to_owned(), destination.to_owned())];
    let mut copied_entries = 0_u64;
    let mut copied_bytes = 0_u64;
    while let Some((source_directory, destination_directory)) = pending.pop() {
        let mut entries = fs::read_dir(&source_directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let source_path = entry.path();
            let destination_path = destination_directory.join(entry.file_name());
            let before = fs::symlink_metadata(&source_path)?;
            copied_entries = copied_entries
                .checked_add(1)
                .ok_or(WorkflowJobError::WorkspaceLimitExceeded)?;
            if copied_entries > MAX_WORKSPACE_FILES {
                return Err(WorkflowJobError::WorkspaceLimitExceeded);
            }
            if before.file_type().is_symlink() {
                return Err(WorkflowJobError::UnsupportedPreparedEntry(source_path));
            }
            if before.file_type().is_dir() {
                if before.permissions().mode() & 0o7777 != 0o555 {
                    return Err(WorkflowJobError::UnsupportedPreparedEntry(source_path));
                }
                create_private_job_directory(&destination_path)?;
                pending.push((source_path, destination_path));
                continue;
            }
            if !before.file_type().is_file()
                || before.nlink() != 1
                || !matches!(before.permissions().mode() & 0o7777, 0o444 | 0o555)
            {
                return Err(WorkflowJobError::UnsupportedPreparedEntry(source_path));
            }
            copied_bytes = copied_bytes
                .checked_add(before.len())
                .ok_or(WorkflowJobError::WorkspaceLimitExceeded)?;
            if copied_bytes > MAX_WORKSPACE_BYTES {
                return Err(WorkflowJobError::WorkspaceLimitExceeded);
            }
            copy_regular_file(&source_path, &destination_path, &before)?;
        }
    }
    Ok(())
}

fn copy_regular_file(
    source: &Path,
    destination: &Path,
    before: &fs::Metadata,
) -> Result<(), WorkflowJobError> {
    let mut input = File::open(source)?;
    let opened = input.metadata()?;
    if !same_file(before, &opened) {
        return Err(WorkflowJobError::PreparedInputChanged(source.to_owned()));
    }
    let mut output_options = OpenOptions::new();
    output_options.write(true).create_new(true).mode(0o600);
    let mut output = output_options.open(destination)?;
    let copied = io::copy(&mut input, &mut output)?;
    let after = fs::symlink_metadata(source)?;
    if copied != opened.len() || !same_file(&opened, &after) {
        return Err(WorkflowJobError::PreparedInputChanged(source.to_owned()));
    }
    output.set_permissions(fs::Permissions::from_mode(
        if before.permissions().mode() & 0o111 == 0 {
            0o600
        } else {
            0o700
        },
    ))?;
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
    #[error("workflow job sealed input root {0} is unsafe")]
    UnsafePreparedRoot(PathBuf),
    #[error("workflow job sealed input contains an unsupported entry at {0}")]
    UnsupportedPreparedEntry(PathBuf),
    #[error("workflow job sealed input changed while it was copied from {0}")]
    PreparedInputChanged(PathBuf),
    #[error("workflow job writable workspace exceeds its fixed source boundary")]
    WorkspaceLimitExceeded,
    #[error("workflow job sealed dependency input is unsafe")]
    UnsafeDependencyInput,
    #[error("workflow job script {0} is unsafe")]
    UnsafeScript(PathBuf),
    #[error("workflow job script {path} could not be inspected: {source}")]
    Script { path: PathBuf, source: io::Error },
    #[error("workflow job script {path} could not be executed: {source}")]
    Exec { path: PathBuf, source: io::Error },
    #[error("workflow job filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("workflow job Cargo dependency manifest failed: {0}")]
    CargoDependency(#[from] CargoPrefetchError),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn sealed_source_is_copied_into_one_private_writable_workspace() {
        let directory = tempdir().expect("temporary directory");
        let prepared = directory.path().join("prepared");
        let source = prepared.join("source");
        let destination = directory.path().join("workspace");
        fs::create_dir(&prepared).expect("create prepared root");
        fs::create_dir(&source).expect("create source");
        fs::write(
            prepared.join(PREPARED_RUN_COMPOSITION_FILE),
            b"internal composition",
        )
        .expect("write internal composition");
        fs::create_dir(source.join("bin")).expect("create source bin");
        fs::write(source.join("bin/ci"), b"#!/bin/sh\nexit 0\n").expect("write script");
        fs::write(source.join("Cargo.lock"), b"version = 4\n").expect("write lockfile");
        fs::set_permissions(source.join("bin/ci"), fs::Permissions::from_mode(0o555))
            .expect("seal script");
        fs::set_permissions(source.join("Cargo.lock"), fs::Permissions::from_mode(0o444))
            .expect("seal lockfile");
        fs::set_permissions(source.join("bin"), fs::Permissions::from_mode(0o555))
            .expect("seal bin directory");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o555)).expect("seal source");
        fs::set_permissions(
            prepared.join(PREPARED_RUN_COMPOSITION_FILE),
            fs::Permissions::from_mode(0o444),
        )
        .expect("seal internal composition");
        fs::set_permissions(&prepared, fs::Permissions::from_mode(0o555))
            .expect("seal prepared root");
        fs::create_dir(&destination).expect("create destination");
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
            .expect("protect destination");

        validate_read_only_root(&prepared).expect("validate prepared root");
        validate_read_only_root(&source).expect("validate sealed source");
        copy_prepared_workspace(&source, &destination).expect("copy sealed source");

        assert_eq!(
            fs::read(destination.join("Cargo.lock")).expect("read copied lockfile"),
            b"version = 4\n"
        );
        assert_eq!(
            fs::metadata(destination.join("Cargo.lock"))
                .expect("copied lockfile metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(destination.join("bin/ci"))
                .expect("copied script metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert!(!destination.join(PREPARED_RUN_COMPOSITION_FILE).exists());
    }

    #[test]
    fn workspace_copy_rejects_links_and_nonempty_destinations() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("prepared");
        let destination = directory.path().join("workspace");
        fs::create_dir(&source).expect("create source");
        fs::write(source.join("input"), b"exact").expect("write input");
        fs::hard_link(source.join("input"), source.join("hard-link")).expect("create hard link");
        symlink("input", source.join("symbolic-link")).expect("create symbolic link");
        fs::set_permissions(source.join("input"), fs::Permissions::from_mode(0o444))
            .expect("seal input");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o555)).expect("seal source");
        fs::create_dir(&destination).expect("create destination");
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
            .expect("protect destination");

        assert!(matches!(
            copy_prepared_workspace(&source, &destination),
            Err(WorkflowJobError::UnsupportedPreparedEntry(_))
        ));

        let clean_source = directory.path().join("clean-prepared");
        fs::create_dir(&clean_source).expect("create clean source");
        fs::write(clean_source.join("input"), b"exact").expect("write clean input");
        fs::set_permissions(
            clean_source.join("input"),
            fs::Permissions::from_mode(0o444),
        )
        .expect("seal clean input");
        fs::set_permissions(&clean_source, fs::Permissions::from_mode(0o555))
            .expect("seal clean source");
        fs::write(destination.join("unexpected"), b"state").expect("dirty destination");
        assert!(matches!(
            copy_prepared_workspace(&clean_source, &destination),
            Err(WorkflowJobError::UnsafeJobDirectory)
        ));
    }

    #[test]
    fn cargo_dependency_config_requires_a_canonical_manifest_and_sealed_vendor() {
        let directory = tempdir().expect("temporary directory");
        let dependency = directory.path().join("dependency");
        let cargo_home = directory.path().join("cargo-home");
        fs::create_dir(&dependency).expect("create dependency root");
        fs::create_dir(&cargo_home).expect("create Cargo home");
        let lock = b"version = 4\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n";
        let plan = rdashboard::cargo_prefetch::CargoLockPlanV1::parse(lock).expect("lock plan");
        let manifest = CargoDependencyManifestV1::new(
            &plan,
            rdashboard::domain::EvidenceDigest::sha256("workflow policy"),
        )
        .expect("dependency manifest");
        fs::write(
            dependency.join(CARGO_DEPENDENCY_MANIFEST_FILE),
            manifest.canonical_bytes().expect("canonical manifest"),
        )
        .expect("write manifest");
        fs::create_dir(dependency.join(CARGO_VENDOR_DIRECTORY)).expect("create vendor");
        fs::set_permissions(
            dependency.join(CARGO_DEPENDENCY_MANIFEST_FILE),
            fs::Permissions::from_mode(0o444),
        )
        .expect("seal manifest");
        fs::set_permissions(
            dependency.join(CARGO_VENDOR_DIRECTORY),
            fs::Permissions::from_mode(0o555),
        )
        .expect("seal vendor");

        assert!(
            configure_cargo_dependency(&dependency, &cargo_home).expect("configure vendored Cargo")
        );
        assert_eq!(
            fs::read(cargo_home.join("config.toml")).expect("Cargo config"),
            CARGO_VENDOR_CONFIG
        );

        let invalid_dependency = directory.path().join("invalid-dependency");
        let other_cargo_home = directory.path().join("other-cargo-home");
        fs::create_dir(&invalid_dependency).expect("create invalid dependency");
        fs::create_dir(invalid_dependency.join(CARGO_VENDOR_DIRECTORY))
            .expect("create unbound vendor");
        fs::create_dir(&other_cargo_home).expect("create other Cargo home");
        assert!(matches!(
            configure_cargo_dependency(&invalid_dependency, &other_cargo_home),
            Err(WorkflowJobError::UnsafeDependencyInput)
        ));
    }
}
