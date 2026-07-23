use std::{
    ffi::OsString,
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    str::FromStr as _,
};

use rdashboard::{
    build_storage::SHARED_TITANIUM_IMPORT_ROOT,
    domain::EvidenceDigest,
    titanium::{
        TITANIUM_REGISTRY_ROOT, TitaniumAcquisitionClassV1, TitaniumArtifactKindV1,
        TitaniumArtifactSpecV1, TitaniumRegistryV1,
    },
};

const ROOT_UID: u32 = 0;
type DynError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), DynError> {
    if rustix::process::geteuid().as_raw() != ROOT_UID {
        return Err(TitaniumCommandError::RootRequired.into());
    }
    let command = Command::parse(std::env::args_os().skip(1).collect())?;
    let registry = TitaniumRegistryV1::open_for_owner(TITANIUM_REGISTRY_ROOT, ROOT_UID)?;
    execute(command, &registry)
}

fn execute(command: Command, registry: &TitaniumRegistryV1) -> Result<(), DynError> {
    match command {
        Command::ImportToolchain {
            root_name,
            target,
            acquisition,
            provenance_digest,
            source_name,
            dependencies,
        } => {
            let source = sealed_import_source(&source_name)?;
            let artifact = registry.publish_installed_toolchain(
                &source,
                root_name,
                acquisition,
                target,
                dependencies,
                provenance_digest,
            )?;
            println!("{}", artifact.artifact_digest.as_str());
        }
        Command::ImportArtifact {
            root_name,
            target,
            kind,
            acquisition,
            provenance_digest,
            source_name,
            dependencies,
        } => {
            let source = sealed_import_source(&source_name)?;
            let artifact = registry.publish_installed_artifact(
                &source,
                root_name,
                TitaniumArtifactSpecV1 {
                    kind,
                    acquisition,
                    target,
                    dependencies,
                    provenance_digest,
                },
            )?;
            println!("{}", artifact.artifact_digest.as_str());
        }
        Command::ImportRelease {
            target,
            provenance_digest,
            source_name,
            dependencies,
        } => {
            let source = sealed_import_source(&source_name)?;
            let artifact = registry.publish_candidate_release(
                &source,
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::Release,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target,
                    dependencies,
                    provenance_digest,
                },
            )?;
            println!("{}", artifact.artifact_digest.as_str());
        }
        Command::DiscardRelease { artifact_digest } => {
            registry.discard_candidate_release(&artifact_digest)?;
        }
        Command::InspectToolchain {
            root_name,
            target,
            interface,
        } => {
            let artifact = registry.installed_artifact(
                &root_name,
                TitaniumArtifactKindV1::CompilerToolchain,
                &target,
                &interface,
            )?;
            println!("{}", artifact.artifact_digest.as_str());
        }
        Command::InspectArtifact {
            root_name,
            target,
            kind,
        } => {
            let artifact = registry.installed_named_artifact(&root_name, kind, &target)?;
            println!("{}", artifact.artifact_digest.as_str());
        }
        Command::CollectGarbage => {
            let report = registry.collect_garbage()?;
            println!(
                "removed_trees={} removed_artifacts={} removed_actions={} removed_staging={}",
                report.removed_trees,
                report.removed_artifacts,
                report.removed_actions,
                report.removed_staging_entries
            );
        }
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    ImportToolchain {
        root_name: String,
        target: String,
        acquisition: TitaniumAcquisitionClassV1,
        provenance_digest: EvidenceDigest,
        source_name: String,
        dependencies: Vec<EvidenceDigest>,
    },
    ImportArtifact {
        root_name: String,
        target: String,
        kind: TitaniumArtifactKindV1,
        acquisition: TitaniumAcquisitionClassV1,
        provenance_digest: EvidenceDigest,
        source_name: String,
        dependencies: Vec<EvidenceDigest>,
    },
    ImportRelease {
        target: String,
        provenance_digest: EvidenceDigest,
        source_name: String,
        dependencies: Vec<EvidenceDigest>,
    },
    DiscardRelease {
        artifact_digest: EvidenceDigest,
    },
    InspectToolchain {
        root_name: String,
        target: String,
        interface: String,
    },
    InspectArtifact {
        root_name: String,
        target: String,
        kind: TitaniumArtifactKindV1,
    },
    CollectGarbage,
}

impl Command {
    fn parse(arguments: Vec<OsString>) -> Result<Self, TitaniumCommandError> {
        let arguments = string_arguments(arguments)?;
        match arguments.as_slice() {
            [
                command,
                root_name,
                target,
                acquisition,
                provenance_digest,
                source_name,
                dependencies @ ..,
            ] if command == "import-toolchain"
                && valid_component(root_name)
                && valid_component(target)
                && valid_component(source_name) =>
            {
                Ok(Self::ImportToolchain {
                    root_name: root_name.clone(),
                    target: target.clone(),
                    acquisition: parse_acquisition(acquisition)?,
                    provenance_digest: EvidenceDigest::from_str(provenance_digest)
                        .map_err(|_| TitaniumCommandError::InvalidInvocation)?,
                    source_name: source_name.clone(),
                    dependencies: parse_dependencies(dependencies)?,
                })
            }
            [
                command,
                target,
                provenance_digest,
                source_name,
                dependencies @ ..,
            ] if command == "import-release"
                && valid_component(target)
                && valid_component(source_name) =>
            {
                Ok(Self::ImportRelease {
                    target: target.clone(),
                    provenance_digest: EvidenceDigest::from_str(provenance_digest)
                        .map_err(|_| TitaniumCommandError::InvalidInvocation)?,
                    source_name: source_name.clone(),
                    dependencies: parse_dependencies(dependencies)?,
                })
            }
            [
                command,
                root_name,
                target,
                kind,
                acquisition,
                provenance_digest,
                source_name,
                dependencies @ ..,
            ] if command == "import-artifact"
                && valid_component(root_name)
                && valid_component(target)
                && valid_component(source_name) =>
            {
                Ok(Self::ImportArtifact {
                    root_name: root_name.clone(),
                    target: target.clone(),
                    kind: parse_import_kind(kind)?,
                    acquisition: parse_acquisition(acquisition)?,
                    provenance_digest: EvidenceDigest::from_str(provenance_digest)
                        .map_err(|_| TitaniumCommandError::InvalidInvocation)?,
                    source_name: source_name.clone(),
                    dependencies: parse_dependencies(dependencies)?,
                })
            }
            [command, root_name, target, interface]
                if command == "inspect-toolchain"
                    && valid_component(root_name)
                    && valid_component(target)
                    && valid_component(interface) =>
            {
                Ok(Self::InspectToolchain {
                    root_name: root_name.clone(),
                    target: target.clone(),
                    interface: interface.clone(),
                })
            }
            [command, root_name, target, kind]
                if command == "inspect-artifact"
                    && valid_component(root_name)
                    && valid_component(target) =>
            {
                Ok(Self::InspectArtifact {
                    root_name: root_name.clone(),
                    target: target.clone(),
                    kind: parse_import_kind(kind)?,
                })
            }
            [command] if command == "gc" => Ok(Self::CollectGarbage),
            [command, artifact_digest] if command == "discard-release" => {
                Ok(Self::DiscardRelease {
                    artifact_digest: EvidenceDigest::from_str(artifact_digest)
                        .map_err(|_| TitaniumCommandError::InvalidInvocation)?,
                })
            }
            _ => Err(TitaniumCommandError::InvalidInvocation),
        }
    }
}

fn string_arguments(arguments: Vec<OsString>) -> Result<Vec<String>, TitaniumCommandError> {
    arguments
        .into_iter()
        .map(|value| {
            value
                .into_string()
                .map_err(|_| TitaniumCommandError::InvalidInvocation)
        })
        .collect()
}

fn sealed_import_source(name: &str) -> Result<PathBuf, TitaniumCommandError> {
    if !valid_component(name) {
        return Err(TitaniumCommandError::InvalidInvocation);
    }
    let root = Path::new(SHARED_TITANIUM_IMPORT_ROOT);
    let root_metadata = fs::symlink_metadata(root).map_err(TitaniumCommandError::Io)?;
    if !root_metadata.is_dir()
        || root_metadata.file_type().is_symlink()
        || root_metadata.uid() != ROOT_UID
        || root_metadata.permissions().mode() & 0o7777 != 0o711
    {
        return Err(TitaniumCommandError::UnsafeImport);
    }
    let source = root.join(name);
    let metadata = fs::symlink_metadata(&source).map_err(TitaniumCommandError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != ROOT_UID
        || metadata.permissions().mode() & 0o7777 != 0o555
    {
        return Err(TitaniumCommandError::UnsafeImport);
    }
    Ok(source)
}

fn parse_import_kind(value: &str) -> Result<TitaniumArtifactKindV1, TitaniumCommandError> {
    match value {
        "build-tool" => Ok(TitaniumArtifactKindV1::BuildTool),
        "runtime-library" => Ok(TitaniumArtifactKindV1::RuntimeLibrary),
        "runtime-support" => Ok(TitaniumArtifactKindV1::RuntimeSupport),
        _ => Err(TitaniumCommandError::InvalidInvocation),
    }
}

fn parse_dependencies(values: &[String]) -> Result<Vec<EvidenceDigest>, TitaniumCommandError> {
    let dependencies = values
        .iter()
        .map(|value| {
            EvidenceDigest::from_str(value).map_err(|_| TitaniumCommandError::InvalidInvocation)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !dependencies.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(TitaniumCommandError::InvalidInvocation);
    }
    Ok(dependencies)
}

fn parse_acquisition(value: &str) -> Result<TitaniumAcquisitionClassV1, TitaniumCommandError> {
    match value {
        "verified-upstream-prebuilt" => Ok(TitaniumAcquisitionClassV1::VerifiedUpstreamPrebuilt),
        "controlled-source-build" => Ok(TitaniumAcquisitionClassV1::ControlledSourceBuild),
        _ => Err(TitaniumCommandError::InvalidInvocation),
    }
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

#[derive(Debug, thiserror::Error)]
enum TitaniumCommandError {
    #[error("rdashboard-titanium must run as root")]
    RootRequired,
    #[error("invalid invocation")]
    InvalidInvocation,
    #[error("Titanium import source must be a sealed root-owned directory")]
    UnsafeImport,
    #[error("Titanium import source inspection failed: {0}")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_surface_accepts_only_fixed_registry_operations_and_relative_source_names() {
        let digest = EvidenceDigest::sha256("provenance");
        let import = Command::parse(
            [
                "import-toolchain",
                "rust-production-linux-x86_64",
                "linux-x86_64",
                "controlled-source-build",
                digest.as_str(),
                "rust-1.96-linux-x86_64",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
        )
        .expect("parse import");
        assert!(matches!(import, Command::ImportToolchain { .. }));
        assert!(matches!(
            Command::parse(
                [
                    "import-release",
                    "linux-x86_64",
                    digest.as_str(),
                    "rimg-release-a",
                ]
                .into_iter()
                .map(OsString::from)
                .collect(),
            ),
            Ok(Command::ImportRelease { .. })
        ));
        assert!(Command::parse(vec![OsString::from("gc")]).is_ok());
        assert!(matches!(
            Command::parse(
                ["discard-release", digest.as_str()]
                    .into_iter()
                    .map(OsString::from)
                    .collect(),
            ),
            Ok(Command::DiscardRelease { .. })
        ));
        assert!(
            Command::parse(
                [
                    "import-toolchain",
                    "rust-production-linux-x86_64",
                    "linux-x86_64",
                    "controlled-source-build",
                    digest.as_str(),
                    "../outside",
                ]
                .into_iter()
                .map(OsString::from)
                .collect(),
            )
            .is_err()
        );
    }
}
