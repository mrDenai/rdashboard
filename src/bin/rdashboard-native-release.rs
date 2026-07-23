use std::{ffi::OsString, str::FromStr as _};

use rdashboard::{
    domain::EvidenceDigest,
    native_release::{
        ManagedNativeRuntimePolicyV1, NativeReleaseActivatorV1, NativeReleaseOutcomeV1,
        SystemdNativeReleaseRuntimeV1,
    },
    titanium::{TITANIUM_REGISTRY_ROOT, TitaniumRegistryV1},
    unix_time_ms,
};

const ROOT_UID: u32 = 0;
type DynError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), DynError> {
    if rustix::process::geteuid().as_raw() != ROOT_UID {
        return Err(NativeReleaseCommandError::RootRequired.into());
    }
    let command = Command::parse(std::env::args_os().skip(1).collect())?;
    if let Command::RenderPolicy { input } = &command {
        let policy = ManagedNativeRuntimePolicyV1::new(input.clone())?;
        println!("{}", String::from_utf8(policy.canonical_bytes()?)?);
        return Ok(());
    }
    let registry = TitaniumRegistryV1::open_existing(TITANIUM_REGISTRY_ROOT, ROOT_UID)?;
    match command {
        Command::Initialize { project_id } => {
            let policy = load_and_verify_policy(&project_id)?;
            NativeReleaseActivatorV1::initialize_installed_project(&policy)?;
        }
        Command::Activate {
            project_id,
            artifact_digest,
        } => {
            let policy = load_and_verify_policy(&project_id)?;
            let activator = NativeReleaseActivatorV1::open_installed(&registry, policy)?;
            let mut runtime = SystemdNativeReleaseRuntimeV1;
            print_outcome(activator.activate(&artifact_digest, &mut runtime, unix_time_ms()?)?);
        }
        Command::Recover { project_id } => {
            recover_project(&registry, &project_id)?;
        }
        Command::RecoverInstalled => {
            for project_id in NativeReleaseActivatorV1::installed_project_ids()? {
                recover_project(&registry, &project_id)?;
            }
        }
        Command::CollectViews { project_id } => {
            let policy = load_and_verify_policy(&project_id)?;
            let activator = NativeReleaseActivatorV1::open_installed(&registry, policy)?;
            println!("removed_views={}", activator.collect_unreferenced_views()?);
        }
        Command::CollectInstalledViews => {
            let mut removed = 0_u64;
            for project_id in NativeReleaseActivatorV1::installed_project_ids()? {
                let policy = load_and_verify_policy(&project_id)?;
                let activator = NativeReleaseActivatorV1::open_installed(&registry, policy)?;
                removed = removed.saturating_add(activator.collect_unreferenced_views()?);
            }
            println!("removed_views={removed}");
        }
        Command::RenderPolicy { .. } => unreachable!("rendering returned before registry access"),
    }
    Ok(())
}

fn load_and_verify_policy(project_id: &str) -> Result<ManagedNativeRuntimePolicyV1, DynError> {
    let policy = ManagedNativeRuntimePolicyV1::load_installed(project_id)?;
    SystemdNativeReleaseRuntimeV1::verify_installed(&policy)?;
    Ok(policy)
}

fn recover_project(registry: &TitaniumRegistryV1, project_id: &str) -> Result<(), DynError> {
    let policy = load_and_verify_policy(project_id)?;
    let activator = NativeReleaseActivatorV1::open_installed(registry, policy)?;
    let mut runtime = SystemdNativeReleaseRuntimeV1;
    if let Some(outcome) = activator.recover(&mut runtime, unix_time_ms()?)? {
        print_outcome(outcome);
    }
    Ok(())
}

fn print_outcome(outcome: NativeReleaseOutcomeV1) {
    let value = match outcome {
        NativeReleaseOutcomeV1::Activated => "activated",
        NativeReleaseOutcomeV1::RolledBack => "rolled_back",
        NativeReleaseOutcomeV1::RejectedFirstRelease => "rejected_first_release",
        NativeReleaseOutcomeV1::CandidateDiscarded => "candidate_discarded",
    };
    println!("{value}");
}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Initialize {
        project_id: String,
    },
    Activate {
        project_id: String,
        artifact_digest: EvidenceDigest,
    },
    Recover {
        project_id: String,
    },
    RecoverInstalled,
    CollectViews {
        project_id: String,
    },
    CollectInstalledViews,
    RenderPolicy {
        input: rdashboard::native_release::ManagedNativeRuntimePolicyInputV1,
    },
}

impl Command {
    fn parse(arguments: Vec<OsString>) -> Result<Self, NativeReleaseCommandError> {
        let arguments = arguments
            .into_iter()
            .map(|value| {
                value
                    .into_string()
                    .map_err(|_| NativeReleaseCommandError::InvalidInvocation)
            })
            .collect::<Result<Vec<_>, _>>()?;
        match arguments.as_slice() {
            [command, project_id] if command == "initialize" && valid_component(project_id) => {
                Ok(Self::Initialize {
                    project_id: project_id.clone(),
                })
            }
            [command, project_id, artifact_digest]
                if command == "activate" && valid_component(project_id) =>
            {
                Ok(Self::Activate {
                    project_id: project_id.clone(),
                    artifact_digest: EvidenceDigest::from_str(artifact_digest)
                        .map_err(|_| NativeReleaseCommandError::InvalidInvocation)?,
                })
            }
            [command, project_id] if command == "recover" && valid_component(project_id) => {
                Ok(Self::Recover {
                    project_id: project_id.clone(),
                })
            }
            [command] if command == "recover-installed" => Ok(Self::RecoverInstalled),
            [command, project_id] if command == "collect-views" && valid_component(project_id) => {
                Ok(Self::CollectViews {
                    project_id: project_id.clone(),
                })
            }
            [command] if command == "collect-installed-views" => Ok(Self::CollectInstalledViews),
            [
                command,
                project_id,
                target,
                release_interface,
                entrypoint,
                runtime_contract_digest,
                systemd_unit_sha256,
                health_url,
                health_expected_status,
                health_timeout_ms,
            ] if command == "render-policy"
                && valid_component(project_id)
                && valid_component(target)
                && valid_component(release_interface) =>
            {
                Ok(Self::RenderPolicy {
                    input: rdashboard::native_release::ManagedNativeRuntimePolicyInputV1 {
                        project_id: project_id.clone(),
                        target: target.clone(),
                        release_interface: release_interface.clone(),
                        entrypoint: entrypoint.clone(),
                        runtime_contract_digest: EvidenceDigest::from_str(runtime_contract_digest)
                            .map_err(|_| NativeReleaseCommandError::InvalidInvocation)?,
                        systemd_unit_sha256: EvidenceDigest::from_str(systemd_unit_sha256)
                            .map_err(|_| NativeReleaseCommandError::InvalidInvocation)?,
                        health_url: health_url.clone(),
                        health_expected_status: health_expected_status
                            .parse()
                            .map_err(|_| NativeReleaseCommandError::InvalidInvocation)?,
                        health_timeout_ms: health_timeout_ms
                            .parse()
                            .map_err(|_| NativeReleaseCommandError::InvalidInvocation)?,
                    },
                })
            }
            _ => Err(NativeReleaseCommandError::InvalidInvocation),
        }
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
enum NativeReleaseCommandError {
    #[error("rdashboard-native-release must run as root")]
    RootRequired,
    #[error("invalid invocation")]
    InvalidInvocation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_surface_has_no_caller_selected_paths_or_units() {
        let digest = EvidenceDigest::sha256("release");
        assert_eq!(
            Command::parse(
                ["activate", "rimg", digest.as_str()]
                    .into_iter()
                    .map(OsString::from)
                    .collect()
            )
            .expect("activation command"),
            Command::Activate {
                project_id: "rimg".to_owned(),
                artifact_digest: digest,
            }
        );
        assert!(Command::parse(vec![OsString::from("recover-installed")]).is_ok());
        assert!(
            Command::parse(
                ["recover", "rimg+blue"]
                    .into_iter()
                    .map(OsString::from)
                    .collect()
            )
            .is_ok()
        );
        assert!(
            Command::parse(
                ["activate", "../rimg", &"a".repeat(64)]
                    .into_iter()
                    .map(OsString::from)
                    .collect()
            )
            .is_err()
        );
    }
}
