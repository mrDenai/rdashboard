use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs::{self, File},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rdashboard::{
    domain::{EvidenceDigest, InstalledPolicyIdentity, ProjectId, ReleaseClass},
    installed_source::{
        InstalledSourceConfigInputV1, InstalledSourceConfigV1, InstalledSourceGitSshV1,
        InstalledSourceGithubWebhookV1, InstalledSourceProjectInputV1, InstalledSourceProjectV1,
        load_installed_source_config,
    },
    installed_workflow::InstalledWorkflowCatalogV1,
};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

const ATTESTATION_SEED_PATH: &str = "/etc/rdashboard/credentials/source-attestation-seed";
const SOURCE_CONTROLS_PATH: &str = "/etc/rdashboard/source-projects.jcs";
const SOURCE_CREDENTIAL_ROOT: &str = "/etc/rdashboard/credentials";
const SOURCE_CONTROLS_SCHEMA_VERSION: u16 = 1;
const MAX_PRIVATE_INPUT_BYTES: u64 = 64 * 1024;
const MAX_WEBHOOK_SECRET_BYTES: u64 = 4 * 1024;
const MAX_PROJECTS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Arguments {
    source_uid: u32,
    ingress_uid: u32,
    ingress_gid: u32,
    controller_uid: u32,
    controller_gid: u32,
    build_reader_gid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Command {
    Build(Arguments),
    CanonicalizeControls,
    SystemdCredentials,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceProjectControlsCatalogV1 {
    purpose: String,
    schema_version: u16,
    projects: Vec<SourceProjectControlV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceProjectControlV1 {
    project_id: ProjectId,
    installed_policy_version: u64,
    auto_deploy: bool,
    maximum_attempts: u32,
    release_class: ReleaseClass,
}

impl SourceProjectControlsCatalogV1 {
    fn validate(&self) -> Result<(), std::io::Error> {
        if self.purpose != "rdashboard.source-project-controls.v1"
            || self.schema_version != SOURCE_CONTROLS_SCHEMA_VERSION
            || self.projects.is_empty()
            || self.projects.len() > MAX_PROJECTS
        {
            return Err(invalid_input("source project controls are invalid"));
        }
        let mut projects = BTreeSet::new();
        for project in &self.projects {
            if project.installed_policy_version == 0
                || !(1..=10).contains(&project.maximum_attempts)
                || project.release_class == ReleaseClass::Rollback
                || !projects.insert(project.project_id.clone())
            {
                return Err(invalid_input("source project controls are invalid"));
            }
        }
        Ok(())
    }

    fn by_project(&self) -> BTreeMap<ProjectId, &SourceProjectControlV1> {
        self.projects
            .iter()
            .map(|project| (project.project_id.clone(), project))
            .collect()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_arguments = std::env::args().collect::<Vec<_>>();
    match parse_command(&raw_arguments)? {
        Command::Build(arguments) => {
            let workflows =
                InstalledWorkflowCatalogV1::load_root_owned_for_group(arguments.controller_gid)?;
            let controls = load_controls(Path::new(SOURCE_CONTROLS_PATH))?;
            let attestation_seed = Zeroizing::new(read_root_private_file(
                Path::new(ATTESTATION_SEED_PATH),
                32,
            )?);
            let config = build_config(
                &arguments,
                &workflows,
                &controls,
                &attestation_seed,
                |path| {
                    let maximum = if path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("source-webhook-"))
                    {
                        MAX_WEBHOOK_SECRET_BYTES
                    } else {
                        MAX_PRIVATE_INPUT_BYTES
                    };
                    read_root_private_file(path, maximum)
                },
            )?;
            std::io::stdout().write_all(&serde_jcs::to_vec(&config)?)?;
        }
        Command::SystemdCredentials => {
            let config = load_installed_source_config()?;
            std::io::stdout().write_all(render_systemd_credentials(&config)?.as_bytes())?;
        }
        Command::CanonicalizeControls => {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(MAX_PRIVATE_INPUT_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.is_empty()
                || bytes.len() > usize::try_from(MAX_PRIVATE_INPUT_BYTES).unwrap_or(usize::MAX)
            {
                return Err(invalid_input("source project controls input is oversized").into());
            }
            let controls = decode_controls(&bytes)?;
            std::io::stdout().write_all(&serde_jcs::to_vec(&controls)?)?;
        }
    }
    Ok(())
}

fn parse_command(values: &[String]) -> Result<Command, std::io::Error> {
    if values.len() == 2 && values[1] == "systemd-credentials" {
        return Ok(Command::SystemdCredentials);
    }
    if values.len() == 2 && values[1] == "canonicalize-controls" {
        return Ok(Command::CanonicalizeControls);
    }
    if values.len() != 8 || values[1] != "build" {
        return Err(invalid_input(
            "usage: rdashboard-source-config build SOURCE_UID INGRESS_UID INGRESS_GID CONTROLLER_UID CONTROLLER_GID BUILD_READER_GID | rdashboard-source-config canonicalize-controls | rdashboard-source-config systemd-credentials",
        ));
    }
    let parse_identity = |value: &str, name: &str| {
        value
            .parse::<u32>()
            .map_err(|_| invalid_input(&format!("{name} must be a decimal u32")))
            .and_then(|identity| {
                if identity == 0 || identity == u32::MAX {
                    Err(invalid_input(&format!(
                        "{name} must be a non-root identity"
                    )))
                } else {
                    Ok(identity)
                }
            })
    };
    let arguments = Arguments {
        source_uid: parse_identity(&values[2], "SOURCE_UID")?,
        ingress_uid: parse_identity(&values[3], "INGRESS_UID")?,
        ingress_gid: parse_identity(&values[4], "INGRESS_GID")?,
        controller_uid: parse_identity(&values[5], "CONTROLLER_UID")?,
        controller_gid: parse_identity(&values[6], "CONTROLLER_GID")?,
        build_reader_gid: parse_identity(&values[7], "BUILD_READER_GID")?,
    };
    if arguments.source_uid == arguments.ingress_uid
        || arguments.source_uid == arguments.controller_uid
        || arguments.ingress_uid == arguments.controller_uid
    {
        return Err(invalid_input(
            "source, ingress and controller UIDs must be distinct",
        ));
    }
    Ok(Command::Build(arguments))
}

fn load_controls(path: &Path) -> Result<SourceProjectControlsCatalogV1, std::io::Error> {
    let bytes = read_root_private_file(path, MAX_PRIVATE_INPUT_BYTES)?;
    let controls = decode_controls(&bytes)?;
    if serde_jcs::to_vec(&controls)
        .map_err(|error| invalid_input(&format!("encode source project controls: {error}")))?
        != bytes
    {
        return Err(invalid_input(
            "source project controls must use canonical JCS encoding",
        ));
    }
    Ok(controls)
}

fn decode_controls(bytes: &[u8]) -> Result<SourceProjectControlsCatalogV1, std::io::Error> {
    let controls: SourceProjectControlsCatalogV1 = serde_json::from_slice(bytes)
        .map_err(|error| invalid_input(&format!("decode source project controls: {error}")))?;
    controls.validate()?;
    Ok(controls)
}

fn build_config<F>(
    arguments: &Arguments,
    workflows: &InstalledWorkflowCatalogV1,
    controls: &SourceProjectControlsCatalogV1,
    attestation_seed: &[u8],
    mut read_credential: F,
) -> Result<InstalledSourceConfigV1, std::io::Error>
where
    F: FnMut(&Path) -> Result<Vec<u8>, std::io::Error>,
{
    controls.validate()?;
    let mut seed: [u8; 32] = attestation_seed
        .try_into()
        .map_err(|_| invalid_input("source attestation seed must contain exactly 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let controls_by_project = controls.by_project();
    if workflows.projects().len() != controls_by_project.len()
        || controls_by_project
            .keys()
            .any(|project_id| workflows.project(project_id).is_none())
    {
        return Err(invalid_input(
            "source controls must exactly cover the installed workflow catalog",
        ));
    }

    let mut projects = Vec::with_capacity(workflows.projects().len());
    for workflow in workflows.projects() {
        let manifest = &workflow.manifest;
        let control = controls_by_project
            .get(&manifest.project_id)
            .ok_or_else(|| invalid_input("installed workflow project lacks source controls"))?;
        let remote_url = manifest.source.remote_url.clone();
        let git_ssh = if Url::parse(remote_url.as_str()).is_ok_and(|url| url.scheme() == "ssh") {
            let private_key_path = credential_path(&manifest.project_id, "git", "private-key");
            let known_hosts_path = credential_path(&manifest.project_id, "git", "known-hosts");
            let private_key = Zeroizing::new(read_credential(&private_key_path)?);
            let known_hosts = Zeroizing::new(read_credential(&known_hosts_path)?);
            let binding = InstalledSourceGitSshV1::new(
                &manifest.project_id,
                EvidenceDigest::sha256(private_key.as_slice()),
                EvidenceDigest::sha256(known_hosts.as_slice()),
            );
            Some(binding)
        } else {
            None
        };
        let webhook_secret_path = credential_path(&manifest.project_id, "webhook", "secret");
        let webhook_secret = Zeroizing::new(read_credential(&webhook_secret_path)?);
        if webhook_secret.len() < 16 {
            return Err(invalid_input(
                "each GitHub webhook secret must contain at least 16 bytes",
            ));
        }
        let webhook = InstalledSourceGithubWebhookV1::new(
            &manifest.project_id,
            &remote_url,
            EvidenceDigest::sha256(webhook_secret.as_slice()),
        )
        .map_err(|error| invalid_input(&error.to_string()))?;
        projects.push(
            InstalledSourceProjectV1::new(InstalledSourceProjectInputV1 {
                project_id: manifest.project_id.clone(),
                remote_url,
                git_ssh,
                github_webhook: webhook,
                installed_policy: InstalledPolicyIdentity {
                    digest: workflow.workflow_policy_digest.clone(),
                    version: control.installed_policy_version,
                },
                auto_deploy: control.auto_deploy,
                maximum_attempts: control.maximum_attempts,
                release_class: control.release_class,
            })
            .map_err(|error| invalid_input(&error.to_string()))?,
        );
    }

    let public_key = signing_key.verifying_key().to_bytes();
    let public_key_digest = EvidenceDigest::sha256(public_key);
    InstalledSourceConfigV1::new(InstalledSourceConfigInputV1 {
        source_uid: arguments.source_uid,
        ingress_uid: arguments.ingress_uid,
        ingress_gid: arguments.ingress_gid,
        controller_uid: arguments.controller_uid,
        controller_gid: arguments.controller_gid,
        build_reader_gid: arguments.build_reader_gid,
        max_connections: 16,
        request_timeout_ms: 2_000,
        reconcile_interval_ms: 30_000,
        attestation_ttl_ms: 120_000,
        attestation_key_id: format!("source-{}", &public_key_digest.as_str()[..16]),
        attestation_public_key: URL_SAFE_NO_PAD.encode(public_key),
        projects,
    })
    .map_err(|error| invalid_input(&error.to_string()))
}

fn credential_path(project_id: &ProjectId, purpose: &str, name: &str) -> PathBuf {
    Path::new(SOURCE_CREDENTIAL_ROOT).join(format!("source-{purpose}-{project_id}-{name}"))
}

fn render_systemd_credentials(config: &InstalledSourceConfigV1) -> Result<String, std::io::Error> {
    config
        .validate()
        .map_err(|error| invalid_input(&error.to_string()))?;
    let mut output = String::from(
        "[Service]\nLoadCredential=source-attestation-seed:/etc/rdashboard/credentials/source-attestation-seed\n",
    );
    for project in &config.projects {
        if let Some(git_ssh) = &project.git_ssh {
            writeln!(
                output,
                "LoadCredential={}:/etc/rdashboard/credentials/{}",
                git_ssh.private_key_credential, git_ssh.private_key_credential
            )
            .map_err(|_| invalid_input("render systemd credential drop-in"))?;
            writeln!(
                output,
                "LoadCredential={}:/etc/rdashboard/credentials/{}",
                git_ssh.known_hosts_credential, git_ssh.known_hosts_credential
            )
            .map_err(|_| invalid_input("render systemd credential drop-in"))?;
        }
        writeln!(
            output,
            "LoadCredential={}:/etc/rdashboard/credentials/{}",
            project.github_webhook.secret_credential, project.github_webhook.secret_credential
        )
        .map_err(|_| invalid_input("render systemd credential drop-in"))?;
    }
    Ok(output)
}

fn read_root_private_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, std::io::Error> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_input("credential path has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    let path_metadata = fs::symlink_metadata(path)?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.permissions().mode() & 0o022 != 0
        || path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != 0
        || path_metadata.permissions().mode() & 0o077 != 0
        || path_metadata.len() == 0
        || path_metadata.len() > maximum_bytes
    {
        return Err(invalid_input(
            "input is not a stable root-owned private file",
        ));
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(invalid_input("input changed while it was opened"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    if let Err(error) = file
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
    {
        bytes.zeroize();
        return Err(error);
    }
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
        || bytes.len() != usize::try_from(opened_metadata.len()).unwrap_or(usize::MAX)
    {
        bytes.zeroize();
        return Err(invalid_input("input changed while it was read"));
    }
    Ok(bytes)
}

fn invalid_input(detail: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdashboard::domain::{ProjectManifestV2, RemoteUrl};
    use std::str::FromStr as _;

    fn arguments() -> Arguments {
        Arguments {
            source_uid: 991,
            ingress_uid: 992,
            ingress_gid: 992,
            controller_uid: 993,
            controller_gid: 993,
            build_reader_gid: 994,
        }
    }

    fn workflow_catalog() -> InstalledWorkflowCatalogV1 {
        let ralert: ProjectManifestV2 =
            serde_json::from_str(include_str!("../../config/project-manifests/ralert.json"))
                .expect("ralert manifest");
        let mut rimg = ralert.clone();
        rimg.project_id = ProjectId::from_str("rimg").expect("rimg project");
        rimg.display_name = "rimg".to_owned();
        rimg.source.remote_url =
            RemoteUrl::from_str("ssh://git@github.com/mrDenai/rimg.git").expect("rimg remote");
        InstalledWorkflowCatalogV1::from_manifests([ralert, rimg]).expect("workflow catalog")
    }

    fn controls() -> SourceProjectControlsCatalogV1 {
        SourceProjectControlsCatalogV1 {
            purpose: "rdashboard.source-project-controls.v1".to_owned(),
            schema_version: 1,
            projects: vec![
                SourceProjectControlV1 {
                    project_id: ProjectId::from_str("ralert").expect("ralert project"),
                    installed_policy_version: 1,
                    auto_deploy: false,
                    maximum_attempts: 3,
                    release_class: ReleaseClass::StatefulCompatible,
                },
                SourceProjectControlV1 {
                    project_id: ProjectId::from_str("rimg").expect("rimg project"),
                    installed_policy_version: 4,
                    auto_deploy: false,
                    maximum_attempts: 2,
                    release_class: ReleaseClass::CodeOnlyCompatible,
                },
            ],
        }
    }

    #[test]
    fn repository_source_controls_render_canonically_and_cover_the_current_catalog() {
        let bytes = include_bytes!("../../config/source-projects.json");
        let controls: SourceProjectControlsCatalogV1 =
            serde_json::from_slice(bytes).expect("repository source controls");
        controls.validate().expect("valid source controls");
        let canonical = serde_jcs::to_vec(&controls).expect("canonical source controls");
        let decoded: SourceProjectControlsCatalogV1 =
            serde_json::from_slice(&canonical).expect("decode canonical source controls");
        assert_eq!(decoded, controls);
        let manifest: ProjectManifestV2 =
            serde_json::from_str(include_str!("../../config/project-manifests/ralert.json"))
                .expect("ralert manifest");
        let workflows =
            InstalledWorkflowCatalogV1::from_manifests([manifest]).expect("workflow catalog");
        let config = build_config(&arguments(), &workflows, &controls, &[61_u8; 32], |path| {
            assert_eq!(
                path.file_name().and_then(|name| name.to_str()),
                Some("source-webhook-ralert-secret")
            );
            Ok(b"ralert webhook secret".to_vec())
        })
        .expect("source config from repository controls");
        assert_eq!(config.projects.len(), 1);
        assert_eq!(config.projects[0].project_id.as_str(), "ralert");
        assert!(!config.projects[0].auto_deploy);
    }

    #[test]
    fn installed_workflow_catalog_generates_all_projects_without_serializing_secrets() {
        let seed = [61_u8; 32];
        let config = build_config(
            &arguments(),
            &workflow_catalog(),
            &controls(),
            &seed,
            |path| {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("name");
                Ok(match name {
                    "source-git-rimg-private-key" => b"private rimg key bytes".to_vec(),
                    "source-git-rimg-known-hosts" => {
                        b"github.com ssh-ed25519 aG9zdGtleQ==\n".to_vec()
                    }
                    "source-webhook-ralert-secret" => b"ralert webhook secret".to_vec(),
                    "source-webhook-rimg-secret" => b"rimg webhook secret!!".to_vec(),
                    other => panic!("unexpected credential {other}"),
                })
            },
        )
        .expect("build source config");
        let encoded = serde_jcs::to_vec(&config).expect("canonical config");
        let text = String::from_utf8(encoded).expect("UTF-8 config");

        assert_eq!(config.projects.len(), 2);
        assert_eq!(config.reconcile_interval_ms, 30_000);
        assert_eq!(config.projects[0].project_id.as_str(), "ralert");
        assert_eq!(config.projects[1].project_id.as_str(), "rimg");
        assert_eq!(
            config.projects[1].github_webhook.repository_full_name,
            "mrDenai/rimg"
        );
        assert!(!text.contains("private rimg key bytes"));
        assert!(!text.contains("webhook secret"));
        assert!(!text.contains(&URL_SAFE_NO_PAD.encode(seed)));
        assert!(text.contains("source-git-rimg-private-key"));
        assert!(text.contains("source-webhook-ralert-secret"));
        assert!(config.projects.iter().all(|project| !project.auto_deploy));

        let drop_in = render_systemd_credentials(&config).expect("credential drop-in");
        assert!(drop_in.starts_with("[Service]\nLoadCredential=source-attestation-seed:"));
        assert!(drop_in.contains("source-git-rimg-private-key"));
        assert!(drop_in.contains("source-webhook-ralert-secret"));
        assert!(drop_in.contains("source-webhook-rimg-secret"));
        assert!(!drop_in.contains("ralert webhook secret"));
    }

    #[test]
    fn controls_must_exactly_cover_workflows_and_keep_credentials_distinct() {
        let workflows = workflow_catalog();
        let mut incomplete = controls();
        incomplete.projects.pop();
        assert!(
            build_config(&arguments(), &workflows, &incomplete, &[61_u8; 32], |_| {
                unreachable!("mismatched catalogs fail before reading credentials")
            })
            .is_err()
        );

        let result = build_config(
            &arguments(),
            &workflows,
            &controls(),
            &[61_u8; 32],
            |path| {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("name");
                Ok(if name.contains("known-hosts") {
                    b"github.com ssh-ed25519 aG9zdGtleQ==\n".to_vec()
                } else if name.contains("private-key") {
                    b"private rimg key bytes".to_vec()
                } else {
                    b"same webhook secret".to_vec()
                })
            },
        );
        assert!(
            result.is_err(),
            "webhook secrets must be unique per project"
        );
    }

    #[test]
    fn arguments_reject_missing_invalid_or_colliding_identity_values() {
        assert_eq!(
            parse_command(&["tool".to_owned(), "systemd-credentials".to_owned()])
                .expect("credential mode"),
            Command::SystemdCredentials
        );
        assert_eq!(
            parse_command(&["tool".to_owned(), "canonicalize-controls".to_owned()])
                .expect("canonical controls mode"),
            Command::CanonicalizeControls
        );
        for values in [
            vec!["tool".to_owned()],
            vec![
                "tool".to_owned(),
                "build".to_owned(),
                "0".to_owned(),
                "992".to_owned(),
                "992".to_owned(),
                "993".to_owned(),
                "993".to_owned(),
                "994".to_owned(),
            ],
            vec![
                "tool".to_owned(),
                "build".to_owned(),
                "991".to_owned(),
                "991".to_owned(),
                "992".to_owned(),
                "993".to_owned(),
                "993".to_owned(),
                "994".to_owned(),
            ],
        ] {
            assert!(parse_command(&values).is_err());
        }
    }
}
