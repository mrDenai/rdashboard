use std::{
    fs::{self, File},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    str::FromStr as _,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rdashboard::{
    domain::{EvidenceDigest, InstalledPolicyIdentity, ProjectId, ReleaseClass, RemoteUrl},
    installed_source::{
        InstalledSourceConfigInputV1, InstalledSourceConfigV1, InstalledSourceGitSshV1,
        InstalledSourceProjectV1,
    },
};
use zeroize::Zeroize as _;

const ATTESTATION_SEED_PATH: &str = "/etc/rdashboard/credentials/source-attestation-seed";
const RIMG_PRIVATE_KEY_PATH: &str = "/etc/rdashboard/credentials/source-git-rimg-private-key";
const RIMG_KNOWN_HOSTS_PATH: &str = "/etc/rdashboard/credentials/source-git-rimg-known-hosts";
const MAX_PRIVATE_INPUT_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Arguments {
    source_uid: u32,
    controller_uid: u32,
    controller_gid: u32,
    build_reader_gid: u32,
    installed_policy_digest: EvidenceDigest,
    installed_policy_version: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_arguments = std::env::args().collect::<Vec<_>>();
    let arguments = parse_arguments(&raw_arguments)?;
    let mut attestation_seed = read_root_private_file(Path::new(ATTESTATION_SEED_PATH), 32)?;
    let mut private_key =
        read_root_private_file(Path::new(RIMG_PRIVATE_KEY_PATH), MAX_PRIVATE_INPUT_BYTES)?;
    let known_hosts =
        read_root_private_file(Path::new(RIMG_KNOWN_HOSTS_PATH), MAX_PRIVATE_INPUT_BYTES)?;
    let result = build_config(&arguments, &attestation_seed, &private_key, &known_hosts);
    attestation_seed.zeroize();
    private_key.zeroize();
    let config = result?;
    std::io::stdout().write_all(&serde_jcs::to_vec(&config)?)?;
    Ok(())
}

fn parse_arguments(values: &[String]) -> Result<Arguments, std::io::Error> {
    if values.len() != 7 {
        return Err(invalid_input(
            "usage: rdashboard-source-config SOURCE_UID CONTROLLER_UID CONTROLLER_GID BUILD_READER_GID INSTALLED_POLICY_SHA256 INSTALLED_POLICY_VERSION",
        ));
    }
    let arguments = Arguments {
        source_uid: values[1]
            .parse()
            .map_err(|_| invalid_input("SOURCE_UID must be a decimal u32"))?,
        controller_uid: values[2]
            .parse()
            .map_err(|_| invalid_input("CONTROLLER_UID must be a decimal u32"))?,
        controller_gid: values[3]
            .parse()
            .map_err(|_| invalid_input("CONTROLLER_GID must be a decimal u32"))?,
        build_reader_gid: values[4]
            .parse()
            .map_err(|_| invalid_input("BUILD_READER_GID must be a decimal u32"))?,
        installed_policy_digest: EvidenceDigest::from_str(&values[5])
            .map_err(|_| invalid_input("INSTALLED_POLICY_SHA256 must be lowercase SHA-256"))?,
        installed_policy_version: values[6]
            .parse()
            .map_err(|_| invalid_input("INSTALLED_POLICY_VERSION must be a decimal u64"))?,
    };
    if arguments.source_uid == 0
        || arguments.controller_uid == 0
        || arguments.controller_gid == 0
        || arguments.build_reader_gid == 0
        || arguments.installed_policy_version == 0
        || arguments.source_uid == u32::MAX
        || arguments.controller_uid == u32::MAX
        || arguments.controller_gid == u32::MAX
        || arguments.build_reader_gid == u32::MAX
    {
        return Err(invalid_input(
            "numeric identities and policy version must be nonzero",
        ));
    }
    Ok(arguments)
}

fn build_config(
    arguments: &Arguments,
    attestation_seed: &[u8],
    private_key: &[u8],
    known_hosts: &[u8],
) -> Result<InstalledSourceConfigV1, std::io::Error> {
    let mut seed: [u8; 32] = attestation_seed
        .try_into()
        .map_err(|_| invalid_input("source attestation seed must contain exactly 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let project_id = ProjectId::from_str("rimg").map_err(|_| invalid_input("invalid project"))?;
    let git_ssh = InstalledSourceGitSshV1::new(
        &project_id,
        EvidenceDigest::sha256(private_key),
        EvidenceDigest::sha256(known_hosts),
    );
    let project = InstalledSourceProjectV1::new(
        project_id,
        RemoteUrl::from_str("ssh://git@github.com/mrDenai/rimg.git")
            .map_err(|_| invalid_input("invalid fixed rimg remote"))?,
        Some(git_ssh),
        InstalledPolicyIdentity {
            digest: arguments.installed_policy_digest.clone(),
            version: arguments.installed_policy_version,
        },
        false,
        3,
        ReleaseClass::StatefulCompatible,
    )
    .map_err(|error| invalid_input(&error.to_string()))?;
    let public_key = signing_key.verifying_key().to_bytes();
    let public_key_digest = EvidenceDigest::sha256(public_key);
    InstalledSourceConfigV1::new(InstalledSourceConfigInputV1 {
        source_uid: arguments.source_uid,
        controller_uid: arguments.controller_uid,
        controller_gid: arguments.controller_gid,
        build_reader_gid: arguments.build_reader_gid,
        max_connections: 16,
        request_timeout_ms: 2_000,
        reconcile_interval_ms: 60_000,
        attestation_ttl_ms: 120_000,
        attestation_key_id: format!("source-rimg-{}", &public_key_digest.as_str()[..16]),
        attestation_public_key: URL_SAFE_NO_PAD.encode(public_key),
        projects: vec![project],
    })
    .map_err(|error| invalid_input(&error.to_string()))
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
            "credential is not a stable root-owned private file",
        ));
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(invalid_input("credential changed while it was opened"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
        || bytes.len() != usize::try_from(opened_metadata.len()).unwrap_or(usize::MAX)
    {
        bytes.zeroize();
        return Err(invalid_input("credential changed while it was read"));
    }
    Ok(bytes)
}

fn invalid_input(detail: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Arguments {
        Arguments {
            source_uid: 991,
            controller_uid: 993,
            controller_gid: 993,
            build_reader_gid: 992,
            installed_policy_digest: EvidenceDigest::sha256("installed policy"),
            installed_policy_version: 1,
        }
    }

    #[test]
    fn fixed_rimg_config_is_canonical_secret_free_and_per_project_credential_bound() {
        let seed = [61_u8; 32];
        let private_key = b"private key bytes that must not enter config";
        let known_hosts = b"github.com ssh-ed25519 aG9zdGtleQ==\n";
        let config = build_config(&arguments(), &seed, private_key, known_hosts)
            .expect("build source config");
        let encoded = serde_jcs::to_vec(&config).expect("canonical config");
        let text = String::from_utf8(encoded).expect("UTF-8 config");

        assert!(!text.contains("private key bytes"));
        assert!(!text.contains(&URL_SAFE_NO_PAD.encode(seed)));
        assert!(text.contains("ssh://git@github.com/mrDenai/rimg.git"));
        assert!(text.contains("source-git-rimg-private-key"));
        assert!(text.contains(EvidenceDigest::sha256(private_key).as_str()));
        assert!(text.contains(EvidenceDigest::sha256(known_hosts).as_str()));
        assert!(!config.projects[0].auto_deploy);
    }

    #[test]
    fn arguments_reject_missing_invalid_or_zero_identity_values() {
        for values in [
            vec!["tool".to_owned()],
            vec![
                "tool".to_owned(),
                "0".to_owned(),
                "993".to_owned(),
                "993".to_owned(),
                "992".to_owned(),
                EvidenceDigest::sha256("policy").to_string(),
                "1".to_owned(),
            ],
            vec![
                "tool".to_owned(),
                "991".to_owned(),
                "993".to_owned(),
                "993".to_owned(),
                "992".to_owned(),
                "not-a-digest".to_owned(),
                "1".to_owned(),
            ],
        ] {
            assert!(parse_arguments(&values).is_err());
        }
    }
}
