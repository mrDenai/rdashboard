use std::path::Path;

use crate::{
    phase6::{InstalledRimgPolicyV1, Phase6ContractError},
    rimg_adapter::{RimgAdapterError, runtime::read_stable_private_file},
};

pub const INSTALLED_RIMG_POLICY_PATH: &str =
    "/etc/rdashboard/projects/rimg/installed-rimg-policy.jcs";

const MAX_INSTALLED_POLICY_BYTES: u64 = 512 * 1024;

pub fn load_installed_rimg_policy() -> Result<InstalledRimgPolicyV1, InstalledPolicyLoadError> {
    load_installed_rimg_policy_from(Path::new(INSTALLED_RIMG_POLICY_PATH), 0)
}

pub(crate) fn load_installed_rimg_policy_from(
    path: &Path,
    required_uid: u32,
) -> Result<InstalledRimgPolicyV1, InstalledPolicyLoadError> {
    let bytes = read_stable_private_file(path, required_uid, MAX_INSTALLED_POLICY_BYTES)?;
    Ok(InstalledRimgPolicyV1::decode_canonical(&bytes)?)
}

#[derive(Debug, thiserror::Error)]
pub enum InstalledPolicyLoadError {
    #[error(transparent)]
    Runtime(#[from] RimgAdapterError),
    #[error(transparent)]
    Contract(#[from] Phase6ContractError),
}
