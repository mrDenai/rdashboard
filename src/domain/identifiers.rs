use std::{fmt, str::FromStr};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};

pub(crate) const MAX_APPLICATION_SCHEMA_VERSION_BYTES: usize = 96;

pub(crate) fn valid_application_schema_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_APPLICATION_SCHEMA_VERSION_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProjectId(String);

impl ProjectId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(value: &str) -> bool {
        let bytes = value.as_bytes();
        (1..=64).contains(&bytes.len())
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    }
}

impl fmt::Display for ProjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ProjectId {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if Self::validate(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(IdentifierError::InvalidProjectId)
        }
    }
}

impl<'de> Deserialize<'de> for ProjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct GitCommitId(String);

impl GitCommitId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(value: &str) -> bool {
        matches!(value.len(), 40 | 64)
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    }
}

impl fmt::Display for GitCommitId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for GitCommitId {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if Self::validate(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(IdentifierError::InvalidGitCommit)
        }
    }
}

impl<'de> Deserialize<'de> for GitCommitId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EvidenceDigest(String);

impl EvidenceDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn sha256(value: impl AsRef<[u8]>) -> Self {
        let bytes = Sha256::digest(value.as_ref());
        let mut encoded = String::with_capacity(64);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        Self(encoded)
    }

    fn validate(value: &str) -> bool {
        value.len() == 64
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    }
}

impl fmt::Display for EvidenceDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for EvidenceDigest {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if Self::validate(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(IdentifierError::InvalidEvidenceDigest)
        }
    }
}

impl<'de> Deserialize<'de> for EvidenceDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RunbookId(String);

impl RunbookId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RunbookId {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if ProjectId::validate(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(IdentifierError::InvalidRunbookId)
        }
    }
}

impl<'de> Deserialize<'de> for RunbookId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdentifierError {
    #[error("project ID must be 1-64 lowercase ASCII letters, digits, or interior hyphens")]
    InvalidProjectId,
    #[error("Git commit must be a full lowercase 40- or 64-character hexadecimal ID")]
    InvalidGitCommit,
    #[error("evidence digest must be a lowercase 64-character hexadecimal value")]
    InvalidEvidenceDigest,
    #[error("runbook ID must follow the project-ID format")]
    InvalidRunbookId,
}

#[cfg(test)]
mod tests {
    use super::valid_application_schema_version;

    #[test]
    fn application_schema_versions_have_one_cross_contract_format() {
        assert!(valid_application_schema_version("rimg-schema-v1"));
        assert!(valid_application_schema_version("2026.07.15+sha.abcdef"));
        assert!(!valid_application_schema_version(""));
        assert!(!valid_application_schema_version("v1 beta"));
        assert!(!valid_application_schema_version("схема-v1"));
        assert!(!valid_application_schema_version(&"v".repeat(97)));
    }
}
