use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::domain::{EvidenceDigest, WorkflowOciBaseInputV1, WorkflowOciDigest};

pub const OCI_MANIFEST_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const OCI_BLOB_MAX_BYTES: u64 = 128 * 1024 * 1024;
const OCI_BASE_PLAN_PURPOSE: &str = "rdashboard.oci-base-plan.v1";
const OCI_LAYOUT_VERSION: &str = "1.0.0";
const MAX_LAYERS: usize = 256;
const OCI_LAYOUT_MAX_INODES_PER_BASE: u64 = MAX_LAYERS as u64 + 7;

pub fn maximum_oci_base_inodes(base_count: usize) -> Result<u64, OciBaseError> {
    if base_count > 16 {
        return Err(OciBaseError::InvalidBasePlan);
    }
    u64::try_from(base_count)
        .map_err(|_| OciBaseError::PayloadTooLarge)?
        .checked_mul(OCI_LAYOUT_MAX_INODES_PER_BASE)
        .and_then(|inodes| inodes.checked_add(u64::from(base_count != 0)))
        .ok_or(OciBaseError::PayloadTooLarge)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OciRegistryObjectKindV1 {
    Manifest,
    Blob,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OciRegistryObjectV1 {
    pub repository: String,
    pub digest: WorkflowOciDigest,
    pub kind: OciRegistryObjectKindV1,
    pub maximum_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_bytes: Option<u64>,
}

impl OciRegistryObjectV1 {
    pub fn manifest(base: &WorkflowOciBaseInputV1) -> Self {
        Self {
            repository: base.repository().to_owned(),
            digest: base.manifest_digest.clone(),
            kind: OciRegistryObjectKindV1::Manifest,
            maximum_bytes: OCI_MANIFEST_MAX_BYTES,
            expected_bytes: None,
        }
    }

    fn blob(repository: &str, descriptor: &OciDescriptor) -> Result<Self, OciBaseError> {
        let expected_bytes = descriptor.size;
        let object = Self {
            repository: repository.to_owned(),
            digest: descriptor.digest.clone(),
            kind: OciRegistryObjectKindV1::Blob,
            maximum_bytes: expected_bytes.min(OCI_BLOB_MAX_BYTES),
            expected_bytes: Some(expected_bytes),
        };
        object.validate()?;
        Ok(object)
    }

    pub fn validate(&self) -> Result<(), OciBaseError> {
        if !valid_repository(&self.repository)
            || self.maximum_bytes == 0
            || self.maximum_bytes > OCI_BLOB_MAX_BYTES
            || (self.kind == OciRegistryObjectKindV1::Manifest
                && (self.maximum_bytes > OCI_MANIFEST_MAX_BYTES || self.expected_bytes.is_some()))
            || self
                .expected_bytes
                .is_some_and(|bytes| bytes == 0 || bytes > self.maximum_bytes)
        {
            return Err(OciBaseError::InvalidRegistryObject);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct OciBasePlanPayload<'a> {
    purpose: &'static str,
    bases: &'a [WorkflowOciBaseInputV1],
}

pub fn oci_base_plan_digest(
    bases: &[WorkflowOciBaseInputV1],
) -> Result<Option<EvidenceDigest>, OciBaseError> {
    validate_bases(bases)?;
    if bases.is_empty() {
        return Ok(None);
    }
    Ok(Some(EvidenceDigest::sha256(serde_jcs::to_vec(
        &OciBasePlanPayload {
            purpose: OCI_BASE_PLAN_PURPOSE,
            bases,
        },
    )?)))
}

pub fn materialize_oci_base_layouts<F, E, C>(
    payload: &Path,
    bases: &[WorkflowOciBaseInputV1],
    maximum_payload_bytes: u64,
    maximum_payload_inodes: u64,
    mut fetch: F,
    mut cancelled: C,
) -> Result<(), OciBaseError>
where
    F: FnMut(&OciRegistryObjectV1) -> Result<Vec<u8>, E>,
    E: std::fmt::Display,
    C: FnMut() -> bool,
{
    validate_bases(bases)?;
    if bases.is_empty() {
        return Ok(());
    }
    let (mut used_bytes, mut used_inodes) = inspect_existing_payload(payload)?;
    let layouts_root = payload.join("oci-layouts");
    create_directory(&layouts_root)?;
    used_inodes = used_inodes
        .checked_add(1)
        .ok_or(OciBaseError::PayloadTooLarge)?;
    check_budget(
        used_bytes,
        used_inodes,
        maximum_payload_bytes,
        maximum_payload_inodes,
    )?;

    for base in bases {
        ensure_not_cancelled(&mut cancelled)?;
        let manifest_object = OciRegistryObjectV1::manifest(base);
        let manifest = fetch_verified(&manifest_object, &mut fetch)?;
        let parsed = parse_manifest(&manifest)?;
        let descriptors = unique_descriptors(&parsed)?;
        let layout_document = serde_jcs::to_vec(&OciLayoutDocument {
            image_layout_version: OCI_LAYOUT_VERSION,
        })?;
        let index_document = serde_jcs::to_vec(&OciIndexDocument {
            schema_version: 2,
            manifests: vec![OciIndexDescriptor {
                media_type: parsed.media_type.clone(),
                digest: base.manifest_digest.clone(),
                size: u64::try_from(manifest.len()).map_err(|_| OciBaseError::PayloadTooLarge)?,
                platform: OciPlatform {
                    architecture: "amd64",
                    os: "linux",
                },
            }],
        })?;
        check_planned_base_budget(
            (used_bytes, used_inodes),
            [&manifest, &layout_document, &index_document],
            descriptors.values(),
            (maximum_payload_bytes, maximum_payload_inodes),
        )?;
        let layout = layouts_root.join(&base.layout_name);
        create_directory(&layout)?;
        let blobs = layout.join("blobs");
        create_directory(&blobs)?;
        let sha256 = blobs.join("sha256");
        create_directory(&sha256)?;
        used_inodes = used_inodes
            .checked_add(3)
            .ok_or(OciBaseError::PayloadTooLarge)?;

        write_blob(&sha256, &base.manifest_digest, &manifest)?;
        add_usage(&mut used_bytes, &mut used_inodes, manifest.len())?;
        check_budget(
            used_bytes,
            used_inodes,
            maximum_payload_bytes,
            maximum_payload_inodes,
        )?;

        for descriptor in descriptors.into_values() {
            ensure_not_cancelled(&mut cancelled)?;
            let object = OciRegistryObjectV1::blob(base.repository(), &descriptor)?;
            let bytes = fetch_verified(&object, &mut fetch)?;
            if descriptor.digest == parsed.config.digest {
                validate_config(&bytes)?;
            }
            write_blob(&sha256, &descriptor.digest, &bytes)?;
            add_usage(&mut used_bytes, &mut used_inodes, bytes.len())?;
            check_budget(
                used_bytes,
                used_inodes,
                maximum_payload_bytes,
                maximum_payload_inodes,
            )?;
        }

        write_new_file(&layout.join("oci-layout"), &layout_document)?;
        write_new_file(&layout.join("index.json"), &index_document)?;
        add_usage(&mut used_bytes, &mut used_inodes, layout_document.len())?;
        add_usage(&mut used_bytes, &mut used_inodes, index_document.len())?;
        check_budget(
            used_bytes,
            used_inodes,
            maximum_payload_bytes,
            maximum_payload_inodes,
        )?;
    }
    Ok(())
}

pub fn validate_oci_layout(layout: &Path, expected_manifest: &str) -> Result<(), OciBaseError> {
    let expected_manifest: WorkflowOciDigest = expected_manifest
        .parse()
        .map_err(|_| OciBaseError::InvalidBasePlan)?;
    validate_directory(layout)?;
    validate_directory(&layout.join("blobs"))?;
    let expected_layout = serde_jcs::to_vec(&OciLayoutDocument {
        image_layout_version: OCI_LAYOUT_VERSION,
    })?;
    if read_regular_bounded(&layout.join("oci-layout"), 1024)? != expected_layout {
        return Err(OciBaseError::InvalidLayout);
    }
    let index_bytes = read_regular_bounded(&layout.join("index.json"), OCI_MANIFEST_MAX_BYTES)?;
    let index: RawOciIndexDocument = serde_json::from_slice(&index_bytes)?;
    if index.schema_version != 2 || index.manifests.len() != 1 {
        return Err(OciBaseError::InvalidLayout);
    }
    let indexed = &index.manifests[0];
    if indexed.digest != expected_manifest
        || indexed.size == 0
        || indexed.size > OCI_MANIFEST_MAX_BYTES
        || indexed.platform.architecture != "amd64"
        || indexed.platform.os != "linux"
    {
        return Err(OciBaseError::InvalidLayout);
    }
    let blob_root = layout.join("blobs/sha256");
    validate_directory(&blob_root)?;
    let manifest = read_blob(&blob_root, &expected_manifest, indexed.size)?;
    let parsed = parse_manifest(&manifest)?;
    if parsed.media_type != indexed.media_type {
        return Err(OciBaseError::InvalidLayout);
    }
    let manifest_bytes =
        u64::try_from(manifest.len()).map_err(|_| OciBaseError::PayloadTooLarge)?;
    let expected_index = serde_jcs::to_vec(&OciIndexDocument {
        schema_version: 2,
        manifests: vec![OciIndexDescriptor {
            media_type: parsed.media_type.clone(),
            digest: expected_manifest.clone(),
            size: manifest_bytes,
            platform: OciPlatform {
                architecture: "amd64",
                os: "linux",
            },
        }],
    })?;
    if index_bytes != expected_index {
        return Err(OciBaseError::InvalidLayout);
    }
    let mut expected_blobs = BTreeMap::new();
    expected_blobs.insert(expected_manifest.clone(), indexed.size);
    for descriptor in std::iter::once(&parsed.config).chain(parsed.layers.iter()) {
        validate_descriptor(descriptor)?;
        if expected_blobs
            .insert(descriptor.digest.clone(), descriptor.size)
            .is_some_and(|size| size != descriptor.size)
        {
            return Err(OciBaseError::ConflictingDescriptor);
        }
    }
    for (digest, size) in &expected_blobs {
        let bytes = read_blob(&blob_root, digest, *size)?;
        if *digest == parsed.config.digest {
            validate_config(&bytes)?;
        }
    }
    let mut actual = fs::read_dir(&blob_root)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort();
    let expected = expected_blobs
        .keys()
        .map(|digest| digest.hex().into())
        .collect::<Vec<std::ffi::OsString>>();
    if actual != expected {
        return Err(OciBaseError::InvalidLayout);
    }
    Ok(())
}

fn validate_bases(bases: &[WorkflowOciBaseInputV1]) -> Result<(), OciBaseError> {
    if bases.len() > 16
        || !bases.windows(2).all(|pair| pair[0] < pair[1])
        || bases.iter().any(|base| base.validate().is_err())
        || bases
            .iter()
            .map(|base| base.source.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != bases.len()
        || bases
            .iter()
            .map(|base| base.layout_name.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != bases.len()
    {
        return Err(OciBaseError::InvalidBasePlan);
    }
    Ok(())
}

fn fetch_verified<F, E>(
    object: &OciRegistryObjectV1,
    fetch: &mut F,
) -> Result<Vec<u8>, OciBaseError>
where
    F: FnMut(&OciRegistryObjectV1) -> Result<Vec<u8>, E>,
    E: std::fmt::Display,
{
    object.validate()?;
    let bytes = fetch(object).map_err(|error| OciBaseError::Fetch(error.to_string()))?;
    let length = u64::try_from(bytes.len()).map_err(|_| OciBaseError::PayloadTooLarge)?;
    if bytes.is_empty()
        || length > object.maximum_bytes
        || object
            .expected_bytes
            .is_some_and(|expected| expected != length)
        || EvidenceDigest::sha256(&bytes).as_str() != object.digest.hex()
    {
        return Err(OciBaseError::IntegrityMismatch);
    }
    Ok(bytes)
}

fn parse_manifest(bytes: &[u8]) -> Result<OciManifest, OciBaseError> {
    let manifest: OciManifest = serde_json::from_slice(bytes)?;
    if manifest.schema_version != 2
        || !matches!(
            manifest.media_type.as_str(),
            "application/vnd.oci.image.manifest.v1+json"
                | "application/vnd.docker.distribution.manifest.v2+json"
        )
        || manifest.layers.len() > MAX_LAYERS
    {
        return Err(OciBaseError::InvalidManifest);
    }
    validate_descriptor(&manifest.config)?;
    if !matches!(
        manifest.config.media_type.as_str(),
        "application/vnd.oci.image.config.v1+json"
            | "application/vnd.docker.container.image.v1+json"
    ) {
        return Err(OciBaseError::InvalidManifest);
    }
    for layer in &manifest.layers {
        validate_descriptor(layer)?;
        if !matches!(
            layer.media_type.as_str(),
            "application/vnd.oci.image.layer.v1.tar"
                | "application/vnd.oci.image.layer.v1.tar+gzip"
                | "application/vnd.oci.image.layer.v1.tar+zstd"
                | "application/vnd.docker.image.rootfs.diff.tar.gzip"
        ) {
            return Err(OciBaseError::InvalidManifest);
        }
    }
    unique_descriptors(&manifest)?;
    Ok(manifest)
}

fn unique_descriptors(
    manifest: &OciManifest,
) -> Result<BTreeMap<WorkflowOciDigest, OciDescriptor>, OciBaseError> {
    let mut descriptors = BTreeMap::new();
    for descriptor in std::iter::once(&manifest.config).chain(&manifest.layers) {
        if descriptors
            .insert(descriptor.digest.clone(), descriptor.clone())
            .is_some_and(|existing| {
                existing.size != descriptor.size || existing.media_type != descriptor.media_type
            })
        {
            return Err(OciBaseError::ConflictingDescriptor);
        }
    }
    Ok(descriptors)
}

fn check_planned_base_budget<'a>(
    used: (u64, u64),
    documents: [&[u8]; 3],
    mut descriptors: impl Iterator<Item = &'a OciDescriptor>,
    maximum: (u64, u64),
) -> Result<(), OciBaseError> {
    let (descriptor_bytes, descriptor_count) =
        descriptors.try_fold((0_u64, 0_u64), |(bytes, count), descriptor| {
            Ok::<_, OciBaseError>((
                bytes
                    .checked_add(descriptor.size)
                    .ok_or(OciBaseError::PayloadTooLarge)?,
                count.checked_add(1).ok_or(OciBaseError::PayloadTooLarge)?,
            ))
        })?;
    let planned_bytes = documents
        .into_iter()
        .try_fold(descriptor_bytes, |total, bytes| {
            total
                .checked_add(u64::try_from(bytes.len()).map_err(|_| OciBaseError::PayloadTooLarge)?)
                .ok_or(OciBaseError::PayloadTooLarge)
        })?;
    let planned_inodes = descriptor_count
        .checked_add(6)
        .ok_or(OciBaseError::PayloadTooLarge)?;
    check_budget(
        used.0
            .checked_add(planned_bytes)
            .ok_or(OciBaseError::PayloadTooLarge)?,
        used.1
            .checked_add(planned_inodes)
            .ok_or(OciBaseError::PayloadTooLarge)?,
        maximum.0,
        maximum.1,
    )
}

fn validate_descriptor(descriptor: &OciDescriptor) -> Result<(), OciBaseError> {
    if descriptor.size == 0 || descriptor.size > OCI_BLOB_MAX_BYTES || !descriptor.urls.is_empty() {
        return Err(OciBaseError::InvalidManifest);
    }
    Ok(())
}

fn validate_config(bytes: &[u8]) -> Result<(), OciBaseError> {
    let config: OciImageConfig = serde_json::from_slice(bytes)?;
    if config.architecture != "amd64" || config.os != "linux" {
        return Err(OciBaseError::PlatformMismatch);
    }
    Ok(())
}

fn read_blob(
    root: &Path,
    digest: &WorkflowOciDigest,
    expected_bytes: u64,
) -> Result<Vec<u8>, OciBaseError> {
    let bytes = read_regular_bounded(&root.join(digest.hex()), expected_bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| OciBaseError::PayloadTooLarge)? != expected_bytes
        || EvidenceDigest::sha256(&bytes).as_str() != digest.hex()
    {
        return Err(OciBaseError::IntegrityMismatch);
    }
    Ok(bytes)
}

fn read_regular_bounded(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, OciBaseError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(OciBaseError::InvalidLayout);
    }
    Ok(fs::read(path)?)
}

fn validate_directory(path: &Path) -> Result<(), OciBaseError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(OciBaseError::InvalidLayout);
    }
    Ok(())
}

fn valid_repository(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.split('/').all(|component| {
            let bytes = component.as_bytes();
            !component.is_empty()
                && component.len() <= 128
                && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                && component.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
}

fn inspect_existing_payload(root: &Path) -> Result<(u64, u64), OciBaseError> {
    let mut bytes = 0_u64;
    let mut inodes = 0_u64;
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(OciBaseError::UnsafeExistingPayload);
            }
            inodes = inodes.checked_add(1).ok_or(OciBaseError::PayloadTooLarge)?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or(OciBaseError::PayloadTooLarge)?;
            } else {
                return Err(OciBaseError::UnsafeExistingPayload);
            }
        }
    }
    Ok((bytes, inodes))
}

fn create_directory(path: &Path) -> Result<(), io::Error> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700).create(path)
}

fn write_blob(root: &Path, digest: &WorkflowOciDigest, bytes: &[u8]) -> Result<(), io::Error> {
    write_new_file(&root.join(digest.hex()), bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    let mut options = OpenOptions::new();
    let mut file = options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()
}

fn add_usage(bytes: &mut u64, inodes: &mut u64, length: usize) -> Result<(), OciBaseError> {
    *bytes = bytes
        .checked_add(u64::try_from(length).map_err(|_| OciBaseError::PayloadTooLarge)?)
        .ok_or(OciBaseError::PayloadTooLarge)?;
    *inodes = inodes.checked_add(1).ok_or(OciBaseError::PayloadTooLarge)?;
    Ok(())
}

fn check_budget(
    bytes: u64,
    inodes: u64,
    maximum_bytes: u64,
    maximum_inodes: u64,
) -> Result<(), OciBaseError> {
    if bytes > maximum_bytes || inodes > maximum_inodes {
        return Err(OciBaseError::PayloadTooLarge);
    }
    Ok(())
}

fn ensure_not_cancelled<C: FnMut() -> bool>(cancelled: &mut C) -> Result<(), OciBaseError> {
    if cancelled() {
        Err(OciBaseError::Cancelled)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciManifest {
    schema_version: u16,
    media_type: String,
    config: OciDescriptor,
    layers: Vec<OciDescriptor>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciDescriptor {
    media_type: String,
    digest: WorkflowOciDigest,
    size: u64,
    #[serde(default)]
    urls: Vec<String>,
}

#[derive(Deserialize)]
struct OciImageConfig {
    architecture: String,
    os: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawOciIndexDocument {
    schema_version: u16,
    manifests: Vec<RawOciIndexDescriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawOciIndexDescriptor {
    media_type: String,
    digest: WorkflowOciDigest,
    size: u64,
    platform: RawOciPlatform,
}

#[derive(Deserialize)]
struct RawOciPlatform {
    architecture: String,
    os: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OciLayoutDocument<'a> {
    image_layout_version: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OciIndexDocument {
    schema_version: u16,
    manifests: Vec<OciIndexDescriptor>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OciIndexDescriptor {
    media_type: String,
    digest: WorkflowOciDigest,
    size: u64,
    platform: OciPlatform,
}

#[derive(Serialize)]
struct OciPlatform {
    architecture: &'static str,
    os: &'static str,
}

#[derive(Debug, thiserror::Error)]
pub enum OciBaseError {
    #[error("OCI base plan is invalid")]
    InvalidBasePlan,
    #[error("OCI registry object request is invalid")]
    InvalidRegistryObject,
    #[error("OCI registry fetch failed: {0}")]
    Fetch(String),
    #[error("OCI registry object digest or size does not match its descriptor")]
    IntegrityMismatch,
    #[error("OCI image manifest is invalid or unsupported")]
    InvalidManifest,
    #[error("OCI image manifest contains conflicting descriptors")]
    ConflictingDescriptor,
    #[error("OCI image platform is not linux/amd64")]
    PlatformMismatch,
    #[error("OCI base preparation exceeded its payload boundary")]
    PayloadTooLarge,
    #[error("OCI base preparation was cancelled")]
    Cancelled,
    #[error("existing dependency payload is unsafe")]
    UnsafeExistingPayload,
    #[error("OCI image layout is invalid")]
    InvalidLayout,
    #[error("OCI base filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("OCI base JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn digest(bytes: &[u8]) -> WorkflowOciDigest {
        format!("sha256:{}", EvidenceDigest::sha256(bytes))
            .parse()
            .expect("OCI digest")
    }

    fn base(manifest_digest: WorkflowOciDigest) -> WorkflowOciBaseInputV1 {
        WorkflowOciBaseInputV1 {
            source: format!(
                "docker.io/library/debian:trixie-slim@{}",
                manifest_digest.as_str()
            ),
            layout_name: "debian-trixie".to_owned(),
            manifest_digest,
        }
    }

    #[test]
    fn exact_objects_become_one_buildkit_consumable_sealed_layout_shape() {
        let config = br#"{"architecture":"amd64","os":"linux"}"#.to_vec();
        let layer = b"exact compressed layer".to_vec();
        let config_digest = digest(&config);
        let layer_digest = digest(&layer);
        let manifest = format!(
            "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{}\",\"size\":{}}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"{}\",\"size\":{}}}]}}",
            config_digest.as_str(),
            config.len(),
            layer_digest.as_str(),
            layer.len()
        )
        .into_bytes();
        let manifest_digest = digest(&manifest);
        let base = base(manifest_digest.clone());
        let directory = tempfile::tempdir().expect("temporary directory");
        materialize_oci_base_layouts(
            directory.path(),
            &[base],
            1024 * 1024,
            32,
            |object| {
                if object.digest == manifest_digest {
                    Ok::<_, io::Error>(manifest.clone())
                } else if object.digest == config_digest {
                    Ok(config.clone())
                } else if object.digest == layer_digest {
                    Ok(layer.clone())
                } else {
                    Err(io::Error::other("unexpected object"))
                }
            },
            || false,
        )
        .expect("materialize OCI layout");

        let layout = directory.path().join("oci-layouts/debian-trixie");
        validate_oci_layout(&layout, manifest_digest.as_str()).expect("validate sealed layout");
        assert_eq!(
            fs::read(layout.join("oci-layout")).expect("layout document"),
            br#"{"imageLayoutVersion":"1.0.0"}"#
        );
        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(layout.join("index.json")).expect("index document"))
                .expect("decode index");
        assert_eq!(index["manifests"][0]["digest"], manifest_digest.as_str());
        assert_eq!(index["manifests"][0]["platform"]["os"], "linux");
        assert_eq!(
            fs::read(layout.join("blobs/sha256").join(config_digest.hex())).expect("config blob"),
            config
        );
        assert_eq!(
            fs::read(layout.join("blobs/sha256").join(layer_digest.hex())).expect("layer blob"),
            layer
        );
    }

    #[test]
    fn rejects_registry_object_digest_mismatch() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let expected = digest(b"expected manifest");
        assert!(matches!(
            materialize_oci_base_layouts(
                directory.path(),
                &[base(expected)],
                1024,
                16,
                |_| Ok::<_, io::Error>(b"different".to_vec()),
                || false,
            ),
            Err(OciBaseError::IntegrityMismatch)
        ));
    }

    #[test]
    fn rejects_existing_payload_symlinks_before_fetching() {
        let directory = tempfile::tempdir().expect("temporary directory");
        symlink("/etc/passwd", directory.path().join("unsafe-link")).expect("create symlink");
        let expected = digest(b"expected manifest");
        let mut fetched = false;
        assert!(matches!(
            materialize_oci_base_layouts(
                directory.path(),
                &[base(expected)],
                1024,
                16,
                |_| {
                    fetched = true;
                    Ok::<_, io::Error>(Vec::new())
                },
                || false,
            ),
            Err(OciBaseError::UnsafeExistingPayload)
        ));
        assert!(!fetched);
    }

    #[test]
    fn rejects_declared_base_graph_before_fetching_blobs_when_budget_is_too_small() {
        let config = br#"{"architecture":"amd64","os":"linux"}"#.to_vec();
        let layer = b"exact layer".to_vec();
        let config_digest = digest(&config);
        let layer_digest = digest(&layer);
        let manifest = format!(
            "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{}\",\"size\":{}}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"{}\",\"size\":{}}}]}}",
            config_digest.as_str(),
            config.len(),
            layer_digest.as_str(),
            layer.len()
        )
        .into_bytes();
        let manifest_digest = digest(&manifest);
        let mut fetches = 0;
        let directory = tempfile::tempdir().expect("temporary directory");
        assert!(matches!(
            materialize_oci_base_layouts(
                directory.path(),
                &[base(manifest_digest.clone())],
                1,
                32,
                |object| {
                    fetches += 1;
                    if object.digest == manifest_digest {
                        Ok::<_, io::Error>(manifest.clone())
                    } else {
                        Err(io::Error::other("blob must not be fetched"))
                    }
                },
                || false,
            ),
            Err(OciBaseError::PayloadTooLarge)
        ));
        assert_eq!(fetches, 1);
    }

    #[test]
    fn rejects_foreign_layer_urls_and_wrong_platform_configs() {
        let config = br#"{"architecture":"amd64","os":"linux"}"#;
        let layer = b"layer";
        let manifest = format!(
            "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{}\",\"size\":{}}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"{}\",\"size\":{},\"urls\":[\"https://example.invalid/layer\"]}}]}}",
            digest(config).as_str(),
            config.len(),
            digest(layer).as_str(),
            layer.len()
        );
        assert!(matches!(
            parse_manifest(manifest.as_bytes()),
            Err(OciBaseError::InvalidManifest)
        ));
        assert!(matches!(
            validate_config(br#"{"architecture":"arm64","os":"linux"}"#),
            Err(OciBaseError::PlatformMismatch)
        ));
    }
}
