use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Component, Path, PathBuf},
};

use crate::{
    adapter_identity::AdapterOperationIdentityV1,
    adapter_result::{FixedAdapterResultV1, MAX_FIXED_ADAPTER_RESULT_BYTES},
    phase6::{AuthorizedPhaseSpecV1, FixedAdapterProfileV1, FixedAdapterRequestV1},
};

pub const ADAPTER_SPEC_PATH: &str = "/job/spec.jcs";
pub const ADAPTER_REQUEST_PATH: &str = "/job/request.jcs";
pub const ADAPTER_RESULT_PATH: &str = "/job/result.jcs";
pub const ADAPTER_INPUT_ROOT: &str = "/inputs";
pub const ADAPTER_OPERATION_IDENTITY_PATH: &str = "/job/operation-identity.jcs";

const MAX_AUTHORIZATION_DOCUMENT_BYTES: u64 = 256 * 1024;
const PENDING_RESULT_FILE_NAME: &str = "result.jcs.pending";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedAdapterInvocationV1 {
    pub subcommand: String,
    pub spec_path: PathBuf,
    pub request_path: PathBuf,
    pub result_path: PathBuf,
    pub inputs_path: PathBuf,
    pub operation_identity_path: PathBuf,
}

impl FixedAdapterInvocationV1 {
    pub fn parse_installed(arguments: &[String]) -> Result<Self, AdapterEntrypointError> {
        let invocation = Self::parse(arguments)?;
        if invocation.spec_path != Path::new(ADAPTER_SPEC_PATH)
            || invocation.request_path != Path::new(ADAPTER_REQUEST_PATH)
            || invocation.result_path != Path::new(ADAPTER_RESULT_PATH)
            || invocation.inputs_path != Path::new(ADAPTER_INPUT_ROOT)
            || invocation.operation_identity_path != Path::new(ADAPTER_OPERATION_IDENTITY_PATH)
        {
            return Err(AdapterEntrypointError::InvalidInvocation);
        }
        Ok(invocation)
    }

    pub fn parse(arguments: &[String]) -> Result<Self, AdapterEntrypointError> {
        let [
            subcommand,
            spec_flag,
            spec_path,
            request_flag,
            request_path,
            result_flag,
            result_path,
            inputs_flag,
            inputs_path,
            identity_flag,
            operation_identity_path,
        ] = arguments
        else {
            return Err(AdapterEntrypointError::InvalidInvocation);
        };
        if spec_flag != "--spec"
            || request_flag != "--request"
            || result_flag != "--result"
            || inputs_flag != "--inputs"
            || identity_flag != "--identity"
            || !valid_subcommand(subcommand)
        {
            return Err(AdapterEntrypointError::InvalidInvocation);
        }
        let invocation = Self {
            subcommand: subcommand.clone(),
            spec_path: PathBuf::from(spec_path),
            request_path: PathBuf::from(request_path),
            result_path: PathBuf::from(result_path),
            inputs_path: PathBuf::from(inputs_path),
            operation_identity_path: PathBuf::from(operation_identity_path),
        };
        if !normalized_absolute(&invocation.spec_path)
            || !normalized_absolute(&invocation.request_path)
            || !normalized_absolute(&invocation.result_path)
            || !normalized_absolute(&invocation.inputs_path)
            || !normalized_absolute(&invocation.operation_identity_path)
            || invocation.spec_path.parent() != invocation.request_path.parent()
            || invocation.spec_path.parent() != invocation.result_path.parent()
            || invocation.spec_path.parent() != invocation.operation_identity_path.parent()
        {
            return Err(AdapterEntrypointError::InvalidInvocation);
        }
        Ok(invocation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedAdapterJobV1 {
    pub spec: AuthorizedPhaseSpecV1,
    pub request: FixedAdapterRequestV1,
    pub prior_results: Vec<FixedAdapterResultV1>,
    result_path: PathBuf,
    operation_identity_path: PathBuf,
    required_uid: u32,
}

impl LoadedAdapterJobV1 {
    pub fn load_installed(
        invocation: &FixedAdapterInvocationV1,
        expected_profile: FixedAdapterProfileV1,
    ) -> Result<Self, AdapterEntrypointError> {
        Self::load(invocation, expected_profile, 0)
    }

    pub fn load(
        invocation: &FixedAdapterInvocationV1,
        expected_profile: FixedAdapterProfileV1,
        required_uid: u32,
    ) -> Result<Self, AdapterEntrypointError> {
        let spec_bytes = read_private_file(
            &invocation.spec_path,
            required_uid,
            MAX_AUTHORIZATION_DOCUMENT_BYTES,
        )?;
        let spec = AuthorizedPhaseSpecV1::decode_canonical(&spec_bytes)?;
        let request_bytes = read_private_file(
            &invocation.request_path,
            required_uid,
            MAX_AUTHORIZATION_DOCUMENT_BYTES,
        )?;
        let request = FixedAdapterRequestV1::decode_authorized(
            &request_bytes,
            &spec,
            expected_sequence(&spec, expected_profile)?,
        )?;
        if request.profile != expected_profile {
            return Err(AdapterEntrypointError::ProfileMismatch);
        }
        let prior_results = load_prior_results(
            &invocation.inputs_path,
            required_uid,
            &spec,
            request.sequence,
        )?;
        Ok(Self {
            spec,
            request,
            prior_results,
            result_path: invocation.result_path.clone(),
            operation_identity_path: invocation.operation_identity_path.clone(),
            required_uid,
        })
    }

    pub fn operation_identity(&self) -> Result<AdapterOperationIdentityV1, AdapterEntrypointError> {
        let bytes = read_private_file(
            &self.operation_identity_path,
            self.required_uid,
            MAX_AUTHORIZATION_DOCUMENT_BYTES,
        )?;
        Ok(AdapterOperationIdentityV1::decode_authorized(
            &bytes,
            &self.spec,
            &self.request,
        )?)
    }

    pub fn existing_result(&self) -> Result<Option<FixedAdapterResultV1>, AdapterEntrypointError> {
        read_optional_result(
            &self.result_path,
            self.required_uid,
            &self.spec,
            self.request.sequence,
            &self.prior_results,
        )
    }

    pub fn reconcile_pending_result(
        &self,
    ) -> Result<Option<FixedAdapterResultV1>, AdapterEntrypointError> {
        if let Some(result) = self.existing_result()? {
            return Ok(Some(result));
        }
        let pending_path = self.pending_result_path()?;
        let Some(result) = read_optional_result(
            &pending_path,
            self.required_uid,
            &self.spec,
            self.request.sequence,
            &self.prior_results,
        )?
        else {
            return Ok(None);
        };
        self.publish_encoded_result(&result)?;
        Ok(Some(result))
    }

    pub fn publish_result(
        &self,
        result: &FixedAdapterResultV1,
    ) -> Result<(), AdapterEntrypointError> {
        result.validate_for_adapter(&self.spec, self.request.sequence, &self.prior_results)?;
        self.publish_encoded_result(result)
    }

    fn publish_encoded_result(
        &self,
        result: &FixedAdapterResultV1,
    ) -> Result<(), AdapterEntrypointError> {
        let bytes = result.canonical_bytes()?;
        if let Some(existing) = self.existing_result()? {
            return if existing == *result {
                Ok(())
            } else {
                Err(AdapterEntrypointError::ResultConflict)
            };
        }
        let pending_path = self.pending_result_path()?;
        materialize_pending_result(
            &pending_path,
            self.required_uid,
            &bytes,
            &self.spec,
            self.request.sequence,
            &self.prior_results,
        )?;
        match fs::hard_link(&pending_path, &self.result_path) {
            Ok(()) => sync_parent(&self.result_path)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = self
                    .existing_result()?
                    .ok_or(AdapterEntrypointError::ResultConflict)?;
                if existing != *result {
                    return Err(AdapterEntrypointError::ResultConflict);
                }
            }
            Err(error) => return Err(AdapterEntrypointError::Io(error)),
        }
        match fs::remove_file(&pending_path) {
            Ok(()) => sync_parent(&pending_path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(AdapterEntrypointError::Io(error)),
        }
        let existing = self
            .existing_result()?
            .ok_or(AdapterEntrypointError::ResultConflict)?;
        if existing == *result {
            Ok(())
        } else {
            Err(AdapterEntrypointError::ResultConflict)
        }
    }

    fn pending_result_path(&self) -> Result<PathBuf, AdapterEntrypointError> {
        Ok(self
            .result_path
            .parent()
            .ok_or(AdapterEntrypointError::InvalidInvocation)?
            .join(PENDING_RESULT_FILE_NAME))
    }
}

fn expected_sequence(
    spec: &AuthorizedPhaseSpecV1,
    expected_profile: FixedAdapterProfileV1,
) -> Result<u16, AdapterEntrypointError> {
    spec.steps
        .iter()
        .find(|step| step.profile == expected_profile)
        .map(|step| step.sequence)
        .ok_or(AdapterEntrypointError::ProfileMismatch)
}

fn load_prior_results(
    input_root: &Path,
    required_uid: u32,
    spec: &AuthorizedPhaseSpecV1,
    sequence: u16,
) -> Result<Vec<FixedAdapterResultV1>, AdapterEntrypointError> {
    let mut results = Vec::with_capacity(usize::from(sequence.saturating_sub(1)));
    for prior_sequence in 1..sequence {
        let path = input_root
            .join(format!("step-{prior_sequence:05}"))
            .join("result.jcs");
        let bytes = read_private_file(
            &path,
            required_uid,
            u64::try_from(MAX_FIXED_ADAPTER_RESULT_BYTES).unwrap_or(u64::MAX),
        )?;
        let result =
            FixedAdapterResultV1::decode_authorized(&bytes, spec, prior_sequence, &results)?;
        results.push(result);
    }
    Ok(results)
}

fn read_optional_result(
    path: &Path,
    required_uid: u32,
    spec: &AuthorizedPhaseSpecV1,
    sequence: u16,
    prior_results: &[FixedAdapterResultV1],
) -> Result<Option<FixedAdapterResultV1>, AdapterEntrypointError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(AdapterEntrypointError::Io(error)),
        Ok(_) => {
            let bytes = read_private_file(
                path,
                required_uid,
                u64::try_from(MAX_FIXED_ADAPTER_RESULT_BYTES).unwrap_or(u64::MAX),
            )?;
            Ok(Some(FixedAdapterResultV1::decode_authorized(
                &bytes,
                spec,
                sequence,
                prior_results,
            )?))
        }
    }
}

fn materialize_pending_result(
    path: &Path,
    required_uid: u32,
    bytes: &[u8],
    spec: &AuthorizedPhaseSpecV1,
    sequence: u16,
    prior_results: &[FixedAdapterResultV1],
) -> Result<(), AdapterEntrypointError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            match options.open(path) {
                Ok(mut file) => {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    sync_parent(path)?;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(AdapterEntrypointError::Io(error)),
            }
        }
        Err(error) => return Err(AdapterEntrypointError::Io(error)),
    }
    let existing = read_private_file(
        path,
        required_uid,
        u64::try_from(MAX_FIXED_ADAPTER_RESULT_BYTES).unwrap_or(u64::MAX),
    )?;
    if existing != bytes {
        return Err(AdapterEntrypointError::ResultConflict);
    }
    FixedAdapterResultV1::decode_authorized(&existing, spec, sequence, prior_results)?;
    Ok(())
}

fn read_private_file(
    path: &Path,
    required_uid: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, AdapterEntrypointError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.mode() & 0o077 != 0
        || path_metadata.len() == 0
        || path_metadata.len() > maximum_bytes
    {
        return Err(AdapterEntrypointError::UnsafeDocument);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(AdapterEntrypointError::DocumentChanged);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
    {
        return Err(AdapterEntrypointError::DocumentChanged);
    }
    Ok(bytes)
}

fn sync_parent(path: &Path) -> Result<(), AdapterEntrypointError> {
    File::open(
        path.parent()
            .ok_or(AdapterEntrypointError::InvalidInvocation)?,
    )?
    .sync_all()?;
    Ok(())
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().as_encoded_bytes().len() <= 512
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>() == path
}

fn valid_subcommand(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterEntrypointError {
    #[error("fixed adapter invocation is not the installed exact-argv contract")]
    InvalidInvocation,
    #[error("fixed adapter invocation does not match the authorized profile")]
    ProfileMismatch,
    #[error("fixed adapter document is not a bounded owner-only regular file")]
    UnsafeDocument,
    #[error("fixed adapter document changed while it was being read")]
    DocumentChanged,
    #[error("fixed adapter result conflicts with a durable result or pending publication")]
    ResultConflict,
    #[error("fixed adapter filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Phase6(#[from] crate::phase6::Phase6ContractError),
    #[error(transparent)]
    Identity(#[from] crate::adapter_identity::AdapterIdentityError),
    #[error(transparent)]
    Result(#[from] crate::adapter_result::AdapterResultContractError),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::tempdir;

    use super::*;
    use crate::{
        adapter_result::{FixedAdapterEvidenceV1, PhaseObservationEvidenceV1},
        domain::{EvidenceDigest, PhaseArtifacts},
        phase6::tests::test_health_phase_spec,
    };

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap_or_else(|error| panic!("write fixture: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("fixture permissions: {error}"));
    }

    fn invocation(root: &Path) -> FixedAdapterInvocationV1 {
        FixedAdapterInvocationV1 {
            subcommand: "readiness-v1".to_owned(),
            spec_path: root.join("spec.jcs"),
            request_path: root.join("request.jcs"),
            result_path: root.join("result.jcs"),
            inputs_path: root.join("inputs"),
            operation_identity_path: root.join("operation-identity.jcs"),
        }
    }

    fn materialize_job(root: &Path) -> (FixedAdapterInvocationV1, AuthorizedPhaseSpecV1, u32) {
        let spec = test_health_phase_spec();
        let invocation = invocation(root);
        fs::create_dir(&invocation.inputs_path)
            .unwrap_or_else(|error| panic!("input root: {error}"));
        write_private(
            &invocation.spec_path,
            &spec
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("spec bytes: {error}")),
        );
        write_private(
            &invocation.request_path,
            &spec
                .fixed_adapter_request(1)
                .and_then(|request| request.canonical_bytes())
                .unwrap_or_else(|error| panic!("request bytes: {error}")),
        );
        let uid = fs::metadata(root)
            .unwrap_or_else(|error| panic!("root metadata: {error}"))
            .uid();
        (invocation, spec, uid)
    }

    fn readiness_result(spec: &AuthorizedPhaseSpecV1) -> FixedAdapterResultV1 {
        let artifacts = spec
            .bind_artifacts(PhaseArtifacts {
                health_evidence_digest: Some(EvidenceDigest::sha256("runtime readiness")),
                ..PhaseArtifacts::default()
            })
            .unwrap_or_else(|error| panic!("bind health artifacts: {error}"));
        FixedAdapterResultV1::new(
            spec,
            1,
            FixedAdapterEvidenceV1::ReadinessEvidence(
                PhaseObservationEvidenceV1::new(
                    200,
                    EvidenceDigest::sha256("runtime readiness observation"),
                    artifacts,
                )
                .unwrap_or_else(|error| panic!("readiness evidence: {error}")),
            ),
            &[],
        )
        .unwrap_or_else(|error| panic!("readiness result: {error}"))
    }

    #[test]
    fn exact_invocation_parser_rejects_path_or_argument_substitution() {
        let exact = [
            "readiness-v1",
            "--spec",
            ADAPTER_SPEC_PATH,
            "--request",
            ADAPTER_REQUEST_PATH,
            "--result",
            ADAPTER_RESULT_PATH,
            "--inputs",
            ADAPTER_INPUT_ROOT,
            "--identity",
            ADAPTER_OPERATION_IDENTITY_PATH,
        ]
        .map(str::to_owned);
        assert!(FixedAdapterInvocationV1::parse_installed(&exact).is_ok());

        let mut substituted = exact.to_vec();
        substituted[2] = "/tmp/spec.jcs".to_owned();
        assert!(matches!(
            FixedAdapterInvocationV1::parse_installed(&substituted),
            Err(AdapterEntrypointError::InvalidInvocation)
        ));
        substituted.push("extra".to_owned());
        assert!(matches!(
            FixedAdapterInvocationV1::parse_installed(&substituted),
            Err(AdapterEntrypointError::InvalidInvocation)
        ));
    }

    #[test]
    fn canonical_job_load_and_result_publication_are_restart_idempotent() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let (invocation, spec, uid) = materialize_job(directory.path());
        let job = LoadedAdapterJobV1::load(&invocation, FixedAdapterProfileV1::RimgReadiness, uid)
            .unwrap_or_else(|error| panic!("load adapter job: {error}"));
        assert!(job.existing_result().unwrap_or(None).is_none());
        let result = readiness_result(&spec);
        job.publish_result(&result)
            .unwrap_or_else(|error| panic!("publish result: {error}"));
        job.publish_result(&result)
            .unwrap_or_else(|error| panic!("replay result: {error}"));
        assert_eq!(job.existing_result().unwrap_or(None), Some(result.clone()));
        assert_eq!(
            fs::metadata(&invocation.result_path)
                .unwrap_or_else(|error| panic!("result metadata: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        fs::remove_file(&invocation.result_path)
            .unwrap_or_else(|error| panic!("remove published result: {error}"));
        write_private(
            &directory.path().join(PENDING_RESULT_FILE_NAME),
            &result
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("result bytes: {error}")),
        );
        assert_eq!(
            job.reconcile_pending_result()
                .unwrap_or_else(|error| panic!("reconcile pending: {error}")),
            Some(result)
        );
        assert!(!directory.path().join(PENDING_RESULT_FILE_NAME).exists());
    }

    #[test]
    fn tampered_authorization_or_pending_result_fails_closed() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let (invocation, spec, uid) = materialize_job(directory.path());
        write_private(&invocation.request_path, b"{}");
        assert!(
            LoadedAdapterJobV1::load(&invocation, FixedAdapterProfileV1::RimgReadiness, uid,)
                .is_err()
        );

        write_private(
            &invocation.request_path,
            &spec
                .fixed_adapter_request(1)
                .and_then(|request| request.canonical_bytes())
                .unwrap_or_else(|error| panic!("request bytes: {error}")),
        );
        let job = LoadedAdapterJobV1::load(&invocation, FixedAdapterProfileV1::RimgReadiness, uid)
            .unwrap_or_else(|error| panic!("reload adapter job: {error}"));
        write_private(&directory.path().join(PENDING_RESULT_FILE_NAME), b"{}");
        assert!(job.reconcile_pending_result().is_err());
        assert!(!invocation.result_path.exists());
    }
}
