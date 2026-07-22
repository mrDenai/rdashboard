use crate::{
    domain::ProjectId,
    installed_source::{InstalledSourceConfigV1, InstalledSourceError, InstalledSourceProjectV1},
    installed_workflow::{InstalledWorkflowCatalogV1, InstalledWorkflowProjectV1},
    scheduler::{
        DurableWorkflowScheduler, WorkflowAdmissionOutcomeV1, WorkflowAdmissionV1,
        WorkflowExecutionModeV1, WorkflowTriggerChannelV1,
    },
    source::{
        GitSourceProjectConfig, SourceAttestationError, SourceAttestationVerifier, SourceChannel,
        SourceError, SourceOutboxEntryV1, SourceShadowEntryV1,
    },
    store::StoreError,
};

#[derive(Clone, Debug)]
pub struct SourceWorkflowAdmitterV1 {
    scheduler: DurableWorkflowScheduler,
    workflow_catalog: InstalledWorkflowCatalogV1,
    source_config: InstalledSourceConfigV1,
    verifier: SourceAttestationVerifier,
}

impl SourceWorkflowAdmitterV1 {
    pub fn new(
        scheduler: DurableWorkflowScheduler,
        workflow_catalog: InstalledWorkflowCatalogV1,
        source_config: InstalledSourceConfigV1,
    ) -> Result<Self, SourceWorkflowDeliveryError> {
        source_config.validate()?;
        for source_project in source_config
            .projects
            .iter()
            .filter(|project| project.auto_deploy)
        {
            let workflow_project = workflow_catalog
                .project(&source_project.project_id)
                .ok_or_else(|| {
                    SourceWorkflowDeliveryError::WorkflowProjectMissing(
                        source_project.project_id.clone(),
                    )
                })?;
            validate_project_binding(source_project, workflow_project)?;
        }
        let verifier = source_config.attestation_verifier()?;
        Ok(Self {
            scheduler,
            workflow_catalog,
            source_config,
            verifier,
        })
    }

    pub fn admit(
        &self,
        entry: &SourceOutboxEntryV1,
        admitted_at_ms: i64,
    ) -> Result<WorkflowAdmissionOutcomeV1, SourceWorkflowDeliveryError> {
        if admitted_at_ms < 0 {
            return Err(SourceWorkflowDeliveryError::InvalidAdmissionTime);
        }
        entry.validate()?;
        let payload = self.verifier.verify(&entry.attestation, admitted_at_ms)?;
        if payload.project_id != entry.project_id
            || payload.sequence != entry.source_sequence
            || entry.attestation.digest()? != entry.attestation_digest
        {
            return Err(SourceWorkflowDeliveryError::AttestationBindingMismatch);
        }
        let source_project = self
            .source_config
            .project(&payload.project_id)
            .ok_or_else(|| {
                SourceWorkflowDeliveryError::SourceProjectMissing(payload.project_id.clone())
            })?;
        if !source_project.auto_deploy {
            return Err(SourceWorkflowDeliveryError::AutoDeployDisabled(
                payload.project_id.clone(),
            ));
        }
        let workflow_project = self
            .workflow_catalog
            .project(&payload.project_id)
            .ok_or_else(|| {
                SourceWorkflowDeliveryError::WorkflowProjectMissing(payload.project_id.clone())
            })?;
        validate_project_binding(source_project, workflow_project)?;
        if payload.repository_identity != source_project.repository_identity
            || payload.installed_policy != source_project.installed_policy
        {
            return Err(SourceWorkflowDeliveryError::AttestationBindingMismatch);
        }
        let admission = WorkflowAdmissionV1 {
            project_id: payload.project_id.clone(),
            workflow_policy_digest: workflow_project.workflow_policy_digest.clone(),
            source_sha: payload.head.clone(),
            execution_mode: WorkflowExecutionModeV1::Deploy,
            source_sequence: payload.sequence,
            source_attestation_digest: entry.attestation_digest.clone(),
            trigger_channel: trigger_channel(payload.accepted_via),
            delivery_id: entry.scheduler_delivery_id(),
            payload_digest: entry.attestation_digest.clone(),
            priority: trigger_priority(payload.accepted_via),
        };
        self.scheduler
            .admit(&workflow_project.manifest, &admission, admitted_at_ms)
            .map_err(SourceWorkflowDeliveryError::Scheduler)
    }

    pub fn admit_shadow(
        &self,
        entry: &SourceShadowEntryV1,
        admitted_at_ms: i64,
    ) -> Result<WorkflowAdmissionOutcomeV1, SourceWorkflowDeliveryError> {
        if admitted_at_ms < 0 || admitted_at_ms < entry.observed_at_ms {
            return Err(SourceWorkflowDeliveryError::InvalidAdmissionTime);
        }
        entry.validate()?;
        let payload = self.verifier.verify(&entry.attestation, admitted_at_ms)?;
        if payload.project_id != entry.project_id
            || payload.sequence != entry.source_sequence
            || entry.attestation.digest()? != entry.attestation_digest
        {
            return Err(SourceWorkflowDeliveryError::AttestationBindingMismatch);
        }
        let source_project = self
            .source_config
            .project(&payload.project_id)
            .ok_or_else(|| {
                SourceWorkflowDeliveryError::SourceProjectMissing(payload.project_id.clone())
            })?;
        if source_project.auto_deploy {
            return Err(
                SourceWorkflowDeliveryError::ShadowRequiresAutoDeployDisabled(
                    payload.project_id.clone(),
                ),
            );
        }
        let workflow_project = self
            .workflow_catalog
            .project(&payload.project_id)
            .ok_or_else(|| {
                SourceWorkflowDeliveryError::WorkflowProjectMissing(payload.project_id.clone())
            })?;
        validate_project_binding(source_project, workflow_project)?;
        if payload.repository_identity != source_project.repository_identity
            || payload.installed_policy != source_project.installed_policy
        {
            return Err(SourceWorkflowDeliveryError::AttestationBindingMismatch);
        }
        let admission = WorkflowAdmissionV1 {
            project_id: payload.project_id.clone(),
            workflow_policy_digest: workflow_project.workflow_policy_digest.clone(),
            source_sha: payload.head.clone(),
            execution_mode: WorkflowExecutionModeV1::Shadow,
            source_sequence: payload.sequence,
            source_attestation_digest: entry.attestation_digest.clone(),
            trigger_channel: WorkflowTriggerChannelV1::ManualShadow,
            delivery_id: entry.scheduler_delivery_id(),
            payload_digest: entry.attestation_digest.clone(),
            priority: 1,
        };
        self.scheduler
            .admit(&workflow_project.manifest, &admission, admitted_at_ms)
            .map_err(SourceWorkflowDeliveryError::Scheduler)
    }
}

fn validate_project_binding(
    source_project: &InstalledSourceProjectV1,
    workflow_project: &InstalledWorkflowProjectV1,
) -> Result<(), SourceWorkflowDeliveryError> {
    if source_project.project_id != workflow_project.manifest.project_id
        || source_project.remote_url != workflow_project.manifest.source.remote_url
        || source_project.installed_policy.digest != workflow_project.workflow_policy_digest
    {
        return Err(SourceWorkflowDeliveryError::InstalledPolicyMismatch(
            source_project.project_id.clone(),
        ));
    }
    let workflow_repository_identity = GitSourceProjectConfig {
        project_id: workflow_project.manifest.project_id.clone(),
        remote_url: workflow_project.manifest.source.remote_url.clone(),
        ssh_transport: None,
    }
    .repository_identity();
    if workflow_repository_identity != source_project.repository_identity {
        return Err(SourceWorkflowDeliveryError::RepositoryIdentityMismatch(
            source_project.project_id.clone(),
        ));
    }
    Ok(())
}

const fn trigger_channel(channel: SourceChannel) -> WorkflowTriggerChannelV1 {
    match channel {
        SourceChannel::GithubWebhook => WorkflowTriggerChannelV1::GithubWebhook,
        SourceChannel::SourceReconciliation => WorkflowTriggerChannelV1::SourceReconciliation,
        SourceChannel::DirectPush => WorkflowTriggerChannelV1::DirectPush,
    }
}

const fn trigger_priority(channel: SourceChannel) -> u8 {
    match channel {
        SourceChannel::GithubWebhook | SourceChannel::DirectPush => 3,
        SourceChannel::SourceReconciliation => 1,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SourceWorkflowDeliveryError {
    #[error("source workflow admission time is invalid")]
    InvalidAdmissionTime,
    #[error("installed source configuration failed: {0}")]
    InstalledSource(#[from] InstalledSourceError),
    #[error("source outbox entry failed validation: {0}")]
    Source(#[from] SourceError),
    #[error("source attestation failed verification: {0}")]
    Attestation(#[from] SourceAttestationError),
    #[error("source outbox attestation binding does not match the installed source project")]
    AttestationBindingMismatch,
    #[error("source project {0} is absent from the installed source catalog")]
    SourceProjectMissing(ProjectId),
    #[error("source project {0} is absent from the installed workflow catalog")]
    WorkflowProjectMissing(ProjectId),
    #[error("automatic workflow delivery is disabled for source project {0}")]
    AutoDeployDisabled(ProjectId),
    #[error("shadow workflow admission requires auto_deploy=false for source project {0}")]
    ShadowRequiresAutoDeployDisabled(ProjectId),
    #[error("source project {0} does not bind the installed workflow policy")]
    InstalledPolicyMismatch(ProjectId),
    #[error("source project {0} does not bind the installed workflow repository")]
    RepositoryIdentityMismatch(ProjectId),
    #[error("workflow scheduler rejected verified source delivery: {0}")]
    Scheduler(#[source] StoreError),
}
