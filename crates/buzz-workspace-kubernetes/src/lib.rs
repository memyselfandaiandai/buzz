//! Kubernetes Job fencing for durable disposable workspaces.

use k8s_openapi::api::batch::v1::Job;
use kube::{
    api::{DeleteParams, Patch, PatchParams, PostParams, Preconditions, PropagationPolicy},
    Api, Client,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const SESSION_ID_ANNOTATION: &str = "buzz.final-form/session-id";
const WORKSPACE_ID_ANNOTATION: &str = "buzz.final-form/workspace-id";
const OWNER_ID_ANNOTATION: &str = "buzz.final-form/owner-id";
const CAPABILITY_DIGEST_ANNOTATION: &str = "buzz.final-form/capability-digest";
const PROVIDER_SCOPE_ANNOTATION: &str = "buzz.final-form/provider-scope";
const LAUNCH_EPOCH_ANNOTATION: &str = "buzz.final-form/launch-epoch";
const ACTIVATION_TOKEN_DIGEST_ANNOTATION: &str = "buzz.final-form/activation-token-digest";
const ACTIVATION_OPERATION_KEY_ANNOTATION: &str = "buzz.final-form/activation-operation-key";
const TASK_INPUT_DIGEST_ANNOTATION: &str = "buzz.final-form/task-input-digest";
const EXECUTION_SPEC_DIGEST_ANNOTATION: &str = "buzz.final-form/execution-spec-digest";
const EXECUTION_CLAIM_TOKEN_DIGEST_ANNOTATION: &str =
    "buzz.final-form/execution-claim-token-digest";
const CONSUMER_BOOT_ID_ANNOTATION: &str = "buzz.final-form/consumer-boot-id";
const CREATE_OPERATION_KEY_ANNOTATION: &str = "buzz.final-form/create-operation-key";
const DELETE_OPERATION_KEY_ANNOTATION: &str = "buzz.final-form/delete-operation-key";
const JOB_SPEC_DIGEST_ANNOTATION: &str = "buzz.final-form/job-spec-digest";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFence {
    pub uid: String,
    pub generation: i64,
    pub job_spec_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobObservation {
    Absent,
    Suspended,
    Activated,
    Claimed,
    Deleting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InertJobIdentity {
    pub session_id: String,
    pub workspace_id: String,
    pub owner_id: String,
    pub capability_digest: String,
    pub provider_scope: String,
    pub create_operation_key: String,
    pub delete_operation_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationProjection {
    pub session_id: String,
    pub workspace_id: String,
    pub owner_id: String,
    pub capability_digest: String,
    pub provider_scope: String,
    pub create_operation_key: String,
    pub delete_operation_key: String,
    pub launch_epoch: i64,
    pub activation_token: String,
    pub activation_operation_key: String,
    pub task_input_digest: String,
    pub execution_spec_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionClaimProjection {
    pub activation: ActivationProjection,
    pub consumer_boot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionClaimReceipt {
    pub token: String,
    pub consumer_boot_id: String,
    pub execution_spec_digest: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kubernetes API error: {0}")]
    Kubernetes(#[from] kube::Error),
    #[error("invalid Kubernetes provider state: {0}")]
    InvalidState(&'static str),
    #[error("Kubernetes provider ownership mismatch")]
    OwnershipMismatch,
    #[error("invalid JSON patch: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct KubernetesJobControl {
    jobs: Api<Job>,
    namespace: String,
    provider_scope: String,
}

impl KubernetesJobControl {
    /// Binds the control to one concrete Kubernetes configuration and namespace.
    /// The durable provider scope is derived from that exact authority; callers
    /// cannot pair an unrelated scope string with a different client.
    pub fn from_config(config: kube::Config, namespace: impl Into<String>) -> Result<Self> {
        let namespace = namespace.into();
        let provider_scope = provider_scope_from_config(&config, &namespace)?;
        let client = Client::try_from(config)?;
        Ok(Self {
            jobs: Api::namespaced(client, &namespace),
            namespace,
            provider_scope,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        client: Client,
        namespace: impl Into<String>,
        provider_scope: impl Into<String>,
    ) -> Self {
        let namespace = namespace.into();
        Self {
            jobs: Api::namespaced(client, &namespace),
            namespace,
            provider_scope: provider_scope.into(),
        }
    }

    pub fn provider_scope(&self) -> &str {
        &self.provider_scope
    }

    fn validate_provider_scope(&self, provider_scope: &str) -> Result<()> {
        if provider_scope != self.provider_scope {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }

    /// Creates a suspended Job and returns only provider-generated identity.
    pub async fn create_inert(
        &self,
        name: &str,
        identity: &InertJobIdentity,
        template: &Job,
    ) -> Result<ProviderFence> {
        validate_job_name(name)?;
        validate_inert_identity(identity)?;
        self.validate_provider_scope(&identity.provider_scope)?;
        let template_spec = template.spec.as_ref().ok_or(Error::InvalidState(
            "workspace Job template is not suspended",
        ))?;
        if template_spec.suspend != Some(true) {
            return Err(Error::InvalidState(
                "workspace Job template is not suspended",
            ));
        }
        if template_spec.manual_selector.is_some() || template_spec.selector.is_some() {
            return Err(Error::InvalidState(
                "workspace Job template cannot supply a selector",
            ));
        }
        validate_supplied_identity_annotations(template, identity)?;
        let mut job = template.clone();
        job.metadata = Default::default();
        job.metadata.name = Some(name.to_owned());
        job.status = None;
        if let Some(spec) = job.spec.as_mut() {
            spec.template.metadata = Default::default();
        }
        let job_spec_digest = job_spec_digest(&job)?;
        let annotations = job.metadata.annotations.get_or_insert_with(BTreeMap::new);
        insert_reserved_annotation(annotations, SESSION_ID_ANNOTATION, &identity.session_id)?;
        insert_reserved_annotation(annotations, WORKSPACE_ID_ANNOTATION, &identity.workspace_id)?;
        insert_reserved_annotation(annotations, OWNER_ID_ANNOTATION, &identity.owner_id)?;
        insert_reserved_annotation(
            annotations,
            CAPABILITY_DIGEST_ANNOTATION,
            &identity.capability_digest,
        )?;
        insert_reserved_annotation(
            annotations,
            PROVIDER_SCOPE_ANNOTATION,
            &identity.provider_scope,
        )?;
        insert_reserved_annotation(
            annotations,
            CREATE_OPERATION_KEY_ANNOTATION,
            &identity.create_operation_key,
        )?;
        insert_reserved_annotation(
            annotations,
            DELETE_OPERATION_KEY_ANNOTATION,
            &identity.delete_operation_key,
        )?;
        insert_reserved_annotation(annotations, JOB_SPEC_DIGEST_ANNOTATION, &job_spec_digest)?;
        match self.jobs.create(&PostParams::default(), &job).await {
            Ok(created) => {
                validate_created_job(
                    &created,
                    name,
                    &self.namespace,
                    identity,
                    &job_spec_digest,
                    &job,
                )?;
                fence_from_job(&created)
            }
            Err(kube::Error::Api(response))
                if response.code == 409 && response.reason == "AlreadyExists" =>
            {
                let existing = self.jobs.get(name).await?;
                validate_created_job(
                    &existing,
                    name,
                    &self.namespace,
                    identity,
                    &job_spec_digest,
                    &job,
                )?;
                fence_from_job(&existing)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Observes the exact owned inert Job. A typed NotFound is authoritative absence.
    pub async fn observe_owned(
        &self,
        name: &str,
        fence: &ProviderFence,
        identity: &InertJobIdentity,
    ) -> Result<JobObservation> {
        validate_job_name(name)?;
        validate_inert_identity(identity)?;
        validate_provider_fence(fence)?;
        self.validate_provider_scope(&identity.provider_scope)?;
        let job = match self.jobs.get(name).await {
            Ok(job) => job,
            Err(kube::Error::Api(response)) if is_exact_job_not_found(&response, name) => {
                return Ok(JobObservation::Absent);
            }
            Err(error) => return Err(error.into()),
        };
        validate_object_location(&job, name, &self.namespace)?;
        validate_identity_annotations(&job, identity)?;
        validate_job_spec_digest(&job, None)?;
        validate_execution_annotations_shape(&job)?;
        validate_never_started(&job)?;
        if fence_from_job(&job)? != *fence {
            return Err(Error::OwnershipMismatch);
        }
        if job.spec.as_ref().and_then(|spec| spec.suspend) != Some(true) {
            return Err(Error::InvalidState("owned workspace Job is not suspended"));
        }
        if job.metadata.deletion_timestamp.is_some() {
            return Ok(JobObservation::Deleting);
        }
        let annotations = job
            .metadata
            .annotations
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        if annotations.contains_key(EXECUTION_CLAIM_TOKEN_DIGEST_ANNOTATION) {
            Ok(JobObservation::Claimed)
        } else if annotations.contains_key(LAUNCH_EPOCH_ANNOTATION) {
            Ok(JobObservation::Activated)
        } else {
            Ok(JobObservation::Suspended)
        }
    }

    /// Requests deletion of only the exact owned provider object.
    /// Success means the request was accepted; callers must observe `Absent` separately.
    pub async fn request_delete_owned(
        &self,
        name: &str,
        fence: &ProviderFence,
        identity: &InertJobIdentity,
    ) -> Result<()> {
        validate_job_name(name)?;
        validate_inert_identity(identity)?;
        validate_provider_fence(fence)?;
        self.validate_provider_scope(&identity.provider_scope)?;
        let job = match self.jobs.get(name).await {
            Ok(job) => job,
            Err(kube::Error::Api(response)) if is_exact_job_not_found(&response, name) => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        validate_object_location(&job, name, &self.namespace)?;
        validate_identity_annotations(&job, identity)?;
        validate_job_spec_digest(&job, None)?;
        validate_execution_annotations_shape(&job)?;
        validate_never_started(&job)?;
        if fence_from_job(&job)? != *fence {
            return Err(Error::OwnershipMismatch);
        }
        if job.spec.as_ref().and_then(|spec| spec.suspend) != Some(true) {
            return Err(Error::InvalidState("owned workspace Job is not suspended"));
        }
        if job.metadata.deletion_timestamp.is_some() {
            return Err(Error::InvalidState("workspace Job is already terminating"));
        }
        let delete = DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(fence.uid.clone()),
                resource_version: Some(resource_version(&job)?.to_owned()),
            }),
            propagation_policy: Some(PropagationPolicy::Foreground),
            ..DeleteParams::default()
        };
        match self.jobs.delete(name, &delete).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(response)) if is_exact_job_not_found(&response, name) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Projects an authorization while proving that the exact provider object is still inert.
    pub async fn activate(
        &self,
        name: &str,
        fence: &ProviderFence,
        projection: &ActivationProjection,
    ) -> Result<()> {
        validate_job_name(name)?;
        validate_provider_fence(fence)?;
        validate_activation_projection(projection)?;
        self.validate_provider_scope(&projection.provider_scope)?;
        let job = self.jobs.get(name).await?;
        validate_owned_job(&job, name, &self.namespace, fence, projection)?;
        validate_execution_annotations_shape(&job)?;
        let annotations = job
            .metadata
            .annotations
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        if [
            LAUNCH_EPOCH_ANNOTATION,
            ACTIVATION_TOKEN_DIGEST_ANNOTATION,
            ACTIVATION_OPERATION_KEY_ANNOTATION,
            TASK_INPUT_DIGEST_ANNOTATION,
            EXECUTION_SPEC_DIGEST_ANNOTATION,
        ]
        .iter()
        .any(|key| annotations.contains_key(*key))
        {
            validate_activation(&job, projection)?;
            return Ok(());
        }
        if job.spec.as_ref().and_then(|spec| spec.suspend) != Some(true) {
            return Err(Error::InvalidState("workspace Job is not suspended"));
        }
        let resource_version = job
            .metadata
            .resource_version
            .as_deref()
            .ok_or(Error::InvalidState("workspace Job has no resourceVersion"))?;
        let patch: json_patch::Patch = serde_json::from_value(json!([
            {"op": "test", "path": "/metadata/uid", "value": fence.uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
            {"op": "test", "path": "/metadata/generation", "value": fence.generation},
            {"op": "test", "path": "/spec/suspend", "value": true},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1launch-epoch", "value": projection.launch_epoch.to_string()},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1activation-token-digest", "value": digest(&projection.activation_token)},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1activation-operation-key", "value": projection.activation_operation_key},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1task-input-digest", "value": projection.task_input_digest},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1execution-spec-digest", "value": projection.execution_spec_digest}
        ]))?;
        let activated = self
            .jobs
            .patch(name, &PatchParams::default(), &Patch::Json::<()>(patch))
            .await?;
        validate_owned_job(&activated, name, &self.namespace, fence, projection)?;
        validate_advanced_resource_version(resource_version, &activated)?;
        validate_execution_annotations_shape(&activated)?;
        validate_activation(&activated, projection)?;
        if activated.spec.as_ref().and_then(|spec| spec.suspend) != Some(true) {
            return Err(Error::InvalidState("activation started workspace Job"));
        }
        Ok(())
    }

    /// Records one exact provider execution claim without starting the suspended Job.
    pub async fn claim_execution(
        &self,
        name: &str,
        fence: &ProviderFence,
        projection: &ExecutionClaimProjection,
    ) -> Result<ExecutionClaimReceipt> {
        validate_job_name(name)?;
        validate_provider_fence(fence)?;
        validate_activation_projection(&projection.activation)?;
        self.validate_provider_scope(&projection.activation.provider_scope)?;
        if projection.consumer_boot_id.is_empty() || projection.consumer_boot_id.contains('\0') {
            return Err(Error::InvalidState("empty consumer boot ID"));
        }
        let job = self.jobs.get(name).await?;
        validate_owned_job(&job, name, &self.namespace, fence, &projection.activation)?;
        validate_execution_annotations_shape(&job)?;
        validate_activation(&job, &projection.activation)?;
        if job.spec.as_ref().and_then(|spec| spec.suspend) != Some(true) {
            return Err(Error::InvalidState("workspace Job is not suspended"));
        }
        let annotations = job
            .metadata
            .annotations
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        let token = execution_claim_token(name, &self.namespace, fence, projection);
        let token_digest = digest(&token);
        match (
            annotations.get(EXECUTION_CLAIM_TOKEN_DIGEST_ANNOTATION),
            annotations.get(CONSUMER_BOOT_ID_ANNOTATION),
        ) {
            (Some(existing_digest), Some(consumer))
                if existing_digest == &token_digest && consumer == &projection.consumer_boot_id =>
            {
                return Ok(ExecutionClaimReceipt {
                    token,
                    consumer_boot_id: consumer.clone(),
                    execution_spec_digest: projection.activation.execution_spec_digest.clone(),
                });
            }
            (None, None) => {}
            _ => return Err(Error::OwnershipMismatch),
        }
        let resource_version = resource_version(&job)?;
        let patch: json_patch::Patch = serde_json::from_value(json!([
            {"op": "test", "path": "/metadata/uid", "value": fence.uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
            {"op": "test", "path": "/metadata/generation", "value": fence.generation},
            {"op": "test", "path": "/spec/suspend", "value": true},
            {"op": "test", "path": "/metadata/annotations/buzz.final-form~1activation-token-digest", "value": digest(&projection.activation.activation_token)},
            {"op": "test", "path": "/metadata/annotations/buzz.final-form~1execution-spec-digest", "value": projection.activation.execution_spec_digest},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1execution-claim-token-digest", "value": token_digest},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1consumer-boot-id", "value": projection.consumer_boot_id}
        ]))?;
        let claimed = self
            .jobs
            .patch(name, &PatchParams::default(), &Patch::Json::<()>(patch))
            .await?;
        let receipt = ExecutionClaimReceipt {
            token,
            consumer_boot_id: projection.consumer_boot_id.clone(),
            execution_spec_digest: projection.activation.execution_spec_digest.clone(),
        };
        validate_owned_job(
            &claimed,
            name,
            &self.namespace,
            fence,
            &projection.activation,
        )?;
        validate_advanced_resource_version(resource_version, &claimed)?;
        validate_execution_annotations_shape(&claimed)?;
        validate_activation(&claimed, &projection.activation)?;
        validate_claim(&claimed, &receipt)?;
        if claimed.spec.as_ref().and_then(|spec| spec.suspend) != Some(true) {
            return Err(Error::InvalidState("execution claim started workspace Job"));
        }
        Ok(receipt)
    }
}

fn validate_owned_job(
    job: &Job,
    name: &str,
    namespace: &str,
    fence: &ProviderFence,
    projection: &ActivationProjection,
) -> Result<()> {
    validate_object_location(job, name, namespace)?;
    validate_job_spec_digest(job, Some(&fence.job_spec_digest))?;
    validate_owned_job_uid(job, fence, projection)?;
    validate_mutable_inert_job(job)?;
    validate_never_started(job)?;
    if job.metadata.generation != Some(fence.generation) {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}

fn validate_owned_job_uid(
    job: &Job,
    fence: &ProviderFence,
    projection: &ActivationProjection,
) -> Result<()> {
    validate_reserved_annotation_namespace(job)?;
    if job.metadata.uid.as_deref() != Some(fence.uid.as_str()) {
        return Err(Error::OwnershipMismatch);
    }
    let annotations = job
        .metadata
        .annotations
        .as_ref()
        .ok_or(Error::OwnershipMismatch)?;
    if annotations.get(SESSION_ID_ANNOTATION) != Some(&projection.session_id)
        || annotations.get(WORKSPACE_ID_ANNOTATION) != Some(&projection.workspace_id)
        || annotations.get(OWNER_ID_ANNOTATION) != Some(&projection.owner_id)
        || annotations.get(CAPABILITY_DIGEST_ANNOTATION) != Some(&projection.capability_digest)
        || annotations.get(PROVIDER_SCOPE_ANNOTATION) != Some(&projection.provider_scope)
        || annotations.get(CREATE_OPERATION_KEY_ANNOTATION)
            != Some(&projection.create_operation_key)
        || annotations.get(DELETE_OPERATION_KEY_ANNOTATION)
            != Some(&projection.delete_operation_key)
    {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}

fn validate_supplied_identity_annotations(job: &Job, identity: &InertJobIdentity) -> Result<()> {
    let Some(annotations) = job.metadata.annotations.as_ref() else {
        return Ok(());
    };
    for (key, value) in [
        (SESSION_ID_ANNOTATION, identity.session_id.as_str()),
        (WORKSPACE_ID_ANNOTATION, identity.workspace_id.as_str()),
        (OWNER_ID_ANNOTATION, identity.owner_id.as_str()),
        (
            CAPABILITY_DIGEST_ANNOTATION,
            identity.capability_digest.as_str(),
        ),
        (PROVIDER_SCOPE_ANNOTATION, identity.provider_scope.as_str()),
        (
            CREATE_OPERATION_KEY_ANNOTATION,
            identity.create_operation_key.as_str(),
        ),
        (
            DELETE_OPERATION_KEY_ANNOTATION,
            identity.delete_operation_key.as_str(),
        ),
    ] {
        if annotations
            .get(key)
            .is_some_and(|existing| existing != value)
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    Ok(())
}

fn insert_reserved_annotation(
    annotations: &mut BTreeMap<String, String>,
    key: &str,
    value: &str,
) -> Result<()> {
    if annotations
        .get(key)
        .is_some_and(|existing| existing != value)
    {
        return Err(Error::OwnershipMismatch);
    }
    annotations.insert(key.to_owned(), value.to_owned());
    Ok(())
}

fn fence_from_job(job: &Job) -> Result<ProviderFence> {
    let uid = job
        .metadata
        .uid
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or(Error::InvalidState("workspace Job has no UID"))?;
    let generation =
        job.metadata
            .generation
            .filter(|value| *value == 1)
            .ok_or(Error::InvalidState(
                "workspace Job generation is not initial",
            ))?;
    resource_version(job)?;
    let job_spec_digest = job
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(JOB_SPEC_DIGEST_ANNOTATION))
        .filter(|value| is_canonical_sha256(value))
        .cloned()
        .ok_or(Error::InvalidState(
            "workspace Job has no canonical spec digest",
        ))?;
    Ok(ProviderFence {
        uid,
        generation,
        job_spec_digest,
    })
}

fn job_spec_digest(job: &Job) -> Result<String> {
    let spec = job
        .spec
        .as_ref()
        .ok_or(Error::InvalidState("workspace Job has no spec"))?;
    let canonical = serde_json::to_value(spec)?;
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&canonical)?)))
}

fn provider_scope_from_config(config: &kube::Config, namespace: &str) -> Result<String> {
    if namespace.is_empty() || namespace.contains(['/', ' ']) {
        return Err(Error::InvalidState("invalid Kubernetes namespace"));
    }
    let mut hasher = Sha256::new();
    let cluster_url = config.cluster_url.to_string();
    for part in [
        b"buzz/kubernetes-provider-scope/v1".as_slice(),
        cluster_url.as_bytes(),
        namespace.as_bytes(),
        config.tls_server_name.as_deref().unwrap_or("").as_bytes(),
        if config.accept_invalid_certs {
            b"1"
        } else {
            b"0"
        },
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    if let Some(certificates) = config.root_cert.as_ref() {
        for certificate in certificates {
            hasher.update((certificate.len() as u64).to_be_bytes());
            hasher.update(certificate);
        }
    }
    Ok(format!("kubernetes:v1:{}", hex::encode(hasher.finalize())))
}

fn is_exact_job_not_found(response: &kube::error::ErrorResponse, name: &str) -> bool {
    response.code == 404
        && response.status == "Failure"
        && response.reason == "NotFound"
        && response.message == format!(r#"jobs.batch "{name}" not found"#)
}

fn validate_job_name(name: &str) -> Result<()> {
    if name.is_empty() || name.contains(['/', '\0']) {
        return Err(Error::InvalidState("invalid workspace Job name"));
    }
    Ok(())
}

fn validate_inert_identity(identity: &InertJobIdentity) -> Result<()> {
    if identity.session_id.is_empty()
        || identity.workspace_id.is_empty()
        || identity.owner_id.is_empty()
        || !is_canonical_sha256(&identity.capability_digest)
        || identity.provider_scope.is_empty()
        || identity.create_operation_key.is_empty()
        || identity.delete_operation_key.is_empty()
        || [
            &identity.session_id,
            &identity.workspace_id,
            &identity.owner_id,
            &identity.provider_scope,
            &identity.create_operation_key,
            &identity.delete_operation_key,
        ]
        .iter()
        .any(|value| value.contains('\0'))
    {
        return Err(Error::InvalidState("invalid inert Job identity"));
    }
    Ok(())
}

fn validate_provider_fence(fence: &ProviderFence) -> Result<()> {
    if fence.uid.is_empty()
        || fence.uid.contains('\0')
        || fence.generation <= 0
        || !is_canonical_sha256(&fence.job_spec_digest)
    {
        return Err(Error::InvalidState("invalid provider fence"));
    }
    Ok(())
}

fn validate_activation_projection(projection: &ActivationProjection) -> Result<()> {
    validate_inert_identity(&InertJobIdentity {
        session_id: projection.session_id.clone(),
        workspace_id: projection.workspace_id.clone(),
        owner_id: projection.owner_id.clone(),
        capability_digest: projection.capability_digest.clone(),
        provider_scope: projection.provider_scope.clone(),
        create_operation_key: projection.create_operation_key.clone(),
        delete_operation_key: projection.delete_operation_key.clone(),
    })?;
    if projection.launch_epoch <= 0
        || projection.activation_token.is_empty()
        || projection.activation_operation_key.is_empty()
        || !is_canonical_sha256(&projection.task_input_digest)
        || !is_canonical_sha256(&projection.execution_spec_digest)
    {
        return Err(Error::InvalidState("invalid activation projection"));
    }
    Ok(())
}

fn validate_object_location(job: &Job, name: &str, namespace: &str) -> Result<()> {
    if job.metadata.name.as_deref() != Some(name)
        || job.metadata.namespace.as_deref() != Some(namespace)
    {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}

fn validate_job_spec_digest(job: &Job, expected: Option<&str>) -> Result<()> {
    let annotations = job
        .metadata
        .annotations
        .as_ref()
        .ok_or(Error::OwnershipMismatch)?;
    let annotated = annotations
        .get(JOB_SPEC_DIGEST_ANNOTATION)
        .filter(|value| is_canonical_sha256(value))
        .ok_or(Error::OwnershipMismatch)?;
    let actual = job_spec_digest(job)?;
    if annotated != &actual || expected.is_some_and(|value| value != actual) {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}

fn validate_created_job(
    job: &Job,
    name: &str,
    namespace: &str,
    identity: &InertJobIdentity,
    expected_spec_digest: &str,
    expected_job: &Job,
) -> Result<()> {
    validate_object_location(job, name, namespace)?;
    if serde_json::to_value(job.spec.as_ref())? != serde_json::to_value(expected_job.spec.as_ref())?
    {
        return Err(Error::OwnershipMismatch);
    }
    validate_job_spec_digest(job, Some(expected_spec_digest))?;
    validate_mutable_inert_job(job)?;
    validate_never_started(job)?;
    validate_no_execution_annotations(job)?;
    validate_identity_annotations(job, identity)
}

fn validate_mutable_inert_job(job: &Job) -> Result<()> {
    if job.metadata.deletion_timestamp.is_some() {
        return Err(Error::InvalidState("workspace Job is terminating"));
    }
    if job.spec.as_ref().and_then(|spec| spec.suspend) != Some(true) {
        return Err(Error::InvalidState("workspace Job is not suspended"));
    }
    Ok(())
}

fn validate_never_started(job: &Job) -> Result<()> {
    if job
        .status
        .as_ref()
        .is_some_and(|status| status != &Default::default())
    {
        return Err(Error::InvalidState("workspace Job has prior-run status"));
    }
    Ok(())
}

fn validate_no_execution_annotations(job: &Job) -> Result<()> {
    let Some(annotations) = job.metadata.annotations.as_ref() else {
        return Ok(());
    };
    if [
        LAUNCH_EPOCH_ANNOTATION,
        ACTIVATION_TOKEN_DIGEST_ANNOTATION,
        ACTIVATION_OPERATION_KEY_ANNOTATION,
        TASK_INPUT_DIGEST_ANNOTATION,
        EXECUTION_SPEC_DIGEST_ANNOTATION,
        EXECUTION_CLAIM_TOKEN_DIGEST_ANNOTATION,
        CONSUMER_BOOT_ID_ANNOTATION,
    ]
    .iter()
    .any(|key| annotations.contains_key(*key))
    {
        return Err(Error::InvalidState(
            "inert workspace Job has execution control metadata",
        ));
    }
    Ok(())
}

fn validate_execution_annotations_shape(job: &Job) -> Result<()> {
    let annotations = job
        .metadata
        .annotations
        .as_ref()
        .ok_or(Error::OwnershipMismatch)?;
    let activation_keys = [
        LAUNCH_EPOCH_ANNOTATION,
        ACTIVATION_TOKEN_DIGEST_ANNOTATION,
        ACTIVATION_OPERATION_KEY_ANNOTATION,
        TASK_INPUT_DIGEST_ANNOTATION,
        EXECUTION_SPEC_DIGEST_ANNOTATION,
    ];
    let activation_count = activation_keys
        .iter()
        .filter(|key| annotations.contains_key(**key))
        .count();
    if activation_count != 0 && activation_count != activation_keys.len() {
        return Err(Error::InvalidState("partial activation metadata"));
    }
    if activation_count == activation_keys.len()
        && (annotations
            .get(LAUNCH_EPOCH_ANNOTATION)
            .and_then(|value| value.parse::<i64>().ok())
            .is_none_or(|value| value <= 0)
            || annotations
                .get(ACTIVATION_TOKEN_DIGEST_ANNOTATION)
                .is_none_or(|value| !is_canonical_sha256(value))
            || annotations
                .get(ACTIVATION_OPERATION_KEY_ANNOTATION)
                .is_none_or(String::is_empty)
            || annotations
                .get(TASK_INPUT_DIGEST_ANNOTATION)
                .is_none_or(|value| !is_canonical_sha256(value))
            || annotations
                .get(EXECUTION_SPEC_DIGEST_ANNOTATION)
                .is_none_or(|value| !is_canonical_sha256(value)))
    {
        return Err(Error::InvalidState("invalid activation metadata"));
    }
    let claim_count = [
        EXECUTION_CLAIM_TOKEN_DIGEST_ANNOTATION,
        CONSUMER_BOOT_ID_ANNOTATION,
    ]
    .iter()
    .filter(|key| annotations.contains_key(**key))
    .count();
    if claim_count != 0 && claim_count != 2 {
        return Err(Error::InvalidState("partial execution claim metadata"));
    }
    if claim_count == 2
        && (activation_count != activation_keys.len()
            || annotations
                .get(EXECUTION_CLAIM_TOKEN_DIGEST_ANNOTATION)
                .is_none_or(|value| !is_canonical_sha256(value))
            || annotations
                .get(CONSUMER_BOOT_ID_ANNOTATION)
                .is_none_or(String::is_empty))
    {
        return Err(Error::InvalidState("invalid execution claim metadata"));
    }
    Ok(())
}

fn validate_reserved_annotation_namespace(job: &Job) -> Result<()> {
    const RESERVED_PREFIX: &str = "buzz.final-form/";
    const ALLOWED: [&str; 15] = [
        SESSION_ID_ANNOTATION,
        WORKSPACE_ID_ANNOTATION,
        OWNER_ID_ANNOTATION,
        CAPABILITY_DIGEST_ANNOTATION,
        PROVIDER_SCOPE_ANNOTATION,
        CREATE_OPERATION_KEY_ANNOTATION,
        DELETE_OPERATION_KEY_ANNOTATION,
        JOB_SPEC_DIGEST_ANNOTATION,
        LAUNCH_EPOCH_ANNOTATION,
        ACTIVATION_TOKEN_DIGEST_ANNOTATION,
        ACTIVATION_OPERATION_KEY_ANNOTATION,
        TASK_INPUT_DIGEST_ANNOTATION,
        EXECUTION_SPEC_DIGEST_ANNOTATION,
        EXECUTION_CLAIM_TOKEN_DIGEST_ANNOTATION,
        CONSUMER_BOOT_ID_ANNOTATION,
    ];
    let annotations = job.metadata.annotations.as_ref();
    if annotations.is_some_and(|values| {
        values
            .keys()
            .any(|key| key.starts_with(RESERVED_PREFIX) && !ALLOWED.contains(&key.as_str()))
    }) {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}

fn validate_identity_annotations(job: &Job, identity: &InertJobIdentity) -> Result<()> {
    validate_reserved_annotation_namespace(job)?;
    let annotations = job
        .metadata
        .annotations
        .as_ref()
        .ok_or(Error::OwnershipMismatch)?;
    if annotations.get(SESSION_ID_ANNOTATION) != Some(&identity.session_id)
        || annotations.get(WORKSPACE_ID_ANNOTATION) != Some(&identity.workspace_id)
        || annotations.get(OWNER_ID_ANNOTATION) != Some(&identity.owner_id)
        || annotations.get(CAPABILITY_DIGEST_ANNOTATION) != Some(&identity.capability_digest)
        || annotations.get(PROVIDER_SCOPE_ANNOTATION) != Some(&identity.provider_scope)
        || annotations.get(CREATE_OPERATION_KEY_ANNOTATION) != Some(&identity.create_operation_key)
        || annotations.get(DELETE_OPERATION_KEY_ANNOTATION) != Some(&identity.delete_operation_key)
    {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}

fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn execution_claim_token(
    name: &str,
    namespace: &str,
    fence: &ProviderFence,
    projection: &ExecutionClaimProjection,
) -> String {
    let mut hasher = Sha256::new();
    let launch_epoch = projection.activation.launch_epoch.to_string();
    let provider_generation = fence.generation.to_string();
    for part in [
        "buzz/workspace-execution-claim/v1",
        projection.activation.session_id.as_str(),
        projection.activation.workspace_id.as_str(),
        projection.activation.owner_id.as_str(),
        projection.activation.capability_digest.as_str(),
        projection.activation.provider_scope.as_str(),
        projection.activation.create_operation_key.as_str(),
        projection.activation.delete_operation_key.as_str(),
        name,
        namespace,
        fence.uid.as_str(),
        provider_generation.as_str(),
        fence.job_spec_digest.as_str(),
        launch_epoch.as_str(),
        projection.activation.activation_token.as_str(),
        projection.activation.activation_operation_key.as_str(),
        projection.activation.task_input_digest.as_str(),
        projection.activation.execution_spec_digest.as_str(),
        projection.consumer_boot_id.as_str(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn validate_advanced_resource_version(previous: &str, job: &Job) -> Result<()> {
    let current = resource_version(job)?;
    if current == previous {
        return Err(Error::InvalidState(
            "Kubernetes mutation response did not advance resourceVersion",
        ));
    }
    Ok(())
}

fn resource_version(job: &Job) -> Result<&str> {
    job.metadata
        .resource_version
        .as_deref()
        .ok_or(Error::InvalidState("workspace Job has no resourceVersion"))
}

fn validate_activation(job: &Job, projection: &ActivationProjection) -> Result<()> {
    let annotations = job
        .metadata
        .annotations
        .as_ref()
        .ok_or(Error::OwnershipMismatch)?;
    let launch_epoch = projection.launch_epoch.to_string();
    let activation_token_digest = digest(&projection.activation_token);
    if annotations.get(LAUNCH_EPOCH_ANNOTATION) != Some(&launch_epoch)
        || annotations.get(ACTIVATION_TOKEN_DIGEST_ANNOTATION) != Some(&activation_token_digest)
        || annotations.get(ACTIVATION_OPERATION_KEY_ANNOTATION)
            != Some(&projection.activation_operation_key)
        || annotations.get(TASK_INPUT_DIGEST_ANNOTATION) != Some(&projection.task_input_digest)
        || annotations.get(EXECUTION_SPEC_DIGEST_ANNOTATION)
            != Some(&projection.execution_spec_digest)
    {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}

#[cfg(test)]
extern crate self as buzz_workspace_kubernetes;

#[cfg(test)]
mod config_scope_tests {
    use super::*;

    #[test]
    fn unchanged_mutation_resource_version_fails_closed() {
        let job: Job = serde_json::from_value(json!({
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "workspace-1", "resourceVersion": "rv-1"},
            "spec": {"template": {"spec": {"containers": [], "restartPolicy": "Never"}}}
        }))
        .unwrap();
        assert!(matches!(
            validate_advanced_resource_version("rv-1", &job),
            Err(Error::InvalidState(_))
        ));
    }

    #[test]
    fn production_scope_is_derived_from_cluster_tls_and_namespace() {
        let first = kube::Config::new("http://127.0.0.1:18080".parse().unwrap());
        let mut changed_tls = kube::Config::new("http://127.0.0.1:18080".parse().unwrap());
        changed_tls.root_cert = Some(vec![b"test-root".to_vec()]);
        let other_cluster = kube::Config::new("http://127.0.0.1:18081".parse().unwrap());
        let mut changed_validation = kube::Config::new("http://127.0.0.1:18080".parse().unwrap());
        changed_validation.accept_invalid_certs = true;
        let mut changed_auth = kube::Config::new("http://127.0.0.1:18080".parse().unwrap());
        changed_auth.auth_info.token = Some("test-auth-material".into());
        let a = provider_scope_from_config(&first, "workspaces").unwrap();
        let b = provider_scope_from_config(&changed_tls, "workspaces").unwrap();
        let c = provider_scope_from_config(&other_cluster, "workspaces").unwrap();
        let d = provider_scope_from_config(
            &kube::Config::new("http://127.0.0.1:18080".parse().unwrap()),
            "other-workspaces",
        )
        .unwrap();
        let e = provider_scope_from_config(&changed_validation, "workspaces").unwrap();
        let f = provider_scope_from_config(&changed_auth, "workspaces").unwrap();
        assert!(a.starts_with("kubernetes:v1:"));
        assert_eq!(a.len(), "kubernetes:v1:".len() + 64);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);
        assert_eq!(a, f);
        assert!(!a.contains("127.0.0.1"));
    }
}

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod test_common;

#[cfg(test)]
#[path = "../tests/claim.rs"]
mod claim_tests;
#[cfg(test)]
#[path = "../tests/cleanup.rs"]
mod cleanup_tests;
#[cfg(test)]
#[path = "../tests/create_conflict.rs"]
mod create_conflict_tests;
#[cfg(test)]
#[path = "../tests/create.rs"]
mod create_tests;
#[cfg(test)]
#[path = "../tests/job_cas.rs"]
mod job_cas_tests;

fn validate_claim(job: &Job, receipt: &ExecutionClaimReceipt) -> Result<()> {
    let annotations = job
        .metadata
        .annotations
        .as_ref()
        .ok_or(Error::OwnershipMismatch)?;
    let receipt_digest = digest(&receipt.token);
    if annotations.get(EXECUTION_CLAIM_TOKEN_DIGEST_ANNOTATION) != Some(&receipt_digest)
        || annotations.get(CONSUMER_BOOT_ID_ANNOTATION) != Some(&receipt.consumer_boot_id)
        || annotations.get(EXECUTION_SPEC_DIGEST_ANNOTATION) != Some(&receipt.execution_spec_digest)
    {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}
