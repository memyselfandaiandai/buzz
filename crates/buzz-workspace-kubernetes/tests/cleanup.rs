use crate::test_common as common;

use buzz_workspace_kubernetes::{
    Error, InertJobIdentity, JobObservation, KubernetesJobControl, ProviderFence,
};
use common::{provider_job, JOB_SPEC_DIGEST};
use http::{Request, Response};
use kube::{client::Body, Client};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tower::service_fn;

type RecordedRequest = (String, Value);

fn control_with_responses(
    responses: Vec<(u16, Value)>,
) -> (KubernetesJobControl, Arc<Mutex<Vec<RecordedRequest>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&requests);
    let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
    let service = service_fn(move |request: Request<Body>| {
        let observed = Arc::clone(&observed);
        let responses = Arc::clone(&responses);
        async move {
            let method = request.method().to_string();
            let bytes = request.into_body().collect_bytes().await.unwrap();
            let body = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            observed.lock().unwrap().push((method, body));
            let (status, response) = responses.lock().unwrap().pop_front().unwrap();
            Ok::<_, Infallible>(
                Response::builder()
                    .status(status)
                    .body(Body::from(serde_json::to_vec(&response).unwrap()))
                    .unwrap(),
            )
        }
    });
    (
        KubernetesJobControl::new_for_test(
            Client::new(service, "ignored"),
            "workspaces",
            "kubernetes:test:default",
        ),
        requests,
    )
}

fn identity() -> InertJobIdentity {
    InertJobIdentity {
        session_id: "session-1".into(),
        workspace_id: "workspace-1".into(),
        owner_id: "owner-1".into(),
        capability_digest: "a".repeat(64),
        provider_scope: "kubernetes:test:default".into(),
        create_operation_key: "create-op-1".into(),
        delete_operation_key: "delete-op-1".into(),
    }
}

fn job(uid: &str, resource_version: &str) -> Value {
    provider_job(json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "workspace-1",
            "namespace": "workspaces",
            "uid": uid,
            "resourceVersion": resource_version,
            "generation": 1,
            "annotations": {
                "buzz.final-form/session-id": "session-1",
                "buzz.final-form/workspace-id": "workspace-1",
                "buzz.final-form/owner-id": "owner-1",
                "buzz.final-form/capability-digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "buzz.final-form/provider-scope": "kubernetes:test:default",
                "buzz.final-form/create-operation-key": "create-op-1"
            }
        },
        "spec": {
            "suspend": true,
            "template": {
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [{"name": "workspace", "image": "example.invalid/workspace@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
                }
            }
        }
    }))
}

#[tokio::test]
async fn cleanup_uses_exact_uid_and_resource_version_delete_preconditions() {
    let (control, requests) = control_with_responses(vec![
        (200, job("uid-1", "opaque-rv-21")),
        (
            200,
            json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Success",
                "code": 200
            }),
        ),
    ]);
    control
        .request_delete_owned(
            "workspace-1",
            &ProviderFence {
                uid: "uid-1".into(),
                generation: 1,
                job_spec_digest: JOB_SPEC_DIGEST.into(),
            },
            &identity(),
        )
        .await
        .unwrap();

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].0, "DELETE");
    assert_eq!(
        requests[1].1["preconditions"],
        json!({"uid": "uid-1", "resourceVersion": "opaque-rv-21"})
    );
    assert_eq!(requests[1].1["propagationPolicy"], json!("Foreground"));
}

#[tokio::test]
async fn replacement_uid_stops_cleanup_before_delete() {
    let (control, requests) = control_with_responses(vec![(200, job("replacement-uid", "rv-22"))]);
    assert!(matches!(
        control
            .request_delete_owned(
                "workspace-1",
                &ProviderFence {
                    uid: "uid-1".into(),
                    generation: 1,
                    job_spec_digest: JOB_SPEC_DIGEST.into(),
                },
                &identity(),
            )
            .await,
        Err(Error::OwnershipMismatch)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn terminating_job_rejects_delete_before_delete_request() {
    let mut terminating = job("uid-1", "rv-terminating");
    terminating["metadata"]["deletionTimestamp"] = json!("2026-08-15T00:00:00Z");
    let (control, requests) = control_with_responses(vec![(200, terminating)]);
    let fence = ProviderFence {
        uid: "uid-1".into(),
        generation: 1,
        job_spec_digest: JOB_SPEC_DIGEST.into(),
    };
    assert!(matches!(
        control
            .request_delete_owned("workspace-1", &fence, &identity())
            .await,
        Err(Error::InvalidState(_))
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn observation_distinguishes_owned_suspended_and_absent() {
    let fence = ProviderFence {
        uid: "uid-1".into(),
        generation: 1,
        job_spec_digest: JOB_SPEC_DIGEST.into(),
    };
    let (control, requests) = control_with_responses(vec![(200, job("uid-1", "opaque-rv-22"))]);
    assert_eq!(
        control
            .observe_owned("workspace-1", &fence, &identity())
            .await
            .unwrap(),
        JobObservation::Suspended
    );
    assert_eq!(requests.lock().unwrap().len(), 1);

    let not_found = json!({
        "status": "Failure", "message": "jobs.batch \"workspace-1\" not found",
        "reason": "NotFound", "code": 404
    });
    let (control, requests) = control_with_responses(vec![(404, not_found)]);
    assert_eq!(
        control
            .observe_owned("workspace-1", &fence, &identity())
            .await
            .unwrap(),
        JobObservation::Absent
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn observation_reports_deleting_and_rejects_runnable_state() {
    let fence = ProviderFence {
        uid: "uid-1".into(),
        generation: 1,
        job_spec_digest: JOB_SPEC_DIGEST.into(),
    };
    let mut deleting = job("uid-1", "rv-23");
    deleting["metadata"]["deletionTimestamp"] = json!("2026-08-15T00:00:00Z");
    let (control, _) = control_with_responses(vec![(200, deleting)]);
    assert_eq!(
        control
            .observe_owned("workspace-1", &fence, &identity())
            .await
            .unwrap(),
        JobObservation::Deleting
    );

    let mut runnable = job("uid-1", "rv-24");
    runnable["spec"]["suspend"] = json!(false);
    let runnable = provider_job(runnable);
    let (control, _) = control_with_responses(vec![(200, runnable)]);
    assert!(matches!(
        control
            .observe_owned("workspace-1", &fence, &identity())
            .await,
        Err(Error::OwnershipMismatch)
    ));
}

#[tokio::test]
async fn observation_rejects_partial_activation_metadata() {
    let fence = ProviderFence {
        uid: "uid-1".into(),
        generation: 1,
        job_spec_digest: JOB_SPEC_DIGEST.into(),
    };
    let mut partial = job("uid-1", "rv-25");
    partial["metadata"]["annotations"]["buzz.final-form/launch-epoch"] = json!("7");
    let (control, requests) = control_with_responses(vec![(200, partial)]);
    assert!(matches!(
        control
            .observe_owned("workspace-1", &fence, &identity())
            .await,
        Err(Error::InvalidState(_))
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn observation_classifies_complete_activation_and_claim_phases() {
    let fence = ProviderFence {
        uid: "uid-1".into(),
        generation: 1,
        job_spec_digest: JOB_SPEC_DIGEST.into(),
    };
    let mut activated = job("uid-1", "opaque-rv-activation");
    for (key, value) in [
        ("buzz.final-form/launch-epoch", "7"),
        ("buzz.final-form/activation-token-digest", JOB_SPEC_DIGEST),
        ("buzz.final-form/activation-operation-key", "activate-op-7"),
        ("buzz.final-form/task-input-digest", JOB_SPEC_DIGEST),
        ("buzz.final-form/execution-spec-digest", JOB_SPEC_DIGEST),
    ] {
        activated["metadata"]["annotations"][key] = json!(value);
    }
    let mut claimed = activated.clone();
    claimed["metadata"]["resourceVersion"] = json!("opaque-rv-claim");
    claimed["metadata"]["annotations"]["buzz.final-form/execution-claim-token-digest"] =
        json!(JOB_SPEC_DIGEST);
    claimed["metadata"]["annotations"]["buzz.final-form/consumer-boot-id"] = json!("worker-boot-1");
    let (control, _) = control_with_responses(vec![(200, activated), (200, claimed)]);

    assert_eq!(
        control
            .observe_owned("workspace-1", &fence, &identity())
            .await
            .unwrap(),
        JobObservation::Activated
    );
    assert_eq!(
        control
            .observe_owned("workspace-1", &fence, &identity())
            .await
            .unwrap(),
        JobObservation::Claimed
    );
}

#[tokio::test]
async fn generic_typed_not_found_does_not_prove_exact_object_absence() {
    let substituted = json!({
        "status": "Failure", "message": "not found", "reason": "NotFound", "code": 404
    });
    let (control, requests) = control_with_responses(vec![(404, substituted)]);
    let result = control
        .observe_owned(
            "workspace-1",
            &ProviderFence {
                uid: "uid-1".into(),
                generation: 1,
                job_spec_digest: JOB_SPEC_DIGEST.into(),
            },
            &identity(),
        )
        .await;
    assert!(matches!(result, Err(Error::Kubernetes(_))));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn malformed_identity_fails_before_observation_request() {
    let (control, requests) = control_with_responses(vec![]);
    let mut malformed = identity();
    malformed.delete_operation_key.clear();
    let fence = ProviderFence {
        uid: "uid-1".into(),
        generation: 1,
        job_spec_digest: JOB_SPEC_DIGEST.into(),
    };
    assert!(matches!(
        control
            .observe_owned("workspace-1", &fence, &malformed)
            .await,
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(
        control
            .request_delete_owned("workspace-1", &fence, &malformed)
            .await,
        Err(Error::InvalidState(_))
    ));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn provider_scope_drift_fails_before_kubernetes_request() {
    let (control, requests) = control_with_responses(vec![]);
    let mut drifted = identity();
    drifted.provider_scope = "kubernetes:test:other".into();
    let fence = ProviderFence {
        uid: "uid-1".into(),
        generation: 1,
        job_spec_digest: JOB_SPEC_DIGEST.into(),
    };

    assert!(matches!(
        control.observe_owned("workspace-1", &fence, &drifted).await,
        Err(Error::OwnershipMismatch)
    ));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn durable_job_spec_fence_rejects_drifted_owned_job() {
    let (control, requests) = control_with_responses(vec![(200, job("uid-1", "rv-26"))]);
    let fence = ProviderFence {
        uid: "uid-1".into(),
        generation: 1,
        job_spec_digest: "d".repeat(64),
    };

    assert!(matches!(
        control
            .observe_owned("workspace-1", &fence, &identity())
            .await,
        Err(Error::OwnershipMismatch)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}
