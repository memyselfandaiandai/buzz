use crate::test_common as common;

use buzz_workspace_kubernetes::{
    ActivationProjection, Error, ExecutionClaimProjection, KubernetesJobControl, ProviderFence,
};
use common::{provider_job, JOB_SPEC_DIGEST};
use http::{Request, Response};
use kube::{client::Body, Client};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tower::service_fn;

type RecordedRequest = (String, String, Value);

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn claim_token(consumer_boot_id: &str) -> String {
    claim_token_for("uid-1", 1, consumer_boot_id)
}

fn claim_token_for(uid: &str, generation: i64, consumer_boot_id: &str) -> String {
    let mut hasher = Sha256::new();
    let launch_epoch = "7";
    let provider_generation = generation.to_string();
    let task_input_digest = "a".repeat(64);
    let execution_spec_digest = "b".repeat(64);
    for part in [
        "buzz/workspace-execution-claim/v1",
        "session-1",
        "workspace-1",
        "owner-1",
        &"c".repeat(64),
        "cluster-a/workspaces",
        "create-op-1",
        "delete-op-1",
        "workspace-1",
        "workspaces",
        uid,
        &provider_generation,
        JOB_SPEC_DIGEST,
        launch_epoch,
        "activation-token",
        "activate-op-1",
        &task_input_digest,
        &execution_spec_digest,
        consumer_boot_id,
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn control_with_responses(
    responses: Vec<Value>,
) -> (KubernetesJobControl, Arc<Mutex<Vec<RecordedRequest>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&requests);
    let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
    let service = service_fn(move |request: Request<Body>| {
        let observed = Arc::clone(&observed);
        let responses = Arc::clone(&responses);
        async move {
            let method = request.method().to_string();
            let uri = request.uri().to_string();
            let body = request.into_body().collect_bytes().await.unwrap();
            let body = if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&body).unwrap()
            };
            let mut response = responses.lock().unwrap().pop_front().unwrap();
            if method == "PATCH" {
                for operation in body.as_array().into_iter().flatten() {
                    let annotation = match operation["path"].as_str() {
                        Some(
                            "/metadata/annotations/buzz.final-form~1execution-claim-token-digest",
                        ) => Some("buzz.final-form/execution-claim-token-digest"),
                        Some("/metadata/annotations/buzz.final-form~1consumer-boot-id") => {
                            Some("buzz.final-form/consumer-boot-id")
                        }
                        _ => None,
                    };
                    if let (Some(annotation), Some(value)) = (annotation, operation.get("value")) {
                        response["metadata"]["annotations"][annotation] = value.clone();
                    }
                }
            }
            observed.lock().unwrap().push((method, uri, body));
            Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .body(Body::from(serde_json::to_vec(&response).unwrap()))
                    .unwrap(),
            )
        }
    });
    (
        KubernetesJobControl::new_for_test(
            Client::new(service, "ignored"),
            "workspaces",
            "cluster-a/workspaces",
        ),
        requests,
    )
}

fn activation() -> ActivationProjection {
    ActivationProjection {
        session_id: "session-1".into(),
        workspace_id: "workspace-1".into(),
        owner_id: "owner-1".into(),
        capability_digest: "c".repeat(64),
        provider_scope: "cluster-a/workspaces".into(),
        create_operation_key: "create-op-1".into(),
        delete_operation_key: "delete-op-1".into(),
        launch_epoch: 7,
        activation_token: "activation-token".into(),
        activation_operation_key: "activate-op-1".into(),
        task_input_digest: "a".repeat(64),
        execution_spec_digest: "b".repeat(64),
    }
}

fn claim_projection(consumer_boot_id: &str) -> ExecutionClaimProjection {
    ExecutionClaimProjection {
        activation: activation(),
        consumer_boot_id: consumer_boot_id.into(),
    }
}

fn fence() -> ProviderFence {
    ProviderFence {
        uid: "uid-1".into(),
        generation: 1,
        job_spec_digest: JOB_SPEC_DIGEST.into(),
    }
}

fn job(resource_version: &str, suspended: bool, claim: Option<(&str, &str)>) -> Value {
    let mut annotations = json!({
        "buzz.final-form/session-id": "session-1",
        "buzz.final-form/workspace-id": "workspace-1",
        "buzz.final-form/owner-id": "owner-1",
        "buzz.final-form/capability-digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "buzz.final-form/provider-scope": "cluster-a/workspaces",
        "buzz.final-form/create-operation-key": "create-op-1",
        "buzz.final-form/launch-epoch": "7",
        "buzz.final-form/activation-token-digest": digest("activation-token"),
        "buzz.final-form/activation-operation-key": "activate-op-1",
        "buzz.final-form/task-input-digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "buzz.final-form/execution-spec-digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    });
    if let Some((token, consumer)) = claim {
        annotations["buzz.final-form/execution-claim-token-digest"] = json!(digest(token));
        annotations["buzz.final-form/consumer-boot-id"] = json!(consumer);
    }
    provider_job(json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "workspace-1",
            "namespace": "workspaces",
            "uid": "uid-1",
            "resourceVersion": resource_version,
            "generation": 1,
            "annotations": annotations
        },
        "spec": {
            "suspend": suspended,
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
async fn first_execution_claim_is_one_use_and_keeps_job_suspended() {
    let (control, requests) =
        control_with_responses(vec![job("rv-18", true, None), job("rv-19", true, None)]);
    let receipt = control
        .claim_execution("workspace-1", &fence(), &claim_projection("boot-1"))
        .await
        .unwrap();

    assert_eq!(receipt.token, claim_token("boot-1"));
    assert_ne!(
        receipt.token,
        claim_token_for("replacement-uid", 1, "boot-1")
    );
    assert_ne!(receipt.token, claim_token_for("uid-1", 2, "boot-1"));
    assert_eq!(receipt.consumer_boot_id, "boot-1");
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].0, "PATCH");
    let operations = requests[1].2.as_array().unwrap();
    assert!(operations.contains(&json!({
        "op": "test",
        "path": "/metadata/resourceVersion",
        "value": "rv-18"
    })));
    assert!(operations.contains(&json!({
        "op": "test",
        "path": "/spec/suspend",
        "value": true
    })));
    assert!(operations.contains(&json!({
        "op": "add",
        "path": "/metadata/annotations/buzz.final-form~1execution-claim-token-digest",
        "value": digest(&receipt.token)
    })));
    assert!(!serde_json::to_string(&requests[1].2)
        .unwrap()
        .contains(&receipt.token));
    assert!(!operations.iter().any(|operation| {
        operation.get("path") == Some(&json!("/spec/suspend"))
            && operation.get("op") == Some(&json!("replace"))
    }));
}

#[tokio::test]
async fn claim_retry_is_same_consumer_idempotent_and_competing_consumer_fails_closed() {
    let token = claim_token("boot-1");
    let (control, requests) =
        control_with_responses(vec![job("rv-19", true, Some((&token, "boot-1")))]);
    let receipt = control
        .claim_execution("workspace-1", &fence(), &claim_projection("boot-1"))
        .await
        .unwrap();
    assert_eq!(receipt.token, token);
    assert_eq!(requests.lock().unwrap().len(), 1);

    let token = claim_token("boot-1");
    let (control, requests) =
        control_with_responses(vec![job("rv-19", true, Some((&token, "boot-1")))]);
    assert!(matches!(
        control
            .claim_execution("workspace-1", &fence(), &claim_projection("boot-2"))
            .await,
        Err(Error::OwnershipMismatch)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn deleting_job_fails_before_execution_claim_patch() {
    let mut deleting = job("rv-19", true, None);
    deleting["metadata"]["deletionTimestamp"] = json!("2026-08-15T00:00:00Z");
    let (control, requests) = control_with_responses(vec![deleting]);
    assert!(matches!(
        control
            .claim_execution("workspace-1", &fence(), &claim_projection("boot-1"))
            .await,
        Err(Error::InvalidState(_))
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}
