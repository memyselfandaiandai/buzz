use crate::test_common as common;

use buzz_workspace_kubernetes::{ActivationProjection, Error, KubernetesJobControl, ProviderFence};
use common::{provider_job, JOB_SPEC_DIGEST};
use http::{Request, Response};
use kube::{client::Body, Client};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tower::service_fn;

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[tokio::test]
async fn activation_tests_uid_resource_version_and_suspended_state_before_mutation() {
    let requests = Arc::new(Mutex::new(Vec::<(String, String, Value)>::new()));
    let observed = Arc::clone(&requests);
    let service = service_fn(move |request: Request<Body>| {
        let observed = Arc::clone(&observed);
        async move {
            let method = request.method().to_string();
            let uri = request.uri().to_string();
            let body = request.into_body().collect_bytes().await.unwrap();
            let body = if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&body).unwrap()
            };
            observed.lock().unwrap().push((method.clone(), uri, body));
            let response = if method == "GET" {
                json!({
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "metadata": {
                        "name": "workspace-1",
                        "namespace": "workspaces",
                        "uid": "uid-1",
                        "resourceVersion": "rv-opaque-17",
                        "generation": 1,
                        "annotations": {
                            "buzz.final-form/session-id": "session-1",
                            "buzz.final-form/workspace-id": "workspace-1",
                            "buzz.final-form/owner-id": "owner-1",
                            "buzz.final-form/capability-digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                            "buzz.final-form/provider-scope": "cluster-a/workspaces",
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
                })
            } else {
                json!({
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "metadata": {
                        "name": "workspace-1",
                        "namespace": "workspaces",
                        "uid": "uid-1",
                        "resourceVersion": "rv-opaque-18",
                        "generation": 1,
                        "annotations": {
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
                        }
                    },
                    "spec": {"suspend": true, "template": {"spec": {"restartPolicy": "Never", "containers": [{"name": "workspace", "image": "example.invalid/workspace@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}}
                })
            };
            let response = provider_job(response);
            Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .body(Body::from(serde_json::to_vec(&response).unwrap()))
                    .unwrap(),
            )
        }
    });
    let control = KubernetesJobControl::new_for_test(
        Client::new(service, "ignored"),
        "workspaces",
        "cluster-a/workspaces",
    );
    let fence = ProviderFence {
        uid: "uid-1".into(),
        generation: 1,
        job_spec_digest: JOB_SPEC_DIGEST.into(),
    };
    let projection = ActivationProjection {
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
    };

    control
        .activate("workspace-1", &fence, &projection)
        .await
        .unwrap();

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].0, "GET");
    assert_eq!(requests[1].0, "PATCH");
    assert_eq!(
        requests[1].1,
        "/apis/batch/v1/namespaces/workspaces/jobs/workspace-1?"
    );
    assert_eq!(
        requests[1].2,
        json!([
            {"op": "test", "path": "/metadata/uid", "value": "uid-1"},
            {"op": "test", "path": "/metadata/resourceVersion", "value": "rv-opaque-17"},
            {"op": "test", "path": "/metadata/generation", "value": 1},
            {"op": "test", "path": "/spec/suspend", "value": true},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1launch-epoch", "value": "7"},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1activation-token-digest", "value": digest("activation-token")},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1activation-operation-key", "value": "activate-op-1"},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1task-input-digest", "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            {"op": "add", "path": "/metadata/annotations/buzz.final-form~1execution-spec-digest", "value": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
        ])
    );
}

fn replay_projection() -> ActivationProjection {
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

async fn activation_retry(
    token: &str,
    owner: &str,
    deleting: bool,
    partial_claim: bool,
    alter_spec: bool,
) -> (buzz_workspace_kubernetes::Result<()>, usize) {
    let calls = Arc::new(Mutex::new(0));
    let observed = Arc::clone(&calls);
    let token = token.to_owned();
    let owner = owner.to_owned();
    let service = service_fn(move |request: Request<Body>| {
        let observed = Arc::clone(&observed);
        let token = token.clone();
        let owner = owner.clone();
        async move {
            let is_get = request.method() == http::Method::GET;
            request.into_body().collect_bytes().await.unwrap();
            *observed.lock().unwrap() += 1;
            let mut response = json!({
                "apiVersion": "batch/v1", "kind": "Job",
                "metadata": {"name": "workspace-1", "namespace": "workspaces", "uid": "uid-1", "resourceVersion": "rv-18", "generation": 1,
                    "annotations": {"buzz.final-form/session-id": "session-1", "buzz.final-form/workspace-id": "workspace-1",
                            "buzz.final-form/owner-id": owner,
                            "buzz.final-form/capability-digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                            "buzz.final-form/provider-scope": "cluster-a/workspaces",
                            "buzz.final-form/create-operation-key": "create-op-1",
                        "buzz.final-form/launch-epoch": "7", "buzz.final-form/activation-token-digest": digest(&token),
                        "buzz.final-form/activation-operation-key": "activate-op-1",
                        "buzz.final-form/task-input-digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "buzz.final-form/execution-spec-digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
                "spec": {"suspend": true, "template": {"spec": {"restartPolicy": "Never", "containers": [{"name": "workspace", "image": "example.invalid/workspace@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}}
            });
            if alter_spec {
                response["spec"]["template"]["spec"]["containers"] = json!([]);
            }
            if deleting {
                response["metadata"]["deletionTimestamp"] = json!("2026-08-15T00:00:00Z");
            }
            if partial_claim && is_get {
                for key in [
                    "buzz.final-form/launch-epoch",
                    "buzz.final-form/activation-token-digest",
                    "buzz.final-form/activation-operation-key",
                    "buzz.final-form/task-input-digest",
                    "buzz.final-form/execution-spec-digest",
                ] {
                    response["metadata"]["annotations"]
                        .as_object_mut()
                        .unwrap()
                        .remove(key);
                }
            } else if partial_claim {
                response["metadata"]["annotations"]["buzz.final-form/consumer-boot-id"] =
                    json!("worker-boot-1");
            }
            let response = provider_job(response);
            Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .body(Body::from(serde_json::to_vec(&response).unwrap()))
                    .unwrap(),
            )
        }
    });
    let control = KubernetesJobControl::new_for_test(
        Client::new(service, "ignored"),
        "workspaces",
        "cluster-a/workspaces",
    );
    let result = control
        .activate(
            "workspace-1",
            &ProviderFence {
                uid: "uid-1".into(),
                generation: 1,
                job_spec_digest: JOB_SPEC_DIGEST.into(),
            },
            &replay_projection(),
        )
        .await;
    let count = *calls.lock().unwrap();
    (result, count)
}

#[tokio::test]
async fn exact_activation_retry_is_read_only() {
    let (result, calls) =
        activation_retry("activation-token", "owner-1", false, false, false).await;
    result.unwrap();
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn activation_retry_rejects_self_consistent_spec_drift_against_durable_fence() {
    let (result, calls) = activation_retry("activation-token", "owner-1", false, false, true).await;
    assert!(matches!(result, Err(Error::OwnershipMismatch)));
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn activation_retry_rejects_partial_claim_annotations() {
    let (result, calls) = activation_retry("activation-token", "owner-1", false, true, false).await;
    assert!(matches!(result, Err(Error::InvalidState(_))));
    assert_eq!(calls, 2);
}

#[tokio::test]
async fn conflicting_activation_fails_before_patch() {
    let (result, calls) = activation_retry("foreign-token", "owner-1", false, false, false).await;
    assert!(matches!(result, Err(Error::OwnershipMismatch)));
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn foreign_owner_fails_before_activation_patch() {
    let (result, calls) =
        activation_retry("activation-token", "foreign-owner", false, false, false).await;
    assert!(matches!(result, Err(Error::OwnershipMismatch)));
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn deleting_job_fails_before_activation_patch() {
    let (result, calls) = activation_retry("activation-token", "owner-1", true, false, false).await;
    assert!(matches!(result, Err(Error::InvalidState(_))));
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn noncanonical_digest_fails_before_kubernetes_request() {
    let calls = Arc::new(Mutex::new(0_u32));
    let observed = Arc::clone(&calls);
    let service = service_fn(move |_request: Request<Body>| {
        let observed = Arc::clone(&observed);
        async move {
            *observed.lock().unwrap() += 1;
            Ok::<_, Infallible>(Response::builder().status(500).body(Body::empty()).unwrap())
        }
    });
    let control = KubernetesJobControl::new_for_test(
        Client::new(service, "ignored"),
        "workspaces",
        "cluster-a/workspaces",
    );
    let mut projection = replay_projection();
    projection.task_input_digest = "g".repeat(64);
    let result = control
        .activate(
            "workspace-1",
            &ProviderFence {
                uid: "uid-1".into(),
                generation: 1,
                job_spec_digest: JOB_SPEC_DIGEST.into(),
            },
            &projection,
        )
        .await;
    assert!(matches!(result, Err(Error::InvalidState(_))));
    assert_eq!(*calls.lock().unwrap(), 0);
}
