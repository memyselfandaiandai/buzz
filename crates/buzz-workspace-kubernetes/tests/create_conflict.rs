use crate::test_common as common;

use buzz_workspace_kubernetes::{Error, InertJobIdentity, KubernetesJobControl, ProviderFence};
use common::{provider_job, JOB_SPEC_DIGEST};
use http::{Request, Response, StatusCode};
use k8s_openapi::api::batch::v1::Job;
use kube::{client::Body, Client};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tower::service_fn;

fn control_with_responses(
    responses: Vec<(StatusCode, Value)>,
) -> (KubernetesJobControl, Arc<Mutex<Vec<String>>>) {
    let methods = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&methods);
    let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
    let service = service_fn(move |request: Request<Body>| {
        let observed = Arc::clone(&observed);
        let responses = Arc::clone(&responses);
        async move {
            observed.lock().unwrap().push(request.method().to_string());
            let (status, body) = responses.lock().unwrap().pop_front().unwrap();
            Ok::<_, Infallible>(
                Response::builder()
                    .status(status)
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
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
        methods,
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

fn template() -> Job {
    serde_json::from_value(json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
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
    .unwrap()
}

fn already_exists() -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Status",
        "status": "Failure",
        "message": "jobs.batch workspace-1 already exists",
        "reason": "AlreadyExists",
        "code": 409
    })
}

fn unrelated_conflict() -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Status",
        "status": "Failure",
        "message": "admission policy rejected the request",
        "reason": "Conflict",
        "code": 409
    })
}

fn existing(create_operation_key: &str) -> Value {
    provider_job(json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "workspace-1",
            "namespace": "workspaces",
            "uid": "provider-uid-1",
            "resourceVersion": "opaque-rv-11",
            "generation": 1,
            "annotations": {
                "buzz.final-form/session-id": "session-1",
                "buzz.final-form/workspace-id": "workspace-1",
                "buzz.final-form/owner-id": "owner-1",
                "buzz.final-form/capability-digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "buzz.final-form/provider-scope": "kubernetes:test:default",
                "buzz.final-form/create-operation-key": create_operation_key
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
async fn already_exists_adopts_only_exact_owned_inert_job() {
    let (control, methods) = control_with_responses(vec![
        (StatusCode::CONFLICT, already_exists()),
        (StatusCode::OK, existing("create-op-1")),
    ]);
    let fence = control
        .create_inert("workspace-1", &identity(), &template())
        .await
        .unwrap();
    assert_eq!(
        fence,
        ProviderFence {
            uid: "provider-uid-1".into(),
            generation: 1,
            job_spec_digest: JOB_SPEC_DIGEST.into(),
        }
    );
    assert_eq!(&*methods.lock().unwrap(), &["POST", "GET"]);
}

#[tokio::test]
async fn already_exists_with_foreign_operation_key_fails_closed() {
    let (control, methods) = control_with_responses(vec![
        (StatusCode::CONFLICT, already_exists()),
        (StatusCode::OK, existing("create:foreign")),
    ]);
    assert!(matches!(
        control
            .create_inert("workspace-1", &identity(), &template())
            .await,
        Err(Error::OwnershipMismatch)
    ));
    assert_eq!(&*methods.lock().unwrap(), &["POST", "GET"]);
}

#[tokio::test]
async fn already_exists_with_stale_execution_metadata_fails_closed() {
    let mut stale = existing("create-op-1");
    stale["metadata"]["annotations"]["buzz.final-form/launch-epoch"] = json!("7");
    let (control, methods) = control_with_responses(vec![
        (StatusCode::CONFLICT, already_exists()),
        (StatusCode::OK, stale),
    ]);
    assert!(matches!(
        control
            .create_inert("workspace-1", &identity(), &template())
            .await,
        Err(Error::InvalidState(_))
    ));
    assert_eq!(&*methods.lock().unwrap(), &["POST", "GET"]);
}

#[tokio::test]
async fn already_exists_with_prior_run_status_fails_closed() {
    let mut completed = existing("create-op-1");
    completed["status"] = json!({"succeeded": 1});
    let (control, methods) = control_with_responses(vec![
        (StatusCode::CONFLICT, already_exists()),
        (StatusCode::OK, completed),
    ]);
    assert!(matches!(
        control
            .create_inert("workspace-1", &identity(), &template())
            .await,
        Err(Error::InvalidState(_))
    ));
    assert_eq!(&*methods.lock().unwrap(), &["POST", "GET"]);
}

#[tokio::test]
async fn already_exists_with_generation_two_fails_closed() {
    let mut replaced = existing("create-op-1");
    replaced["metadata"]["generation"] = json!(2);
    let (control, methods) = control_with_responses(vec![
        (StatusCode::CONFLICT, already_exists()),
        (StatusCode::OK, replaced),
    ]);
    assert!(matches!(
        control
            .create_inert("workspace-1", &identity(), &template())
            .await,
        Err(Error::InvalidState(_))
    ));
    assert_eq!(&*methods.lock().unwrap(), &["POST", "GET"]);
}

#[tokio::test]
async fn already_exists_with_uncounted_terminated_pods_fails_closed() {
    let mut prior = existing("create-op-1");
    prior["status"] = json!({
        "uncountedTerminatedPods": {"succeeded": ["prior-pod-uid"]}
    });
    let (control, methods) = control_with_responses(vec![
        (StatusCode::CONFLICT, already_exists()),
        (StatusCode::OK, prior),
    ]);
    assert!(matches!(
        control
            .create_inert("workspace-1", &identity(), &template())
            .await,
        Err(Error::InvalidState(_))
    ));
    assert_eq!(&*methods.lock().unwrap(), &["POST", "GET"]);
}

#[tokio::test]
async fn unrelated_http_409_is_not_treated_as_already_exists() {
    let (control, methods) =
        control_with_responses(vec![(StatusCode::CONFLICT, unrelated_conflict())]);
    assert!(matches!(
        control
            .create_inert("workspace-1", &identity(), &template())
            .await,
        Err(Error::Kubernetes(_))
    ));
    assert_eq!(&*methods.lock().unwrap(), &["POST"]);
}

#[tokio::test]
async fn already_exists_with_self_consistent_but_altered_job_spec_fails_closed() {
    let mut altered = existing("create-op-1");
    altered["spec"]["template"]["spec"]["containers"][0]["image"] =
        json!("example.invalid/foreign@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let altered = provider_job(altered);
    let (control, methods) = control_with_responses(vec![
        (StatusCode::CONFLICT, already_exists()),
        (StatusCode::OK, altered),
    ]);

    assert!(matches!(
        control
            .create_inert("workspace-1", &identity(), &template())
            .await,
        Err(Error::OwnershipMismatch)
    ));
    assert_eq!(&*methods.lock().unwrap(), &["POST", "GET"]);
}

#[tokio::test]
async fn already_exists_with_wrong_namespace_fails_closed() {
    let mut wrong_namespace = existing("create-op-1");
    wrong_namespace["metadata"]["namespace"] = json!("foreign");
    let (control, methods) = control_with_responses(vec![
        (StatusCode::CONFLICT, already_exists()),
        (StatusCode::OK, wrong_namespace),
    ]);

    assert!(matches!(
        control
            .create_inert("workspace-1", &identity(), &template())
            .await,
        Err(Error::OwnershipMismatch)
    ));
    assert_eq!(&*methods.lock().unwrap(), &["POST", "GET"]);
}

#[tokio::test]
async fn already_exists_with_foreign_delete_authority_fails_closed() {
    let mut foreign = identity();
    foreign.delete_operation_key = "delete:foreign".into();
    let (control, methods) = control_with_responses(vec![
        (StatusCode::CONFLICT, already_exists()),
        (StatusCode::OK, existing("create-op-1")),
    ]);

    assert!(matches!(
        control
            .create_inert("workspace-1", &foreign, &template())
            .await,
        Err(Error::OwnershipMismatch)
    ));
    assert_eq!(&*methods.lock().unwrap(), &["POST", "GET"]);
}

#[tokio::test]
async fn already_exists_with_unknown_reserved_annotation_fails_closed() {
    let mut collision = existing("create-op-1");
    collision["metadata"]["annotations"]["buzz.final-form/future-control"] = json!("foreign");
    let (control, methods) = control_with_responses(vec![
        (StatusCode::CONFLICT, already_exists()),
        (StatusCode::OK, collision),
    ]);

    assert!(matches!(
        control
            .create_inert("workspace-1", &identity(), &template())
            .await,
        Err(Error::OwnershipMismatch)
    ));
    assert_eq!(&*methods.lock().unwrap(), &["POST", "GET"]);
}
