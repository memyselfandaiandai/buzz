use crate::test_common as common;

use buzz_workspace_kubernetes::{Error, InertJobIdentity, KubernetesJobControl, ProviderFence};
use common::{provider_job, JOB_SPEC_DIGEST};
use http::{Request, Response};
use k8s_openapi::api::batch::v1::Job;
use kube::{client::Body, Client};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tower::service_fn;

type RequestLog = Arc<Mutex<Vec<(String, Value)>>>;

fn control_with_response(response: Value) -> (KubernetesJobControl, RequestLog) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&requests);
    let service = service_fn(move |request: Request<Body>| {
        let observed = Arc::clone(&observed);
        let response = response.clone();
        async move {
            let method = request.method().to_string();
            let bytes = request.into_body().collect_bytes().await.unwrap();
            let body = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            observed.lock().unwrap().push((method, body));
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

fn template(suspended: bool) -> Job {
    serde_json::from_value(json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "caller-name",
            "namespace": "caller-namespace",
            "uid": "caller-predicted-uid",
            "resourceVersion": "caller-predicted-rv",
            "generation": 99,
            "annotations": {
                "unrelated-secret": "raw-bearer-placeholder",
                "buzz.final-form/launch-epoch": "999"
            }
        },
        "spec": {
            "suspend": suspended,
            "template": {
                "metadata": {
                    "annotations": {"pod-secret": "raw-bearer-placeholder"},
                    "labels": {"pod-secret": "raw-bearer-placeholder"}
                },
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [{"name": "workspace", "image": "example.invalid/workspace@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
                }
            }
        }
    }))
    .unwrap()
}

#[tokio::test]
async fn create_sanitizes_metadata_and_returns_only_provider_generated_identity() {
    let created = provider_job(json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "workspace-1",
            "namespace": "workspaces",
            "uid": "provider-uid-1",
            "resourceVersion": "opaque-rv-17",
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
    }));
    let (control, requests) = control_with_response(created);
    let fence = control
        .create_inert("workspace-1", &identity(), &template(true))
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
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "POST");
    let metadata = &requests[0].1["metadata"];
    assert_eq!(metadata["name"], "workspace-1");
    assert!(metadata.get("uid").is_none());
    assert!(metadata.get("resourceVersion").is_none());
    assert!(metadata.get("generation").is_none());
    assert_eq!(requests[0].1["spec"]["suspend"], true);
    let pod_metadata = &requests[0].1["spec"]["template"]["metadata"];
    assert!(pod_metadata.get("annotations").is_none());
    assert!(pod_metadata.get("labels").is_none());
    let annotations = metadata["annotations"].as_object().unwrap();
    assert_eq!(annotations.len(), 8);
    assert_eq!(
        annotations["buzz.final-form/create-operation-key"],
        "create-op-1"
    );
    assert_eq!(
        annotations["buzz.final-form/delete-operation-key"],
        "delete-op-1"
    );
    let spec_digest = annotations["buzz.final-form/job-spec-digest"]
        .as_str()
        .unwrap();
    assert_eq!(spec_digest.len(), 64);
    assert!(spec_digest
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
}

#[tokio::test]
async fn caller_job_selector_fails_before_kubernetes_mutation() {
    let (control, requests) = control_with_response(Value::Null);
    let mut selected = template(true);
    let spec = selected.spec.as_mut().unwrap();
    spec.manual_selector = Some(true);
    spec.selector = Some(Default::default());

    assert!(matches!(
        control
            .create_inert("workspace-1", &identity(), &selected)
            .await,
        Err(Error::InvalidState(
            "workspace Job template cannot supply a selector"
        ))
    ));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unsuspended_template_fails_before_kubernetes_mutation() {
    let (control, requests) = control_with_response(Value::Null);
    assert!(matches!(
        control
            .create_inert("workspace-1", &identity(), &template(false))
            .await,
        Err(Error::InvalidState(
            "workspace Job template is not suspended"
        ))
    ));
    assert!(requests.lock().unwrap().is_empty());
}
