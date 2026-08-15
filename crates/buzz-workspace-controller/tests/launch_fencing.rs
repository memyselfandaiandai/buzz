use buzz_workspace_controller::{
    AdmissionRequest, Controller, ControllerError, CrashPoint, Decision, ExecutionSpec,
    FakeKubernetes, Ledger, Lifecycle, ProviderWorkloadState, Scope, TerminalReceipt,
    WorkspaceAdapter,
};
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::tempdir;

const NOW: i64 = 1_900_000_000;
const TASK_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn execution_spec() -> ExecutionSpec {
    ExecutionSpec::new(
        std::env::current_exe().unwrap().to_string_lossy(),
        vec!["--never-executed-in-launch-tests".into()],
        TASK_DIGEST,
    )
    .unwrap()
}

fn request() -> AdmissionRequest {
    AdmissionRequest {
        session_id: "session-1".into(),
        jti: "jti-1".into(),
        capability_digest: "sha256:cap-1".into(),
        owner_id: "agent:alice".into(),
        workspace_id: "workspace-1".into(),
        scope: Scope::Tenant("tenant:acme".into()),
        signed_max_concurrency: 20,
        deployment_max_concurrency: 20,
        artifact_limit_bytes: 100,
        expires_at: 2_000_000_000,
    }
}

fn reopen(root: &std::path::Path) -> Controller<FakeKubernetes> {
    Controller::new(
        Ledger::open(root.join("ledger.db")).unwrap(),
        FakeKubernetes::open(root.join("provider.db")).unwrap(),
    )
}

fn inert(controller: &Controller<FakeKubernetes>) {
    controller.provision_inert(&request(), None).unwrap();
    assert_eq!(
        controller.adapter().workload_state("session-1").unwrap(),
        ProviderWorkloadState::Inert
    );
    assert_eq!(
        controller.ledger().state("session-1").unwrap(),
        Lifecycle::Creating
    );
}

#[test]
fn inert_workload_cannot_redeem_or_receive_task_material_before_activation() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    inert(&controller);
    let capability = controller
        .authorize_launch("session-1", &execution_spec(), NOW + 60, NOW)
        .unwrap();

    assert!(matches!(
        controller.redeem_launch(&capability, "worker-boot-1", &execution_spec(), NOW),
        Err(ControllerError::ActivationNotObserved)
    ));
    assert_eq!(
        controller.ledger().state("session-1").unwrap(),
        Lifecycle::Creating
    );
    assert_eq!(controller.ledger().launch_epoch("session-1").unwrap(), 1);
}

#[test]
fn cancellation_before_or_after_inert_creation_prevents_authorization() {
    let before = tempdir().unwrap();
    let controller = reopen(before.path());
    assert!(matches!(
        controller.provision(&request(), Some(CrashPoint::AfterCreating)),
        Err(ControllerError::SimulatedCrash(CrashPoint::AfterCreating))
    ));
    controller.cancel_session("session-1", "operator").unwrap();
    assert_eq!(controller.adapter().workload_count().unwrap(), 0);

    let after = tempdir().unwrap();
    let controller = reopen(after.path());
    inert(&controller);
    controller.cancel_session("session-1", "operator").unwrap();
    assert!(matches!(
        controller.authorize_launch("session-1", &execution_spec(), NOW + 60, NOW),
        Err(ControllerError::ExecutionAborted)
    ));
    assert_eq!(controller.adapter().workload_count().unwrap(), 0);
}

#[test]
fn cancellation_and_authorization_have_one_ledger_linearization_order() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    inert(&controller);
    let root = dir.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(3));

    let auth_barrier = Arc::clone(&barrier);
    let auth_root = root.clone();
    let auth = thread::spawn(move || {
        let controller = reopen(&auth_root);
        auth_barrier.wait();
        controller.authorize_launch("session-1", &execution_spec(), NOW + 60, NOW)
    });
    let cancel_barrier = Arc::clone(&barrier);
    let cancel_root = root.clone();
    let cancel = thread::spawn(move || {
        let controller = reopen(&cancel_root);
        cancel_barrier.wait();
        controller
            .ledger()
            .request_cancellation("session-1", "race")
    });
    barrier.wait();

    let authorization = auth.join().unwrap();
    cancel.join().unwrap().unwrap();
    let restarted = reopen(&root);
    assert!(restarted
        .ledger()
        .cancellation_requested("session-1")
        .unwrap());
    match authorization {
        Ok(capability) => assert!(matches!(
            restarted.redeem_launch(&capability, "worker-boot-1", &execution_spec(), NOW),
            Err(ControllerError::ActivationRevoked | ControllerError::ExecutionAborted)
        )),
        Err(ControllerError::ExecutionAborted) => {}
        other => panic!("unexpected authorization result: {other:?}"),
    }
}

#[test]
fn cancellation_after_authorization_or_racing_provider_activation_never_redeems() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    inert(&controller);
    let capability = controller
        .authorize_launch("session-1", &execution_spec(), NOW + 60, NOW)
        .unwrap();
    let root = dir.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(3));

    let activate_barrier = Arc::clone(&barrier);
    let activate_root = root.clone();
    let activate_capability = capability.clone();
    let activate = thread::spawn(move || {
        let controller = reopen(&activate_root);
        activate_barrier.wait();
        controller.activate_launch(&activate_capability)
    });
    let cancel_barrier = Arc::clone(&barrier);
    let cancel_root = root.clone();
    let cancel = thread::spawn(move || {
        let controller = reopen(&cancel_root);
        cancel_barrier.wait();
        controller
            .ledger()
            .request_cancellation("session-1", "race")
    });
    barrier.wait();

    let _ = activate.join().unwrap();
    cancel.join().unwrap().unwrap();
    let restarted = reopen(&root);
    assert!(matches!(
        restarted.redeem_launch(&capability, "worker-boot-1", &execution_spec(), NOW),
        Err(ControllerError::ActivationRevoked | ControllerError::ExecutionAborted)
    ));
    restarted.reconcile_session("session-1").unwrap();
    assert_eq!(
        restarted.ledger().state("session-1").unwrap(),
        Lifecycle::Cleaned
    );
    assert_eq!(restarted.adapter().workload_count().unwrap(), 0);
}

#[test]
fn provider_create_and_activation_commit_boundaries_recover_idempotently() {
    let create_dir = tempdir().unwrap();
    let controller = reopen(create_dir.path());
    assert!(matches!(
        controller.provision_inert(&request(), Some(CrashPoint::AfterProviderCreate)),
        Err(ControllerError::SimulatedCrash(
            CrashPoint::AfterProviderCreate
        ))
    ));
    drop(controller);

    let restarted = reopen(create_dir.path());
    restarted.reconcile_session("session-1").unwrap();
    restarted.reconcile_session("session-1").unwrap();
    assert_eq!(
        restarted.ledger().state("session-1").unwrap(),
        Lifecycle::Creating
    );
    assert_eq!(
        restarted.adapter().workload_state("session-1").unwrap(),
        ProviderWorkloadState::Inert
    );
    assert_eq!(
        restarted.adapter().create_mutations("session-1").unwrap(),
        1
    );

    let activation_dir = tempdir().unwrap();
    let controller = reopen(activation_dir.path());
    inert(&controller);
    let capability = controller
        .authorize_launch("session-1", &execution_spec(), NOW + 60, NOW)
        .unwrap();
    drop(controller);

    let restarted = reopen(activation_dir.path());
    restarted.reconcile_session("session-1").unwrap();
    restarted.reconcile_session("session-1").unwrap();
    assert_eq!(
        restarted.ledger().state("session-1").unwrap(),
        Lifecycle::Creating
    );
    assert_eq!(restarted.ledger().launch_epoch("session-1").unwrap(), 1);
    assert_eq!(
        restarted.adapter().workload_state("session-1").unwrap(),
        ProviderWorkloadState::Activated
    );
    assert_eq!(
        restarted
            .adapter()
            .activation_mutations("session-1")
            .unwrap(),
        1
    );
    let _grant = restarted
        .redeem_launch(&capability, "worker-boot-1", &execution_spec(), NOW)
        .unwrap();
    assert_eq!(
        restarted.ledger().state("session-1").unwrap(),
        Lifecycle::Active
    );
}

#[test]
fn activation_success_with_lost_response_is_observed_and_not_repeated() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    inert(&controller);
    controller
        .adapter()
        .lose_next_activation_response_for_test("session-1")
        .unwrap();
    let capability = controller
        .authorize_launch("session-1", &execution_spec(), NOW + 60, NOW)
        .unwrap();
    assert!(controller.activate_launch(&capability).is_err());
    drop(controller);

    let restarted = reopen(dir.path());
    assert_eq!(
        restarted.adapter().workload_state("session-1").unwrap(),
        ProviderWorkloadState::Activated
    );
    restarted.reconcile_session("session-1").unwrap();
    assert_eq!(
        restarted.ledger().state("session-1").unwrap(),
        Lifecycle::Creating
    );
    assert_eq!(
        restarted
            .adapter()
            .activation_mutations("session-1")
            .unwrap(),
        1
    );
}

#[test]
fn stale_tampered_or_replayed_capabilities_fail_closed() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    inert(&controller);
    let capability = controller
        .authorize_launch("session-1", &execution_spec(), NOW + 60, NOW)
        .unwrap();

    let mut tampered = capability.clone();
    tampered.task_input_digest = "b".repeat(64);
    assert!(matches!(
        controller.activate_launch(&tampered),
        Err(ControllerError::ActivationBindingMismatch)
    ));

    controller.activate_launch(&capability).unwrap();
    let grant = controller
        .redeem_launch(&capability, "worker-boot-1", &execution_spec(), NOW)
        .unwrap();
    let recovered = controller
        .redeem_launch(&capability, "worker-boot-1", &execution_spec(), NOW)
        .unwrap();
    assert_eq!(grant, recovered);
    assert!(matches!(
        controller.redeem_launch(&capability, "worker-boot-2", &execution_spec(), NOW,),
        Err(ControllerError::ActivationReplay)
    ));

    let receipt = TerminalReceipt {
        receipt_digest: "f".repeat(64),
        result_digest: "c".repeat(64),
        transfer_receipt_digests: Vec::new(),
        session_id: "session-1".into(),
        decision: Decision::Accepted,
        artifact_bytes: 0,
    };
    controller
        .accept_and_cleanup(&receipt, "agent:alice", "workspace-1", None)
        .unwrap();
    assert!(matches!(
        controller.activate_launch(&capability),
        Err(ControllerError::ActivationReplay | ControllerError::ExecutionAborted)
    ));
}

#[test]
fn workload_uid_or_generation_replacement_blocks_activation_and_redemption() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    inert(&controller);
    let capability = controller
        .authorize_launch("session-1", &execution_spec(), NOW + 60, NOW)
        .unwrap();
    controller
        .adapter()
        .replace_uid_for_test("session-1", "replacement-uid", 2)
        .unwrap();
    assert!(matches!(
        controller.activate_launch(&capability),
        Err(ControllerError::OwnershipMismatch)
    ));
    assert!(matches!(
        controller.redeem_launch(&capability, "worker-boot-1", &execution_spec(), NOW),
        Err(ControllerError::ActivationNotObserved | ControllerError::OwnershipMismatch)
    ));
}

#[test]
fn duplicate_reconcilers_issue_one_epoch_and_project_activation_once() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    inert(&controller);
    let _capability = controller
        .authorize_launch("session-1", &execution_spec(), NOW + 60, NOW)
        .unwrap();
    drop(controller);
    let root = dir.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let worker_root = root.clone();
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let controller = reopen(&worker_root);
            worker_barrier.wait();
            controller.reconcile_session("session-1")
        }));
    }
    barrier.wait();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }

    let restarted = reopen(&root);
    assert_eq!(
        restarted.ledger().state("session-1").unwrap(),
        Lifecycle::Creating
    );
    assert_eq!(restarted.ledger().launch_epoch("session-1").unwrap(), 1);
    assert_eq!(
        restarted
            .adapter()
            .activation_mutations("session-1")
            .unwrap(),
        1
    );
}

#[test]
fn terminal_result_after_authoritative_cancellation_is_rejected() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    controller.provision(&request(), None).unwrap();
    controller
        .ledger()
        .request_cancellation("session-1", "operator")
        .unwrap();
    let receipt = TerminalReceipt {
        receipt_digest: "e".repeat(64),
        result_digest: "d".repeat(64),
        transfer_receipt_digests: Vec::new(),
        session_id: "session-1".into(),
        decision: Decision::Accepted,
        artifact_bytes: 0,
    };
    assert!(matches!(
        controller.ledger().record_terminal(&receipt),
        Err(ControllerError::ExecutionAborted)
    ));
}

#[test]
fn expired_authorization_rotates_to_a_higher_epoch_and_old_capability_fails_closed() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    inert(&controller);

    assert!(matches!(
        controller.authorize_launch("session-1", &execution_spec(), NOW + 301, NOW),
        Err(ControllerError::ActivationExpired)
    ));
    let first = controller
        .authorize_launch("session-1", &execution_spec(), NOW + 1, NOW)
        .unwrap();
    assert_eq!(first.launch_epoch, 1);

    let second = controller
        .authorize_launch("session-1", &execution_spec(), NOW + 60, NOW + 2)
        .unwrap();
    assert_eq!(second.launch_epoch, 2);
    assert!(matches!(
        controller.activate_launch(&first),
        Err(ControllerError::ActivationBindingMismatch
            | ControllerError::ActivationRevoked
            | ControllerError::ActivationExpired)
    ));

    controller.activate_launch(&second).unwrap();
    let _grant = controller
        .redeem_launch(&second, "worker-boot-1", &execution_spec(), NOW + 2)
        .unwrap();
    assert_eq!(controller.ledger().launch_epoch("session-1").unwrap(), 2);
}

#[test]
fn provider_creation_returns_identity_that_the_ledger_persists() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    inert(&controller);

    let identity = controller.ledger().identity("session-1").unwrap();
    assert!(!identity.provider_uid.starts_with("fake-uid:"));
    assert!(identity.provider_generation > 0);
    let observed = controller.adapter().observe_owned(&identity).unwrap();
    assert_eq!(observed.provider_uid, identity.provider_uid);
    assert_eq!(observed.provider_generation, identity.provider_generation);
}

#[test]
fn material_consumption_creates_one_provider_execution_claim_for_exact_boot() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    inert(&controller);
    let capability = controller
        .authorize_launch("session-1", &execution_spec(), NOW + 60, NOW)
        .unwrap();
    controller.activate_launch(&capability).unwrap();

    controller
        .redeem_launch(&capability, "worker-boot-1", &execution_spec(), NOW)
        .unwrap();
    assert_eq!(
        controller
            .adapter()
            .execution_claim_mutations("session-1")
            .unwrap(),
        1
    );
    assert_eq!(
        controller
            .adapter()
            .execution_claim_consumer("session-1")
            .unwrap()
            .as_deref(),
        Some("worker-boot-1")
    );
}
