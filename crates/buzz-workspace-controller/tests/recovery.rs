use buzz_workspace_controller::{
    AdmissionRequest, Controller, ControllerError, CrashPoint, Decision, ExecutionSpec,
    FakeKubernetes, Ledger, Lifecycle, Scope, TerminalReceipt,
};
use tempfile::tempdir;

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

fn redeem_to_active(controller: &Controller<FakeKubernetes>) {
    let spec = ExecutionSpec::new(
        std::env::current_exe().unwrap().to_string_lossy(),
        vec!["--help".into()],
        "a".repeat(64),
    )
    .unwrap();
    let capability = controller
        .authorize_launch("session-1", &spec, 1_900_000_060, 1_900_000_000)
        .unwrap();
    controller.activate_launch(&capability).unwrap();
    controller
        .redeem_launch(&capability, "recovery-test-boot", &spec, 1_900_000_000)
        .unwrap();
}

#[test]
fn every_provision_crash_point_reconciles_without_duplicate_workloads_or_reservations() {
    let points = [
        CrashPoint::AfterPrepared,
        CrashPoint::AfterAdmitted,
        CrashPoint::AfterCreating,
        CrashPoint::AfterProviderCreate,
    ];
    for point in points {
        let dir = tempdir().unwrap();
        let controller = reopen(dir.path());
        assert!(matches!(
            controller.provision(&request(), Some(point)),
            Err(ControllerError::SimulatedCrash(actual)) if actual == point
        ));
        drop(controller);

        let restarted = reopen(dir.path());
        restarted.reconcile_session("session-1").unwrap();
        restarted.reconcile_session("session-1").unwrap();
        assert_eq!(
            restarted.ledger().state("session-1").unwrap(),
            Lifecycle::Creating,
            "{point:?}"
        );
        assert_eq!(
            restarted.adapter().workload_count().unwrap(),
            1,
            "{point:?}"
        );
        assert_eq!(
            restarted.adapter().create_mutations("session-1").unwrap(),
            1,
            "{point:?}"
        );
        assert_eq!(
            restarted
                .ledger()
                .reservation_count(&Scope::Tenant("tenant:acme".into()))
                .unwrap(),
            1,
            "{point:?}"
        );
        let mut replay = request();
        replay.session_id = "replay-session".into();
        replay.workspace_id = "replay-workspace".into();
        assert!(matches!(
            restarted.ledger().prepare_and_admit(&replay),
            Err(ControllerError::JtiReplay)
        ));
    }
}

#[test]
fn every_cleanup_crash_point_reconciles_to_owned_idempotent_cleanup() {
    let points = [
        CrashPoint::AfterTerminal,
        CrashPoint::AfterCleaning,
        CrashPoint::AfterProviderDelete,
        CrashPoint::AfterCleaned,
    ];
    for point in points {
        let dir = tempdir().unwrap();
        let controller = reopen(dir.path());
        controller.provision(&request(), None).unwrap();
        redeem_to_active(&controller);
        let receipt = TerminalReceipt {
            receipt_digest: "f".repeat(64),
            result_digest: "a".repeat(64),
            transfer_receipt_digests: Vec::new(),
            session_id: "session-1".into(),
            decision: Decision::Accepted,
            artifact_bytes: 0,
        };
        assert!(matches!(
            controller.accept_and_cleanup(&receipt, "agent:alice", "workspace-1", Some(point)),
            Err(ControllerError::SimulatedCrash(actual)) if actual == point
        ));
        drop(controller);

        let restarted = reopen(dir.path());
        restarted.reconcile_session("session-1").unwrap();
        restarted.reconcile_session("session-1").unwrap();
        assert_eq!(
            restarted.ledger().state("session-1").unwrap(),
            Lifecycle::Cleaned,
            "{point:?}"
        );
        assert_eq!(
            restarted.adapter().workload_count().unwrap(),
            0,
            "{point:?}"
        );
        assert_eq!(
            restarted.adapter().create_mutations("session-1").unwrap(),
            1,
            "{point:?}"
        );
        assert_eq!(
            restarted.adapter().delete_mutations("session-1").unwrap(),
            1,
            "{point:?}"
        );
        assert_eq!(
            restarted
                .ledger()
                .reservation_count(&Scope::Tenant("tenant:acme".into()))
                .unwrap(),
            0,
            "{point:?}"
        );
    }
}

#[test]
fn fake_provider_refuses_cross_session_or_workspace_cleanup() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    controller.provision(&request(), None).unwrap();
    let identity = controller.ledger().identity("session-1").unwrap();
    let mut wrong_workspace = identity.clone();
    wrong_workspace.workspace_id = "workspace-other".into();
    assert!(matches!(
        controller.adapter().delete_owned(&wrong_workspace),
        Err(ControllerError::OwnershipMismatch)
    ));
    let mut wrong_session = identity;
    wrong_session.session_id = "session-other".into();
    assert!(matches!(
        controller.adapter().delete_owned(&wrong_session),
        Err(ControllerError::OwnershipMismatch)
    ));
    assert_eq!(controller.adapter().workload_count().unwrap(), 1);
}

#[test]
fn fake_provider_aba_replacement_blocks_cleanup_and_retains_reservation() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    controller.provision(&request(), None).unwrap();
    redeem_to_active(&controller);
    controller
        .adapter()
        .replace_uid_for_test("session-1", "replacement-uid", 2)
        .unwrap();
    let receipt = TerminalReceipt {
        receipt_digest: "e".repeat(64),
        result_digest: "b".repeat(64),
        transfer_receipt_digests: Vec::new(),
        session_id: "session-1".into(),
        decision: Decision::Rejected,
        artifact_bytes: 0,
    };
    assert!(matches!(
        controller.accept_and_cleanup(&receipt, "agent:alice", "workspace-1", None),
        Err(ControllerError::OwnershipMismatch)
    ));
    assert_eq!(
        controller.ledger().state("session-1").unwrap(),
        Lifecycle::Cleaning
    );
    assert_eq!(
        controller
            .ledger()
            .reservation_count(&Scope::Tenant("tenant:acme".into()))
            .unwrap(),
        1
    );
    assert_eq!(controller.adapter().workload_count().unwrap(), 1);
}

#[test]
fn cleaned_workspace_id_is_a_permanent_tombstone() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    controller.provision(&request(), None).unwrap();
    redeem_to_active(&controller);
    let receipt = TerminalReceipt {
        receipt_digest: "d".repeat(64),
        result_digest: "c".repeat(64),
        transfer_receipt_digests: Vec::new(),
        session_id: "session-1".into(),
        decision: Decision::Accepted,
        artifact_bytes: 0,
    };
    controller
        .accept_and_cleanup(&receipt, "agent:alice", "workspace-1", None)
        .unwrap();
    assert_eq!(
        controller.ledger().state("session-1").unwrap(),
        Lifecycle::Cleaned
    );

    let mut reuse = request();
    reuse.session_id = "session-reuse".into();
    reuse.jti = "jti-reuse".into();
    reuse.capability_digest = "sha256:cap-reuse".into();
    assert!(matches!(
        controller.ledger().prepare_and_admit(&reuse),
        Err(ControllerError::WorkspaceOwned)
    ));
    assert!(matches!(
        controller.ledger().state("session-reuse"),
        Err(ControllerError::SessionNotFound)
    ));
    assert_eq!(controller.adapter().workload_count().unwrap(), 0);
}

#[test]
fn cancellation_before_or_after_fake_create_never_resurrects_execution() {
    let before = tempdir().unwrap();
    let controller = reopen(before.path());
    assert!(matches!(
        controller.provision(&request(), Some(CrashPoint::AfterCreating)),
        Err(ControllerError::SimulatedCrash(CrashPoint::AfterCreating))
    ));
    controller
        .ledger()
        .request_cancellation("session-1", "operator")
        .unwrap();
    controller.reconcile_session("session-1").unwrap();
    assert_eq!(
        controller.ledger().state("session-1").unwrap(),
        Lifecycle::Cleaned
    );
    assert_eq!(controller.adapter().workload_count().unwrap(), 0);

    let after = tempdir().unwrap();
    let controller = reopen(after.path());
    controller.provision(&request(), None).unwrap();
    controller
        .ledger()
        .request_cancellation("session-1", "operator")
        .unwrap();
    controller
        .ledger()
        .mark_recovery_error("session-1", "late provider observation")
        .unwrap();
    controller.reconcile_session("session-1").unwrap();
    assert_eq!(
        controller.ledger().state("session-1").unwrap(),
        Lifecycle::Cleaned
    );
    assert_eq!(controller.adapter().workload_count().unwrap(), 0);

    let expired = tempdir().unwrap();
    let controller = reopen(expired.path());
    controller.provision(&request(), None).unwrap();
    controller.expire_session("session-1").unwrap();
    assert_eq!(
        controller.ledger().state("session-1").unwrap(),
        Lifecycle::Cleaned
    );
    assert_eq!(controller.adapter().workload_count().unwrap(), 0);
}

#[test]
fn capacity_rejection_and_exact_replay_never_reach_the_provider() {
    let dir = tempdir().unwrap();
    let controller = reopen(dir.path());
    let mut first = request();
    first.signed_max_concurrency = 1;
    first.deployment_max_concurrency = 1;
    controller.provision(&first, None).unwrap();

    let mut second = request();
    second.session_id = "session-2".into();
    second.jti = "jti-2".into();
    second.capability_digest = "sha256:cap-2".into();
    second.workspace_id = "workspace-2".into();
    second.signed_max_concurrency = 1;
    second.deployment_max_concurrency = 1;
    assert!(matches!(
        controller.provision(&second, None),
        Err(ControllerError::CapacityExceeded { .. })
    ));
    assert_eq!(
        controller.ledger().state("session-2").unwrap(),
        Lifecycle::Rejected
    );
    assert!(matches!(
        controller.provision(&second, None),
        Err(ControllerError::AdmissionRejected)
    ));
    assert_eq!(controller.adapter().workload_count().unwrap(), 1);
}
