use buzz_workspace_controller::{
    AdmissionOutcome, AdmissionRequest, Artifact, Controller, ControllerError, Decision,
    ExecutionSpec, FakeKubernetes, Ledger, Lifecycle, Scope, TerminalReceipt,
};
use tempfile::tempdir;

fn request(session: &str, jti: &str, workspace: &str, signed_max: u32) -> AdmissionRequest {
    AdmissionRequest {
        session_id: session.into(),
        jti: jti.into(),
        capability_digest: format!("sha256:{jti}"),
        owner_id: "agent:alice".into(),
        workspace_id: workspace.into(),
        scope: Scope::Agent("agent:alice".into()),
        signed_max_concurrency: signed_max,
        deployment_max_concurrency: 20,
        artifact_limit_bytes: 10,
        expires_at: 2_000_000_000,
    }
}

#[test]
fn wal_admission_is_durable_replay_safe_and_scoped() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let ledger = Ledger::open(&db).unwrap();
    assert_eq!(ledger.journal_mode().unwrap().to_ascii_lowercase(), "wal");
    assert_eq!(ledger.schema_version().unwrap(), 4);
    assert_eq!(Ledger::session_job_quota(), 1);

    assert_eq!(
        ledger
            .prepare_and_admit(&request("s1", "j1", "w1", 2))
            .unwrap(),
        AdmissionOutcome::Admitted
    );
    assert_eq!(
        ledger
            .prepare_and_admit(&request("s2", "j2", "w2", 2))
            .unwrap(),
        AdmissionOutcome::Admitted
    );
    assert!(matches!(
        ledger.prepare_and_admit(&request("s3", "j3", "w3", 2)),
        Err(ControllerError::CapacityExceeded { .. })
    ));
    assert_eq!(ledger.state("s3").unwrap(), Lifecycle::Rejected);
    assert!(matches!(
        ledger.prepare_and_admit(&request("replay", "j1", "other", 20)),
        Err(ControllerError::JtiReplay)
    ));
    assert!(matches!(
        ledger.prepare_and_admit(&request("other", "j4", "w1", 20)),
        Err(ControllerError::WorkspaceOwned)
    ));
    drop(ledger);

    let reopened = Ledger::open(&db).unwrap();
    assert_eq!(reopened.state("s1").unwrap(), Lifecycle::Admitted);
    assert_eq!(
        reopened
            .reservation_count(&Scope::Agent("agent:alice".into()))
            .unwrap(),
        2
    );
    assert_eq!(
        reopened
            .prepare_and_admit(&request("s1", "j1", "w1", 2))
            .unwrap(),
        AdmissionOutcome::Existing(Lifecycle::Admitted)
    );

    let mut low = request("low", "j-low", "w-low", 2);
    low.scope = Scope::Tenant("tenant:mixed".into());
    let mut high = request("high", "j-high", "w-high", 20);
    high.scope = Scope::Tenant("tenant:mixed".into());
    let mut high_replay = request("high-2", "j-high-2", "w-high-2", 20);
    high_replay.scope = Scope::Tenant("tenant:mixed".into());
    assert_eq!(
        reopened.prepare_and_admit(&low).unwrap(),
        AdmissionOutcome::Admitted
    );
    assert_eq!(
        reopened.prepare_and_admit(&high).unwrap(),
        AdmissionOutcome::Admitted
    );
    assert!(matches!(
        reopened.prepare_and_admit(&high_replay),
        Err(ControllerError::CapacityExceeded { limit: 2, .. })
    ));
}

#[test]
fn lifecycle_artifacts_acceptance_and_owned_cleanup_are_transactional() {
    let dir = tempdir().unwrap();
    let ledger = Ledger::open(dir.path().join("ledger.db")).unwrap();
    let adapter = FakeKubernetes::open(dir.path().join("provider.db")).unwrap();
    let controller = Controller::new(ledger.clone(), adapter);
    controller
        .provision(&request("s1", "j1", "w1", 20), None)
        .unwrap();
    let spec = ExecutionSpec::new(
        std::env::current_exe().unwrap().to_string_lossy(),
        vec!["--help".into()],
        "a".repeat(64),
    )
    .unwrap();
    let capability = controller
        .authorize_launch("s1", &spec, 1_900_000_060, 1_900_000_000)
        .unwrap();
    controller.activate_launch(&capability).unwrap();
    controller
        .redeem_launch(&capability, "ledger-test-boot", &spec, 1_900_000_000)
        .unwrap();

    assert!(matches!(
        ledger.begin_cleanup("s1", "agent:alice", "w1", "too-early"),
        Err(ControllerError::InvalidTransition { .. })
    ));
    ledger
        .record_artifact("s1", &Artifact::new("a.txt", "a".repeat(64), 4))
        .unwrap();
    ledger
        .record_artifact("s1", &Artifact::new("dir\\b.txt", "b".repeat(64), 6))
        .unwrap();
    assert!(matches!(
        ledger.record_artifact("s1", &Artifact::new("c.txt", "c".repeat(64), 1)),
        Err(ControllerError::ArtifactLimitExceeded)
    ));
    assert!(matches!(
        ledger.record_artifact("s1", &Artifact::new("a.txt", "d".repeat(64), 4)),
        Err(ControllerError::DuplicateArtifact)
    ));
    assert!(matches!(
        ledger.record_artifact("s1", &Artifact::new("dir/b.txt", "e".repeat(64), 6)),
        Err(ControllerError::DuplicateArtifact)
    ));

    let receipt = TerminalReceipt {
        receipt_digest: "f".repeat(64),
        result_digest: "c".repeat(64),
        transfer_receipt_digests: vec!["b".repeat(64), "a".repeat(64)],
        session_id: "s1".into(),
        decision: Decision::Accepted,
        artifact_bytes: 10,
    };
    let mut incomplete = receipt.clone();
    incomplete.transfer_receipt_digests.pop();
    assert!(matches!(
        ledger.record_terminal(&incomplete),
        Err(ControllerError::TerminalReceiptMismatch)
    ));
    assert_eq!(ledger.state("s1").unwrap(), Lifecycle::Active);
    ledger.record_terminal(&receipt).unwrap();
    let mut conflicting_retry = receipt.clone();
    conflicting_retry.decision = Decision::Rejected;
    assert!(matches!(
        ledger.record_terminal(&conflicting_retry),
        Err(ControllerError::TerminalReceiptMismatch)
    ));
    assert_eq!(ledger.state("s1").unwrap(), Lifecycle::Terminal);
    assert!(matches!(
        ledger.begin_cleanup("s1", "agent:bob", "w1", "claim-bad"),
        Err(ControllerError::OwnershipMismatch)
    ));
    ledger
        .begin_cleanup("s1", "agent:alice", "w1", "claim-1")
        .unwrap();
    assert_eq!(ledger.state("s1").unwrap(), Lifecycle::Cleaning);
    ledger.mark_cleaned("s1", "claim-1").unwrap();
    ledger.mark_cleaned("s1", "claim-1").unwrap();
    assert_eq!(ledger.state("s1").unwrap(), Lifecycle::Cleaned);
    assert_eq!(
        ledger
            .reservation_count(&Scope::Agent("agent:alice".into()))
            .unwrap(),
        0
    );
}

#[test]
fn cancellation_expiry_rejection_and_recovery_states_preserve_uncertain_capacity() {
    let dir = tempdir().unwrap();
    let ledger = Ledger::open(dir.path().join("ledger.db")).unwrap();
    let adapter = FakeKubernetes::open(dir.path().join("provider.db")).unwrap();
    Controller::new(ledger.clone(), adapter)
        .provision(&request("cancel", "jc", "wc", 20), None)
        .unwrap();
    ledger.request_cancellation("cancel", "operator").unwrap();
    ledger.request_cancellation("cancel", "operator").unwrap();
    assert_eq!(ledger.state("cancel").unwrap(), Lifecycle::Cancelled);
    assert!(ledger.cancellation_requested("cancel").unwrap());
    assert_eq!(
        ledger
            .reservation_count(&Scope::Agent("agent:alice".into()))
            .unwrap(),
        1
    );

    ledger
        .mark_recovery_error("cancel", "provider uncertain")
        .unwrap();
    assert_eq!(ledger.state("cancel").unwrap(), Lifecycle::Cancelled);
    assert_eq!(
        ledger
            .reservation_count(&Scope::Agent("agent:alice".into()))
            .unwrap(),
        1
    );

    ledger.prepare(&request("expired", "je", "we", 20)).unwrap();
    ledger.admit("expired").unwrap();
    ledger.mark_expired("expired").unwrap();
    assert_eq!(ledger.state("expired").unwrap(), Lifecycle::Expired);

    ledger
        .prepare(&request("rejected", "jr", "wr", 20))
        .unwrap();
    ledger.reject("rejected", "policy").unwrap();
    assert_eq!(ledger.state("rejected").unwrap(), Lifecycle::Rejected);
}

#[test]
fn schema_v1_rows_are_quarantined_during_launch_fencing_v4_migration() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch(
        "CREATE TABLE controller_schema(
             singleton INTEGER PRIMARY KEY CHECK(singleton=1),
             version INTEGER NOT NULL
         );
         INSERT INTO controller_schema(singleton,version) VALUES(1,1);
         CREATE TABLE sessions(
             session_id TEXT PRIMARY KEY,
             jti TEXT NOT NULL UNIQUE,
             capability_digest TEXT NOT NULL UNIQUE,
             owner_id TEXT NOT NULL,
             workspace_id TEXT NOT NULL UNIQUE,
             scope_kind TEXT NOT NULL CHECK(scope_kind IN ('agent','tenant','issuer')),
             scope_id TEXT NOT NULL,
             signed_max_concurrency INTEGER NOT NULL CHECK(signed_max_concurrency > 0),
             deployment_max_concurrency INTEGER NOT NULL CHECK(deployment_max_concurrency > 0),
             artifact_limit_bytes INTEGER NOT NULL CHECK(artifact_limit_bytes > 0),
             artifact_bytes INTEGER NOT NULL DEFAULT 0 CHECK(artifact_bytes >= 0),
             expires_at INTEGER NOT NULL,
             state TEXT NOT NULL CHECK(state IN (
                 'prepared','admitted','creating','active','terminal','cleaning','cleaned',
                 'rejected','cancelled','expired','recovery_error'
             )),
             reserved INTEGER NOT NULL DEFAULT 0 CHECK(reserved IN (0,1)),
             cancellation_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancellation_requested IN (0,1)),
             terminal_decision TEXT CHECK(terminal_decision IN ('accepted','rejected')),
             terminal_receipt_digest TEXT UNIQUE,
             terminal_result_digest TEXT,
             terminal_transfer_digest_set TEXT,
             cleanup_claim TEXT,
             last_error TEXT,
             version INTEGER NOT NULL DEFAULT 0,
             created_at INTEGER NOT NULL DEFAULT(unixepoch()),
             updated_at INTEGER NOT NULL DEFAULT(unixepoch())
         );
         INSERT INTO sessions(
             session_id,jti,capability_digest,owner_id,workspace_id,scope_kind,scope_id,
             signed_max_concurrency,deployment_max_concurrency,artifact_limit_bytes,
             expires_at,state,reserved
         ) VALUES(
             'legacy-session','legacy-jti','sha256:legacy','agent:legacy','legacy-workspace',
             'agent','agent:legacy',1,1,1024,2000000000,'active',1
         );",
    )
    .unwrap();
    drop(conn);

    let ledger = Ledger::open(&db).unwrap();
    assert_eq!(ledger.schema_version().unwrap(), 4);
    assert_eq!(
        ledger.state("legacy-session").unwrap(),
        Lifecycle::RecoveryError
    );
    assert!(ledger.cancellation_requested("legacy-session").unwrap());
    assert_eq!(
        ledger
            .reservation_count(&Scope::Agent("agent:legacy".into()))
            .unwrap(),
        1,
        "uncertain legacy capacity remains reserved until owned cleanup"
    );

    let conn = rusqlite::Connection::open(&db).unwrap();
    let columns = conn
        .prepare("PRAGMA table_info(sessions)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    assert!(columns.iter().any(|column| column == "launch_epoch"));
    assert!(columns.iter().any(|column| column == "authority_version"));
    let quarantine: (i64, String, i64) = conn
        .query_row(
            "SELECT authority_version,last_error,version FROM sessions WHERE session_id='legacy-session'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(quarantine, (0, "legacy-authority-quarantined".into(), 1));
    let authorization_table: String = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='launch_authorizations'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(authorization_table, "launch_authorizations");
    drop(conn);

    Ledger::open(&db).unwrap();
    let conn = rusqlite::Connection::open(&db).unwrap();
    let session_version: i64 = conn
        .query_row(
            "SELECT version FROM sessions WHERE session_id='legacy-session'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        session_version, 1,
        "quarantine migration must be idempotent"
    );
}
