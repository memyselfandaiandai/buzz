use std::sync::{Arc, Barrier};
use std::thread;

use buzz_lifecycle::{
    AdmissionRequest, DeliveryMode, DispatchIntent, LifecycleError, LifecycleStore, RecoveryAction,
    RunClaimIdentity, RunLane, RunLaneCapacity, RuntimeLeaseIdentity, ScheduleIntent,
    ScheduledAdmissionOutcome, SchedulerPolicy, TerminalUpdate, TurnState,
};
use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;

fn authority(instance_id: &str) -> RuntimeLeaseIdentity {
    RuntimeLeaseIdentity {
        owner_id: "owner".to_owned(),
        agent_id: "agent".to_owned(),
        instance_id: instance_id.to_owned(),
    }
}

fn request(nonce: &str, received_at_ms: i64, expires_at_ms: i64) -> AdmissionRequest {
    AdmissionRequest {
        owner_id: "owner".to_owned(),
        agent_id: "agent".to_owned(),
        requester_id: "requester".to_owned(),
        channel_id: "channel".to_owned(),
        client_nonce: nonce.to_owned(),
        input_digest: format!("digest-{nonce}"),
        received_at_ms,
        expires_at_ms,
    }
}

fn dispatch(not_before_ms: i64) -> DispatchIntent {
    DispatchIntent {
        prompt_tag: "prompt".to_owned(),
        delivery_mode: DeliveryMode::Normal,
        retry_count: 0,
        not_before_ms,
        rule_fingerprint: None,
    }
}

fn capacity(user: u64, agent: u64, background: u64) -> RunLaneCapacity {
    RunLaneCapacity {
        user,
        agent,
        background,
    }
}

#[allow(clippy::too_many_arguments)]
fn admit(
    store: &LifecycleStore,
    lease: &RuntimeLeaseIdentity,
    nonce: &str,
    received_at_ms: i64,
    expires_at_ms: i64,
    due_at_ms: i64,
    lane: RunLane,
    source: &str,
    limits: RunLaneCapacity,
) -> buzz_lifecycle::Result<ScheduledAdmissionOutcome> {
    store.admit_scheduled_for_runtime_lease(
        lease,
        &request(nonce, received_at_ms, expires_at_ms),
        &dispatch(due_at_ms),
        &ScheduleIntent::new(lane, source)?,
        &serde_json::to_string(&json!({"event": nonce}))?,
        limits,
        json!({"nonce": nonce}),
        received_at_ms,
    )
}

#[test]
fn capacity_is_per_lane_exact_replay_precedes_capacity_and_classification_is_immutable(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite"))?;
    store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 10_000)?;
    let lease = authority("instance-a");
    let limits = capacity(1, 1, 0);

    let first = admit(
        &store,
        &lease,
        "user-1",
        100,
        5_000,
        100,
        RunLane::User,
        "human",
        limits,
    )?;
    assert!(matches!(first, ScheduledAdmissionOutcome::Accepted(_)));
    let replay = admit(
        &store,
        &lease,
        "user-1",
        100,
        5_000,
        100,
        RunLane::User,
        "human",
        capacity(0, 0, 0),
    )?;
    assert!(matches!(replay, ScheduledAdmissionOutcome::Duplicate(_)));

    let full = admit(
        &store,
        &lease,
        "user-2",
        101,
        5_000,
        101,
        RunLane::User,
        "human",
        limits,
    )?;
    assert!(matches!(
        full,
        ScheduledAdmissionOutcome::RejectedCapacity(_)
    ));
    assert_eq!(full.turn().state, TurnState::Rejected);
    assert_eq!(
        store
            .run_scheduler_snapshot("owner", "agent")?
            .lane(RunLane::User)
            .depth,
        1
    );

    let agent = admit(
        &store,
        &lease,
        "agent-1",
        102,
        5_000,
        102,
        RunLane::Agent,
        "teammate",
        limits,
    )?;
    assert!(matches!(agent, ScheduledAdmissionOutcome::Accepted(_)));
    let disabled = admit(
        &store,
        &lease,
        "background-1",
        103,
        5_000,
        103,
        RunLane::Background,
        "routine",
        limits,
    )?;
    assert!(matches!(
        disabled,
        ScheduledAdmissionOutcome::RejectedCapacity(_)
    ));

    assert!(matches!(
        admit(
            &store,
            &lease,
            "user-1",
            100,
            5_000,
            100,
            RunLane::Agent,
            "human",
            limits,
        ),
        Err(LifecycleError::ScheduleConflict)
    ));
    assert!(matches!(
        admit(
            &store,
            &lease,
            "user-1",
            100,
            5_000,
            100,
            RunLane::User,
            "changed",
            limits,
        ),
        Err(LifecycleError::ScheduleConflict)
    ));
    assert!(matches!(
        admit(
            &store,
            &lease,
            "user-1",
            100,
            5_000,
            999,
            RunLane::User,
            "human",
            limits,
        ),
        Err(LifecycleError::DispatchConflict)
    ));
    assert_eq!(
        store.schedule_intent(&first.turn().turn_id)?,
        Some(ScheduleIntent::new(RunLane::User, "human")?)
    );
    Ok(())
}

#[test]
fn expired_capacity_does_not_block_fresh_work_and_stale_work_never_claims(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite"))?;
    store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 10_000)?;
    let lease = authority("instance-a");
    let limits = capacity(1, 1, 1);
    let stale = admit(
        &store,
        &lease,
        "stale",
        20,
        100,
        20,
        RunLane::User,
        "human",
        limits,
    )?;
    let fresh = admit(
        &store,
        &lease,
        "fresh",
        101,
        1_000,
        101,
        RunLane::User,
        "human",
        limits,
    )?;
    assert!(matches!(fresh, ScheduledAdmissionOutcome::Accepted(_)));
    let claim = store
        .claim_next_for_runtime_lease(
            &lease,
            SchedulerPolicy::default(),
            "fresh-execution",
            json!({}),
            102,
        )?
        .ok_or("fresh work should be claimable")?;
    assert_eq!(claim.turn.turn_id, fresh.turn().turn_id);
    assert_eq!(store.turn(&stale.turn().turn_id)?.state, TurnState::Expired);
    Ok(())
}

#[test]
fn claim_expires_heads_preserves_fifo_and_fences_settlement(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite"))?;
    store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 1_000)?;
    let lease = authority("instance-a");
    let limits = capacity(10, 10, 10);
    let expired = admit(
        &store,
        &lease,
        "expired",
        20,
        50,
        20,
        RunLane::User,
        "human",
        limits,
    )?;
    let older = admit(
        &store,
        &lease,
        "older",
        30,
        900,
        30,
        RunLane::User,
        "human",
        limits,
    )?;
    let _newer = admit(
        &store,
        &lease,
        "newer",
        31,
        900,
        31,
        RunLane::User,
        "human",
        limits,
    )?;
    let _agent = admit(
        &store,
        &lease,
        "agent",
        21,
        900,
        21,
        RunLane::Agent,
        "teammate",
        limits,
    )?;

    let claim = store
        .claim_next_for_runtime_lease(
            &lease,
            SchedulerPolicy::default(),
            "execution-1",
            json!({}),
            100,
        )?
        .ok_or("expected claim")?;
    assert_eq!(
        store.turn(&expired.turn().turn_id)?.state,
        TurnState::Expired
    );
    assert_eq!(claim.turn.turn_id, older.turn().turn_id);
    assert_eq!(claim.lane, RunLane::User);
    assert_eq!(claim.identity.epoch, 1);
    assert_eq!(claim.dispatch.prompt_tag, "prompt");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&claim.opaque_input_json)?["event"],
        "older"
    );
    assert_eq!(
        store.run_scheduler_snapshot("owner", "agent")?.active_phase,
        Some(buzz_lifecycle::RunClaimPhase::Reserved)
    );
    store.mark_claim_launched_for_runtime_lease(&lease, &claim.identity, 105)?;
    assert_eq!(
        store.run_scheduler_snapshot("owner", "agent")?.active_phase,
        Some(buzz_lifecycle::RunClaimPhase::Launched)
    );
    assert!(matches!(
        store.mark_claim_launched_for_runtime_lease(&lease, &claim.identity, 106),
        Err(LifecycleError::SchedulerClaimConflict)
    ));
    assert!(matches!(
        store.claim_next_for_runtime_lease(
            &lease,
            SchedulerPolicy::default(),
            "execution-2",
            json!({}),
            101,
        ),
        Err(LifecycleError::SchedulerBusy)
    ));

    let stale = RunClaimIdentity {
        epoch: claim.identity.epoch + 1,
        execution_id: claim.identity.execution_id.clone(),
    };
    assert!(matches!(
        store.release_claim_to_waiting_for_runtime_lease(
            &lease,
            &stale,
            &dispatch(150),
            json!({}),
            110
        ),
        Err(LifecycleError::SchedulerClaimConflict)
    ));
    store.release_claim_to_waiting_for_runtime_lease(
        &lease,
        &claim.identity,
        &dispatch(150),
        json!({}),
        110,
    )?;
    assert!(matches!(
        store.finish_claim_for_runtime_lease(
            &lease,
            &claim.identity,
            &TerminalUpdate {
                state: TurnState::Completed,
                result_digest: Some("late".to_owned()),
                payload: json!({}),
                occurred_at_ms: 120
            },
        ),
        Err(LifecycleError::SchedulerClaimConflict)
    ));
    let next = store
        .claim_next_for_runtime_lease(
            &lease,
            SchedulerPolicy::default(),
            "execution-2",
            json!({}),
            120,
        )?
        .ok_or("expected second claim")?;
    assert_eq!(next.identity.epoch, 2);
    assert_eq!(next.turn.client_nonce, "newer");
    store.mark_claim_launched_for_runtime_lease(&lease, &next.identity, 120)?;
    store.finish_claim_for_runtime_lease(
        &lease,
        &next.identity,
        &TerminalUpdate {
            state: TurnState::Completed,
            result_digest: Some("done".to_owned()),
            payload: json!({}),
            occurred_at_ms: 121,
        },
    )?;
    Ok(())
}

#[test]
fn concurrent_claimers_produce_one_active_execution_and_stale_lease_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let database = directory.path().join("lifecycle.sqlite");
    let store = LifecycleStore::open(&database)?;
    store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 500)?;
    admit(
        &store,
        &authority("instance-a"),
        "one",
        20,
        1_000,
        20,
        RunLane::User,
        "human",
        capacity(10, 10, 10),
    )?;
    let barrier = Arc::new(Barrier::new(3));
    let handles = (0..2)
        .map(|index| {
            let path = database.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let store = LifecycleStore::open(path)?;
                barrier.wait();
                store.claim_next_for_runtime_lease(
                    &authority("instance-a"),
                    SchedulerPolicy::default(),
                    &format!("execution-{index}"),
                    json!({}),
                    100,
                )
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().map_err(|_| "claim thread panicked"))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(Some(_))))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(LifecycleError::SchedulerBusy)))
            .count(),
        1
    );

    store.acquire_runtime_lease("owner", "agent", "instance-b", 500, 1_000)?;
    assert!(matches!(
        store.claim_next_for_runtime_lease(
            &authority("instance-a"),
            SchedulerPolicy::default(),
            "stale",
            json!({}),
            501
        ),
        Err(LifecycleError::RuntimeLeaseConflict)
    ));
    Ok(())
}

#[test]
fn takeover_preserves_uncertain_hold_and_clears_only_matching_active_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite"))?;
    store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 100)?;
    admit(
        &store,
        &authority("instance-a"),
        "one",
        20,
        1_000,
        20,
        RunLane::Agent,
        "teammate",
        capacity(10, 10, 10),
    )?;
    let claim = store
        .claim_next_for_runtime_lease(
            &authority("instance-a"),
            SchedulerPolicy::default(),
            "execution-a",
            json!({}),
            30,
        )?
        .ok_or("expected claim")?;
    store.mark_claim_launched_for_runtime_lease(&authority("instance-a"), &claim.identity, 31)?;
    store.acquire_runtime_lease("owner", "agent", "instance-b", 100, 500)?;
    let recovery = store.recover_for_restart("owner", "agent", "instance-b", 110, 10)?;
    assert_eq!(recovery.len(), 1);
    assert_eq!(recovery[0].action, RecoveryAction::HoldUncertain);
    assert_eq!(recovery[0].turn.state, TurnState::Waiting);
    let snapshot = store.run_scheduler_snapshot("owner", "agent")?;
    assert!(snapshot.active_execution_id.is_none());
    assert!(store
        .claim_next_for_runtime_lease(
            &authority("instance-b"),
            SchedulerPolicy::default(),
            "execution-b",
            json!({}),
            120
        )?
        .is_none());
    assert!(matches!(
        store.finish_claim_for_runtime_lease(
            &authority("instance-b"),
            &claim.identity,
            &TerminalUpdate {
                state: TurnState::Completed,
                result_digest: Some("late".to_owned()),
                payload: json!({}),
                occurred_at_ms: 121
            },
        ),
        Err(LifecycleError::SchedulerClaimConflict)
    ));
    Ok(())
}

#[test]
fn direct_scheduler_recovery_cannot_be_starved_by_queued_backlog(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let database = directory.path().join("lifecycle.sqlite");
    let store = LifecycleStore::open(&database)?;
    store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 5_000)?;
    admit(
        &store,
        &authority("instance-a"),
        "launched-active",
        2_000,
        10_000,
        2_000,
        RunLane::User,
        "human",
        capacity(10, 10, 10),
    )?;
    let launched = store
        .claim_next_for_runtime_lease(
            &authority("instance-a"),
            SchedulerPolicy::default(),
            "launched-execution",
            json!({}),
            2_001,
        )?
        .ok_or("launched claim")?;
    store.mark_claim_launched_for_runtime_lease(
        &authority("instance-a"),
        &launched.identity,
        2_002,
    )?;

    let mut connection = Connection::open(&database)?;
    let transaction = connection.transaction()?;
    for index in 0..1_001 {
        transaction.execute(
            "INSERT INTO turns(
                turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
                version,accepted_at_ms,updated_at_ms,expires_at_ms
             ) VALUES (?1,'owner','agent','requester','channel',?2,?3,'queued',0,?4,?4,10000)",
            rusqlite::params![
                format!("backlog-{index}"),
                format!("backlog-nonce-{index}"),
                format!("backlog-digest-{index}"),
                index,
            ],
        )?;
    }
    transaction.commit()?;

    store.acquire_runtime_lease("owner", "agent", "instance-b", 5_000, 7_000)?;
    let recovered = store
        .recover_scheduler_active_for_runtime_lease(&authority("instance-b"), 5_010)?
        .ok_or("launched active recovery")?;
    assert_eq!(recovered.turn.turn_id, launched.turn.turn_id);
    assert_eq!(recovered.action, RecoveryAction::HoldUncertain);
    assert!(store
        .run_scheduler_snapshot("owner", "agent")?
        .active_execution_id
        .is_none());

    admit(
        &store,
        &authority("instance-b"),
        "reserved-active",
        5_020,
        10_000,
        5_020,
        RunLane::User,
        "human",
        capacity(10, 10, 10),
    )?;
    let reserved = store
        .claim_next_for_runtime_lease(
            &authority("instance-b"),
            SchedulerPolicy::default(),
            "reserved-execution",
            json!({}),
            5_021,
        )?
        .ok_or("reserved claim")?;
    store.acquire_runtime_lease("owner", "agent", "instance-c", 7_000, 9_000)?;
    let recovered = store
        .recover_scheduler_active_for_runtime_lease(&authority("instance-c"), 7_010)?
        .ok_or("reserved active recovery")?;
    assert_eq!(recovered.turn.turn_id, reserved.turn.turn_id);
    assert_eq!(recovered.action, RecoveryAction::Rehydrate);
    assert!(store
        .run_scheduler_snapshot("owner", "agent")?
        .active_execution_id
        .is_none());
    Ok(())
}

#[test]
fn takeover_does_not_clear_a_misclassified_active_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let database = directory.path().join("lifecycle.sqlite");
    let store = LifecycleStore::open(&database)?;
    store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 100)?;
    admit(
        &store,
        &authority("instance-a"),
        "one",
        20,
        1_000,
        20,
        RunLane::Agent,
        "teammate",
        capacity(10, 10, 10),
    )?;
    let claim = store
        .claim_next_for_runtime_lease(
            &authority("instance-a"),
            SchedulerPolicy::default(),
            "execution-a",
            json!({}),
            30,
        )?
        .ok_or("expected claim")?;
    store.mark_claim_launched_for_runtime_lease(&authority("instance-a"), &claim.identity, 31)?;
    Connection::open(&database)?.execute(
        "UPDATE run_scheduler_state SET active_source='corrupt' WHERE owner_id='owner' AND agent_id='agent'",
        [],
    )?;

    store.acquire_runtime_lease("owner", "agent", "instance-b", 100, 500)?;
    let recovery = store.recover_for_restart("owner", "agent", "instance-b", 110, 10)?;
    assert_eq!(recovery[0].action, RecoveryAction::HoldUncertain);
    assert_eq!(
        store
            .run_scheduler_snapshot("owner", "agent")?
            .active_execution_id
            .as_deref(),
        Some("execution-a")
    );
    Ok(())
}

#[test]
fn reserved_crash_requeues_and_legacy_mutation_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite"))?;
    store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 100)?;
    let admitted = admit(
        &store,
        &authority("instance-a"),
        "reserved",
        20,
        1_000,
        20,
        RunLane::User,
        "human",
        capacity(10, 10, 10),
    )?;
    assert!(matches!(
        store.bind_nonces_for_runtime_lease(
            &authority("instance-a"),
            &["reserved".to_owned()],
            "legacy",
            json!({}),
            25
        ),
        Err(LifecycleError::SchedulerModeConflict)
    ));
    let claim = store
        .claim_next_for_runtime_lease(
            &authority("instance-a"),
            SchedulerPolicy::default(),
            "reserved-execution",
            json!({}),
            30,
        )?
        .ok_or("claim")?;
    assert_eq!(claim.turn.turn_id, admitted.turn().turn_id);
    store.acquire_runtime_lease("owner", "agent", "instance-b", 100, 500)?;
    let recovered = store.recover_for_restart("owner", "agent", "instance-b", 110, 10)?;
    assert_eq!(recovered[0].action, RecoveryAction::Rehydrate);
    assert_eq!(recovered[0].turn.state, TurnState::Waiting);
    assert!(store
        .run_scheduler_snapshot("owner", "agent")?
        .active_phase
        .is_none());
    Ok(())
}

#[test]
fn reserved_settlement_and_launch_deadline_are_phase_fenced(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite"))?;
    store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 1_000)?;
    let lease = authority("instance-a");
    let limits = capacity(10, 10, 10);
    admit(
        &store,
        &lease,
        "cancel-before-launch",
        20,
        500,
        20,
        RunLane::User,
        "human",
        limits,
    )?;
    let deadline = admit(
        &store,
        &lease,
        "deadline",
        21,
        100,
        21,
        RunLane::User,
        "human",
        limits,
    )?;

    let reserved = store
        .claim_next_for_runtime_lease(
            &lease,
            SchedulerPolicy::default(),
            "reserved",
            json!({}),
            99,
        )?
        .ok_or("reserved claim")?;
    assert!(matches!(
        store.finish_claim_for_runtime_lease(
            &lease,
            &reserved.identity,
            &TerminalUpdate {
                state: TurnState::Completed,
                result_digest: Some("must-not-settle".into()),
                payload: json!({}),
                occurred_at_ms: 99,
            }
        ),
        Err(LifecycleError::SchedulerClaimConflict)
    ));
    assert_eq!(
        store.turn(&reserved.turn.turn_id)?.state,
        TurnState::Running
    );
    store.finish_claim_for_runtime_lease(
        &lease,
        &reserved.identity,
        &TerminalUpdate {
            state: TurnState::Cancelled,
            result_digest: None,
            payload: json!({"reason":"pre_launch_cancel"}),
            occurred_at_ms: 99,
        },
    )?;

    let expiring = store
        .claim_next_for_runtime_lease(
            &lease,
            SchedulerPolicy::default(),
            "deadline-execution",
            json!({}),
            99,
        )?
        .ok_or("deadline claim")?;
    assert_eq!(expiring.turn.turn_id, deadline.turn().turn_id);
    assert!(matches!(
        store.mark_claim_launched_for_runtime_lease(&lease, &expiring.identity, 100),
        Err(LifecycleError::SchedulerClaimConflict)
    ));
    assert_eq!(
        store.turn(&expiring.turn.turn_id)?.state,
        TurnState::Expired
    );
    let snapshot = store.run_scheduler_snapshot("owner", "agent")?;
    assert!(snapshot.active_execution_id.is_none());
    assert!(snapshot.active_phase.is_none());
    Ok(())
}

#[test]
fn corrupt_stored_opaque_input_is_quarantined_and_next_head_claims(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let database = directory.path().join("lifecycle.sqlite");
    let store = LifecycleStore::open(&database)?;
    store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 100)?;
    let corrupt = admit(
        &store,
        &authority("instance-a"),
        "corrupt",
        20,
        900,
        20,
        RunLane::User,
        "human",
        capacity(10, 10, 10),
    )?;
    Connection::open(&database)?.execute(
        "UPDATE turn_dispatch SET opaque_input_json='not-json' WHERE turn_id=?1",
        [&corrupt.turn().turn_id],
    )?;
    let valid = admit(
        &store,
        &authority("instance-a"),
        "valid",
        21,
        900,
        21,
        RunLane::User,
        "human",
        capacity(10, 10, 10),
    )?;
    let claim = store
        .claim_next_for_runtime_lease(
            &authority("instance-a"),
            SchedulerPolicy::default(),
            "valid-execution",
            json!({}),
            30,
        )?
        .ok_or("valid head should claim after corrupt head is quarantined")?;
    assert_eq!(claim.turn.turn_id, valid.turn().turn_id);
    assert_eq!(
        store.turn(&corrupt.turn().turn_id)?.state,
        TurnState::Cancelled
    );
    assert_eq!(
        store
            .run_scheduler_snapshot("owner", "agent")?
            .active_execution_id
            .as_deref(),
        Some("valid-execution")
    );
    store.finish_claim_for_runtime_lease(
        &authority("instance-a"),
        &claim.identity,
        &TerminalUpdate {
            state: TurnState::Cancelled,
            result_digest: None,
            payload: json!({"reason":"test_cleanup"}),
            occurred_at_ms: 31,
        },
    )?;
    assert!(store
        .claim_next_for_runtime_lease(
            &authority("instance-a"),
            SchedulerPolicy::default(),
            "no-loop",
            json!({}),
            32,
        )?
        .is_none());
    store.acquire_runtime_lease("owner", "agent", "instance-b", 100, 500)?;
    assert!(store
        .recover_for_restart("owner", "agent", "instance-b", 110, 10)?
        .is_empty());
    assert!(store
        .run_scheduler_snapshot("owner", "agent")?
        .active_execution_id
        .is_none());
    Ok(())
}

#[test]
fn scheduler_policy_rejection_is_lease_fenced_replayable_and_never_runnable(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite"))?;
    store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 1_000)?;
    let rejected = store.reject_scheduled_admission_for_runtime_lease(
        &authority("instance-a"),
        &request("policy-reject", 20, 900),
        "scheduler_sender_unclassified",
        json!({"policy":"test"}),
        20,
    )?;
    assert!(matches!(
        rejected,
        buzz_lifecycle::RejectionOutcome::Rejected(_)
    ));
    let replay = store.reject_scheduled_admission_for_runtime_lease(
        &authority("instance-a"),
        &request("policy-reject", 20, 900),
        "scheduler_sender_unclassified",
        json!({"policy":"test"}),
        21,
    )?;
    assert!(matches!(
        replay,
        buzz_lifecycle::RejectionOutcome::Duplicate(_)
    ));
    let mut conflicting = request("policy-reject", 20, 900);
    conflicting.input_digest = "different".into();
    assert!(matches!(
        store.reject_scheduled_admission_for_runtime_lease(
            &authority("instance-a"),
            &conflicting,
            "scheduler_sender_unclassified",
            json!({}),
            22,
        ),
        Err(LifecycleError::NonceConflict)
    ));
    assert!(store
        .claim_next_for_runtime_lease(
            &authority("instance-a"),
            SchedulerPolicy::default(),
            "must-not-launch",
            json!({}),
            23,
        )?
        .is_none());
    let snapshot = store.run_scheduler_snapshot("owner", "agent")?;
    assert!(snapshot.active_execution_id.is_none());
    assert_eq!(snapshot.lane(RunLane::User).depth, 0);
    Ok(())
}

#[test]
fn legacy_and_scheduler_mutations_reject_both_activation_orders(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let legacy_database = directory.path().join("legacy-first.sqlite");
    let legacy_store = LifecycleStore::open(&legacy_database)?;
    legacy_store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 10_000)?;
    legacy_store.admit_queued(&request("legacy", 20, 9_000), &dispatch(20), json!({}), 20)?;
    assert!(matches!(
        admit(
            &legacy_store,
            &authority("instance-a"),
            "scheduler",
            21,
            9_000,
            21,
            RunLane::User,
            "human",
            capacity(10, 10, 10),
        ),
        Err(LifecycleError::SchedulerModeConflict)
    ));
    assert!(matches!(
        legacy_store.reject_scheduled_admission_for_runtime_lease(
            &authority("instance-a"),
            &request("scheduler-reject", 21, 9_000),
            "scheduler_sender_unclassified",
            json!({}),
            21,
        ),
        Err(LifecycleError::SchedulerModeConflict)
    ));
    let scheduler_rows: i64 = Connection::open(&legacy_database)?.query_row(
        "SELECT COUNT(*) FROM run_scheduler_state",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(scheduler_rows, 0);

    let scheduler_store = LifecycleStore::open(directory.path().join("scheduler-first.sqlite"))?;
    scheduler_store.acquire_runtime_lease("owner", "agent", "instance-a", 10, 10_000)?;
    let scheduled = admit(
        &scheduler_store,
        &authority("instance-a"),
        "scheduled",
        20,
        1_000,
        20,
        RunLane::User,
        "human",
        capacity(10, 10, 10),
    )?;
    assert!(matches!(
        scheduler_store.admit_queued(
            &request("legacy-after", 21, 1_000),
            &dispatch(21),
            json!({}),
            21,
        ),
        Err(LifecycleError::SchedulerModeConflict)
    ));
    assert!(matches!(
        scheduler_store.reject_admission_for_runtime_lease(
            &authority("instance-a"),
            &request("reject-after", 21, 1_000),
            "mixed_mode",
            json!({}),
            21,
        ),
        Err(LifecycleError::SchedulerModeConflict)
    ));
    assert!(matches!(
        scheduler_store.mark_running(scheduled.turn().turn_id.as_str(), "legacy", json!({}), 22),
        Err(LifecycleError::SchedulerModeConflict)
    ));
    assert!(matches!(
        scheduler_store.mark_waiting(scheduled.turn().turn_id.as_str(), json!({}), 22),
        Err(LifecycleError::SchedulerModeConflict)
    ));
    assert!(matches!(
        scheduler_store.mark_terminal(
            scheduled.turn().turn_id.as_str(),
            &TerminalUpdate {
                state: TurnState::Cancelled,
                result_digest: None,
                payload: json!({}),
                occurred_at_ms: 22,
            },
        ),
        Err(LifecycleError::SchedulerModeConflict)
    ));
    assert!(scheduler_store.expire_due(2_000, 10)?.is_empty());
    assert_eq!(
        scheduler_store.turn(&scheduled.turn().turn_id)?.state,
        TurnState::Queued
    );
    assert!(matches!(
        scheduler_store.expire_due_for_runtime_lease(&authority("instance-a"), 2_000, 10),
        Err(LifecycleError::SchedulerModeConflict)
    ));
    assert!(scheduler_store
        .claim_pending_outbox(20, 10, "legacy-outbox", 100)?
        .is_empty());
    Ok(())
}

#[test]
fn migrated_v5_rows_have_no_fabricated_input_and_are_not_claimable(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let database = directory.path().join("migration.sqlite");
    let store = LifecycleStore::open(&database)?;
    let legacy = store.admit_queued(&request("legacy", 10, 1_000), &dispatch(10), json!({}), 10)?;
    let connection = Connection::open(&database)?;
    let missing: Option<String> = connection.query_row(
        "SELECT opaque_input_json FROM turn_dispatch WHERE turn_id=?1",
        [&legacy.turn().turn_id],
        |row| row.get(0),
    )?;
    assert!(missing.is_none());
    connection.execute(
        "INSERT INTO run_scheduler_state(owner_id,agent_id,updated_at_ms) VALUES ('owner','agent',20)",
        [],
    )?;
    drop(connection);
    store.acquire_runtime_lease("owner", "agent", "instance-a", 20, 100)?;
    assert!(store
        .claim_next_for_runtime_lease(
            &authority("instance-a"),
            SchedulerPolicy::default(),
            "must-not-claim",
            json!({}),
            21,
        )?
        .is_none());
    assert_eq!(store.turn(&legacy.turn().turn_id)?.state, TurnState::Queued);
    let connection = Connection::open(&database)?;
    connection.execute(
        "UPDATE turns SET state='running',execution_id='v5-execution' WHERE turn_id=?1",
        [&legacy.turn().turn_id],
    )?;
    connection.execute(
        "UPDATE run_scheduler_state
         SET active_epoch=1,active_execution_id='v5-execution',active_lane='user',
             active_source='legacy',active_started_at_ms=30,active_phase=NULL
         WHERE owner_id='owner' AND agent_id='agent'",
        [],
    )?;
    drop(connection);
    store.acquire_runtime_lease("owner", "agent", "instance-b", 100, 500)?;
    let recovered = store.recover_for_restart("owner", "agent", "instance-b", 110, 10)?;
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].action, RecoveryAction::HoldUncertain);
    assert_eq!(recovered[0].turn.state, TurnState::Waiting);
    Ok(())
}
