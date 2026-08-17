mod common;

use std::io;
use std::sync::{Arc, Barrier};

use buzz_lifecycle::{
    AdmissionOutcome, DeliveryMode, DispatchIntent, LifecycleError, LifecycleStore, RecoveryAction,
    RuntimeLeaseIdentity, TerminalUpdate, TurnState,
};
use serde_json::json;

#[test]
fn reopen_recovers_active_tail_and_outbox() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lifecycle.sqlite3");
    let store = LifecycleStore::open(&path)?;
    let admitted = store.admit(&common::request("nonce-a", "digest-a"))?;
    let turn_id = admitted.turn().turn_id.clone();
    store.mark_queued(&turn_id, json!({}), 1_100)?;
    drop(store);

    let reopened = LifecycleStore::open(&path)?;
    let active = reopened.active_turns_page("owner-a", None, 1_000)?.turns;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].turn_id, turn_id);
    assert_eq!(active[0].state, TurnState::Queued);
    assert_eq!(reopened.events_after("owner-a", 0, 10)?.len(), 2);
    assert_eq!(reopened.pending_outbox(2_000, 10)?.len(), 1);

    reopened.mark_terminal(
        &turn_id,
        &TerminalUpdate {
            state: TurnState::Cancelled,
            result_digest: None,
            payload: json!({"reason": "restart-test"}),
            occurred_at_ms: 2_100,
        },
    )?;
    drop(reopened);

    let final_open = LifecycleStore::open(&path)?;
    assert!(final_open
        .active_turns_page("owner-a", None, 1_000)?
        .turns
        .is_empty());
    assert_eq!(final_open.turn(&turn_id)?.state, TurnState::Cancelled);
    assert_eq!(final_open.events_after("owner-a", 0, 10)?.len(), 3);
    assert_eq!(final_open.pending_outbox(3_000, 10)?.len(), 2);
    Ok(())
}

#[test]
fn concurrent_exact_replay_creates_one_turn_and_one_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lifecycle.sqlite3");
    let store = LifecycleStore::open(&path)?;
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let worker_store = store.clone();
        let worker_barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            worker_barrier.wait();
            worker_store.admit(&common::request("nonce-a", "digest-a"))
        }));
    }

    let mut accepted = 0;
    let mut duplicate = 0;
    let mut turn_ids = Vec::new();
    for handle in handles {
        let outcome = handle
            .join()
            .map_err(|_| io::Error::other("admission worker panicked"))??;
        turn_ids.push(outcome.turn().turn_id.clone());
        match outcome {
            AdmissionOutcome::Accepted(_) => accepted += 1,
            AdmissionOutcome::Duplicate(_) => duplicate += 1,
        }
    }

    assert_eq!(accepted, 1);
    assert_eq!(duplicate, 7);
    assert!(turn_ids.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        store.active_turns_page("owner-a", None, 1_000)?.turns.len(),
        1
    );
    assert_eq!(store.events_after("owner-a", 0, 10)?.len(), 1);
    assert_eq!(store.pending_outbox(2_000, 10)?.len(), 1);
    Ok(())
}

fn dispatch(not_before_ms: i64) -> DispatchIntent {
    DispatchIntent {
        prompt_tag: "@mention".to_owned(),
        delivery_mode: DeliveryMode::Normal,
        retry_count: 0,
        not_before_ms,
        rule_fingerprint: None,
    }
}

fn authority(instance_id: &str) -> RuntimeLeaseIdentity {
    RuntimeLeaseIdentity {
        owner_id: "owner-a".to_owned(),
        agent_id: "agent-a".to_owned(),
        instance_id: instance_id.to_owned(),
    }
}

#[test]
fn recovery_queue_ack_suppresses_same_instance_replay_but_not_takeover(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let queued = store.admit_queued(
        &common::request("queued-ack", "queued-ack"),
        &dispatch(1_100),
        json!({}),
        1_100,
    )?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 3_000)?;
    let first = store.recover_for_restart("owner-a", "agent-a", "instance-a", 2_000, 10)?;
    assert_eq!(first.len(), 1);
    store.acknowledge_recovery_enqueued_for_runtime_lease(
        &authority("instance-a"),
        &queued.turn().turn_id,
        first[0].turn.version,
        2_100,
    )?;
    assert!(store
        .recover_for_restart("owner-a", "agent-a", "instance-a", 2_200, 10)?
        .is_empty());

    store.acquire_runtime_lease("owner-a", "agent-a", "instance-b", 3_000, 4_000)?;
    let takeover = store.recover_for_restart("owner-a", "agent-a", "instance-b", 3_000, 10)?;
    assert_eq!(takeover.len(), 1);
    assert_eq!(takeover[0].action, RecoveryAction::Rehydrate);
    Ok(())
}

#[test]
fn same_instance_recovery_advances_waiting_dispatch_when_it_becomes_due(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    store.admit_queued(
        &common::request("future-due", "future-due"),
        &dispatch(2_500),
        json!({}),
        1_100,
    )?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 4_000)?;
    let early = store.recover_for_restart("owner-a", "agent-a", "instance-a", 2_000, 10)?;
    assert_eq!(early[0].action, RecoveryAction::WaitUntilDue);

    let due = store.recover_for_restart("owner-a", "agent-a", "instance-a", 2_500, 10)?;
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].action, RecoveryAction::Rehydrate);
    Ok(())
}

#[test]
fn runtime_lease_fences_restart_recovery_and_holds_uncertain_running_work(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let queued = store.admit_queued(
        &common::request("queued", "digest-queued"),
        &dispatch(1_100),
        serde_json::json!({}),
        1_100,
    )?;
    let running = store.admit_queued(
        &common::request("running", "digest-running"),
        &dispatch(1_100),
        serde_json::json!({}),
        1_100,
    )?;
    store.mark_running(
        &running.turn().turn_id,
        "execution-old",
        serde_json::json!({}),
        1_200,
    )?;
    let future = store.admit_queued(
        &common::request("future", "digest-future"),
        &dispatch(4_000),
        serde_json::json!({}),
        1_100,
    )?;
    let accepted = store.admit(&common::request("legacy", "digest-legacy"))?;

    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 3_000)?;
    assert!(matches!(
        store.acquire_runtime_lease("owner-a", "agent-a", "instance-b", 2_000, 3_000),
        Err(LifecycleError::RuntimeLeaseHeld { .. })
    ));
    assert!(matches!(
        store.recover_for_restart("owner-a", "agent-a", "instance-b", 2_000, 10),
        Err(LifecycleError::RuntimeLeaseConflict)
    ));

    let recovered = store.recover_for_restart("owner-a", "agent-a", "instance-a", 2_000, 10)?;
    assert_eq!(recovered.len(), 4);
    let action_for = |turn_id: &str| {
        recovered
            .iter()
            .find(|item| item.turn.turn_id == turn_id)
            .map(|item| item.action)
    };
    assert_eq!(
        action_for(&queued.turn().turn_id),
        Some(RecoveryAction::Rehydrate)
    );
    assert_eq!(
        action_for(&running.turn().turn_id),
        Some(RecoveryAction::HoldUncertain)
    );
    assert_eq!(
        action_for(&future.turn().turn_id),
        Some(RecoveryAction::WaitUntilDue)
    );
    assert_eq!(
        action_for(&accepted.turn().turn_id),
        Some(RecoveryAction::MissingDispatchIntent)
    );
    assert_eq!(
        store.turn(&running.turn().turn_id)?.state,
        TurnState::Waiting
    );
    assert_eq!(store.turn(&running.turn().turn_id)?.execution_id, None);
    assert!(matches!(
        store.mark_terminal_many_for_execution(
            std::slice::from_ref(&running.turn().turn_id),
            "execution-old",
            &TerminalUpdate {
                state: TurnState::Completed,
                result_digest: Some("sha256:stale".to_owned()),
                payload: serde_json::json!({}),
                occurred_at_ms: 2_100,
            }
        ),
        Err(LifecycleError::ExecutionConflict)
    ));

    let event_count = store.events_after("owner-a", 0, 100)?.len();
    let same_recovery = store.recover_for_restart("owner-a", "agent-a", "instance-a", 2_100, 10)?;
    assert_eq!(same_recovery.len(), 4);
    assert_eq!(store.events_after("owner-a", 0, 100)?.len(), event_count);

    store.acquire_runtime_lease("owner-a", "agent-a", "instance-b", 3_000, 4_000)?;
    let next_recovery = store.recover_for_restart("owner-a", "agent-a", "instance-b", 3_000, 10)?;
    assert_eq!(
        next_recovery
            .iter()
            .find(|item| item.turn.turn_id == running.turn().turn_id)
            .map(|item| item.action),
        Some(RecoveryAction::HoldUncertain)
    );
    Ok(())
}

#[test]
fn second_instance_recovery_does_not_rewrite_unchanged_queued_or_waiting_turns(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let queued = store.admit_queued(
        &common::request("queued", "digest-queued"),
        &dispatch(1_100),
        json!({}),
        1_100,
    )?;
    let waiting = store.admit_queued(
        &common::request("waiting", "digest-waiting"),
        &dispatch(1_100),
        json!({}),
        1_100,
    )?;
    store.mark_waiting(&waiting.turn().turn_id, json!({}), 1_200)?;

    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 2_100)?;
    store.recover_for_restart("owner-a", "agent-a", "instance-a", 2_000, 10)?;

    let queued_after_first = store.turn(&queued.turn().turn_id)?;
    let waiting_after_first = store.turn(&waiting.turn().turn_id)?;
    let events_after_first = store.events_after("owner-a", 0, 100)?.len();

    store.acquire_runtime_lease("owner-a", "agent-a", "instance-b", 2_100, 3_000)?;
    let recovered = store.recover_for_restart("owner-a", "agent-a", "instance-b", 2_100, 10)?;

    assert_eq!(recovered.len(), 2);
    assert_eq!(
        store.turn(&queued.turn().turn_id)?.version,
        queued_after_first.version
    );
    assert_eq!(
        store.turn(&waiting.turn().turn_id)?.version,
        waiting_after_first.version
    );
    assert_eq!(
        store.events_after("owner-a", 0, 100)?.len(),
        events_after_first
    );
    Ok(())
}

#[test]
fn same_instance_recovery_reclassifies_a_turn_that_started_after_initial_recovery(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let queued = store.admit_queued(
        &common::request("queued", "digest-queued"),
        &dispatch(1_100),
        json!({}),
        1_100,
    )?;
    let turn_id = queued.turn().turn_id.clone();

    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 3_000)?;
    let initial = store.recover_for_restart("owner-a", "agent-a", "instance-a", 2_000, 10)?;
    assert_eq!(initial[0].action, RecoveryAction::Rehydrate);

    store.mark_running(&turn_id, "execution-a", json!({}), 2_100)?;
    let recovered = store.recover_for_restart("owner-a", "agent-a", "instance-a", 2_200, 10)?;

    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].prior_state, TurnState::Running);
    assert_eq!(recovered[0].action, RecoveryAction::HoldUncertain);
    let turn = store.turn(&turn_id)?;
    assert_eq!(turn.state, TurnState::Waiting);
    assert_eq!(turn.execution_id, None);
    Ok(())
}
