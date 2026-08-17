mod common;

use buzz_lifecycle::{
    DeliveryMode, DispatchIntent, LifecycleError, LifecycleStore, RuntimeLeaseIdentity,
    TerminalUpdate, TurnState,
};
use serde_json::json;

fn dispatch(mode: DeliveryMode, retry_count: u32, not_before_ms: i64) -> DispatchIntent {
    DispatchIntent {
        prompt_tag: "@mention".to_owned(),
        delivery_mode: mode,
        retry_count,
        not_before_ms,
        rule_fingerprint: Some("rules:v1".to_owned()),
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
fn stale_runtime_cannot_admit_or_reject_new_work_after_takeover(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 2_500)?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-b", 2_500, 4_000)?;

    let admitted_request = common::request("stale-admission", "stale-admission");
    assert!(matches!(
        store.admit_queued_for_runtime_lease(
            &authority("instance-a"),
            &admitted_request,
            &dispatch(DeliveryMode::Normal, 0, 2_600),
            json!({}),
            2_600,
        ),
        Err(LifecycleError::RuntimeLeaseConflict)
    ));
    assert!(store
        .turn_for_nonce("owner-a", "agent-a", "stale-admission")?
        .is_none());

    let rejected_request = common::request("stale-rejection", "stale-rejection");
    assert!(matches!(
        store.reject_admission_for_runtime_lease(
            &authority("instance-a"),
            &rejected_request,
            "queue_capacity",
            json!({}),
            2_600,
        ),
        Err(LifecycleError::RuntimeLeaseConflict)
    ));
    assert!(store
        .turn_for_nonce("owner-a", "agent-a", "stale-rejection")?
        .is_none());
    assert!(store.pending_outbox(3_000, 10)?.is_empty());

    let current = store.admit_queued_for_runtime_lease(
        &authority("instance-b"),
        &admitted_request,
        &dispatch(DeliveryMode::Normal, 0, 2_700),
        json!({}),
        2_700,
    )?;
    assert_eq!(current.turn().state, TurnState::Queued);
    Ok(())
}

#[test]
fn expiry_reconciliation_is_scoped_and_fenced_by_runtime_lease(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let mut request = common::request("expired-event", "expired-event");
    request.expires_at_ms = 1_500;
    let admitted = store.admit_queued(
        &request,
        &dispatch(DeliveryMode::Normal, 0, 1_100),
        json!({}),
        1_100,
    )?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 1_200, 2_000)?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-b", 2_000, 4_000)?;

    assert!(matches!(
        store.expire_due_for_runtime_lease(&authority("instance-a"), 2_100, 10),
        Err(LifecycleError::RuntimeLeaseConflict)
    ));
    assert_eq!(
        store.turn(&admitted.turn().turn_id)?.state,
        TurnState::Queued
    );

    let expired = store.expire_due_for_runtime_lease(&authority("instance-b"), 2_100, 10)?;
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].state, TurnState::Expired);
    assert_eq!(
        store
            .pending_outbox(3_000, 10)?
            .iter()
            .filter(|record| record.kind == buzz_lifecycle::OutboxKind::Terminal)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn outbox_claim_retry_and_delivery_are_fenced_by_runtime_lease(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    store.admit_queued(
        &common::request("outbox-event", "outbox-event"),
        &dispatch(DeliveryMode::Normal, 0, 1_100),
        json!({}),
        1_100,
    )?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 2_500)?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-b", 2_500, 5_000)?;

    assert!(matches!(
        store.claim_pending_outbox_for_runtime_lease(
            &authority("instance-a"),
            2_600,
            10,
            "stale-claim",
            3_000,
        ),
        Err(LifecycleError::RuntimeLeaseConflict)
    ));
    let claimed = store.claim_pending_outbox_for_runtime_lease(
        &authority("instance-b"),
        2_600,
        10,
        "current-claim",
        3_000,
    )?;
    assert_eq!(claimed.len(), 1);
    let outbox_id = &claimed[0].outbox_id;

    assert!(matches!(
        store.record_claimed_outbox_attempt_for_runtime_lease(
            &authority("instance-a"),
            outbox_id,
            "current-claim",
            2_700,
            3_500,
        ),
        Err(LifecycleError::RuntimeLeaseConflict)
    ));
    assert!(matches!(
        store.mark_claimed_outbox_delivered_for_runtime_lease(
            &authority("instance-a"),
            outbox_id,
            "current-claim",
            "event-stale",
            2_700,
        ),
        Err(LifecycleError::RuntimeLeaseConflict)
    ));
    let delivered = store.mark_claimed_outbox_delivered_for_runtime_lease(
        &authority("instance-b"),
        outbox_id,
        "current-claim",
        "event-current",
        2_800,
    )?;
    assert_eq!(
        delivered.delivered_event_id.as_deref(),
        Some("event-current")
    );
    Ok(())
}

#[test]
fn live_reconciler_never_reclassifies_unmarked_queued_or_running_work(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let queued = store.admit_queued(
        &common::request("live-queued", "live-queued"),
        &dispatch(DeliveryMode::Normal, 0, 1_100),
        json!({}),
        1_100,
    )?;
    let running = store.admit_queued(
        &common::request("live-running", "live-running"),
        &dispatch(DeliveryMode::Normal, 0, 1_100),
        json!({}),
        1_100,
    )?;
    store.mark_running(&running.turn().turn_id, "execution-live", json!({}), 1_200)?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 4_000)?;

    assert!(store
        .reconcile_pending_recovery_for_runtime_lease(&authority("instance-a"), 2_100, 10)?
        .is_empty());
    assert_eq!(store.turn(&queued.turn().turn_id)?.state, TurnState::Queued);
    let still_running = store.turn(&running.turn().turn_id)?;
    assert_eq!(still_running.state, TurnState::Running);
    assert_eq!(
        still_running.execution_id.as_deref(),
        Some("execution-live")
    );
    Ok(())
}

#[test]
fn lease_checked_bind_is_all_or_nothing_and_scoped() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let first = store.admit_queued(
        &common::request("event-a", "event-a"),
        &dispatch(DeliveryMode::Normal, 0, 1_100),
        json!({}),
        1_100,
    )?;
    let second = store.admit_queued(
        &common::request("event-b", "event-b"),
        &dispatch(DeliveryMode::Normal, 0, 1_100),
        json!({}),
        1_100,
    )?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 3_000)?;

    let invalid_batch = vec!["event-a".to_owned(), "missing".to_owned()];
    assert!(matches!(
        store.bind_nonces_for_runtime_lease(
            &authority("instance-a"),
            &invalid_batch,
            "execution-a",
            json!({}),
            2_100,
        ),
        Err(LifecycleError::TurnNotFound)
    ));
    assert_eq!(store.turn(&first.turn().turn_id)?.state, TurnState::Queued);

    let valid_batch = vec!["event-a".to_owned(), "event-b".to_owned()];
    store.bind_nonces_for_runtime_lease(
        &authority("instance-a"),
        &valid_batch,
        "execution-a",
        json!({"batchSize": 2}),
        2_200,
    )?;
    for turn_id in [&first.turn().turn_id, &second.turn().turn_id] {
        let turn = store.turn(turn_id)?;
        assert_eq!(turn.state, TurnState::Running);
        assert_eq!(turn.execution_id.as_deref(), Some("execution-a"));
    }
    Ok(())
}

#[test]
fn stale_runtime_cannot_requeue_or_terminalize_results() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let admitted = store.admit_queued(
        &common::request("event-a", "event-a"),
        &dispatch(DeliveryMode::Normal, 0, 1_100),
        json!({}),
        1_100,
    )?;
    let event_ids = vec!["event-a".to_owned()];
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 2_500)?;
    store.bind_nonces_for_runtime_lease(
        &authority("instance-a"),
        &event_ids,
        "execution-a",
        json!({}),
        2_100,
    )?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-b", 2_500, 4_000)?;

    let retry = dispatch(DeliveryMode::Retry, 1, 3_000);
    assert!(matches!(
        store.mark_nonces_waiting_for_runtime_lease(
            &authority("instance-a"),
            &event_ids,
            "execution-a",
            &retry,
            json!({"reason": "retry"}),
            2_600,
        ),
        Err(LifecycleError::RuntimeLeaseConflict)
    ));
    assert!(matches!(
        store.mark_nonces_terminal_for_runtime_lease(
            &authority("instance-a"),
            &event_ids,
            "execution-a",
            &TerminalUpdate {
                state: TurnState::Completed,
                result_digest: Some("sha256:stale".to_owned()),
                payload: json!({}),
                occurred_at_ms: 2_600,
            },
        ),
        Err(LifecycleError::RuntimeLeaseConflict)
    ));
    assert_eq!(
        store.turn(&admitted.turn().turn_id)?.state,
        TurnState::Running
    );

    store.mark_nonces_waiting_for_runtime_lease(
        &authority("instance-b"),
        &event_ids,
        "execution-a",
        &retry,
        json!({"reason": "retry"}),
        2_700,
    )?;
    let waiting = store.turn(&admitted.turn().turn_id)?;
    assert_eq!(waiting.state, TurnState::Waiting);
    assert_eq!(waiting.execution_id, None);
    assert_eq!(store.dispatch_intent(&waiting.turn_id)?, Some(retry));
    Ok(())
}

#[test]
fn lease_checked_terminal_batch_rolls_back_on_execution_conflict(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let first = store.admit_queued(
        &common::request("event-a", "event-a"),
        &dispatch(DeliveryMode::Normal, 0, 1_100),
        json!({}),
        1_100,
    )?;
    let second = store.admit_queued(
        &common::request("event-b", "event-b"),
        &dispatch(DeliveryMode::Normal, 0, 1_100),
        json!({}),
        1_100,
    )?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 4_000)?;
    store.bind_nonces_for_runtime_lease(
        &authority("instance-a"),
        &["event-a".to_owned()],
        "execution-a",
        json!({}),
        2_100,
    )?;
    store.bind_nonces_for_runtime_lease(
        &authority("instance-a"),
        &["event-b".to_owned()],
        "execution-b",
        json!({}),
        2_100,
    )?;

    assert!(matches!(
        store.mark_nonces_terminal_for_runtime_lease(
            &authority("instance-a"),
            &["event-a".to_owned(), "event-b".to_owned()],
            "execution-a",
            &TerminalUpdate {
                state: TurnState::Completed,
                result_digest: Some("sha256:result".to_owned()),
                payload: json!({}),
                occurred_at_ms: 2_200,
            },
        ),
        Err(LifecycleError::ExecutionConflict)
    ));
    assert_eq!(store.turn(&first.turn().turn_id)?.state, TurnState::Running);
    assert_eq!(
        store.turn(&second.turn().turn_id)?.state,
        TurnState::Running
    );
    assert!(store
        .pending_outbox(3_000, 10)?
        .iter()
        .all(|record| record.kind != buzz_lifecycle::OutboxKind::Terminal));
    Ok(())
}

#[test]
fn active_execution_can_be_failed_atomically_without_reconstructing_event_ids(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let admitted = store.admit_queued(
        &common::request("event-a", "event-a"),
        &dispatch(DeliveryMode::Normal, 0, 1_100),
        json!({}),
        1_100,
    )?;
    store.acquire_runtime_lease("owner-a", "agent-a", "instance-a", 2_000, 4_000)?;
    store.bind_nonces_for_runtime_lease(
        &authority("instance-a"),
        &["event-a".to_owned()],
        "execution-a",
        json!({}),
        2_100,
    )?;
    store.mark_execution_terminal_for_runtime_lease(
        &authority("instance-a"),
        "execution-a",
        &TerminalUpdate {
            state: TurnState::Failed,
            result_digest: Some("sha256:panic".to_owned()),
            payload: json!({"reason": "prompt_task_panicked"}),
            occurred_at_ms: 2_200,
        },
    )?;
    assert_eq!(
        store.turn(&admitted.turn().turn_id)?.state,
        TurnState::Failed
    );
    assert_eq!(
        store
            .pending_outbox(3_000, 10)?
            .iter()
            .filter(|record| record.kind == buzz_lifecycle::OutboxKind::Terminal)
            .count(),
        1
    );
    Ok(())
}
