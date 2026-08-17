mod common;

use buzz_lifecycle::{
    ActiveTurnCursor, LifecycleError, LifecycleStore, OutboxKind, OutboxState, TerminalUpdate,
    TransitionOutcome, TurnState,
};
use serde_json::json;

#[test]
fn snapshot_and_tail_follow_ordered_transitions() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let admitted = store.admit(&common::request("nonce-a", "digest-a"))?;
    let turn_id = admitted.turn().turn_id.clone();

    store.mark_queued(&turn_id, json!({"reason": "dispatch"}), 1_100)?;
    store.mark_running(
        &turn_id,
        "execution-a",
        json!({"worker": "legacy-acp"}),
        1_200,
    )?;
    store.mark_waiting(&turn_id, json!({"cardId": "question-a"}), 1_300)?;

    let active = store.active_turns_page("owner-a", None, 1_000)?.turns;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].state, TurnState::Waiting);
    assert_eq!(active[0].execution_id.as_deref(), Some("execution-a"));

    let first_page = store.events_after("owner-a", 0, 2)?;
    assert_eq!(first_page.len(), 2);
    assert_eq!(first_page[0].kind, TurnState::Accepted);
    assert_eq!(first_page[1].kind, TurnState::Queued);
    let second_page = store.events_after("owner-a", first_page[1].sequence, 10)?;
    assert_eq!(second_page.len(), 2);
    assert_eq!(second_page[0].kind, TurnState::Running);
    assert_eq!(second_page[1].kind, TurnState::Waiting);
    Ok(())
}

#[test]
fn active_projection_uses_bounded_keyset_pages_without_replay_or_gaps(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    for suffix in ["a", "b", "c"] {
        store.admit(&common::request(
            &format!("nonce-{suffix}"),
            &format!("digest-{suffix}"),
        ))?;
    }

    let first = store.active_turns_page("owner-a", None, 2)?;
    assert_eq!(first.turns.len(), 2);
    let cursor = first.next_cursor.ok_or("first page must have a cursor")?;
    assert_eq!(cursor.turn_id, first.turns[1].turn_id);

    let second = store.active_turns_page("owner-a", Some(&cursor), 2)?;
    assert_eq!(second.turns.len(), 1);
    assert!(second.next_cursor.is_none());

    let mut ids = first
        .turns
        .into_iter()
        .map(|turn| turn.turn_id)
        .collect::<Vec<_>>();
    ids.extend(second.turns.into_iter().map(|turn| turn.turn_id));
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 3);

    let invalid = ActiveTurnCursor {
        accepted_at_ms: -1,
        turn_id: "turn-a".to_owned(),
    };
    assert!(matches!(
        store.active_turns_page("owner-a", Some(&invalid), 2),
        Err(LifecycleError::InvalidRequest(_))
    ));
    assert!(matches!(
        store.active_turns_page("owner-a", None, 0),
        Err(LifecycleError::InvalidRequest(_))
    ));
    Ok(())
}

#[test]
fn terminal_transition_is_exactly_once_and_removes_active_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let admitted = store.admit(&common::request("nonce-a", "digest-a"))?;
    let turn_id = admitted.turn().turn_id.clone();
    store.mark_running(&turn_id, "execution-a", json!({}), 1_200)?;

    let terminal = TerminalUpdate {
        state: TurnState::Completed,
        result_digest: Some("result-a".to_owned()),
        payload: json!({"messageId": "message-a"}),
        occurred_at_ms: 1_500,
    };
    let first = store.mark_terminal_many_for_execution(
        std::slice::from_ref(&turn_id),
        "execution-a",
        &terminal,
    )?;
    let second = store.mark_terminal_many_for_execution(
        std::slice::from_ref(&turn_id),
        "execution-a",
        &terminal,
    )?;
    let first = &first[0];
    let second = &second[0];
    assert!(matches!(first, TransitionOutcome::Applied(_)));
    assert!(matches!(second, TransitionOutcome::Idempotent(_)));
    assert!(store
        .active_turns_page("owner-a", None, 1_000)?
        .turns
        .is_empty());

    let events = store.events_after("owner-a", 0, 10)?;
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].kind, TurnState::Completed);
    let outbox = store.pending_outbox(2_000, 10)?;
    assert_eq!(outbox.len(), 2);
    assert_eq!(
        outbox
            .iter()
            .filter(|item| item.kind == OutboxKind::Terminal)
            .count(),
        1
    );
    let terminal_record = outbox
        .iter()
        .find(|item| item.kind == OutboxKind::Terminal)
        .ok_or("terminal outbox record missing")?;
    assert_eq!(terminal_record.payload["turnId"], turn_id);
    assert_eq!(terminal_record.payload["state"], "completed");
    assert_eq!(terminal_record.payload["resultDigest"], "result-a");
    assert_eq!(terminal_record.payload["version"], 2);
    assert_eq!(terminal_record.payload["detail"]["messageId"], "message-a");

    let conflicting = TerminalUpdate {
        state: TurnState::Failed,
        result_digest: Some("result-b".to_owned()),
        payload: json!({}),
        occurred_at_ms: 1_600,
    };
    assert!(matches!(
        store.mark_terminal_many_for_execution(
            std::slice::from_ref(&turn_id),
            "execution-a",
            &conflicting
        ),
        Err(LifecycleError::TerminalConflict)
    ));
    assert_eq!(store.events_after("owner-a", 0, 10)?.len(), 3);
    Ok(())
}

#[test]
fn merged_attempt_transitions_all_turns_atomically() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let first = store.admit(&common::request("nonce-a", "digest-a"))?;
    let second = store.admit(&common::request("nonce-b", "digest-b"))?;
    let turn_ids = vec![first.turn().turn_id.clone(), second.turn().turn_id.clone()];

    let running =
        store.mark_running_many(&turn_ids, "execution-a", json!({"batchSize": 2}), 1_200)?;
    assert_eq!(running.len(), 2);
    assert!(running
        .iter()
        .all(|outcome| outcome.turn().state == TurnState::Running));

    let terminal = TerminalUpdate {
        state: TurnState::Completed,
        result_digest: Some("result-a".to_owned()),
        payload: json!({"executionId": "execution-a"}),
        occurred_at_ms: 1_500,
    };
    let completed = store.mark_terminal_many_for_execution(&turn_ids, "execution-a", &terminal)?;
    assert_eq!(completed.len(), 2);
    assert!(completed
        .iter()
        .all(|outcome| outcome.turn().state == TurnState::Completed));
    assert_eq!(
        store
            .pending_outbox(2_000, 10)?
            .iter()
            .filter(|item| item.kind == OutboxKind::Terminal)
            .count(),
        2
    );
    Ok(())
}

#[test]
fn merged_terminal_conflict_rolls_back_the_whole_batch() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let first = store.admit(&common::request("nonce-a", "digest-a"))?;
    let second = store.admit(&common::request("nonce-b", "digest-b"))?;
    let turn_ids = vec![first.turn().turn_id.clone(), second.turn().turn_id.clone()];
    store.mark_terminal(
        &turn_ids[0],
        &TerminalUpdate {
            state: TurnState::Failed,
            result_digest: Some("failure-a".to_owned()),
            payload: json!({}),
            occurred_at_ms: 1_300,
        },
    )?;

    let conflicting = TerminalUpdate {
        state: TurnState::Completed,
        result_digest: Some("result-a".to_owned()),
        payload: json!({}),
        occurred_at_ms: 1_500,
    };
    assert!(matches!(
        store.mark_terminal_many(&turn_ids, &conflicting),
        Err(LifecycleError::TerminalConflict)
    ));
    assert_eq!(store.turn(&turn_ids[0])?.state, TurnState::Failed);
    assert_eq!(store.turn(&turn_ids[1])?.state, TurnState::Accepted);
    assert_eq!(
        store
            .pending_outbox(2_000, 10)?
            .iter()
            .filter(|item| item.kind == OutboxKind::Terminal)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn outbox_retry_and_delivery_are_durable_and_idempotent() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    store.admit(&common::request("nonce-a", "digest-a"))?;
    let pending = store.pending_outbox(1_000, 10)?;
    assert_eq!(pending.len(), 1);

    let claimed = store.claim_pending_outbox(1_000, 10, "publisher-a", 1_500)?;
    assert_eq!(claimed.len(), 1);
    let attempted =
        store.record_claimed_outbox_attempt(&pending[0].outbox_id, "publisher-a", 2_000)?;
    assert_eq!(attempted.attempts, 1);
    assert!(store.pending_outbox(1_999, 10)?.is_empty());
    assert_eq!(store.pending_outbox(2_000, 10)?.len(), 1);

    let claimed = store.claim_pending_outbox(2_000, 10, "publisher-b", 2_500)?;
    assert_eq!(claimed.len(), 1);
    let delivered = store.mark_claimed_outbox_delivered(
        &pending[0].outbox_id,
        "publisher-b",
        "event-a",
        2_100,
    )?;
    assert_eq!(delivered.state, OutboxState::Delivered);
    assert_eq!(delivered.delivered_at_ms, Some(2_100));
    let repeated = store.mark_claimed_outbox_delivered(
        &pending[0].outbox_id,
        "publisher-b",
        "event-a",
        2_200,
    )?;
    assert_eq!(repeated.delivered_at_ms, Some(2_100));
    assert!(store.pending_outbox(3_000, 10)?.is_empty());
    Ok(())
}

#[test]
fn leased_outbox_claim_fences_publishers_and_records_event_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    store.admit(&common::request("nonce-a", "digest-a"))?;

    let claimed = store.claim_pending_outbox(1_000, 10, "publisher-a", 2_000)?;
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].claim_token.as_deref(), Some("publisher-a"));
    assert!(store
        .claim_pending_outbox(1_000, 10, "publisher-b", 2_000)?
        .is_empty());
    assert!(matches!(
        store.mark_claimed_outbox_delivered(&claimed[0].outbox_id, "publisher-b", "event-a", 1_100),
        Err(LifecycleError::OutboxClaimConflict)
    ));

    let delivered = store.mark_claimed_outbox_delivered(
        &claimed[0].outbox_id,
        "publisher-a",
        "event-a",
        1_100,
    )?;
    assert_eq!(delivered.state, OutboxState::Delivered);
    assert_eq!(delivered.delivered_event_id.as_deref(), Some("event-a"));
    let replay = store.mark_claimed_outbox_delivered(
        &claimed[0].outbox_id,
        "publisher-a",
        "event-a",
        1_200,
    )?;
    assert_eq!(replay.delivered_at_ms, Some(1_100));
    Ok(())
}

#[test]
fn expired_outbox_claim_is_reclaimable_and_retry_backoff_is_monotonic(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    store.admit(&common::request("nonce-a", "digest-a"))?;
    let first = store.claim_pending_outbox(1_000, 10, "publisher-a", 1_100)?;
    assert_eq!(first.len(), 1);
    let reclaimed = store.claim_pending_outbox(1_100, 10, "publisher-b", 1_200)?;
    assert_eq!(reclaimed.len(), 1);
    store.record_claimed_outbox_attempt(&reclaimed[0].outbox_id, "publisher-b", 5_000)?;

    let claimed = store.claim_pending_outbox(5_000, 10, "publisher-c", 6_000)?;
    assert_eq!(claimed.len(), 1);
    let attempted =
        store.record_claimed_outbox_attempt(&reclaimed[0].outbox_id, "publisher-c", 2_000)?;
    assert_eq!(attempted.not_before_ms, 5_000);
    assert!(store.pending_outbox(4_999, 10)?.is_empty());
    assert_eq!(store.pending_outbox(5_000, 10)?.len(), 1);
    Ok(())
}

#[test]
fn owner_projection_isolation_is_structural() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    store.admit(&common::request("nonce-a", "digest-a"))?;
    let mut other = common::request("nonce-b", "digest-b");
    other.owner_id = "owner-b".to_owned();
    store.admit(&other)?;
    let mut same_owner_other_agent = common::request("nonce-c", "digest-c");
    same_owner_other_agent.agent_id = "agent-b".to_owned();
    store.admit(&same_owner_other_agent)?;

    assert_eq!(
        store.active_turns_page("owner-a", None, 1_000)?.turns.len(),
        2
    );
    assert_eq!(
        store
            .active_turns_for_agent_page("owner-a", "agent-a", None, 1_000)?
            .turns
            .len(),
        1
    );
    assert_eq!(
        store
            .active_turns_for_agent_page("owner-a", "agent-b", None, 1_000)?
            .turns
            .len(),
        1
    );
    assert_eq!(
        store.active_turns_page("owner-b", None, 1_000)?.turns.len(),
        1
    );
    assert_eq!(store.events_after("owner-a", 0, 10)?.len(), 2);
    assert_eq!(store.events_after("owner-b", 0, 10)?.len(), 1);
    assert!(store.events_after("owner-c", 0, 10)?.is_empty());
    Ok(())
}

#[test]
fn expiry_reconciler_writes_terminal_event_and_outbox_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let admitted = store.admit(&common::request("nonce-a", "digest-a"))?;

    assert!(store.expire_due(60_999, 10)?.is_empty());
    let expired = store.expire_due(61_000, 10)?;
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].turn_id, admitted.turn().turn_id);
    assert_eq!(expired[0].state, TurnState::Expired);
    assert!(store.expire_due(70_000, 10)?.is_empty());
    assert!(store
        .active_turns_page("owner-a", None, 1_000)?
        .turns
        .is_empty());

    let events = store.events_after("owner-a", 0, 10)?;
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].kind, TurnState::Expired);
    let outbox = store.pending_outbox(70_000, 10)?;
    assert_eq!(outbox.len(), 2);
    assert_eq!(
        outbox
            .iter()
            .filter(|item| item.kind == OutboxKind::Terminal)
            .count(),
        1
    );
    Ok(())
}
