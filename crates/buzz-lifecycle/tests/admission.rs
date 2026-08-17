mod common;

use buzz_lifecycle::{
    AdmissionOutcome, DeliveryMode, DispatchIntent, LifecycleError, LifecycleStore, OutboxKind,
    QueueAdmissionOutcome, RejectionOutcome, TurnState,
};

#[test]
fn exact_duplicate_returns_original_without_new_event_or_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let request = common::request("nonce-a", "digest-a");

    let first = store.admit(&request)?;
    let second = store.admit(&request)?;

    assert!(matches!(first, AdmissionOutcome::Accepted(_)));
    assert!(matches!(second, AdmissionOutcome::Duplicate(_)));
    assert_eq!(first.turn().turn_id, second.turn().turn_id);
    assert_eq!(first.turn().state, TurnState::Accepted);
    assert_eq!(
        store
            .turn_for_nonce("owner-a", "agent-a", "nonce-a")?
            .map(|turn| turn.turn_id),
        Some(first.turn().turn_id.clone())
    );
    assert!(store
        .turn_for_nonce("owner-a", "agent-a", "missing")?
        .is_none());
    assert_eq!(store.events_after("owner-a", 0, 10)?.len(), 1);
    let outbox = store.pending_outbox(1_000, 10)?;
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].kind, OutboxKind::Receipt);
    Ok(())
}

#[test]
fn admission_and_queue_intent_commit_atomically_and_replay_repairs_legacy_accepted(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let request = common::request("nonce-a", "digest-a");
    let dispatch = DispatchIntent {
        prompt_tag: "@mention".to_owned(),
        delivery_mode: DeliveryMode::Normal,
        retry_count: 0,
        not_before_ms: 1_100,
        rule_fingerprint: Some("rules:v1".to_owned()),
    };

    store.admit(&request)?;
    let repaired =
        store.admit_queued_decision(&request, &dispatch, serde_json::json!({}), 1_100)?;
    assert!(matches!(repaired, QueueAdmissionOutcome::Repaired(_)));
    assert!(repaired.should_enqueue());
    assert_eq!(repaired.turn().state, TurnState::Queued);
    assert_eq!(
        store.dispatch_intent(&repaired.turn().turn_id)?,
        Some(dispatch.clone())
    );
    let replay = store.admit_queued_decision(&request, &dispatch, serde_json::json!({}), 1_200)?;
    assert!(matches!(replay, QueueAdmissionOutcome::Duplicate(_)));
    assert!(!replay.should_enqueue());
    assert_eq!(replay.turn().version, repaired.turn().version);
    assert_eq!(store.events_after("owner-a", 0, 10)?.len(), 2);
    assert_eq!(store.pending_outbox(2_000, 10)?.len(), 1);

    let mut conflicting = dispatch;
    conflicting.prompt_tag = "all".to_owned();
    assert!(matches!(
        store.admit_queued(&request, &conflicting, serde_json::json!({}), 1_300),
        Err(LifecycleError::DispatchConflict)
    ));
    Ok(())
}

#[test]
fn reused_nonce_with_changed_binding_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let request = common::request("nonce-a", "digest-a");
    store.admit(&request)?;

    let mut changed_digest = request.clone();
    changed_digest.input_digest = "digest-b".to_owned();
    assert!(matches!(
        store.admit(&changed_digest),
        Err(LifecycleError::NonceConflict)
    ));

    let mut changed_channel = request.clone();
    changed_channel.channel_id = "channel-b".to_owned();
    assert!(matches!(
        store.admit(&changed_channel),
        Err(LifecycleError::NonceConflict)
    ));

    let mut changed_requester = request.clone();
    changed_requester.requester_id = "requester-b".to_owned();
    assert!(matches!(
        store.admit(&changed_requester),
        Err(LifecycleError::NonceConflict)
    ));

    let mut changed_expiry = request;
    changed_expiry.expires_at_ms += 1;
    assert!(matches!(
        store.admit(&changed_expiry),
        Err(LifecycleError::NonceConflict)
    ));

    assert_eq!(store.events_after("owner-a", 0, 10)?.len(), 1);
    assert_eq!(store.pending_outbox(2_000, 10)?.len(), 1);
    Ok(())
}

#[test]
fn admission_validates_expiry_and_identity_before_writing() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;

    let mut invalid = common::request("nonce-a", "digest-a");
    invalid.owner_id.clear();
    assert!(matches!(
        store.admit(&invalid),
        Err(LifecycleError::InvalidRequest(_))
    ));

    let mut invalid_expiry = common::request("nonce-b", "digest-b");
    invalid_expiry.expires_at_ms = invalid_expiry.received_at_ms;
    assert!(matches!(
        store.admit(&invalid_expiry),
        Err(LifecycleError::InvalidRequest(_))
    ));

    assert!(store
        .active_turns_page("owner-a", None, 1_000)?
        .turns
        .is_empty());
    assert!(store.events_after("owner-a", 0, 10)?.is_empty());
    assert!(store.pending_outbox(2_000, 10)?.is_empty());
    Ok(())
}

#[test]
fn capacity_rejection_is_a_durable_exactly_once_tombstone() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
    let request = common::request("nonce-a", "digest-a");
    let first = store.reject_admission(
        &request,
        "queue_capacity",
        serde_json::json!({"retryable": true}),
        1_100,
    )?;
    let replay = store.reject_admission(
        &request,
        "queue_capacity",
        serde_json::json!({"retryable": true}),
        1_200,
    )?;
    assert!(matches!(first, RejectionOutcome::Rejected(_)));
    assert!(matches!(replay, RejectionOutcome::Duplicate(_)));
    assert_eq!(first.turn().turn_id, replay.turn().turn_id);
    assert_eq!(first.turn().state, TurnState::Rejected);
    assert!(store
        .active_turns_for_agent_page("owner-a", "agent-a", None, 1_000)?
        .turns
        .is_empty());
    assert_eq!(store.events_after("owner-a", 0, 10)?.len(), 1);
    let outbox = store.pending_outbox(2_000, 10)?;
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].kind, OutboxKind::Terminal);
    assert_eq!(outbox[0].payload["state"], "rejected");
    assert_eq!(outbox[0].payload["version"], 0);
    assert_eq!(outbox[0].payload["detail"]["reasonCode"], "queue_capacity");

    let later_admission = store.admit(&request)?;
    assert!(matches!(later_admission, AdmissionOutcome::Duplicate(_)));
    assert_eq!(later_admission.turn().state, TurnState::Rejected);
    assert_eq!(store.events_after("owner-a", 0, 10)?.len(), 1);
    assert_eq!(store.pending_outbox(2_000, 10)?.len(), 1);
    Ok(())
}
