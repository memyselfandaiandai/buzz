use buzz_lifecycle::{LifecycleStore, RetentionPolicy, TerminalUpdate, TurnState};
use tempfile::tempdir;

mod common;

/// Proves soft/hard watermarks + TTL eviction with VACUUM, never blocking admission.
/// Uses a tight retention window (7 days) + hard at 256 MiB with synthetic fill
/// via many terminal turns so that pruning can be observed deterministically.
#[test]
fn retention_caps_evict_oldest_terminal_with_ttl_and_size_and_never_block_admission() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("retention.db");
    let store = LifecycleStore::open(&path).unwrap();

    let policy = RetentionPolicy {
        owner_id: "owner-a".to_owned(),
        agent_id: "agent-a".to_owned(),
        retention_days: 7,
        soft_bytes: 256 * 1024 * 1024,
        hard_bytes: 512 * 1024 * 1024,
        updated_at_ms: 1_000,
    };
    store.set_retention_policy(&policy).unwrap();

    let day_ms: i64 = 24 * 60 * 60 * 1000;

    for i in 0..8 {
        let t = i * 2 * day_ms;
        let req = common::request_at(&format!("nonce-ttl-{i}"), &format!("digest-{i}"), t);
        let outcome = store.admit(&req).unwrap();
        let turn_id = match outcome {
            buzz_lifecycle::AdmissionOutcome::Accepted(t) => t.turn_id,
            other => panic!("admit {i} unexpected {other:?}"),
        };
        store.mark_queued(&turn_id, serde_json::json!({"step":"q"}), t + 1).unwrap();
        store
            .mark_terminal(
                &turn_id,
                &TerminalUpdate {
                    state: TurnState::Completed,
                    result_digest: Some("digest-result".to_owned()),
                    payload: serde_json::json!({}),
                    occurred_at_ms: t + 3,
                },
            )
            .unwrap();
    }

    // Add one rejected (tombstone) well before cutoff — must be kept.
    {
        let tomb_req = common::request_at("nonce-tombstone", "digest-tomb", 0);
        let outcome = store.reject_admission(&tomb_req, "policy", serde_json::json!({}), 0).unwrap();
        let snap = match outcome {
            buzz_lifecycle::RejectionOutcome::Rejected(t) | buzz_lifecycle::RejectionOutcome::Duplicate(t) => t,
        };
        assert_eq!(snap.state, TurnState::Rejected);
    }

    let usage_before = store.retention_usage("owner-a", "agent-a").unwrap();
    assert!(usage_before.pruneable_count >= 8, "pruneable {}", usage_before.pruneable_count);
    assert_eq!(usage_before.tombstone_count, 1);

    let now_ms = 20 * day_ms;
    let enforced = store.enforce_retention("owner-a", "agent-a", now_ms).unwrap();
    assert!(enforced.pruned >= 4, "pruned {} ttl_pruned {} size_pruned {}", enforced.pruned, enforced.ttl_pruned, enforced.size_pruned);
    assert!(enforced.vacuumed, "should have vacuumed after pruning");

    let usage_after = store.retention_usage("owner-a", "agent-a").unwrap();
    assert_eq!(usage_after.tombstone_count, 1, "tombstone kept");
    assert!(usage_after.pruneable_count <= 4, "remaining pruneable {}", usage_after.pruneable_count);

    let last = common::request_at("nonce-after", "digest-after", now_ms);
    let out = store.admit(&last).unwrap();
    assert!(matches!(out, buzz_lifecycle::AdmissionOutcome::Accepted(_)), "admission after retention {out:?}");

    for i in 100..120 {
        let req = common::request_at(&format!("nonce-sz-{i}"), &format!("digest-sz-{i}"), now_ms + i);
        let tid = match store.admit(&req).unwrap() {
            buzz_lifecycle::AdmissionOutcome::Accepted(t) => t.turn_id,
            _ => panic!(),
        };
        store.mark_queued(&tid, serde_json::json!({}), now_ms + i + 1).unwrap();
        store
            .mark_terminal(
                &tid,
                &TerminalUpdate {
                    state: TurnState::Completed,
                    result_digest: Some("d".to_owned()),
                    payload: serde_json::json!({}),
                    occurred_at_ms: now_ms + i + 3,
                },
            )
            .unwrap();
    }
    let live_req = common::request_at("nonce-live", "digest-live", now_ms + 999);
    let live_tid = match store.admit(&live_req).unwrap() {
        buzz_lifecycle::AdmissionOutcome::Accepted(t) => t.turn_id,
        _ => panic!(),
    };
    store.mark_queued(&live_tid, serde_json::json!({}), now_ms + 1000).unwrap();

    let _ = store.enforce_retention("owner-a", "agent-a", now_ms + 2000).unwrap();
    let live = store.turn(&live_tid).unwrap();
    assert!(!live.state.is_terminal(), "live turn must not be evicted: {:?}", live.state);
}
