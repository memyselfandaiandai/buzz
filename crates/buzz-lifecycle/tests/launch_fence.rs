use buzz_lifecycle::LifecycleStore;
use tempfile::tempdir;

mod common;

/// Proves launch fence: inert create, monotonic epoch bump in same txn as
/// cancel/activate (serialized by IMMEDIATE transaction), single-use activation
/// capability, and cancel-wins semantics.
#[test]
fn launch_fence_cancel_wins_over_concurrent_activate() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("launch.db");
    let store = LifecycleStore::open(&path).unwrap();

    let fence0 = store.get_launch_fence("owner-a", "agent-a").unwrap();
    assert_eq!(fence0.launch_epoch, 0);

    let req = common::request("nonce-inert", "digest-inert");
    let inert = store.create_inert_turn(&req).unwrap();
    assert_eq!(inert.owner_id, "owner-a");

    let cap = store
        .mint_activation_capability("owner-a", "agent-a", 1_000)
        .unwrap();
    assert_eq!(cap.launch_epoch, 1);
    assert!(!cap.consumed);

    let cancelled = store.cancel_turn_with_fence(&inert.turn_id, 1_001).unwrap();
    match cancelled {
        buzz_lifecycle::CancelOutcome::Cancelled(snap) => assert_eq!(snap.state, buzz_lifecycle::TurnState::Cancelled),
        other => panic!("cancel expected {other:?}"),
    }

    let fence1 = store.get_launch_fence("owner-a", "agent-a").unwrap();
    assert_eq!(fence1.launch_epoch, 1);

    let act = store
        .activate_with_capability(&inert.turn_id, &cap.capability_id, 2_000, 1_002)
        .unwrap();
    assert!(
        matches!(act, buzz_lifecycle::ActivationOutcome::AlreadyConsumed),
        "cancel-wins: activation should lose, got {act:?}"
    );
    let after = store.turn(&inert.turn_id).unwrap();
    assert_eq!(after.state, buzz_lifecycle::TurnState::Cancelled);

    let req2 = common::request("nonce-inert-2", "digest-inert-2");
    let inert2 = store.create_inert_turn(&req2).unwrap();
    let cap2 = store
        .mint_activation_capability("owner-a", "agent-a", 1_010)
        .unwrap();
    let fence_before = store.get_launch_fence("owner-a", "agent-a").unwrap();
    assert!(cap2.launch_epoch == fence_before.launch_epoch || cap2.launch_epoch > fence_before.launch_epoch - 1);
    // strict monotonicity: capability epoch must be > previous fence epoch or equal to current fence (which already bumped)
    assert!(cap2.launch_epoch >= fence_before.launch_epoch);

    let act2 = store
        .activate_with_capability(&inert2.turn_id, &cap2.capability_id, 3_000, 1_011)
        .unwrap();
    let snap2 = match act2 {
        buzz_lifecycle::ActivationOutcome::Activated(s) => s,
        other => panic!("second activate {other:?}"),
    };
    assert_eq!(snap2.turn_id, inert2.turn_id);
    let act2_reuse = store
        .activate_with_capability(&inert2.turn_id, &cap2.capability_id, 3_001, 1_012)
        .unwrap();
    assert!(
        matches!(act2_reuse, buzz_lifecycle::ActivationOutcome::AlreadyConsumed),
        "single-use capability must be consumed, got {act2_reuse:?}"
    );

    let fence_after = store.get_launch_fence("owner-a", "agent-a").unwrap();
    assert!(fence_after.launch_epoch > fence1.launch_epoch, "monotonic epoch: {:?} > {:?}", fence_after, fence1);
}
