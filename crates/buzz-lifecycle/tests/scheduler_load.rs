use buzz_lifecycle::{
    AdmissionRequest, DeliveryMode, DispatchIntent, LifecycleError, LifecycleStore, RunLane,
    RunLaneCapacity, RuntimeLeaseIdentity, ScheduleIntent, ScheduledAdmissionOutcome,
    SchedulerPolicy, TerminalUpdate, TurnState,
};
use serde_json::json;
use std::{
    sync::{Arc, Barrier},
    thread,
    time::Instant,
};
use tempfile::TempDir;

fn authority(instance: &str) -> RuntimeLeaseIdentity {
    RuntimeLeaseIdentity {
        owner_id: "load-owner".into(),
        agent_id: "load-agent".into(),
        instance_id: instance.into(),
    }
}

fn admit(
    store: &LifecycleStore,
    authority: &RuntimeLeaseIdentity,
    nonce: String,
    accepted: i64,
    expires: i64,
    lane: RunLane,
) -> buzz_lifecycle::Result<ScheduledAdmissionOutcome> {
    let request = AdmissionRequest {
        owner_id: authority.owner_id.clone(),
        agent_id: authority.agent_id.clone(),
        requester_id: "requester".into(),
        channel_id: "channel".into(),
        client_nonce: nonce.clone(),
        input_digest: format!("digest-{nonce}"),
        received_at_ms: accepted,
        expires_at_ms: expires,
    };
    store.admit_scheduled_for_runtime_lease(
        authority,
        &request,
        &DispatchIntent {
            prompt_tag: "load".into(),
            delivery_mode: DeliveryMode::Normal,
            retry_count: 0,
            not_before_ms: accepted,
            rule_fingerprint: Some("load-v1".into()),
        },
        &ScheduleIntent::new(lane, "keyless-load")?,
        &serde_json::to_string(&json!({"signedFixture": nonce}))?,
        RunLaneCapacity {
            user: 4096,
            agent: 4096,
            background: 4096,
        },
        json!({"gate":"scheduler-load"}),
        accepted,
    )
}

/// Run with `cargo test -p buzz-lifecycle --test scheduler_load -- --ignored --nocapture`.
#[test]
#[ignore = "explicit deterministic SQLite contention/load gate"]
fn keyless_scheduler_contention_and_restart_gate() -> Result<(), Box<dyn std::error::Error>> {
    const WRITERS: usize = 8;
    const EACH: usize = 40;
    let dir = TempDir::new()?;
    let path = dir.path().join("load.sqlite3");
    let store = LifecycleStore::open(&path)?;
    store.acquire_runtime_lease("load-owner", "load-agent", "a", 1, 10_100)?;
    let barrier = Arc::new(Barrier::new(WRITERS + 1));
    let started = Instant::now();
    let handles = (0..WRITERS)
        .map(|writer| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || -> buzz_lifecycle::Result<()> {
                let store = LifecycleStore::open(path)?;
                barrier.wait();
                for item in 0..EACH {
                    let n = writer * EACH + item;
                    let lane = match n % 3 {
                        0 => RunLane::User,
                        1 => RunLane::Agent,
                        _ => RunLane::Background,
                    };
                    assert!(matches!(
                        admit(
                            &store,
                            &authority("a"),
                            format!("{writer}-{item}"),
                            1000 + i64::try_from(n)
                                .map_err(|_| LifecycleError::SequenceOutOfRange)?,
                            90_000,
                            lane
                        )?,
                        ScheduledAdmissionOutcome::Accepted(_)
                    ));
                }
                Ok(())
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    for handle in handles {
        handle.join().map_err(|_| "writer panicked")??;
    }
    let admission_elapsed = started.elapsed();
    assert_eq!(
        store
            .run_scheduler_snapshot("load-owner", "load-agent")?
            .lanes
            .iter()
            .map(|v| v.depth)
            .sum::<u64>(),
        320
    );
    let execution_started = Instant::now();
    let mut settled = 0_u64;
    loop {
        let id = format!("execution-{settled}");
        let Some(claim) = store.claim_next_for_runtime_lease(
            &authority("a"),
            SchedulerPolicy::default(),
            &id,
            json!({}),
            2000 + i64::try_from(settled)?,
        )?
        else {
            break;
        };
        assert_eq!(claim.dispatch.prompt_tag, "load");
        assert!(claim.opaque_input_json.contains("signedFixture"));
        store.mark_claim_launched_for_runtime_lease(
            &authority("a"),
            &claim.identity,
            3000 + i64::try_from(settled)?,
        )?;
        store.finish_claim_for_runtime_lease(
            &authority("a"),
            &claim.identity,
            &TerminalUpdate {
                state: TurnState::Completed,
                result_digest: Some(format!("result-{settled}")),
                payload: json!({}),
                occurred_at_ms: 4000 + i64::try_from(settled)?,
            },
        )?;
        settled += 1;
    }
    assert_eq!(settled, 320);
    let execution_elapsed = execution_started.elapsed();
    admit(
        &store,
        &authority("a"),
        "takeover".into(),
        10_000,
        90_000,
        RunLane::User,
    )?;
    let reserved = store
        .claim_next_for_runtime_lease(
            &authority("a"),
            SchedulerPolicy::default(),
            "reserved",
            json!({}),
            10_001,
        )?
        .ok_or("missing claim")?;
    store.renew_runtime_lease("load-owner", "load-agent", "a", 10_002, 10_100)?;
    store.acquire_runtime_lease("load-owner", "load-agent", "b", 10_100, 100_000)?;
    assert!(matches!(
        store.finish_claim_for_runtime_lease(
            &authority("a"),
            &reserved.identity,
            &TerminalUpdate {
                state: TurnState::Completed,
                result_digest: Some("stale".into()),
                payload: json!({}),
                occurred_at_ms: 10_101
            }
        ),
        Err(LifecycleError::RuntimeLeaseConflict)
    ));
    let recovery = store.recover_for_restart("load-owner", "load-agent", "b", 10_101, 10)?;
    assert_eq!(recovery.len(), 1);
    assert_eq!(recovery[0].turn.state, TurnState::Waiting);
    let recovered_claim = store
        .claim_next_for_runtime_lease(
            &authority("b"),
            SchedulerPolicy::default(),
            "recovered",
            json!({}),
            10_102,
        )?
        .ok_or("recovered claim missing")?;
    store.mark_claim_launched_for_runtime_lease(
        &authority("b"),
        &recovered_claim.identity,
        10_103,
    )?;
    store.finish_claim_for_runtime_lease(
        &authority("b"),
        &recovered_claim.identity,
        &TerminalUpdate {
            state: TurnState::Completed,
            result_digest: Some("recovered".into()),
            payload: json!({}),
            occurred_at_ms: 10_104,
        },
    )?;
    for n in 0_i64..1105 {
        admit(
            &store,
            &authority("b"),
            format!("expiry-{n}"),
            20_000 + n,
            30_000,
            RunLane::Background,
        )?;
    }
    let _ = store.claim_next_for_runtime_lease(
        &authority("b"),
        SchedulerPolicy::default(),
        "expiry-1",
        json!({}),
        40_000,
    )?;
    assert_eq!(
        store
            .run_scheduler_snapshot("load-owner", "load-agent")?
            .lane(RunLane::Background)
            .depth,
        105
    );
    let _ = store.claim_next_for_runtime_lease(
        &authority("b"),
        SchedulerPolicy::default(),
        "expiry-2",
        json!({}),
        40_001,
    )?;
    assert_eq!(
        store
            .run_scheduler_snapshot("load-owner", "load-agent")?
            .lane(RunLane::Background)
            .depth,
        0
    );
    let snapshot_started = Instant::now();
    let snapshot = store.run_scheduler_snapshot("load-owner", "load-agent")?;
    let snapshot_elapsed = snapshot_started.elapsed();
    assert_eq!(snapshot.lanes.len(), 3);
    assert!(snapshot.active_execution_id.is_none());
    eprintln!("scheduler load gate: admissions={admission_elapsed:?}, claim+settle={execution_elapsed:?}, snapshot={snapshot_elapsed:?}, settled={settled}");
    Ok(())
}
