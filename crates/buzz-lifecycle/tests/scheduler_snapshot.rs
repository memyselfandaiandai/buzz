use buzz_lifecycle::{
    AdmissionRequest, DeliveryMode, DispatchIntent, LifecycleStore, RunLane, ScheduleIntent,
    SchedulerCounters, TurnState,
};
use rusqlite::{params, Connection};
use serde_json::json;
use tempfile::TempDir;

fn request(owner_id: &str, agent_id: &str, nonce: &str, received_at_ms: i64) -> AdmissionRequest {
    AdmissionRequest {
        owner_id: owner_id.to_owned(),
        agent_id: agent_id.to_owned(),
        requester_id: "requester".to_owned(),
        channel_id: "channel".to_owned(),
        client_nonce: nonce.to_owned(),
        input_digest: format!("digest-{nonce}"),
        received_at_ms,
        expires_at_ms: received_at_ms + 60_000,
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

fn queued_turn(
    store: &LifecycleStore,
    owner_id: &str,
    agent_id: &str,
    nonce: &str,
    received_at_ms: i64,
    due_at_ms: i64,
) -> buzz_lifecycle::Result<String> {
    let admitted = store.admit_queued(
        &request(owner_id, agent_id, nonce, received_at_ms),
        &dispatch(due_at_ms),
        json!({}),
        received_at_ms,
    )?;
    Ok(admitted.turn().turn_id.clone())
}

fn set_lane(
    connection: &Connection,
    turn_id: &str,
    lane: &str,
    source: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE turn_dispatch SET lane=?2,source=?3 WHERE turn_id=?1",
        params![turn_id, lane, source],
    )?;
    Ok(())
}

#[test]
fn schedule_intent_enforces_a_bounded_nonempty_source() -> buzz_lifecycle::Result<()> {
    let intent = ScheduleIntent::new(RunLane::Agent, "teammate-message")?;
    assert_eq!(intent.lane(), RunLane::Agent);
    assert_eq!(intent.source(), "teammate-message");

    assert!(ScheduleIntent::new(RunLane::User, "").is_err());
    assert!(ScheduleIntent::new(RunLane::Background, "x".repeat(65)).is_err());
    assert!(ScheduleIntent::new(RunLane::Background, "🙂".repeat(64)).is_ok());
    Ok(())
}

#[test]
fn snapshot_reports_fixed_lane_aggregates_active_state_and_scope_isolation(
) -> buzz_lifecycle::Result<()> {
    let directory = TempDir::new()?;
    let database = directory.path().join("lifecycle.sqlite");
    let store = LifecycleStore::open(&database)?;

    let user_newer = queued_turn(&store, "owner-a", "agent-a", "user-newer", 1_000, 5_000)?;
    let user_older = queued_turn(&store, "owner-a", "agent-a", "user-older", 900, 6_000)?;
    store.mark_waiting(&user_older, json!({}), 1_200)?;
    let agent = queued_turn(&store, "owner-a", "agent-a", "agent", 1_100, 4_500)?;
    let running_background = queued_turn(&store, "owner-a", "agent-a", "running", 800, 4_000)?;
    store.mark_running(&running_background, "execution-running", json!({}), 1_300)?;
    let other_agent = queued_turn(&store, "owner-a", "agent-b", "other-agent", 700, 3_000)?;
    let _other_owner = queued_turn(&store, "owner-b", "agent-a", "other-owner", 600, 2_000)?;

    let connection = Connection::open(&database)?;
    set_lane(&connection, &user_newer, "user", "human")?;
    set_lane(&connection, &user_older, "user", "human")?;
    set_lane(&connection, &agent, "agent", "teammate")?;
    set_lane(&connection, &running_background, "background", "routine")?;
    set_lane(&connection, &other_agent, "background", "isolated")?;
    connection.execute(
        "INSERT INTO run_scheduler_state(
            owner_id,agent_id,next_epoch,active_epoch,active_execution_id,active_lane,
            active_source,active_started_at_ms,claims_since_agent,claims_since_background,
            updated_at_ms
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            "owner-a",
            "agent-a",
            12_i64,
            11_i64,
            "execution-active",
            "background",
            "routine",
            1_300_i64,
            4_i64,
            19_i64,
            1_301_i64,
        ],
    )?;
    connection.execute(
        "INSERT INTO run_scheduler_state(owner_id,agent_id,updated_at_ms)
         VALUES ('owner-a','agent-b',9999)",
        [],
    )?;
    let expected_owner_sequence: i64 = connection.query_row(
        "SELECT MAX(sequence) FROM turn_events WHERE owner_id='owner-a'",
        [],
        |row| row.get(0),
    )?;
    drop(connection);

    let snapshot = store.run_scheduler_snapshot("owner-a", "agent-a")?;
    assert_eq!(snapshot.lanes.len(), 3);
    assert_eq!(snapshot.lane(RunLane::User).depth, 2);
    assert_eq!(
        snapshot.lane(RunLane::User).oldest_accepted_at_ms,
        Some(900)
    );
    assert_eq!(snapshot.lane(RunLane::User).oldest_due_at_ms, Some(5_000));
    assert_eq!(snapshot.lane(RunLane::Agent).depth, 1);
    assert_eq!(snapshot.lane(RunLane::Agent).oldest_due_at_ms, Some(4_500));
    assert_eq!(snapshot.lane(RunLane::Background).depth, 0);
    assert_eq!(snapshot.next_epoch, 12);
    assert_eq!(snapshot.active_epoch, Some(11));
    assert_eq!(
        snapshot.active_execution_id.as_deref(),
        Some("execution-active")
    );
    assert_eq!(snapshot.active_lane, Some(RunLane::Background));
    assert_eq!(snapshot.active_source.as_deref(), Some("routine"));
    assert_eq!(snapshot.active_started_at_ms, Some(1_300));
    assert_eq!(
        snapshot.counters,
        SchedulerCounters {
            agent_bypasses: 4,
            background_bypasses: 19,
        }
    );
    assert_eq!(snapshot.updated_at_ms, Some(1_301));
    assert_eq!(
        snapshot.owner_event_sequence,
        u64::try_from(expected_owner_sequence)
            .map_err(|_| buzz_lifecycle::LifecycleError::SequenceOutOfRange)?
    );

    let isolated = store.run_scheduler_snapshot("owner-a", "agent-b")?;
    assert_eq!(isolated.lane(RunLane::Background).depth, 1);
    assert_eq!(isolated.lane(RunLane::User).depth, 0);
    assert_eq!(isolated.next_epoch, 1);
    assert_eq!(isolated.updated_at_ms, Some(9_999));

    let absent = store.run_scheduler_snapshot("owner-c", "agent-c")?;
    assert_eq!(absent.lanes.len(), 3);
    assert!(absent.lanes.iter().all(|lane| lane.depth == 0));
    assert_eq!(absent.owner_event_sequence, 0);
    assert_eq!(absent.next_epoch, 1);
    assert_eq!(absent.updated_at_ms, None);
    assert!(store.run_scheduler_snapshot("", "agent-a").is_err());
    assert!(store.run_scheduler_snapshot("owner-a", "").is_err());
    Ok(())
}

#[test]
fn snapshot_cardinality_is_constant_with_large_event_history() -> buzz_lifecycle::Result<()> {
    let directory = TempDir::new()?;
    let database = directory.path().join("lifecycle.sqlite");
    let store = LifecycleStore::open(&database)?;
    let turn_id = queued_turn(&store, "owner-a", "agent-a", "history", 1_000, 2_000)?;
    let before = store.run_scheduler_snapshot("owner-a", "agent-a")?;

    let mut connection = Connection::open(&database)?;
    let transaction = connection.transaction()?;
    {
        let mut statement = transaction.prepare(
            "INSERT INTO turn_events(
                event_id,turn_id,owner_id,kind,from_state,to_state,payload_json,occurred_at_ms
             ) VALUES (?1,?2,'owner-a','queued','queued','queued','{}',2000)",
        )?;
        for sequence in 0..4_096 {
            statement.execute(params![format!("history-{sequence}"), turn_id])?;
        }
    }
    transaction.commit()?;

    let after = store.run_scheduler_snapshot("owner-a", "agent-a")?;
    assert_eq!(after.lanes.len(), 3);
    assert_eq!(after.lanes, before.lanes);
    assert_eq!(after.next_epoch, before.next_epoch);
    assert_eq!(after.counters, before.counters);
    assert_eq!(
        after.owner_event_sequence,
        before.owner_event_sequence + 4_096
    );
    assert_eq!(store.turn(&turn_id)?.state, TurnState::Queued);
    Ok(())
}
