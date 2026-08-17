use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use buzz_lifecycle::{
    AdmissionRequest, DeliveryMode, DispatchIntent, LifecycleStore, OutboxKind, RecoveryAction,
    RunClaimIdentity, RunLane, RunLaneCapacity, RuntimeLeaseIdentity, ScheduleIntent,
    ScheduledAdmissionOutcome, SchedulerPolicy, TerminalUpdate, TurnState,
};
use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;

const CHILD_ENV: &str = "BUZZ_LIFECYCLE_CRASH_CHILD";
const DATABASE_ENV: &str = "BUZZ_LIFECYCLE_CRASH_DATABASE";
const CHILD_CRASH_EXIT: i32 = 91;
const CHILD_UNEXPECTED_EXIT: i32 = 92;
const OWNER: &str = "crash-owner";
const AGENT: &str = "crash-agent";
const INSTANCE_A: &str = "instance-a";
const INSTANCE_B: &str = "instance-b";
const EXECUTION: &str = "crash-execution";
const LEASE_A_EXPIRES_AT_MS: i64 = 1_000;
const TURN_EXPIRES_AT_MS: i64 = 10_000;

fn authority(instance_id: &str) -> RuntimeLeaseIdentity {
    RuntimeLeaseIdentity {
        owner_id: OWNER.to_owned(),
        agent_id: AGENT.to_owned(),
        instance_id: instance_id.to_owned(),
    }
}

fn request(nonce: &str) -> AdmissionRequest {
    AdmissionRequest {
        owner_id: OWNER.to_owned(),
        agent_id: AGENT.to_owned(),
        requester_id: "crash-requester".to_owned(),
        channel_id: "crash-channel".to_owned(),
        client_nonce: nonce.to_owned(),
        input_digest: format!("digest-{nonce}"),
        received_at_ms: 20,
        expires_at_ms: TURN_EXPIRES_AT_MS,
    }
}

fn dispatch() -> DispatchIntent {
    DispatchIntent {
        prompt_tag: "crash-boundary".to_owned(),
        delivery_mode: DeliveryMode::Normal,
        retry_count: 0,
        not_before_ms: 20,
        rule_fingerprint: Some("crash-matrix-v1".to_owned()),
    }
}

fn capacity() -> RunLaneCapacity {
    RunLaneCapacity {
        user: 8,
        agent: 8,
        background: 8,
    }
}

fn admit(
    store: &LifecycleStore,
    lease: &RuntimeLeaseIdentity,
    nonce: &str,
    occurred_at_ms: i64,
) -> buzz_lifecycle::Result<ScheduledAdmissionOutcome> {
    store.admit_scheduled_for_runtime_lease(
        lease,
        &request(nonce),
        &dispatch(),
        &ScheduleIntent::new(RunLane::User, "crash-matrix")?,
        &serde_json::to_string(&json!({"signedFixture": nonce}))?,
        capacity(),
        json!({"gate":"crash-reopen"}),
        occurred_at_ms,
    )
}

fn setup(database: &Path, nonce: &str) -> buzz_lifecycle::Result<String> {
    let store = LifecycleStore::open(database)?;
    store.acquire_runtime_lease(OWNER, AGENT, INSTANCE_A, 10, LEASE_A_EXPIRES_AT_MS)?;
    let admitted = admit(&store, &authority(INSTANCE_A), nonce, 20)?;
    Ok(admitted.turn().turn_id.clone())
}

fn terminal_update() -> TerminalUpdate {
    TerminalUpdate {
        state: TurnState::Completed,
        result_digest: Some("sha256:crash-boundary-result".to_owned()),
        payload: json!({"gate":"crash-reopen"}),
        occurred_at_ms: 40,
    }
}

fn claim(store: &LifecycleStore) -> buzz_lifecycle::Result<buzz_lifecycle::RunClaim> {
    store
        .claim_next_for_runtime_lease(
            &authority(INSTANCE_A),
            SchedulerPolicy::default(),
            EXECUTION,
            json!({"gate":"crash-reopen"}),
            30,
        )?
        .ok_or(buzz_lifecycle::LifecycleError::SchedulerClaimConflict)
}

fn child_database() -> PathBuf {
    std::env::var_os(DATABASE_ENV)
        .map(PathBuf::from)
        .expect("crash child database path")
}

fn child_checkpoint(label: &str) {
    println!("{label}");
    std::io::stdout().flush().expect("flush child checkpoint");
}

fn wait_for_parent_go() {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .expect("read parent go signal");
    assert_eq!(line.trim(), "GO");
}

/// Child entry point used by `durable_boundaries_survive_process_crash_and_reopen`.
///
/// It is ignored during ordinary test enumeration and explicitly selected in a
/// fresh process by the parent test. Intentional process exits model power loss:
/// destructors do not run and the connection cannot perform graceful cleanup.
#[test]
#[ignore = "subprocess helper selected by the crash/reopen matrix"]
fn crash_boundary_child() {
    let Some(mode) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let mode = mode.to_string_lossy();
    let store = LifecycleStore::open(child_database()).expect("open crash child store");

    match mode.as_ref() {
        "interrupt-claim" => {
            child_checkpoint("OPENED");
            wait_for_parent_go();
            child_checkpoint("CALLING");
            let _ = claim(&store);
            std::process::exit(CHILD_UNEXPECTED_EXIT);
        }
        "reserved" => {
            let claimed = claim(&store).expect("commit reserved claim");
            assert_eq!(claimed.identity.epoch, 1);
            child_checkpoint("RESERVED");
            std::process::exit(CHILD_CRASH_EXIT);
        }
        "launched" => {
            let claimed = claim(&store).expect("commit reserved claim");
            store
                .mark_claim_launched_for_runtime_lease(
                    &authority(INSTANCE_A),
                    &claimed.identity,
                    31,
                )
                .expect("commit launched phase");
            child_checkpoint("LAUNCHED");
            std::process::exit(CHILD_CRASH_EXIT);
        }
        "interrupt-terminal" => {
            child_checkpoint("OPENED");
            wait_for_parent_go();
            child_checkpoint("CALLING");
            let _ = store.finish_claim_for_runtime_lease(
                &authority(INSTANCE_A),
                &RunClaimIdentity {
                    epoch: 1,
                    execution_id: EXECUTION.to_owned(),
                },
                &terminal_update(),
            );
            std::process::exit(CHILD_UNEXPECTED_EXIT);
        }
        "terminal-committed" => {
            let claimed = claim(&store).expect("commit reserved claim");
            store
                .mark_claim_launched_for_runtime_lease(
                    &authority(INSTANCE_A),
                    &claimed.identity,
                    31,
                )
                .expect("commit launched phase");
            store
                .finish_claim_for_runtime_lease(
                    &authority(INSTANCE_A),
                    &claimed.identity,
                    &terminal_update(),
                )
                .expect("commit terminal settlement");
            child_checkpoint("TERMINAL_COMMITTED");
            std::process::exit(CHILD_CRASH_EXIT);
        }
        other => panic!("unknown crash child mode: {other}"),
    }
}

struct CrashChild {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
}

impl CrashChild {
    fn spawn(database: &Path, mode: &str, piped_stdin: bool) -> std::io::Result<Self> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "crash_boundary_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, mode)
            .env(DATABASE_ENV, database)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if piped_stdin {
            command.stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = command.spawn()?;
        let stdout = BufReader::new(child.stdout.take().expect("piped child stdout"));
        Ok(Self { child, stdout })
    }

    fn wait_for(&mut self, checkpoint: &str) -> std::io::Result<()> {
        let mut line = String::new();
        loop {
            line.clear();
            let read = self.stdout.read_line(&mut line)?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("child exited before checkpoint {checkpoint}"),
                ));
            }
            // libtest may print `test crash_boundary_child ... ` without a
            // newline immediately before uncaptured child output.
            if line.split_whitespace().last() == Some(checkpoint) {
                return Ok(());
            }
        }
    }

    fn send_go(&mut self) -> std::io::Result<()> {
        let stdin = self.child.stdin.as_mut().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "child stdin is not piped")
        })?;
        stdin.write_all(b"GO\n")?;
        stdin.flush()
    }

    fn wait(mut self) -> std::io::Result<ExitStatus> {
        self.child.wait()
    }

    fn kill_while_blocked(mut self) -> std::io::Result<ExitStatus> {
        thread::sleep(Duration::from_millis(150));
        assert!(
            self.child.try_wait()?.is_none(),
            "child unexpectedly completed a write while an immediate transaction held the database"
        );
        self.child.kill()?;
        self.child.wait()
    }
}

fn assert_intentional_crash(status: ExitStatus) {
    assert_eq!(status.code(), Some(CHILD_CRASH_EXIT), "{status:?}");
}

fn acquire_takeover(store: &LifecycleStore) -> buzz_lifecycle::Result<RuntimeLeaseIdentity> {
    store.acquire_runtime_lease(OWNER, AGENT, INSTANCE_B, 1_000, 5_000)?;
    Ok(authority(INSTANCE_B))
}

fn terminal_outbox_count(store: &LifecycleStore) -> buzz_lifecycle::Result<usize> {
    Ok(store
        .pending_outbox(5_000, 100)?
        .into_iter()
        .filter(|record| record.kind == OutboxKind::Terminal)
        .count())
}

#[test]
fn durable_boundaries_survive_process_crash_and_reopen() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("crash/reopen boundary 1: claim before commit");
    // Boundary 1: the claim call is interrupted while another immediate
    // transaction prevents its write transaction from committing. Reopen must
    // expose the original runnable turn and no active projection.
    let before_claim = TempDir::new()?;
    let before_claim_db = before_claim.path().join("before-claim.sqlite3");
    let before_claim_turn = setup(&before_claim_db, "before-claim")?;
    let mut child = CrashChild::spawn(&before_claim_db, "interrupt-claim", true)?;
    child.wait_for("OPENED")?;
    let lock = Connection::open(&before_claim_db)?;
    lock.execute_batch("BEGIN IMMEDIATE")?;
    child.send_go()?;
    child.wait_for("CALLING")?;
    let interrupted = child.kill_while_blocked()?;
    assert!(!interrupted.success());
    lock.execute_batch("ROLLBACK")?;
    let store = LifecycleStore::open(&before_claim_db)?;
    assert_eq!(store.turn(&before_claim_turn)?.state, TurnState::Queued);
    assert!(store
        .run_scheduler_snapshot(OWNER, AGENT)?
        .active_execution_id
        .is_none());
    let claimed = claim(&store)?;
    assert_eq!(claimed.turn.turn_id, before_claim_turn);

    // Boundary 2: Reserved is durable, but no provider launch occurred. A new
    // lease must recover it as safely rehydratable and make it claimable again.
    eprintln!("crash/reopen boundary 2: reserved before launch");
    let reserved = TempDir::new()?;
    let reserved_db = reserved.path().join("reserved.sqlite3");
    let reserved_turn = setup(&reserved_db, "reserved")?;
    let mut child = CrashChild::spawn(&reserved_db, "reserved", false)?;
    child.wait_for("RESERVED")?;
    assert_intentional_crash(child.wait()?);
    let store = LifecycleStore::open(&reserved_db)?;
    let takeover = acquire_takeover(&store)?;
    let recovery = store
        .recover_scheduler_active_for_runtime_lease(&takeover, 1_010)?
        .ok_or("reserved recovery missing")?;
    assert_eq!(recovery.turn.turn_id, reserved_turn);
    assert_eq!(recovery.action, RecoveryAction::Rehydrate);
    let reclaimed = store
        .claim_next_for_runtime_lease(
            &takeover,
            SchedulerPolicy::default(),
            "reserved-reclaimed",
            json!({}),
            1_020,
        )?
        .ok_or("reserved work was not re-claimable")?;
    assert_eq!(reclaimed.turn.turn_id, reserved_turn);

    // Boundary 3: Launched may already have caused external side effects. A
    // restart must quarantine it as hold_uncertain and never claim it again.
    eprintln!("crash/reopen boundary 3: launched before result");
    let launched = TempDir::new()?;
    let launched_db = launched.path().join("launched.sqlite3");
    let launched_turn = setup(&launched_db, "launched")?;
    let mut child = CrashChild::spawn(&launched_db, "launched", false)?;
    child.wait_for("LAUNCHED")?;
    assert_intentional_crash(child.wait()?);
    let store = LifecycleStore::open(&launched_db)?;
    let takeover = acquire_takeover(&store)?;
    let recovery = store
        .recover_scheduler_active_for_runtime_lease(&takeover, 1_010)?
        .ok_or("launched recovery missing")?;
    assert_eq!(recovery.turn.turn_id, launched_turn);
    assert_eq!(recovery.action, RecoveryAction::HoldUncertain);
    assert!(store
        .claim_next_for_runtime_lease(
            &takeover,
            SchedulerPolicy::default(),
            "must-not-replay-launched",
            json!({}),
            1_020,
        )?
        .is_none());

    // Boundary 4: terminal settlement is interrupted before commit. The turn,
    // active projection, and terminal outbox must roll back together.
    eprintln!("crash/reopen boundary 4: terminal before commit");
    let interrupted_terminal = TempDir::new()?;
    let interrupted_terminal_db = interrupted_terminal
        .path()
        .join("terminal-interrupted.sqlite3");
    let interrupted_terminal_turn = setup(&interrupted_terminal_db, "terminal-interrupted")?;
    let store = LifecycleStore::open(&interrupted_terminal_db)?;
    let claimed = claim(&store)?;
    store.mark_claim_launched_for_runtime_lease(&authority(INSTANCE_A), &claimed.identity, 31)?;
    let mut child = CrashChild::spawn(&interrupted_terminal_db, "interrupt-terminal", true)?;
    child.wait_for("OPENED")?;
    let lock = Connection::open(&interrupted_terminal_db)?;
    lock.execute_batch("BEGIN IMMEDIATE")?;
    child.send_go()?;
    child.wait_for("CALLING")?;
    let interrupted = child.kill_while_blocked()?;
    assert!(!interrupted.success());
    lock.execute_batch("ROLLBACK")?;
    let store = LifecycleStore::open(&interrupted_terminal_db)?;
    assert_eq!(
        store.turn(&interrupted_terminal_turn)?.state,
        TurnState::Running
    );
    assert_eq!(terminal_outbox_count(&store)?, 0);
    let takeover = acquire_takeover(&store)?;
    let recovery = store
        .recover_scheduler_active_for_runtime_lease(&takeover, 1_010)?
        .ok_or("interrupted terminal recovery missing")?;
    assert_eq!(recovery.action, RecoveryAction::HoldUncertain);
    assert_eq!(terminal_outbox_count(&store)?, 0);

    // Boundary 5: terminal settlement committed, then the process dies before
    // publication acknowledgement. Reopen sees one terminal outbox item; exact
    // input replay and repeated ACK remain idempotent and cannot relaunch work.
    eprintln!("crash/reopen boundary 5: terminal committed before ack");
    let committed_terminal = TempDir::new()?;
    let committed_terminal_db = committed_terminal.path().join("terminal-committed.sqlite3");
    let committed_terminal_turn = setup(&committed_terminal_db, "terminal-committed")?;
    let mut child = CrashChild::spawn(&committed_terminal_db, "terminal-committed", false)?;
    child.wait_for("TERMINAL_COMMITTED")?;
    assert_intentional_crash(child.wait()?);
    let store = LifecycleStore::open(&committed_terminal_db)?;
    assert_eq!(
        store.turn(&committed_terminal_turn)?.state,
        TurnState::Completed
    );
    assert!(store
        .run_scheduler_snapshot(OWNER, AGENT)?
        .active_execution_id
        .is_none());
    assert_eq!(terminal_outbox_count(&store)?, 1);
    let takeover = acquire_takeover(&store)?;
    let replay = admit(&store, &takeover, "terminal-committed", 1_010)?;
    assert!(matches!(replay, ScheduledAdmissionOutcome::Duplicate(_)));
    assert_eq!(replay.turn().state, TurnState::Completed);
    assert!(store
        .claim_next_for_runtime_lease(
            &takeover,
            SchedulerPolicy::default(),
            "must-not-replay-terminal",
            json!({}),
            1_020,
        )?
        .is_none());
    let claimed_outbox = store.claim_pending_outbox_for_runtime_lease(
        &takeover,
        1_020,
        100,
        "publisher-b",
        2_000,
    )?;
    let terminal = claimed_outbox
        .iter()
        .find(|record| record.kind == OutboxKind::Terminal)
        .ok_or("terminal outbox was not claimable after reopen")?;
    let delivered = store.mark_claimed_outbox_delivered_for_runtime_lease(
        &takeover,
        &terminal.outbox_id,
        "publisher-b",
        "relay-event-terminal",
        1_030,
    )?;
    let replayed_ack = store.mark_claimed_outbox_delivered_for_runtime_lease(
        &takeover,
        &terminal.outbox_id,
        "publisher-b",
        "relay-event-terminal",
        1_040,
    )?;
    assert_eq!(replayed_ack.delivered_at_ms, delivered.delivered_at_ms);
    assert_eq!(terminal_outbox_count(&store)?, 0);

    Ok(())
}
