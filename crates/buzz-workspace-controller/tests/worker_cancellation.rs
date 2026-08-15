use buzz_workspace_controller::{
    run_cancellable_process, AdmissionRequest, Controller, ControllerError, ExecutionSpec,
    FakeKubernetes, Ledger, Lifecycle, Scope, TaskMaterialGrant, WorkerExit,
};
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn request() -> AdmissionRequest {
    AdmissionRequest {
        session_id: "worker-session".into(),
        jti: "worker-jti".into(),
        capability_digest: "sha256:worker".into(),
        owner_id: "agent:worker".into(),
        workspace_id: "workspace:worker".into(),
        scope: Scope::Agent("agent:worker".into()),
        signed_max_concurrency: 1,
        deployment_max_concurrency: 20,
        artifact_limit_bytes: 100,
        expires_at: 2_000_000_000,
    }
}

fn active(
    ledger: &Ledger,
    adapter: &FakeKubernetes,
    program: &str,
    args: Vec<String>,
) -> TaskMaterialGrant {
    let controller = Controller::new(ledger.clone(), adapter.clone());
    controller.provision_inert(&request(), None).unwrap();
    let spec = ExecutionSpec::new(program, args, "a".repeat(64)).unwrap();
    let capability = controller
        .authorize_launch("worker-session", &spec, 60, 0)
        .unwrap();
    controller.activate_launch(&capability).unwrap();
    controller
        .redeem_launch(&capability, "worker-boot-1", &spec, 0)
        .unwrap()
}

fn wait_for(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn worker_binary() -> String {
    env!("CARGO_BIN_EXE_buzz-workspace-controller").to_string()
}

fn heartbeat_pid(path: &std::path::Path) -> u32 {
    std::fs::read_to_string(path)
        .unwrap()
        .split(':')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[cfg(windows)]
fn emergency_kill(pid: u32) {
    let _ = Command::new("taskkill.exe")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status();
}

#[cfg(unix)]
fn emergency_kill(pid: u32) {
    // SAFETY: test cleanup targets the dedicated process group created by the worker.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}

#[test]
fn redeemed_grant_spawns_the_exact_authorized_program() {
    let dir = tempdir().unwrap();
    let ledger = Ledger::open(dir.path().join("ledger.db")).unwrap();
    let adapter = FakeKubernetes::open(dir.path().join("provider.db")).unwrap();
    let grant = active(
        &ledger,
        &adapter,
        env!("CARGO_BIN_EXE_buzz-workspace-controller"),
        vec!["unsupported".into()],
    );

    assert_eq!(
        run_cancellable_process(&ledger, &grant, Duration::from_millis(20)).unwrap(),
        WorkerExit::Exited(Some(64))
    );
}

#[test]
fn cancellation_from_another_process_stops_parent_and_descendant_heartbeats() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let parent_heartbeat = dir.path().join("parent-heartbeat");
    let child_heartbeat = dir.path().join("child-heartbeat");
    let ledger = Ledger::open(&db).unwrap();
    let adapter = FakeKubernetes::open(dir.path().join("provider.db")).unwrap();
    let binary = env!("CARGO_BIN_EXE_buzz-workspace-controller").to_string();
    let grant = active(
        &ledger,
        &adapter,
        &binary,
        vec![
            "heartbeat-parent".into(),
            parent_heartbeat.to_str().unwrap().to_string(),
            child_heartbeat.to_str().unwrap().to_string(),
        ],
    );

    let worker_ledger = Ledger::open(&db).unwrap();
    let worker = std::thread::spawn(move || {
        run_cancellable_process(&worker_ledger, &grant, Duration::from_millis(20))
    });

    wait_for(&parent_heartbeat);
    wait_for(&child_heartbeat);
    std::thread::sleep(Duration::from_millis(150));

    let status = Command::new(&binary)
        .args(["cancel", db.to_str().unwrap(), "worker-session"])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(worker.join().unwrap().unwrap(), WorkerExit::Cancelled);
    assert_eq!(
        ledger.state("worker-session").unwrap(),
        Lifecycle::Cancelled
    );

    let parent_after = std::fs::read(&parent_heartbeat).unwrap();
    let child_after = std::fs::read(&child_heartbeat).unwrap();
    std::thread::sleep(Duration::from_millis(350));
    assert_eq!(std::fs::read(&parent_heartbeat).unwrap(), parent_after);
    assert_eq!(std::fs::read(&child_heartbeat).unwrap(), child_after);
}

#[test]
fn pre_cancelled_worker_never_spawns_a_process() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let heartbeat = dir.path().join("must-not-exist");
    let ledger = Ledger::open(&db).unwrap();
    let adapter = FakeKubernetes::open(dir.path().join("provider.db")).unwrap();
    let grant = active(
        &ledger,
        &adapter,
        env!("CARGO_BIN_EXE_buzz-workspace-controller"),
        vec![
            "heartbeat-child".into(),
            heartbeat.to_str().unwrap().to_string(),
        ],
    );
    ledger
        .request_cancellation("worker-session", "test cancellation")
        .unwrap();

    assert!(matches!(
        run_cancellable_process(&ledger, &grant, Duration::from_millis(20)),
        Err(ControllerError::ExecutionAborted)
    ));
    assert!(!heartbeat.exists());
}

#[test]
fn cancellation_channel_failure_terminates_the_spawned_process_tree() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let heartbeat = dir.path().join("heartbeat");
    let ledger = Ledger::open(&db).unwrap();
    let adapter = FakeKubernetes::open(dir.path().join("provider.db")).unwrap();
    let binary = env!("CARGO_BIN_EXE_buzz-workspace-controller").to_string();
    let grant = active(
        &ledger,
        &adapter,
        &binary,
        vec![
            "heartbeat-child".into(),
            heartbeat.to_str().unwrap().to_string(),
        ],
    );

    let worker_ledger = Ledger::open(&db).unwrap();
    let worker = std::thread::spawn(move || {
        run_cancellable_process(&worker_ledger, &grant, Duration::from_millis(20))
    });
    wait_for(&heartbeat);
    let pid = heartbeat_pid(&heartbeat);

    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys=OFF; DROP TABLE transitions; DROP TABLE artifacts; DROP TABLE sessions;",
    )
    .unwrap();
    drop(conn);

    let result = worker.join().unwrap();
    let after = std::fs::read(&heartbeat).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let stopped = std::fs::read(&heartbeat).unwrap() == after;
    if !stopped {
        emergency_kill(pid);
    }
    assert!(result.is_err());
    assert!(
        stopped,
        "worker continued after authoritative ledger failure"
    );
}

#[test]
fn mismatched_execution_spec_cannot_be_redeemed() {
    let dir = tempdir().unwrap();
    let ledger = Ledger::open(dir.path().join("ledger.db")).unwrap();
    let adapter = FakeKubernetes::open(dir.path().join("provider.db")).unwrap();
    let controller = Controller::new(ledger, adapter);
    controller.provision_inert(&request(), None).unwrap();
    let executable = worker_binary();
    let authorized = ExecutionSpec::new(
        executable.clone(),
        vec!["heartbeat-child".into(), "allowed".into()],
        "a".repeat(64),
    )
    .unwrap();
    let different = ExecutionSpec::new(
        executable,
        vec!["heartbeat-child".into(), "forbidden".into()],
        "a".repeat(64),
    )
    .unwrap();
    let capability = controller
        .authorize_launch("worker-session", &authorized, 60, 0)
        .unwrap();
    controller.activate_launch(&capability).unwrap();

    assert!(matches!(
        controller.redeem_launch(&capability, "worker-boot-1", &different, 0),
        Err(ControllerError::ActivationBindingMismatch)
    ));
}

#[test]
fn one_material_grant_cannot_spawn_twice() {
    let dir = tempdir().unwrap();
    let ledger = Ledger::open(dir.path().join("ledger.db")).unwrap();
    let adapter = FakeKubernetes::open(dir.path().join("provider.db")).unwrap();
    let heartbeat = dir.path().join("one-spawn");
    let grant = active(
        &ledger,
        &adapter,
        env!("CARGO_BIN_EXE_buzz-workspace-controller"),
        vec![
            "heartbeat-child".into(),
            heartbeat.to_str().unwrap().to_string(),
        ],
    );
    let worker_ledger = ledger.clone();
    let first_grant = grant.clone();
    let first = std::thread::spawn(move || {
        run_cancellable_process(&worker_ledger, &first_grant, Duration::from_millis(20))
    });
    wait_for(&heartbeat);

    assert!(matches!(
        run_cancellable_process(&ledger, &grant, Duration::from_millis(20)),
        Err(ControllerError::ExecutionReplay)
    ));
    ledger
        .request_cancellation("worker-session", "test complete")
        .unwrap();
    assert_eq!(first.join().unwrap().unwrap(), WorkerExit::Cancelled);
}
