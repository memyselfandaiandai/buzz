use buzz_workspace_controller::{Ledger, Scope};
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use tempfile::tempdir;

struct AdmitSpec<'a> {
    session: &'a str,
    jti: &'a str,
    workspace: &'a str,
    scope_kind: &'a str,
    scope_id: &'a str,
    signed: u32,
    deployment: u32,
}

fn spawn_admit(db: &Path, barrier: &Path, spec: AdmitSpec<'_>) -> Child {
    Command::new(env!("CARGO_BIN_EXE_buzz-workspace-controller"))
        .args([
            "admit",
            db.to_str().unwrap(),
            spec.session,
            spec.jti,
            spec.workspace,
            spec.scope_kind,
            spec.scope_id,
            &spec.signed.to_string(),
            &spec.deployment.to_string(),
            barrier.to_str().unwrap(),
        ])
        .spawn()
        .unwrap()
}

fn release_and_wait(mut children: Vec<Child>, barrier: &Path) -> Vec<ExitStatus> {
    std::fs::write(barrier, b"go").unwrap();
    children
        .iter_mut()
        .map(|child| child.wait().unwrap())
        .collect()
}

#[test]
fn thirty_two_processes_respect_twenty_workspace_scope_capacity() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let barrier = dir.path().join("start");
    let mut children = Vec::new();
    for index in 0..32 {
        children.push(spawn_admit(
            &db,
            &barrier,
            AdmitSpec {
                session: &format!("session-{index}"),
                jti: &format!("jti-{index}"),
                workspace: &format!("workspace-{index}"),
                scope_kind: "tenant",
                scope_id: "tenant:range-test",
                signed: 20,
                deployment: 20,
            },
        ));
    }
    let statuses = release_and_wait(children, &barrier);
    assert_eq!(
        statuses
            .iter()
            .filter(|status| status.code() == Some(0))
            .count(),
        20
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| status.code() == Some(20))
            .count(),
        12
    );
    assert!(statuses
        .iter()
        .all(|status| matches!(status.code(), Some(0 | 20))));

    let ledger = Ledger::open(&db).unwrap();
    assert_eq!(
        ledger
            .reservation_count(&Scope::Tenant("tenant:range-test".into()))
            .unwrap(),
        20
    );
}

#[test]
fn sixteen_processes_racing_one_jti_admit_exactly_once() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let barrier = dir.path().join("start");
    let mut children = Vec::new();
    for index in 0..16 {
        children.push(spawn_admit(
            &db,
            &barrier,
            AdmitSpec {
                session: &format!("replay-session-{index}"),
                jti: "shared-jti",
                workspace: &format!("replay-workspace-{index}"),
                scope_kind: "issuer",
                scope_id: "issuer:final-form",
                signed: 20,
                deployment: 20,
            },
        ));
    }
    let statuses = release_and_wait(children, &barrier);
    assert_eq!(
        statuses
            .iter()
            .filter(|status| status.code() == Some(0))
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| status.code() == Some(21))
            .count(),
        15
    );
    assert!(statuses
        .iter()
        .all(|status| matches!(status.code(), Some(0 | 21))));

    let ledger = Ledger::open(&db).unwrap();
    assert_eq!(
        ledger
            .reservation_count(&Scope::Issuer("issuer:final-form".into()))
            .unwrap(),
        1
    );
}

#[test]
fn independent_agent_scopes_each_receive_their_signed_capacity() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let barrier = dir.path().join("start");
    let mut children = Vec::new();
    for agent in ["a", "b"] {
        for index in 0..10 {
            children.push(spawn_admit(
                &db,
                &barrier,
                AdmitSpec {
                    session: &format!("{agent}-session-{index}"),
                    jti: &format!("{agent}-jti-{index}"),
                    workspace: &format!("{agent}-workspace-{index}"),
                    scope_kind: "agent",
                    scope_id: &format!("agent:{agent}"),
                    signed: 6,
                    deployment: 20,
                },
            ));
        }
    }
    let statuses = release_and_wait(children, &barrier);
    assert_eq!(
        statuses
            .iter()
            .filter(|status| status.code() == Some(0))
            .count(),
        12
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| status.code() == Some(20))
            .count(),
        8
    );

    let ledger = Ledger::open(&db).unwrap();
    for agent in ["a", "b"] {
        assert_eq!(
            ledger
                .reservation_count(&Scope::Agent(format!("agent:{agent}")))
                .unwrap(),
            6
        );
    }
}
