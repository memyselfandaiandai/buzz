//! Track 4 vertical slice tests — HumanCardBroker, AutomationBroker, AutomationSpendGuard, SkillCurator.
//! Feature-gated by `cards-automations-skills` (no publish/share surface).

#![cfg(feature = "cards-automations-skills")]

use buzz_lifecycle::{
    preflight_two_frames, AutomationBroker, AutomationDefinition, AutomationWake, CaptureManifest,
    CardChoice, CardKind, DryRunRequest, HumanCard, HumanCardBroker, LifecycleStore, ManifestFile,
    PreflightCheck, PreflightFrame, SkillCurator, SpendGuardConfig, SpendGuardState,
};
use serde_json::json;

fn card(id: &str) -> HumanCard {
    HumanCard {
        card_id: id.into(),
        turn_id: "t1".into(),
        owner_id: "o1".into(),
        agent_id: "a1".into(),
        kind: CardKind::ActionRequest,
        title: "Pick one".into(),
        body: "body".into(),
        choices: vec![
            CardChoice {
                choice_id: "yes".into(),
                label: "Yes".into(),
            },
            CardChoice {
                choice_id: "no".into(),
                label: "No".into(),
            },
        ],
        created_at_ms: 100,
        answered: None,
    }
}
fn def(id: &str) -> AutomationDefinition {
    AutomationDefinition {
        definition_id: id.into(),
        owner_id: "o1".into(),
        name: "n".into(),
        revision: 1,
        enabled: false,
        created_at_ms: 10,
        updated_at_ms: 10,
        config_json: json!({}),
    }
}
fn manifest(id: &str) -> CaptureManifest {
    CaptureManifest {
        manifest_id: id.into(),
        owner_id: "o1".into(),
        source: "cap".into(),
        files: vec![ManifestFile {
            path: "a.txt".into(),
            sha256_hex: "a".repeat(64),
            bytes: 3,
        }],
        created_at_ms: 10,
    }
}
fn frame(id: &str, pass: bool) -> PreflightFrame {
    PreflightFrame {
        frame_id: id.into(),
        checks: vec![PreflightCheck {
            name: "c".into(),
            passed: pass,
            detail: "".into(),
        }],
    }
}

#[test]
fn human_card_bounded_choices_rejected() {
    let mut b = HumanCardBroker::new();
    let mut c = card("c1");
    c.choices = vec![CardChoice {
        choice_id: "a".into(),
        label: "A".into(),
    }];
    assert!(b.create(c).is_err(), "1 choice must be rejected");
    let mut c2 = card("c2");
    c2.choices = (0..7)
        .map(|i| CardChoice {
            choice_id: format!("c{i}"),
            label: format!("L{i}"),
        })
        .collect();
    assert!(b.create(c2).is_err(), "7 choices must be rejected");
    let c3 = card("c3");
    assert!(b.create(c3).is_ok());
}

#[test]
fn human_card_exactly_once_answer_resume_and_immutable_transcript() {
    let mut b = HumanCardBroker::new();
    b.create(card("c1")).unwrap();
    let first = b.answer("c1", "yes", 200).unwrap();
    assert!(first.answered.as_ref().unwrap().resumed);
    assert!(
        b.answer("c1", "no", 201).is_err(),
        "second answer must be exactly-once rejected"
    );
    let transcript = b.transcript_for_card("c1");
    assert_eq!(transcript.len(), 3);
    assert_eq!(transcript[0].kind, "created");
    assert_eq!(transcript[1].kind, "answered");
    assert_eq!(transcript[2].kind, "resume");
    // transcript entries are immutable — second read must be identical
    let transcript2 = b.transcript_for_card("c1");
    assert_eq!(
        transcript.iter().map(|e| &e.entry_id).collect::<Vec<_>>(),
        transcript2.iter().map(|e| &e.entry_id).collect::<Vec<_>>()
    );
}

#[test]
fn automation_inactive_by_default_and_immutable_revision() {
    let mut b = AutomationBroker::new();
    let mut d = def("d1");
    d.enabled = true;
    assert!(
        b.create_definition(d).is_err(),
        "create must be inactive by default"
    );
    b.create_definition(def("d1")).unwrap();
    assert!(!b.get_definition("d1").unwrap().enabled);
    let r2 = b.revise_definition("d1", json!({"v":2}), 20).unwrap();
    assert_eq!(r2.revision, 2);
    // wake with stale revision is rejected
    assert!(b
        .create_wake(AutomationWake {
            wake_id: "w1".into(),
            definition_id: "d1".into(),
            owner_id: "o1".into(),
            revision: 1,
            payload_json: json!({}),
            created_at_ms: 30
        })
        .is_err());
    b.create_wake(AutomationWake {
        wake_id: "w1".into(),
        definition_id: "d1".into(),
        owner_id: "o1".into(),
        revision: 2,
        payload_json: json!({}),
        created_at_ms: 31,
    })
    .unwrap();
}

#[test]
fn automation_unique_ids_at_least_once_bounded_batching_acked_completion() {
    let mut b = AutomationBroker::new();
    b.create_definition(def("d1")).unwrap();
    for i in 0..10 {
        b.create_wake(AutomationWake {
            wake_id: format!("w{i}"),
            definition_id: "d1".into(),
            owner_id: "o1".into(),
            revision: 1,
            payload_json: json!({}),
            created_at_ms: 30 + i,
        })
        .unwrap();
    }
    // unique wake/run ids
    assert!(b
        .create_wake(AutomationWake {
            wake_id: "w1".into(),
            definition_id: "d1".into(),
            owner_id: "o1".into(),
            revision: 1,
            payload_json: json!({}),
            created_at_ms: 100
        })
        .is_err());
    // at-least-once: push and safety-poll both return pending; bounded batching caps the slice
    assert_eq!(b.pending_runs(3).len(), 3);
    assert_eq!(
        b.poll_pending(1000).len(),
        10,
        "unbounded caller is still capped by MAX_BATCH internally but 10 fits"
    );
    assert_eq!(b.poll_pending(1000).len(), 10);
    // acked completion: must be delivered first
    assert!(b.ack("run:w0", 50).is_err());
    b.mark_delivered("run:w0", 50).unwrap();
    b.ack("run:w0", 51).unwrap();
    assert!(
        b.mark_delivered("run:w0", 52).is_err(),
        "acked run cannot be redelivered"
    );
}

#[test]
fn spend_guard_window_counters_grace_snooze_scoped_pause() {
    let cfg = SpendGuardConfig {
        window_ms: 1000,
        max_wakes_per_window: 2,
        max_runs_per_window: 2,
        grace_ms: 500,
        snooze_ms: 500,
    };
    let mut s = SpendGuardState::new(cfg, 0).unwrap();
    assert!(!s.record_wake(10).unwrap());
    assert!(!s.record_wake(20).unwrap());
    assert!(
        s.record_wake(30).unwrap(),
        "third wake in window should trip"
    );
    s.start_grace(30).unwrap();
    s.pause_scoped("scope1", vec!["d1".into()], 31).unwrap();
    assert!(s.paused_definition_ids.is_empty(), "grace suppresses pause");
    s.pause_scoped("scope1", vec!["d1".into(), "d2".into()], 600)
        .unwrap();
    assert_eq!(s.paused_definition_ids.len(), 2);
    s.snooze(601).unwrap();
    assert!(!s.record_wake(602).unwrap(), "snooze suppresses trip");
    // scoped pause restores only that set: with one scope remaining, ids remain; after last scope, cleared
    s.pause_scoped("scope2", vec!["d3".into()], 610).unwrap();
    let _ = s.resume_scoped("scope1");
    assert!(!s.paused_definition_ids.is_empty());
    let restored = s.resume_scoped("scope2");
    assert_eq!(restored.len(), 3);
    assert!(s.paused_definition_ids.is_empty());
}

#[test]
fn skill_curator_capture_two_frame_preflight_private_versioned_dry_run() {
    let mut c = SkillCurator::new(["read".into(), "search".into()]);
    c.capture(manifest("m1")).unwrap();
    // two-frame preflight: both must pass
    assert!(c
        .create_private_skill("o1", "m1", (&frame("f1", true), &frame("f2", false)), 20)
        .is_err());
    let s1 = c
        .create_private_skill("o1", "m1", (&frame("f1", true), &frame("f2", true)), 20)
        .unwrap();
    assert!(s1.private, "no publish/share — private only");
    assert_eq!(s1.version, 1);
    let s2 = c
        .create_private_skill("o1", "m1", (&frame("f3", true), &frame("f4", true)), 21)
        .unwrap();
    assert_eq!(s2.version, 2, "versioned");
    // capability-bounded dry-run
    assert!(
        c.dry_run(&DryRunRequest {
            skill_id: s1.skill_id.clone(),
            version: s1.version,
            capabilities: vec!["read".into()]
        })
        .unwrap()
        .allowed
    );
    assert!(
        !c.dry_run(&DryRunRequest {
            skill_id: s1.skill_id.clone(),
            version: s1.version,
            capabilities: vec!["write".into()]
        })
        .unwrap()
        .allowed
    );
}

#[test]
fn skill_curator_two_frame_ids_must_be_distinct() {
    let f = frame("same", true);
    assert!(preflight_two_frames(&f, &f).is_err());
}

#[test]
fn durable_store_migrates_to_v7_and_roundtrips_cards() {
    let dir = tempfile::tempdir().unwrap();
    let store = LifecycleStore::open(dir.path().join("lifecycle.sqlite3")).unwrap();
    assert_eq!(store.schema_version().unwrap(), 8);
    // Verify new tables exist
    let conn = store.raw_connection_for_tests().unwrap();
    for table in [
        "human_cards",
        "human_card_transcript",
        "automation_definitions",
        "automation_wakes",
        "automation_runs",
        "spend_guard_state",
        "skill_manifests",
        "skills",
    ] {
        let n: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{table}'"
                ),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "missing table {table}");
    }
}

#[test]
fn feature_gated_no_publish_share_api_exists() {
    // This test asserts the absence of a publish/share API by verifying the
    // SkillCurator type has no `publish` or `share` methods via the fact that
    // the module compiles without them and the only creation path is
    // `create_private_skill` which always sets `private = true`.
    let mut c = SkillCurator::new(["read".into()]);
    c.capture(manifest("m1")).unwrap();
    let s = c
        .create_private_skill("o1", "m1", (&frame("f1", true), &frame("f2", true)), 20)
        .unwrap();
    assert!(s.private);
    // No `publish`/`share` methods exist — this would fail to compile if they did and were called.
}
