use std::process::Command;

const CHILD_MARKER_ENV: &str = "BUZZ_CREDENTIAL_MODE_FAKE_CHILD_MARKER";

#[test]
fn credential_mode_fake_child() {
    let Some(marker) = std::env::var_os(CHILD_MARKER_ENV) else {
        return;
    };
    std::fs::write(marker, b"spawned").expect("write fake-child marker");
}

#[test]
fn broker_mode_blocks_every_helper_before_child_spawn() {
    let directory = tempfile::tempdir().expect("startup-gate tempdir");
    let test_executable = std::env::current_exe().expect("current integration-test executable");
    let binary = env!("CARGO_BIN_EXE_buzz-acp");

    for helper in ["models", "auth-methods", "authenticate"] {
        let marker = directory.path().join(format!("{helper}.spawned"));
        let mut command = Command::new(binary);
        command
            .arg(helper)
            .env("BUZZ_CREDENTIAL_MODE", "broker-v1")
            .env("BUZZ_ACP_AGENT_COMMAND", &test_executable)
            .env(
                "BUZZ_ACP_AGENT_ARGS",
                "--exact,credential_mode_fake_child,--nocapture",
            )
            .env(CHILD_MARKER_ENV, &marker);
        if helper == "authenticate" {
            command.args(["--method-id", "fake"]);
        }

        let output = command.output().expect("run buzz-acp helper");
        assert!(!output.status.success(), "broker mode must fail startup");
        assert!(
            !marker.exists(),
            "{helper} spawned a legacy child before the broker fail gate"
        );
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        #[cfg(feature = "signing-capability-broker")]
        assert!(diagnostic
            .contains("broker-v1 local pilot does not support standalone ACP helper processes"));
        #[cfg(not(feature = "signing-capability-broker"))]
        assert!(diagnostic
            .contains("BUZZ_CREDENTIAL_MODE=broker-v1 requires a signing-capability-broker build"));
    }
}

#[test]
fn invalid_mode_fails_before_helper_child_spawn() {
    let directory = tempfile::tempdir().expect("startup-gate tempdir");
    let marker = directory.path().join("invalid.spawned");
    let output = Command::new(env!("CARGO_BIN_EXE_buzz-acp"))
        .arg("models")
        .env("BUZZ_CREDENTIAL_MODE", "invalid-mode")
        .env(
            "BUZZ_ACP_AGENT_COMMAND",
            std::env::current_exe().expect("current integration-test executable"),
        )
        .env(
            "BUZZ_ACP_AGENT_ARGS",
            "--exact,credential_mode_fake_child,--nocapture",
        )
        .env(CHILD_MARKER_ENV, &marker)
        .output()
        .expect("run buzz-acp helper");

    assert!(!output.status.success());
    assert!(!marker.exists(), "invalid mode must not spawn a child");
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(diagnostic.contains("must be exactly 'legacy-env' or 'broker-v1'"));
}
