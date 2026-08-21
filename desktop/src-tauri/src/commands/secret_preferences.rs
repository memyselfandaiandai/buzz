use serde::Serialize;
#[cfg(test)]
use std::process::Stdio;
#[cfg(test)]
use std::time::Duration;
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroizing;

use buzz_secrets::{
    clear_bws_keyring_config, load_bws_keyring_config, store_bws_keyring_config,
    validate_bws_secret_bindings, BwsKeyringConfig, BwsSecretBinding, SecretBackendKind,
    SecretError, SecretLeaseMetadata, SecretPolicy, SecretVaultProvider,
    PROVIDER_BACKEND_KEY as BACKEND_KEY, PROVIDER_CONFIG_SERVICE,
};

use crate::{app_state::AppState, secret_store::SecretStore};

const PROBE_KEY: &str = "connectivity_probe";

#[derive(Debug, Clone, Serialize)]
pub struct SecretBackendStatus {
    pub backend: SecretBackendKind,
    pub binding_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecretBackendTestResult {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecretAccessOverview {
    pub policies: Vec<SecretPolicy>,
    pub active_leases: Vec<SecretLeaseMetadata>,
}

fn provider_config_vault() -> buzz_secrets::OsKeyringVault {
    buzz_secrets::OsKeyringVault::new(PROVIDER_CONFIG_SERVICE)
}

async fn load_stored_bws_config() -> Result<Option<BwsKeyringConfig>, String> {
    load_bws_keyring_config(&provider_config_vault())
        .await
        .map_err(|_| "Unable to read BWS configuration from the OS keyring".to_string())
}

fn apply_binding_update(
    existing: Vec<BwsSecretBinding>,
    update: Option<Vec<BwsSecretBinding>>,
) -> Result<Vec<BwsSecretBinding>, String> {
    let selected = update.unwrap_or(existing);
    let validated = validate_bws_secret_bindings(&selected)
        .map_err(|_| "BWS secret bindings are invalid".to_string())?;
    Ok(validated
        .into_iter()
        .map(|(logical_key, secret_id)| BwsSecretBinding {
            logical_key,
            secret_id: secret_id.to_string(),
        })
        .collect())
}

async fn load_bws_connection(
) -> Result<(Zeroizing<String>, Option<String>, Vec<BwsSecretBinding>), String> {
    if let Some(stored) = load_stored_bws_config().await? {
        return Ok((
            stored.access_token,
            Some(stored.project_id),
            stored.bindings,
        ));
    }
    Err("BWS access token is not configured".to_string())
}

#[cfg(all(test, unix))]
fn configure_cli_process_tree(command: &mut tokio::process::Command) {
    use std::os::unix::process::CommandExt;

    command.as_std_mut().process_group(0);
}

#[cfg(all(test, not(any(unix, windows))))]
fn configure_cli_process_tree(_command: &mut tokio::process::Command) {}

#[cfg(all(test, unix))]
struct CliProbeProcessTree(i32);

#[cfg(all(test, unix))]
impl CliProbeProcessTree {
    fn attach(child: &tokio::process::Child) -> Option<Self> {
        child.id().map(|pid| Self(pid as i32))
    }

    fn terminate(&self) {
        use nix::sys::signal::{killpg, Signal};
        use nix::unistd::Pid;

        let _ = killpg(Pid::from_raw(self.0), Signal::SIGKILL);
    }
}

#[cfg(all(test, unix))]
impl Drop for CliProbeProcessTree {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(all(test, not(any(unix, windows))))]
struct CliProbeProcessTree;

#[cfg(all(test, not(any(unix, windows))))]
impl CliProbeProcessTree {
    fn attach(_child: &tokio::process::Child) -> Option<Self> {
        Some(Self)
    }

    fn terminate(&self) {}
}

#[cfg(all(test, not(windows)))]
async fn terminate_and_reap_cli_probe(
    child: &mut tokio::process::Child,
    process_tree: CliProbeProcessTree,
) {
    process_tree.terminate();
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
}
#[cfg(all(test, not(windows)))]
async fn cli_command_succeeds(program: &str, args: &[&str], timeout: Duration) -> bool {
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    configure_cli_process_tree(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return false,
    };
    let Some(process_tree) = CliProbeProcessTree::attach(&child) else {
        #[cfg(windows)]
        if let Some(pid) = child.id() {
            let _ = crate::managed_agents::taskkill_tree(pid);
        }
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        return false;
    };

    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => {
            // A nominal CLI can still leave descendants behind. Terminate the
            // containment unit before returning so they cannot outlive a probe.
            process_tree.terminate();
            status.success()
        }
        Ok(Err(_)) | Err(_) => {
            terminate_and_reap_cli_probe(&mut child, process_tree).await;
            false
        }
    }
}

#[cfg(all(test, windows))]
const WINDOWS_TEST_COMMAND_BRIDGE: &str = r#"
$ErrorActionPreference = 'Stop'
$program = [Console]::In.ReadLine()
$testName = [Console]::In.ReadLine()
if (($null -eq $program) -or ($null -eq $testName)) { exit 64 }
& $program '--ignored' '--exact' $testName
if ($null -eq $LASTEXITCODE) { exit 1 }
exit $LASTEXITCODE
"#;

#[cfg(all(test, windows))]
async fn windows_gated_cli_probe(
    bridge_script: &'static str,
    stdin_payload: &[u8],
    timeout: Duration,
    #[cfg(test)] pre_attach_delay: Duration,
) -> bool {
    use process_wrap::tokio::{CommandWrap, JobObject, KillOnDrop};
    use tokio::io::AsyncWriteExt;

    let Ok(powershell) = buzz_secrets::trusted_windows_powershell_path() else {
        return false;
    };
    let mut command = tokio::process::Command::new(powershell);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            bridge_script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut command = CommandWrap::from(command);
    command.wrap(JobObject).wrap(KillOnDrop);
    // JobObject starts the trusted bridge suspended, assigns it to a
    // kill-on-close Job, and only then resumes it. The stdin gate stays closed
    // until after containment exists.
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return false,
    };
    #[cfg(test)]
    if !pre_attach_delay.is_zero() {
        tokio::time::sleep(pre_attach_delay).await;
    }
    let Some(mut stdin) = child.stdin().take() else {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        return false;
    };

    let deadline = tokio::time::Instant::now() + timeout;
    let result = tokio::time::timeout_at(deadline, async {
        stdin.write_all(stdin_payload).await?;
        stdin.shutdown().await?;
        drop(stdin);
        child.wait().await
    })
    .await;
    match result {
        Ok(Ok(status)) => status.success(),
        Ok(Err(_)) | Err(_) => {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            false
        }
    }
}

#[cfg(all(test, windows))]
async fn windows_test_cli_command_succeeds(
    program: &std::path::Path,
    test_name: &str,
    timeout: Duration,
    pre_attach_delay: Duration,
) -> bool {
    let Some(program) = program.to_str() else {
        return false;
    };
    if program.contains(['\r', '\n']) || test_name.contains(['\r', '\n']) {
        return false;
    }
    let payload = format!("{program}\n{test_name}\n");
    windows_gated_cli_probe(
        WINDOWS_TEST_COMMAND_BRIDGE,
        payload.as_bytes(),
        timeout,
        pre_attach_delay,
    )
    .await
}

#[tauri::command]
pub async fn get_secret_backend_status() -> Result<SecretBackendStatus, String> {
    let backend = match provider_config_vault().get_secret(BACKEND_KEY).await {
        Ok(value) => SecretBackendKind::parse(Some(&value))
            .map_err(|_| "Unable to read secret backend status".to_string())?,
        Err(SecretError::NotFound(_)) => SecretBackendKind::default(),
        Err(_) => return Err("Unable to read secret backend status".to_string()),
    };
    let bindings = load_stored_bws_config()
        .await
        .map_err(|_| "Unable to read secret backend status".to_string())?
        .map(|config| config.bindings)
        .unwrap_or_default();
    let validated = validate_bws_secret_bindings(&bindings)
        .map_err(|_| "Unable to read secret backend status".to_string())?;
    Ok(SecretBackendStatus {
        backend,
        binding_keys: validated.into_keys().collect(),
    })
}

#[tauri::command]
pub async fn set_secret_backend(backend: SecretBackendKind) -> Result<SecretBackendStatus, String> {
    provider_config_vault()
        .set_secret(BACKEND_KEY, backend.as_str(), None)
        .await
        .map_err(|_| "Failed to persist secret backend preference".to_string())?;
    get_secret_backend_status().await
}

#[tauri::command]
pub async fn configure_bws_credentials(
    access_token: Option<String>,
    project_id: Option<String>,
    bindings: Option<Vec<BwsSecretBinding>>,
) -> Result<SecretBackendStatus, String> {
    let access_token = access_token.map(Zeroizing::new);
    configure_bws_credentials_zeroizing(access_token, project_id, bindings).await
}

async fn configure_bws_credentials_zeroizing(
    access_token: Option<Zeroizing<String>>,
    project_id: Option<String>,
    bindings: Option<Vec<BwsSecretBinding>>,
) -> Result<SecretBackendStatus, String> {
    let existing = load_stored_bws_config().await?;
    let (stored_token, stored_project, stored_bindings) = match existing {
        Some(config) => (
            Some(config.access_token),
            Some(config.project_id),
            config.bindings,
        ),
        None => (None, None, Vec::new()),
    };
    let token = access_token
        .or(stored_token)
        .ok_or_else(|| "BWS access token is required".to_string())?;
    let project_id = match project_id {
        Some(project_id) if !project_id.trim().is_empty() => project_id,
        Some(_) => return Err("BWS project ID is required".to_string()),
        None => stored_project.ok_or_else(|| "BWS project ID is required".to_string())?,
    };
    let bindings = apply_binding_update(stored_bindings, bindings)?;
    let config = BwsKeyringConfig::new(token, project_id, bindings)
        .map_err(|_| "BWS configuration is invalid".to_string())?;
    store_bws_keyring_config(&provider_config_vault(), &config)
        .await
        .map_err(|_| "Failed to atomically store BWS configuration".to_string())?;
    get_secret_backend_status().await
}

#[tauri::command]
pub async fn clear_bws_credentials() -> Result<SecretBackendStatus, String> {
    let vault = provider_config_vault();
    clear_bws_keyring_config(&vault)
        .await
        .map_err(|_| "Failed to clear BWS configuration from the OS keyring".to_string())?;
    get_secret_backend_status().await
}

#[tauri::command]
pub async fn test_secret_backend(
    backend: SecretBackendKind,
) -> Result<SecretBackendTestResult, String> {
    match backend {
        SecretBackendKind::Bws => {
            let (token, project_id, bindings) = match load_bws_connection().await {
                Ok(connection) => connection,
                Err(_) => {
                    return Ok(SecretBackendTestResult {
                        ok: false,
                        message: "Unable to test secret backend".to_string(),
                    });
                }
            };
            let vault = match buzz_secrets::BwsVault::from_zeroizing(Some(token))
                .with_project_id(project_id)
                .with_bindings(&bindings)
            {
                Ok(vault) => vault,
                Err(_) => {
                    return Ok(SecretBackendTestResult {
                        ok: false,
                        message: "Unable to test secret backend".to_string(),
                    });
                }
            };
            match vault.test_connection().await {
                Ok(()) => Ok(SecretBackendTestResult {
                    ok: true,
                    message: "Secret backend test passed".to_string(),
                }),
                Err(_) => Ok(SecretBackendTestResult {
                    ok: false,
                    message: "Unable to test secret backend".to_string(),
                }),
            }
        }
        SecretBackendKind::OsKeyring | SecretBackendKind::LocalAirGapped => {
            let service = match backend {
                SecretBackendKind::OsKeyring => "buzz-secret-provider-probe",
                SecretBackendKind::LocalAirGapped => "buzz-air-gapped-vault-probe",
                SecretBackendKind::Bws => unreachable!(),
            };
            let probe_store = SecretStore::keyring(service);
            let value = Zeroizing::new(Uuid::new_v4().to_string());
            let result = probe_store
                .store(PROBE_KEY, value.as_str())
                .and_then(|_| probe_store.load(PROBE_KEY))
                .and_then(|loaded| {
                    (loaded.as_deref() == Some(value.as_str()))
                        .then_some(())
                        .ok_or_else(|| "secure storage readback mismatch".to_string())
                });
            let _ = probe_store.delete(PROBE_KEY);
            Ok(SecretBackendTestResult {
                ok: result.is_ok(),
                message: if result.is_ok() {
                    "Secret backend test passed".to_string()
                } else {
                    "Unable to test secret backend".to_string()
                },
            })
        }
    }
}

#[tauri::command]
pub async fn get_secret_access_overview(
    state: State<'_, AppState>,
) -> Result<SecretAccessOverview, String> {
    secret_access_overview(state.secret_access_broker.as_deref()).await
}

async fn secret_access_overview(
    broker: Option<&buzz_secrets::SecretBroker>,
) -> Result<SecretAccessOverview, String> {
    let broker = broker.ok_or_else(|| "Unable to read secret ACL audit metadata".to_string())?;
    Ok(SecretAccessOverview {
        policies: broker
            .policies()
            .await
            .map_err(|_| "Unable to read secret ACL audit metadata".to_string())?,
        active_leases: broker
            .active_leases()
            .await
            .map_err(|_| "Unable to read active secret lease metadata".to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_parser_defaults_only_when_unconfigured() {
        assert_eq!(
            SecretBackendKind::parse(None).unwrap(),
            SecretBackendKind::OsKeyring
        );
        assert!(SecretBackendKind::parse(Some("unknown")).is_err());
    }

    #[test]
    fn bws_credentials_require_valid_token_and_project_uuid() {
        let token = "0123456789abcdefghij";
        let project = "8B7B9142-F5C1-4A7A-A9FA-179C3BE1B135";
        let config = BwsKeyringConfig::new(
            Zeroizing::new(token.to_string()),
            project.to_string(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(config.project_id, "8b7b9142-f5c1-4a7a-a9fa-179c3be1b135");
        assert!(BwsKeyringConfig::new(
            Zeroizing::new(String::new()),
            project.to_string(),
            Vec::new(),
        )
        .is_err());
        assert!(BwsKeyringConfig::new(
            Zeroizing::new("0123456789 abcdefghij".to_string()),
            project.to_string(),
            Vec::new(),
        )
        .is_err());
        assert!(BwsKeyringConfig::new(
            Zeroizing::new(token.to_string()),
            "invalid".to_string(),
            Vec::new(),
        )
        .is_err());
    }

    #[test]
    fn backend_values_round_trip() {
        for backend in [
            SecretBackendKind::OsKeyring,
            SecretBackendKind::Bws,
            SecretBackendKind::LocalAirGapped,
        ] {
            assert_eq!(
                SecretBackendKind::parse(Some(backend.as_str())).unwrap(),
                backend
            );
        }
    }

    #[test]
    fn stored_bws_config_owns_access_token_in_zeroizing_storage() {
        fn assert_zeroizing_string(_: &Zeroizing<String>) {}

        let config = BwsKeyringConfig::new(
            Zeroizing::new("0123456789abcdefghij".to_string()),
            "8b7b9142-f5c1-4a7a-a9fa-179c3be1b135".to_string(),
            Vec::new(),
        )
        .unwrap();
        assert_zeroizing_string(&config.access_token);
    }

    #[test]
    fn backend_status_serializes_only_logical_key_metadata() {
        let value = serde_json::to_value(SecretBackendStatus {
            backend: SecretBackendKind::Bws,
            binding_keys: vec!["logical-key".to_string()],
        })
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "backend": "bws",
                "binding_keys": ["logical-key"]
            })
        );
    }

    #[test]
    fn omitted_binding_update_preserves_existing_exact_bindings() {
        let existing = vec![BwsSecretBinding {
            logical_key: "existing-key".to_string(),
            secret_id: "bd34a60b-f794-46fb-8aa5-97fdd96e69b1".to_string(),
        }];

        assert_eq!(
            apply_binding_update(existing.clone(), None).unwrap(),
            existing
        );
    }

    #[tokio::test]
    async fn unavailable_secret_audit_returns_fixed_generic_overview_error() {
        let error = secret_access_overview(None).await.unwrap_err();

        assert_eq!(error, "Unable to read secret ACL audit metadata");
        assert!(!error.contains("audit.sqlite"));
        assert!(!error.contains("SQLite"));
    }

    #[tokio::test]
    async fn cli_probe_has_a_short_hard_timeout() {
        let started = std::time::Instant::now();
        #[cfg(windows)]
        let succeeded = windows_test_cli_command_succeeds(
            &std::env::current_exe().unwrap(),
            CLI_PROBE_SLEEP_HELPER_TEST,
            Duration::from_millis(25),
            Duration::ZERO,
        )
        .await;
        #[cfg(unix)]
        let succeeded =
            cli_command_succeeds("sh", &["-c", "sleep 2"], Duration::from_millis(25)).await;

        assert!(!succeeded);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[cfg(any(windows, unix))]
    const CLI_PROBE_HELPER_TEST: &str =
        "commands::secret_preferences::tests::cli_probe_descendant_helper";
    #[cfg(windows)]
    const CLI_PROBE_SLEEP_HELPER_TEST: &str =
        "commands::secret_preferences::tests::cli_probe_sleep_helper";
    #[cfg(any(windows, unix))]
    const CLI_PROBE_ROLE_ENV: &str = "BUZZ_DESKTOP_CLI_PROBE_TEST_ROLE";
    #[cfg(any(windows, unix))]
    const CLI_PROBE_READY_ENV: &str = "BUZZ_DESKTOP_CLI_PROBE_TEST_READY";
    #[cfg(any(windows, unix))]
    const CLI_PROBE_MARKER_ENV: &str = "BUZZ_DESKTOP_CLI_PROBE_TEST_MARKER";

    /// Runs only as a subprocess of `cli_probe_timeout_kills_descendants`.
    #[cfg(any(windows, unix))]
    #[test]
    #[ignore = "subprocess helper"]
    #[allow(clippy::zombie_processes)] // The parent test verifies timeout tree cleanup.
    fn cli_probe_descendant_helper() {
        match std::env::var(CLI_PROBE_ROLE_ENV).as_deref() {
            Ok("wrapper") => {
                let current_exe = std::env::current_exe().unwrap();
                let _descendant = std::process::Command::new(current_exe)
                    .args(["--ignored", "--exact", CLI_PROBE_HELPER_TEST])
                    .env(CLI_PROBE_ROLE_ENV, "descendant")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                std::fs::write(std::env::var(CLI_PROBE_READY_ENV).unwrap(), b"ready").unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            Ok("descendant") => {
                std::thread::sleep(Duration::from_millis(750));
                std::fs::write(std::env::var(CLI_PROBE_MARKER_ENV).unwrap(), b"survived").unwrap();
            }
            _ => {}
        }
    }

    /// Runs only as a subprocess of `cli_probe_has_a_short_hard_timeout`.
    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess helper"]
    fn cli_probe_sleep_helper() {
        std::thread::sleep(Duration::from_secs(2));
    }

    #[cfg(any(windows, unix))]
    #[tokio::test]
    async fn cli_probe_timeout_kills_descendants() {
        static ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        struct EnvCleanup;
        impl Drop for EnvCleanup {
            fn drop(&mut self) {
                std::env::remove_var(CLI_PROBE_ROLE_ENV);
                std::env::remove_var(CLI_PROBE_READY_ENV);
                std::env::remove_var(CLI_PROBE_MARKER_ENV);
            }
        }

        let _env_guard = ENV_MUTEX.lock().await;
        let temp = tempfile::TempDir::new().unwrap();
        let ready = temp.path().join("ready");
        let marker = temp.path().join("descendant-survived");

        std::env::set_var(CLI_PROBE_ROLE_ENV, "wrapper");
        std::env::set_var(CLI_PROBE_READY_ENV, &ready);
        std::env::set_var(CLI_PROBE_MARKER_ENV, &marker);
        let _env_cleanup = EnvCleanup;

        let program = std::env::current_exe().unwrap();
        let started = std::time::Instant::now();
        #[cfg(windows)]
        let succeeded = windows_test_cli_command_succeeds(
            &program,
            CLI_PROBE_HELPER_TEST,
            Duration::from_millis(300),
            Duration::from_secs(1),
        )
        .await;
        #[cfg(unix)]
        let succeeded = {
            let program = program.to_string_lossy();
            let args = ["--ignored", "--exact", CLI_PROBE_HELPER_TEST];
            cli_command_succeeds(&program, &args, Duration::from_millis(300)).await
        };

        assert!(!succeeded, "the wrapper must hit the probe deadline");
        assert!(
            ready.is_file(),
            "subprocess helper did not start before the deadline"
        );
        while started.elapsed() < Duration::from_millis(2_000) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !marker.exists(),
            "a descendant escaped the timed-out CLI probe process tree"
        );
    }
}
