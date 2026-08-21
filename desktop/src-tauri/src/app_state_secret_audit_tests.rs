use super::*;

#[test]
fn available_secret_audit_constructs_broker_and_signing_state() {
    let temp = tempfile::tempdir().unwrap();
    let audit = buzz_secrets::SecretAuditStore::open(temp.path().join("secret-audit.sqlite"));

    let state = build_app_state_with_secret_audit(audit);

    assert!(state.secret_access_broker.is_some());
    assert!(state.signing_keys().is_ok());
}

#[test]
fn unavailable_secret_audit_keeps_signing_state_available() {
    let state = build_app_state_with_secret_audit(Err(buzz_secrets::SecretError::Audit(
        "C:\\sensitive\\audit.sqlite: database disk image is malformed".to_string(),
    )));

    assert!(state.secret_access_broker.is_none());
    assert!(
        state.signing_keys().is_ok(),
        "optional secret audit failure must not block unrelated signing state"
    );
}
