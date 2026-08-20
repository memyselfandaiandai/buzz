//! End-to-end integration test for the standalone capability broker and client.
//!
//! Tests:
//! 1. Broker starts up, binds port, discovers/advertises IP.
//! 2. Capability lease is issued, activated, and projected to env.
//! 3. Remote signer / CapabilityClient connects and executes operations:
//!    - `identity_metadata`
//!    - `sign_nostr_event`
//!    - `sign_nip98`
//! 4. Expired/revoked capability handling.

use anyhow::Result;
use buzz_acp::capability_broker::{BrokerChildSpawner, CapabilityBroker};
use buzz_acp::config::{
    CliArgs, Config, CredentialMode, DedupMode, MultipleEventHandling, PermissionMode, RespondTo,
    SubscribeMode,
};
use buzz_capability_client::{
    CapabilityClient, ClientError, HttpMethod, Nip98SignRequest, NostrEventSignRequest,
    RelayOrigin, StableErrorKind, StructuredTag,
};
use nostr::Keys;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_broker_standalone_end_to_end() -> Result<()> {
    let keys = Keys::generate();
    let relay_url = "wss://relay.example.com".to_string();
    let channel_id = Uuid::new_v4();

    let cli_args = CliArgs {
        relay_url: relay_url.clone(),
        private_key: keys.secret_key().to_secret_hex(),
        agent_owner: None,
        agent_command: "standalone-broker-test".to_string(),
        agent_args: vec![],
        mcp_command: "".to_string(),
        idle_timeout: None,
        max_turn_duration: 7200,
        turn_timeout: None,
        system_prompt: None,
        system_prompt_file: None,
        agents: 1,
        heartbeat_interval: 0,
        turn_liveness_secs: 10,
        heartbeat_prompt: None,
        heartbeat_prompt_file: None,
        initial_message: None,
        subscribe: SubscribeMode::Mentions,
        kinds: None,
        channels: Some(vec![channel_id.to_string()]),
        no_mention_filter: false,
        config: std::path::PathBuf::from("./buzz-acp.toml"),
        dedup: DedupMode::Queue,
        multiple_event_handling: MultipleEventHandling::Steer,
        no_ignore_self: false,
        context_message_limit: 12,
        max_turns_per_session: 0,
        no_presence: true,
        no_typing: true,
        memory: false,
        no_memory: true,
        no_base_prompt: false,
        base_prompt_file: None,
        capture_visible_final: false,
        model: None,
        session_title: None,
        permission_mode: PermissionMode::BypassPermissions,
        respond_to: RespondTo::OwnerOnly,
        respond_to_allowlist: None,
        allowed_respond_to: None,
        team_instructions: None,
        relay_observer: false,
        exit_after_inactivity: 0,
        lazy_pool: false,
        idle_pool_sleep: 0,
        broker_advertise_ip: Some(std::net::Ipv4Addr::LOCALHOST),
        broker_allowed_secrets: None,
        broker_allowed_secret_tools: None,
    };

    let config = Config::from_args_with_credential_mode(cli_args, CredentialMode::BrokerV1)?;
    let broker = Arc::new(CapabilityBroker::from_config(&config, None).await?);
    let spawner = BrokerChildSpawner::for_channels(Arc::clone(&broker), &config, [channel_id])?;

    let mut lease = spawner.issue()?;
    lease.activate()?;

    let env_vars: Vec<(std::ffi::OsString, std::ffi::OsString)> = lease
        .mcp_env()
        .into_iter()
        .map(|v| (v.name.into(), v.value.into()))
        .collect();

    let client = CapabilityClient::from_env_iter(env_vars).await?;

    // 1. Identity metadata
    let meta = client.identity_metadata().await?;
    assert_eq!(meta.public_key, keys.public_key().to_hex());
    assert_eq!(
        meta.relay.as_str().trim_end_matches('/'),
        relay_url.trim_end_matches('/')
    );

    // 2. Sign Nostr event
    let req = NostrEventSignRequest {
        relay: RelayOrigin::parse(&relay_url)?,
        kind: 9,
        content: "Test Nostr message from standalone broker".to_string(),
        tags: vec![StructuredTag(vec!["h".into(), channel_id.to_string()])],
        requested_created_at: None,
    };
    let signed_event = client.sign_nostr_event(req).await?;
    assert_eq!(signed_event.kind.as_u16(), 9);
    assert_eq!(signed_event.pubkey, keys.public_key());
    signed_event.verify()?;

    // 3. Sign NIP-98
    let nip98_req = Nip98SignRequest {
        relay: RelayOrigin::parse(&relay_url)?,
        method: HttpMethod::Post,
        path: "/events".to_string(),
        payload_sha256: Some(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
    };
    let nip98_auth = client.sign_nip98(nip98_req).await?;
    assert!(nip98_auth.authorization().starts_with("Nostr "));

    // 4. Secret Leasing
    let secret_error = client
        .acquire_secret("TEST_SECRET_KEY", "test_tool")
        .await
        .expect_err("default production scope must disable secret leasing");
    assert_eq!(
        secret_error,
        ClientError::Broker(StableErrorKind::OperationNotAllowed)
    );

    // 5. Revocation
    lease.revoke()?;
    let fail_req = NostrEventSignRequest {
        relay: RelayOrigin::parse(&relay_url)?,
        kind: 9,
        content: "Should fail after revocation".to_string(),
        tags: vec![StructuredTag(vec!["h".into(), channel_id.to_string()])],
        requested_created_at: None,
    };
    let res = client.sign_nostr_event(fail_req).await;
    assert!(res.is_err());

    Ok(())
}
