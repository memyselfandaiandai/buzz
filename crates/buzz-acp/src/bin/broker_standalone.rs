//! Standalone capability broker for cross-machine integration testing.
//!
//! Starts a broker with Tailscale IP discovery, prints the WebSocket endpoint
//! and capability environment to stdout, and waits for SIGINT / shutdown signal.
//! Designed to be run on Final-Form while `buzz-remote-signer` connects from GX10.
//!
//! Usage:
//!   BUZZ_RELAY_URL=wss://relay.example \
//!   BUZZ_PRIVATE_KEY=nsec1... \
//!   cargo run --bin buzz-acp-broker --features signing-capability-broker

use anyhow::{Context, Result};
use clap::Parser;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::signal;
use uuid::Uuid;

use buzz_acp::capability_broker::{BrokerChildSpawner, CapabilityBroker};
use buzz_acp::config::{
    CliArgs, Config, CredentialMode, DedupMode, MultipleEventHandling, PermissionMode, RespondTo,
    SubscribeMode,
};

#[derive(Parser, Debug)]
#[command(
    name = "buzz-acp-broker",
    about = "Standalone capability broker for cross-machine signer testing"
)]
struct Args {
    /// Relay URL (wss://...).
    #[arg(long, env = "BUZZ_RELAY_URL", default_value = "wss://relay.damus.io")]
    relay_url: String,

    /// Nostr private key (nsec or hex).
    #[arg(long, env = "BUZZ_PRIVATE_KEY", hide_env_values = true)]
    private_key: String,

    /// Advertised IP address override (e.g. Tailscale 100.x.y.z).
    /// Auto-discovered from Tailscale if omitted.
    #[arg(long, env = "BUZZ_ACP_BROKER_ADVERTISE_IP")]
    broker_advertise_ip: Option<Ipv4Addr>,

    /// Channel UUID to scope this broker test capability lease to.
    #[arg(long, env = "BUZZ_CHANNEL_ID")]
    channel_id: Option<Uuid>,

    /// Optional auth attestation tag JSON.
    #[arg(long, env = "BUZZ_AUTH_TAG")]
    auth_tag: Option<String>,

    /// Secret identifiers explicitly allowed for SecretLease operations.
    #[arg(
        long = "broker-allowed-secret",
        env = "BUZZ_ACP_BROKER_ALLOWED_SECRETS",
        hide_env_values = true,
        value_delimiter = ','
    )]
    broker_allowed_secrets: Option<Vec<String>>,

    /// Tool identifiers explicitly allowed to consume SecretLease operations.
    #[arg(
        long = "broker-allowed-secret-tool",
        env = "BUZZ_ACP_BROKER_ALLOWED_SECRET_TOOLS",
        hide_env_values = true,
        value_delimiter = ','
    )]
    broker_allowed_secret_tools: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "buzz_acp=info,buzz_acp_broker=info".to_string()),
        )
        .init();

    let args = Args::parse();

    let channel_id = args.channel_id.unwrap_or_else(Uuid::new_v4);

    let cli_args = CliArgs {
        relay_url: args.relay_url.clone(),
        private_key: args.private_key.clone(),
        agent_owner: None,
        agent_command: "standalone-broker".to_string(),
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
        broker_advertise_ip: args.broker_advertise_ip,
        broker_allowed_secrets: args.broker_allowed_secrets,
        broker_allowed_secret_tools: args.broker_allowed_secret_tools,
    };

    let config = Config::from_args_with_credential_mode(cli_args, CredentialMode::BrokerV1)
        .context("failed to construct broker config")?;

    let broker = Arc::new(
        CapabilityBroker::from_config(&config, args.auth_tag.as_deref())
            .await
            .context("failed to start capability broker")?,
    );

    let spawner = BrokerChildSpawner::for_channels(Arc::clone(&broker), &config, [channel_id])
        .context("failed to construct broker child spawner")?;

    let mut lease = spawner.issue().context("failed to issue broker lease")?;
    lease
        .activate()
        .context("failed to activate broker lease")?;

    println!("============================================================");
    println!("BUZZ ACP STANDALONE CAPABILITY BROKER RUNNING");
    println!("============================================================");
    println!("Bound Address: {}", broker.address);
    if let Some(adv) = broker.advertised_ip {
        println!("Advertised IP: {}", adv);
    }
    println!("Scoper Channel: {}", channel_id);
    println!("------------------------------------------------------------");
    println!("EXPORT THE FOLLOWING IN YOUR REMOTE CLIENT ENVIRONMENT:");
    println!("------------------------------------------------------------");
    for env_var in lease.mcp_env() {
        println!("export {}={:?}", env_var.name, env_var.value);
    }
    println!("============================================================");
    println!("Press Ctrl+C or send SIGINT/SIGTERM to stop broker...");

    signal::ctrl_c()
        .await
        .context("failed to listen for ctrl+c signal")?;

    println!("\nShutdown signal received. Revoking leases and closing broker...");
    lease.revoke().context("failed to revoke broker lease")?;
    drop(lease);
    drop(spawner);
    let broker = Arc::try_unwrap(broker)
        .map_err(|_| anyhow::anyhow!("broker still has live owners during shutdown"))?;
    broker.shutdown().await.context("failed to stop broker")?;

    println!("Broker shutdown complete.");
    Ok(())
}
