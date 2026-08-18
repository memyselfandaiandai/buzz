//! `buzz-remote-signer` — standalone remote capability signer.
//!
//! Connects to a Buzz capability broker over WebSocket using a capability
//! projection, authenticates, and performs structured signing operations.
//! Designed for GX10 and other Tailscale-connected remote workers.
//!
//! # Usage
//!
//! ```text
//! buzz-remote-signer --endpoint ws://100.x.y.z:12345 \
//!   --capability-id 550e8400-e29b-41d4-a716-446655440000 \
//!   --token <token> \
//!   --public-key <hex> \
//!   --relay wss://relay.example \
//!   --expires-at <unix-ms> \
//!   identity-metadata
//! ```

use anyhow::{Context, Result};
use buzz_capability_client::{
    CapabilityClient, Nip98SignRequest, NostrEventSignRequest, RelayOrigin,
    StructuredTag,
};
use buzz_signing_capability::HttpMethod;
use clap::{Parser, Subcommand};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "buzz-remote-signer", about = "Remote capability signer for the Buzz broker")]
struct Cli {
    /// Capability broker WebSocket endpoint (ws://ip:port).
    #[arg(long, env = "BUZZ_CAPABILITY_ENDPOINT")]
    endpoint: String,

    /// Capability identifier (UUID).
    #[arg(long, env = "BUZZ_CAPABILITY_ID")]
    capability_id: String,

    /// Capability bearer token.
    #[arg(long, env = "BUZZ_CAPABILITY_TOKEN", hide_env_values = true)]
    token: String,

    /// Projected public key hex.
    #[arg(long, env = "BUZZ_PUBLIC_KEY")]
    public_key: String,

    /// Relay URL (wss://...).
    #[arg(long, env = "BUZZ_RELAY_URL")]
    relay: String,

    /// Capability absolute expiry in Unix milliseconds.
    #[arg(long, env = "BUZZ_CAPABILITY_EXPIRES_AT")]
    expires_at: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch and verify broker identity metadata.
    IdentityMetadata,
    /// Sign one structured Nostr event.
    SignNostr {
        /// Event kind number.
        #[arg(long, default_value_t = 9)]
        kind: u16,

        /// Event content text.
        #[arg(long)]
        content: String,

        /// Channel identifier (h-tag).
        #[arg(long)]
        channel: String,

        /// Optional requested created-at timestamp (Unix seconds).
        #[arg(long)]
        created_at: Option<u64>,

        /// Relay URL for this event (overrides capability relay).
        #[arg(long)]
        event_relay: Option<String>,
    },
    /// Sign one relay-bound NIP-98 authorization.
    SignNip98 {
        /// HTTP method (GET|POST|PUT|DELETE).
        #[arg(long, default_value_t = String::from("GET"))]
        method: String,

        /// HTTP path.
        #[arg(long)]
        path: String,

        /// Optional payload SHA-256 hex (required for POST/PUT).
        #[arg(long)]
        payload_sha256: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "buzz_remote_signer=info".to_string()),
        )
        .init();

    let cli = Cli::parse();

    // Validate endpoint scheme without requiring url dep import.
    let endpoint = cli.endpoint.clone();
    if !endpoint.starts_with("ws://") {
        anyhow::bail!(
            "endpoint must use ws:// scheme, got scheme in {endpoint:?}"
        );
    }

    let _capability_id = Uuid::parse_str(&cli.capability_id)
        .context("invalid capability ID")?;
    let _relay = RelayOrigin::parse(&cli.relay)
        .context("invalid relay")?;
    let _expires_at = cli.expires_at.parse::<i64>()
        .context("invalid expiry")?;

    let client = CapabilityClient::from_env_iter([
        ("BUZZ_CAPABILITY_ENDPOINT".into(), cli.endpoint.clone().into()),
        ("BUZZ_CAPABILITY_ID".into(), cli.capability_id.clone().into()),
        ("BUZZ_CAPABILITY_TOKEN".into(), cli.token.into()),
        ("BUZZ_PUBLIC_KEY".into(), cli.public_key.into()),
        ("BUZZ_RELAY_URL".into(), cli.relay.clone().into()),
        ("BUZZ_CAPABILITY_EXPIRES_AT".into(), cli.expires_at.into()),
    ])
    .await
    .context("failed to initialize capability client")?;

    match cli.command {
        Command::IdentityMetadata => {
            let meta = client.identity_metadata().await
                .context("identity metadata request failed")?;
            println!("{}", serde_json::to_string_pretty(&meta)?);
        }
        Command::SignNostr {
            kind,
            content,
            channel,
            created_at,
            event_relay,
        } => {
            let relay = match event_relay {
                Some(r) => RelayOrigin::parse(&r).context("invalid event relay")?,
                None => RelayOrigin::parse(&cli.relay).context("invalid event relay")?,
            };
            let request = NostrEventSignRequest {
                relay,
                kind: kind as u32,
                content,
                tags: vec![StructuredTag(vec!["h".into(), channel])],
                requested_created_at: created_at,
            };
            let event = client.sign_nostr_event(request).await
                .context("Nostr event signing failed")?;
            println!("{}", serde_json::to_string_pretty(&event)?);
        }
        Command::SignNip98 {
            method,
            path,
            payload_sha256,
        } => {
            let http_method = match method.to_uppercase().as_str() {
                "GET" => HttpMethod::Get,
                "POST" => HttpMethod::Post,
                "PUT" => HttpMethod::Put,
                "DELETE" => HttpMethod::Delete,
                other => anyhow::bail!("unsupported HTTP method: {other}"),
            };
            let request = Nip98SignRequest {
                relay: RelayOrigin::parse(&cli.relay).context("invalid relay")?,
                method: http_method,
                path,
                payload_sha256,
            };
            let auth = client.sign_nip98(request).await
                .context("NIP-98 signing failed")?;
            println!("Authorization: {}", auth.authorization());
            if let Some(tag) = auth.auth_tag() {
                println!("Auth-Tag: {tag}");
            }
        }
    }

    Ok(())
}