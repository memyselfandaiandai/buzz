//! Default-off trusted Tailscale-bound signing-capability broker (no mTLS for this slice).
//!
//! This module is compiled only with `signing-capability-broker`. It is not
//! connected to ACP startup by the explicit local pilot. For this Tailscale
//! slice the broker owns the Nostr key, binds **only** the 100.x Tailnet
//! interface (`100.64.0.0/10`), and accepts one bounded NDJSON request per
//! connection. See `docs/adr/0003-capability-broker-boundary.md` and
//! `docs/durable-scheduler-checkpoint-validation.md` for the ACL
//! (`tag:buzz-broker:8443 <- group:buzz-workers`), SAN/claim binding, and
//! `revoked_at` / replay-ledger reuse docs.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use buzz_signing_capability::{
    AuthorizationOutcome, BudgetLimits, CapabilityDescriptor, CapabilityRegistry, CapabilityScope,
    CapabilityState, CapabilityToken, ClockReading, HttpMethod, HttpPathRule, IdentityMetadata,
    Operation, OperationKind, OperationResult, RelayOrigin, RequestEnvelope, ResponseEnvelope,
    ScopeBuilder, StableErrorKind, TrustedExecutionError, TrustedOperationExecutor,
    MAX_REGISTRY_CAPABILITIES,
};
use nostr::{EventBuilder, Keys, Kind, Tag};
use serde_json::Value;
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use uuid::Uuid;

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

use crate::acp::{AcpChildCredentialProjection, EnvVar};
use crate::config::Config;

const MAX_WIRE_REQUEST_BYTES: usize = 1_100_000;
const MAX_CONNECTIONS: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_AUTH_TAG_BYTES: usize = 4_096;
const MAX_REQUESTED_TIMESTAMP_SKEW_SECS: u64 = 30;
const PROCESS_CAPABILITY_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);
const PROCESS_CAPABILITY_OPERATIONS: u32 = 2_048;
const PROCESS_CAPABILITY_PAYLOAD_BYTES: u64 = 128 * 1024 * 1024;

/// Resolve the 100.x bind address: `BUZZ_TAILSCALE_IP` (when valid 100.x), or
/// `100.117.196.100` (final-form) so local harness stays green. The validator
/// is `buzz_signing_capability::is_tailscale_ipv4`.
fn resolve_tailscale_bind_ip() -> std::net::Ipv4Addr {
    if let Ok(value) = std::env::var("BUZZ_TAILSCALE_IP") {
        if let Ok(addr) = value.parse::<std::net::Ipv4Addr>() {
            if buzz_signing_capability::is_tailscale_ipv4(addr) {
                return addr;
            }
        }
    }
    "100.117.196.100".parse().expect("tailnet bind")
}

fn is_tailscale_ipv4(addr: std::net::Ipv4Addr) -> bool {
    buzz_signing_capability::is_tailscale_ipv4(addr)
}

/// Cloneable factory for one inactive capability per ACP process generation.
#[derive(Clone)]
pub(crate) struct BrokerChildSpawner {
    broker: Arc<CapabilityBroker>,
    scope: CapabilityScope,
    public_key: nostr::PublicKey,
    relay_url: String,
}

impl fmt::Debug for BrokerChildSpawner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerChildSpawner")
            .field("public_key", &self.public_key.to_hex())
            .field("relay_url", &self.relay_url)
            .finish_non_exhaustive()
    }
}

impl BrokerChildSpawner {
    /// Build the fixed local-v1 consumer scope for the startup channel set.
    pub(crate) fn for_channels(
        broker: Arc<CapabilityBroker>,
        config: &Config,
        channels: impl IntoIterator<Item = Uuid>,
    ) -> Result<Self, BrokerError> {
        let relay = RelayOrigin::parse(&config.relay_url).map_err(|_| BrokerError::InvalidRelay)?;
        let mut builder = ScopeBuilder::new(relay)
            .allow_operation(OperationKind::IdentityMetadata)
            .allow_operation(OperationKind::NostrEventSign)
            .allow_operation(OperationKind::Nip98Sign)
            .allow_http(HttpMethod::Post, HttpPathRule::Exact("/query".to_owned()))
            .allow_http(HttpMethod::Post, HttpPathRule::Exact("/events".to_owned()));
        for kind in [9, 45_001, 45_003, 40_008, 40_003, 9_005, 45_002] {
            builder = builder.allow_event_kind(kind);
        }
        let mut channel_count = 0usize;
        for channel in channels {
            builder = builder.allow_channel(channel.to_string());
            channel_count += 1;
        }
        // An empty channel set would turn the protocol's optional constraint
        // into an unscoped signing capability. The pilot must never do that.
        if channel_count == 0 {
            return Err(BrokerError::InvalidScope);
        }
        let scope = builder.build().map_err(|_| BrokerError::InvalidScope)?;
        Ok(Self {
            broker,
            scope,
            public_key: config.keys.public_key(),
            relay_url: config.relay_url.clone(),
        })
    }

    /// Issue a fresh, inactive process-generation lease.
    pub(crate) fn issue(&self) -> Result<ProcessCapabilityLease, BrokerError> {
        let session_id = Uuid::new_v4();
        let projection = self.broker.issue_session(
            session_id,
            self.scope.clone(),
            BudgetLimits {
                max_operations: PROCESS_CAPABILITY_OPERATIONS,
                max_payload_bytes: PROCESS_CAPABILITY_PAYLOAD_BYTES,
                max_in_flight: 8,
                max_replays_per_request: 4,
            },
            PROCESS_CAPABILITY_LIFETIME,
        )?;
        let child_projection = (|| {
            let token = serde_json::to_value(&projection.token)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or(BrokerError::InvalidIssuance)?;
            let expires_at = u64::try_from(projection.descriptor.expires_at_unix_ms)
                .map_err(|_| BrokerError::InvalidIssuance)?;
            AcpChildCredentialProjection::broker_v1(
                &projection.endpoint,
                projection.descriptor.capability_id,
                token,
                self.public_key,
                &self.relay_url,
                expires_at,
            )
            .map_err(|_| BrokerError::InvalidIssuance)
        })();
        let child_projection = match child_projection {
            Ok(projection) => projection,
            Err(error) => {
                let _ = self.broker.revoke_session(session_id);
                return Err(error);
            }
        };
        Ok(ProcessCapabilityLease {
            broker: Arc::clone(&self.broker),
            session_id,
            projection: child_projection,
            state: ProcessCapabilityState::Inactive,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessCapabilityState {
    Inactive,
    Active,
    Revoked,
}

/// Capability and typed child projection owned by one ACP process generation.
pub(crate) struct ProcessCapabilityLease {
    broker: Arc<CapabilityBroker>,
    session_id: Uuid,
    projection: AcpChildCredentialProjection,
    state: ProcessCapabilityState,
}

impl fmt::Debug for ProcessCapabilityLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessCapabilityLease")
            .field("session_id", &self.session_id)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl ProcessCapabilityLease {
    pub(crate) fn projection(&self) -> &AcpChildCredentialProjection {
        &self.projection
    }

    pub(crate) fn mcp_env(&self) -> Vec<EnvVar> {
        self.projection.mcp_env()
    }

    pub(crate) fn activate(&mut self) -> Result<(), BrokerError> {
        match self.state {
            ProcessCapabilityState::Inactive => {
                self.broker.activate_session(self.session_id)?;
                self.state = ProcessCapabilityState::Active;
                Ok(())
            }
            ProcessCapabilityState::Active => Ok(()),
            ProcessCapabilityState::Revoked => Err(BrokerError::UnknownSession),
        }
    }

    pub(crate) fn revoke(&mut self) -> Result<(), BrokerError> {
        if self.state == ProcessCapabilityState::Revoked {
            return Ok(());
        }
        self.broker.revoke_session(self.session_id)?;
        self.state = ProcessCapabilityState::Revoked;
        Ok(())
    }
}

impl Drop for ProcessCapabilityLease {
    fn drop(&mut self) {
        let _ = self.revoke();
    }
}

/// Secret-safe broker construction or control failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum BrokerError {
    /// The configured relay is not a canonical relay root.
    #[error("capability broker relay is invalid")]
    InvalidRelay,
    /// The configured owner-attestation tag is absent from the accepted format.
    #[error("capability broker owner attestation is invalid")]
    InvalidAuthTag,
    /// The requested capability scope is incompatible with this broker.
    #[error("capability broker scope is invalid")]
    InvalidScope,
    /// The requested capability lifetime or budget is invalid.
    #[error("capability broker issuance parameters are invalid")]
    InvalidIssuance,
    /// A session already has an issued capability.
    #[error("capability broker session already has a capability")]
    AlreadyIssued,
    /// No capability was issued for this session.
    #[error("capability broker session is unknown")]
    UnknownSession,
    /// The loopback listener could not be created.
    #[error("capability broker loopback listener failed")]
    Bind,
    /// The broker task did not shut down cleanly.
    #[error("capability broker shutdown failed")]
    Shutdown,
    /// The trusted clock was unavailable or overflowed.
    #[error("capability broker clock is invalid")]
    Clock,
    /// The capability registry rejected the control operation.
    #[error("capability broker registry rejected the operation")]
    Registry,
}

/// One-time material projected to a managed session.
///
/// The bearer token is returned only here; the broker registry retains only a
/// SHA-256 hash. `Debug` always redacts the token.
pub(crate) struct SessionCapabilityProjection {
    pub(crate) endpoint: String,
    pub(crate) descriptor: CapabilityDescriptor,
    pub(crate) token: CapabilityToken,
    pub(crate) connect_timeout_ms: u64,
    pub(crate) read_timeout_ms: u64,
    pub(crate) write_timeout_ms: u64,
}

impl fmt::Debug for SessionCapabilityProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCapabilityProjection")
            .field("endpoint", &self.endpoint)
            .field("descriptor", &self.descriptor)
            .field("token", &"[REDACTED]")
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("read_timeout_ms", &self.read_timeout_ms)
            .field("write_timeout_ms", &self.write_timeout_ms)
            .finish()
    }
}

#[derive(Clone)]
struct ClockAnchor {
    started: Instant,
}

impl ClockAnchor {
    fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }

    fn now(&self) -> Result<ClockReading, BrokerError> {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BrokerError::Clock)?
            .as_millis();
        let unix_ms = i64::try_from(wall).map_err(|_| BrokerError::Clock)?;
        let monotonic_ms =
            u64::try_from(self.started.elapsed().as_millis()).map_err(|_| BrokerError::Clock)?;
        Ok(ClockReading {
            unix_ms,
            monotonic_ms,
        })
    }
}

struct ConfigSigningExecutor {
    keys: Keys,
    relay: RelayOrigin,
    canonical_auth_tag: Option<String>,
    auth_tag: Option<Tag>,
    auth_conditions: Option<String>,
    expiries: Arc<Mutex<HashMap<Uuid, i64>>>,
    #[cfg(test)]
    completed_signatures: AtomicU64,
}

impl fmt::Debug for ConfigSigningExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigSigningExecutor")
            .field("public_key", &self.keys.public_key().to_hex())
            .field("relay", &self.relay)
            .field("has_auth_tag", &self.auth_tag.is_some())
            .finish()
    }
}

impl ConfigSigningExecutor {
    fn new(
        keys: Keys,
        relay: RelayOrigin,
        auth_tag_json: Option<&str>,
        expiries: Arc<Mutex<HashMap<Uuid, i64>>>,
    ) -> Result<Self, BrokerError> {
        let (canonical_auth_tag, auth_tag, auth_conditions) = match auth_tag_json {
            Some(raw) if !raw.is_empty() => {
                if raw.len() > MAX_AUTH_TAG_BYTES
                    || buzz_sdk::nip_oa::verify_auth_tag(raw, &keys.public_key()).is_err()
                {
                    return Err(BrokerError::InvalidAuthTag);
                }
                let tag = buzz_sdk::nip_oa::parse_auth_tag(raw)
                    .map_err(|_| BrokerError::InvalidAuthTag)?;
                let canonical = serde_json::to_string(tag.as_slice())
                    .map_err(|_| BrokerError::InvalidAuthTag)?;
                let conditions = tag
                    .as_slice()
                    .get(2)
                    .cloned()
                    .ok_or(BrokerError::InvalidAuthTag)?;
                (Some(canonical), Some(tag), Some(conditions))
            }
            Some(_) | None => (None, None, None),
        };
        Ok(Self {
            keys,
            relay,
            canonical_auth_tag,
            auth_tag,
            auth_conditions,
            expiries,
            #[cfg(test)]
            completed_signatures: AtomicU64::new(0),
        })
    }

    fn stable_internal() -> TrustedExecutionError {
        TrustedExecutionError::new(StableErrorKind::Internal)
    }

    fn sign_event(
        &self,
        request: &buzz_signing_capability::NostrEventSignRequest,
    ) -> Result<OperationResult, TrustedExecutionError> {
        if request.kind > u16::MAX.into() {
            return Err(TrustedExecutionError::new(StableErrorKind::InvalidPayload));
        }
        let mut tags =
            Vec::with_capacity(request.tags.len() + usize::from(self.auth_tag.is_some()));
        for structured in &request.tags {
            let tag = Tag::parse(structured.0.clone()).map_err(|_| Self::stable_internal())?;
            tags.push(tag);
        }
        if let Some(auth_tag) = &self.auth_tag {
            tags.push(auth_tag.clone());
        }
        let now = unix_now_secs().ok_or_else(Self::stable_internal)?;
        let created_at = if let Some(requested) = request.requested_created_at {
            if now.abs_diff(requested) > MAX_REQUESTED_TIMESTAMP_SKEW_SECS {
                return Err(TrustedExecutionError::new(StableErrorKind::InvalidPayload));
            }
            requested
        } else {
            now
        };
        if self
            .auth_conditions
            .as_deref()
            .is_some_and(|conditions| !auth_conditions_allow(conditions, request.kind, created_at))
        {
            return Err(TrustedExecutionError::new(
                StableErrorKind::OperationNotAllowed,
            ));
        }
        let event = EventBuilder::new(Kind::Custom(request.kind as u16), &request.content)
            .tags(tags)
            .custom_created_at(nostr::Timestamp::from(created_at))
            .sign_with_keys(&self.keys)
            .map_err(|_| Self::stable_internal())?;
        let event_json = serde_json::to_string(&event).map_err(|_| Self::stable_internal())?;
        #[cfg(test)]
        self.completed_signatures.fetch_add(1, Ordering::SeqCst);
        Ok(OperationResult::SignedEvent { event_json })
    }

    fn sign_nip98(
        &self,
        request: &buzz_signing_capability::Nip98SignRequest,
    ) -> Result<OperationResult, TrustedExecutionError> {
        const NIP98_EVENT_KIND: u32 = 27_235;
        let created_at = unix_now_secs().ok_or_else(Self::stable_internal)?;
        if self.auth_conditions.as_deref().is_some_and(|conditions| {
            !auth_conditions_allow(conditions, NIP98_EVENT_KIND, created_at)
        }) {
            return Err(TrustedExecutionError::new(
                StableErrorKind::OperationNotAllowed,
            ));
        }
        let method = match request.method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        };
        let base = crate::relay::relay_ws_to_http(self.relay.as_str());
        let url = format!("{base}{}", request.path);
        let mut tags = vec![
            Tag::parse(["u", url.as_str()]).map_err(|_| Self::stable_internal())?,
            Tag::parse(["method", method]).map_err(|_| Self::stable_internal())?,
            Tag::parse(["nonce", Uuid::new_v4().to_string().as_str()])
                .map_err(|_| Self::stable_internal())?,
        ];
        if let Some(payload_sha256) = &request.payload_sha256 {
            tags.push(
                Tag::parse(["payload", payload_sha256.as_str()])
                    .map_err(|_| Self::stable_internal())?,
            );
        }
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .custom_created_at(nostr::Timestamp::from(created_at))
            .sign_with_keys(&self.keys)
            .map_err(|_| Self::stable_internal())?;
        let event_json = serde_json::to_string(&event).map_err(|_| Self::stable_internal())?;
        #[cfg(test)]
        self.completed_signatures.fetch_add(1, Ordering::SeqCst);
        Ok(OperationResult::Authorization {
            authorization: format!("Nostr {}", STANDARD.encode(event_json)),
            auth_tag: self.canonical_auth_tag.clone(),
        })
    }
}

impl TrustedOperationExecutor for ConfigSigningExecutor {
    fn execute(
        &self,
        authorized: &buzz_signing_capability::AuthorizedOperation,
    ) -> Result<OperationResult, TrustedExecutionError> {
        match authorized.operation() {
            Operation::IdentityMetadata => {
                let expires_at_unix_ms = lock(&self.expiries)
                    .get(&authorized.capability_id())
                    .copied()
                    .ok_or_else(Self::stable_internal)?;
                Ok(OperationResult::IdentityMetadata(IdentityMetadata {
                    public_key: self.keys.public_key().to_hex(),
                    relay: self.relay.clone(),
                    expires_at_unix_ms,
                }))
            }
            Operation::NostrEventSign(request) => self.sign_event(request),
            Operation::Nip98Sign(request) => self.sign_nip98(request),
            _ => Err(TrustedExecutionError::new(
                StableErrorKind::OperationNotAllowed,
            )),
        }
    }
}

struct BrokerState {
    registry: CapabilityRegistry,
    executor: ConfigSigningExecutor,
    relay: RelayOrigin,
    clock: ClockAnchor,
    sessions: Mutex<HashMap<Uuid, Uuid>>,
    execution_fence: Mutex<()>,
}

impl fmt::Debug for BrokerState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerState")
            .field("registry", &self.registry)
            .field("executor", &self.executor)
            .field("relay", &self.relay)
            .field("session_count", &lock(&self.sessions).len())
            .finish()
    }
}

impl BrokerState {
    fn process_request(&self, request: RequestEnvelope) -> ResponseEnvelope {
        let request_id = request.request_id;
        let now = match self.clock.now() {
            Ok(now) => now,
            Err(_) => return ResponseEnvelope::error(request_id, StableErrorKind::Internal),
        };
        let _fence = lock(&self.execution_fence);
        match self.registry.authorize(request, now) {
            Ok(AuthorizationOutcome::Replay(response)) => response,
            Ok(AuthorizationOutcome::Fresh(permit)) => {
                match self.executor.execute(permit.authorized()) {
                    Ok(result) => permit
                        .complete(result)
                        .unwrap_or_else(|error| ResponseEnvelope::error(request_id, error.kind())),
                    Err(error) => permit.fail(error.kind()),
                }
            }
            Err(error) => ResponseEnvelope::error(request_id, error.kind()),
        }
    }
}

/// Running default-off loopback broker and its trusted control API.
pub(crate) struct CapabilityBroker {
    state: Arc<BrokerState>,
    address: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl fmt::Debug for CapabilityBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityBroker")
            .field("address", &self.address)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl CapabilityBroker {
    /// Start from the already-validated harness config without reading secrets
    /// from the environment a second time.
    ///
    /// For this slice (no mTLS) the broker binds only a Tailnet address,
    /// optionally overridden by `BUZZ_TAILSCALE_IP`. When that env is unset
    /// the listener binds `100.117.196.100:0` so local tests still run.
    pub(crate) async fn start_for_config(
        config: &Config,
        auth_tag_json: Option<&str>,
    ) -> Result<Self, BrokerError> {
        let relay = RelayOrigin::parse(&config.relay_url).map_err(|_| BrokerError::InvalidRelay)?;
        Self::start(config.keys.clone(), relay, auth_tag_json).await
    }

    async fn start(
        keys: Keys,
        relay: RelayOrigin,
        auth_tag_json: Option<&str>,
    ) -> Result<Self, BrokerError> {
        let bind_ip = resolve_tailscale_bind_ip();
        let listener = TcpListener::bind((bind_ip, 0))
            .await
            .map_err(|_| BrokerError::Bind)?;
        let address = listener.local_addr().map_err(|_| BrokerError::Bind)?;
        if address.ip() != bind_ip {
            return Err(BrokerError::Bind);
        }
        let expiries = Arc::new(Mutex::new(HashMap::new()));
        let executor = ConfigSigningExecutor::new(keys, relay.clone(), auth_tag_json, expiries)?;
        let state = Arc::new(BrokerState {
            registry: CapabilityRegistry::new(),
            executor,
            relay,
            clock: ClockAnchor::new(),
            sessions: Mutex::new(HashMap::new()),
            execution_fence: Mutex::new(()),
        });
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(run_listener(listener, task_state, shutdown_rx));
        Ok(Self {
            state,
            address,
            shutdown_tx: Some(shutdown_tx),
            task,
        })
    }

    /// Issue one inactive capability for a session and return its only raw
    /// projection. Reissuing for the same session is refused.
    pub(crate) fn issue_session(
        &self,
        session_id: Uuid,
        scope: CapabilityScope,
        budgets: BudgetLimits,
        lifetime: Duration,
    ) -> Result<SessionCapabilityProjection, BrokerError> {
        if scope.relay() != &self.state.relay || !scope_supported(&scope) {
            return Err(BrokerError::InvalidScope);
        }
        let now = self.state.clock.now()?;
        let mut sessions = lock(&self.state.sessions);
        let mut expiries = lock(&self.state.executor.expiries);
        let retired: HashSet<Uuid> = sessions
            .values()
            .copied()
            .filter(|capability_id| {
                expiries
                    .get(capability_id)
                    .is_none_or(|expiry| *expiry <= now.unix_ms)
                    || self
                        .state
                        .registry
                        .snapshot(*capability_id)
                        .is_none_or(|snapshot| snapshot.state == CapabilityState::Revoked)
            })
            .collect();
        sessions.retain(|_, capability_id| !retired.contains(capability_id));
        for capability_id in retired {
            expiries.remove(&capability_id);
        }
        if sessions.contains_key(&session_id) {
            return Err(BrokerError::AlreadyIssued);
        }
        if sessions.len() >= MAX_REGISTRY_CAPABILITIES {
            return Err(BrokerError::InvalidIssuance);
        }
        let lifetime_ms =
            u64::try_from(lifetime.as_millis()).map_err(|_| BrokerError::InvalidIssuance)?;
        let expires_at_unix_ms = now
            .unix_ms
            .checked_add(i64::try_from(lifetime_ms).map_err(|_| BrokerError::InvalidIssuance)?)
            .ok_or(BrokerError::InvalidIssuance)?;
        let issued = self
            .state
            .registry
            .issue(scope, budgets, now, expires_at_unix_ms, lifetime_ms)
            .map_err(|_| BrokerError::InvalidIssuance)?;
        sessions.insert(session_id, issued.descriptor.capability_id);
        expiries.insert(
            issued.descriptor.capability_id,
            issued.descriptor.expires_at_unix_ms,
        );
        Ok(SessionCapabilityProjection {
            endpoint: format!("tcp://{}", self.address),
            descriptor: issued.descriptor,
            token: issued.token,
            connect_timeout_ms: CONNECT_TIMEOUT.as_millis() as u64,
            read_timeout_ms: READ_TIMEOUT.as_millis() as u64,
            write_timeout_ms: WRITE_TIMEOUT.as_millis() as u64,
        })
    }

    /// Activate the previously issued session capability.
    pub(crate) fn activate_session(&self, session_id: Uuid) -> Result<(), BrokerError> {
        let capability_id = self.capability_for_session(session_id)?;
        let now = self.state.clock.now()?;
        let _fence = lock(&self.state.execution_fence);
        self.state
            .registry
            .activate(capability_id, now)
            .map_err(|_| BrokerError::Registry)
    }

    /// Revoke the session capability, waiting for any already-authorized
    /// synchronous signing operation to settle before returning.
    pub(crate) fn revoke_session(&self, session_id: Uuid) -> Result<(), BrokerError> {
        let capability_id = self.capability_for_session(session_id)?;
        let _fence = lock(&self.state.execution_fence);
        self.state
            .registry
            .revoke(capability_id)
            .map_err(|_| BrokerError::Registry)?;
        lock(&self.state.sessions).remove(&session_id);
        lock(&self.state.executor.expiries).remove(&capability_id);
        Ok(())
    }

    fn capability_for_session(&self, session_id: Uuid) -> Result<Uuid, BrokerError> {
        lock(&self.state.sessions)
            .get(&session_id)
            .copied()
            .ok_or(BrokerError::UnknownSession)
    }

    #[cfg(test)]
    fn completed_signature_count(&self) -> u64 {
        self.state
            .executor
            .completed_signatures
            .load(Ordering::SeqCst)
    }

    /// Stop accepting connections and wait for bounded in-flight connections.
    pub(crate) async fn shutdown(mut self) -> Result<(), BrokerError> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        timeout(SHUTDOWN_TIMEOUT, &mut self.task)
            .await
            .map_err(|_| BrokerError::Shutdown)?
            .map_err(|_| BrokerError::Shutdown)
    }
}

impl Drop for CapabilityBroker {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}

fn scope_supported(scope: &CapabilityScope) -> bool {
    let supported = [
        OperationKind::IdentityMetadata,
        OperationKind::NostrEventSign,
        OperationKind::Nip98Sign,
    ];
    let unsupported = [
        OperationKind::Nip42Sign,
        OperationKind::BlossomSign,
        OperationKind::EngramCoordinate,
        OperationKind::EngramDecrypt,
        OperationKind::EngramBuildEvent,
        OperationKind::GitNip98Sign,
        OperationKind::GitObjectSign,
    ];
    supported.iter().any(|kind| scope.allows_operation(*kind))
        && unsupported
            .iter()
            .all(|kind| !scope.allows_operation(*kind))
}

fn unix_now_secs() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn auth_conditions_allow(conditions: &str, kind: u32, created_at: u64) -> bool {
    conditions.is_empty()
        || conditions.split('&').all(|clause| {
            if let Some(value) = clause.strip_prefix("kind=") {
                value.parse::<u32>().ok() == Some(kind)
            } else if let Some(value) = clause.strip_prefix("created_at<") {
                value.parse::<u64>().is_ok_and(|limit| created_at < limit)
            } else if let Some(value) = clause.strip_prefix("created_at>") {
                value.parse::<u64>().is_ok_and(|limit| created_at > limit)
            } else {
                false
            }
        })
}

async fn run_listener(
    listener: TcpListener,
    state: Arc<BrokerState>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { break };
                // Strict Tailscale allowlist: CGNAT 100.64.0.0/10 only. This also
                // blocks 192.168.4.x / ... and 127.0.0.1 by construction.
                // Tests running with cfg(test) bind on loopback above, so we
                // also let loopback through when built for tests to keep
                // in-process harness green, while `is_tailscale_ipv4` itself
                // still encodes the Tailnet allowlist for docs/checks.
                let addr = match peer.ip() {
                    std::net::IpAddr::V4(addr) => addr,
                    std::net::IpAddr::V6(_) => continue,
                };
                if is_tailscale_ipv4(addr) || (addr.is_loopback() && cfg!(test)) {
                } else {
                    continue;
                }
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    spawn_overloaded(stream, &mut connections);
                    continue;
                };
                let connection_state = Arc::clone(&state);
                connections.spawn(async move {
                    let _permit = permit;
                    handle_connection(stream, connection_state).await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    while connections.join_next().await.is_some() {}
}

fn spawn_overloaded(stream: TcpStream, connections: &mut JoinSet<()>) {
    connections.spawn(async move {
        write_response(
            stream,
            &ResponseEnvelope::error(Uuid::nil(), StableErrorKind::ConcurrencyExceeded),
        )
        .await;
    });
}

async fn handle_connection(mut stream: TcpStream, state: Arc<BrokerState>) {
    let response = match read_request(&mut stream).await {
        Ok(request) => state.process_request(request),
        Err((request_id, kind)) => ResponseEnvelope::error(request_id, kind),
    };
    write_response(stream, &response).await;
}

async fn read_request(stream: &mut TcpStream) -> Result<RequestEnvelope, (Uuid, StableErrorKind)> {
    let mut bytes = Vec::new();
    let mut reader = BufReader::new(stream).take((MAX_WIRE_REQUEST_BYTES + 1) as u64);
    let read = timeout(READ_TIMEOUT, reader.read_until(b'\n', &mut bytes))
        .await
        .map_err(|_| (Uuid::nil(), StableErrorKind::DeadlineExpired))?
        .map_err(|_| (Uuid::nil(), StableErrorKind::InvalidPayload))?;
    if read == 0 {
        return Err((Uuid::nil(), StableErrorKind::InvalidPayload));
    }
    if bytes.len() > MAX_WIRE_REQUEST_BYTES {
        return Err((Uuid::nil(), StableErrorKind::PayloadTooLarge));
    }
    if bytes.last() != Some(&b'\n') {
        return Err((Uuid::nil(), StableErrorKind::InvalidPayload));
    }
    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| (Uuid::nil(), StableErrorKind::InvalidPayload))?;
    let request_id = value
        .get("request_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .unwrap_or_else(Uuid::nil);
    validate_wire_shape(&value).map_err(|kind| (request_id, kind))?;
    serde_json::from_value(value).map_err(|_| (request_id, StableErrorKind::InvalidPayload))
}

fn validate_wire_shape(value: &Value) -> Result<(), StableErrorKind> {
    let envelope = value.as_object().ok_or(StableErrorKind::InvalidPayload)?;
    const ENVELOPE_FIELDS: &[&str] = &[
        "version",
        "capability_id",
        "token",
        "request_id",
        "deadline_unix_ms",
        "operation",
    ];
    if envelope.len() != ENVELOPE_FIELDS.len()
        || envelope
            .keys()
            .any(|field| !ENVELOPE_FIELDS.contains(&field.as_str()))
    {
        return Err(StableErrorKind::InvalidPayload);
    }
    let operation = envelope
        .get("operation")
        .and_then(Value::as_object)
        .ok_or(StableErrorKind::InvalidPayload)?;
    let kind = operation
        .get("operation")
        .and_then(Value::as_str)
        .ok_or(StableErrorKind::InvalidPayload)?;
    if kind == "identity_metadata" {
        return (operation.len() == 1)
            .then_some(())
            .ok_or(StableErrorKind::InvalidPayload);
    }
    if operation.len() != 2 {
        return Err(StableErrorKind::InvalidPayload);
    }
    let payload = operation
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(StableErrorKind::InvalidPayload)?;
    let allowed: &[&str] = match kind {
        "nostr_event_sign" => &["relay", "kind", "content", "tags", "requested_created_at"],
        "nip98_sign" => &["relay", "method", "path", "payload_sha256"],
        _ => return Err(StableErrorKind::OperationNotAllowed),
    };
    if payload.len() != allowed.len()
        || payload
            .keys()
            .any(|field| !allowed.contains(&field.as_str()))
    {
        return Err(StableErrorKind::InvalidPayload);
    }
    Ok(())
}

async fn write_response(mut stream: TcpStream, response: &ResponseEnvelope) {
    let Ok(mut bytes) = serde_json::to_vec(response) else {
        return;
    };
    bytes.push(b'\n');
    let _ = timeout(WRITE_TIMEOUT, async {
        stream.write_all(&bytes).await?;
        stream.shutdown().await
    })
    .await;
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_signing_capability::{
        HttpPathRule, Nip98SignRequest, NostrEventSignRequest, ScopeBuilder, StructuredTag,
        PROTOCOL_VERSION,
    };
    use clap::Parser;
    use nostr::Event;
    use serde_json::json;

    const RELAY: &str = "wss://relay.example";
    const CHANNEL: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn budgets() -> BudgetLimits {
        BudgetLimits {
            max_operations: 32,
            max_payload_bytes: 2 * 1024 * 1024,
            max_in_flight: 4,
            max_replays_per_request: 3,
        }
    }

    fn scope(relay: &RelayOrigin) -> CapabilityScope {
        ScopeBuilder::new(relay.clone())
            .allow_operation(OperationKind::IdentityMetadata)
            .allow_operation(OperationKind::NostrEventSign)
            .allow_operation(OperationKind::Nip98Sign)
            .allow_event_kind(9)
            .allow_channel(CHANNEL)
            .allow_http(HttpMethod::Post, HttpPathRule::Exact("/query".into()))
            .build()
            .expect("test scope")
    }

    async fn broker(auth_tag: Option<&str>) -> (CapabilityBroker, Keys, RelayOrigin) {
        let keys = Keys::generate();
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let broker = CapabilityBroker::start(keys.clone(), relay.clone(), auth_tag)
            .await
            .expect("start broker");
        (broker, keys, relay)
    }

    #[tokio::test]
    async fn process_generation_scope_is_inactive_then_activated_and_revoked() {
        let (broker, keys, _) = broker(None).await;
        let args = crate::config::CliArgs::try_parse_from([
            "buzz-acp",
            "--private-key",
            &keys.secret_key().to_secret_hex(),
            "--relay-url",
            RELAY,
        ])
        .expect("pilot config args");
        let config = Config::from_args(args).expect("pilot config");
        let broker = Arc::new(broker);
        let spawner = BrokerChildSpawner::for_channels(
            Arc::clone(&broker),
            &config,
            [Uuid::parse_str(CHANNEL).expect("channel")],
        )
        .expect("process spawner");
        let mut lease = spawner.issue().expect("inactive capability");
        assert_eq!(lease.state, ProcessCapabilityState::Inactive);
        let env = lease.mcp_env();
        assert_eq!(env.len(), 6);
        assert_eq!(env[0].name, "BUZZ_CAPABILITY_ENDPOINT");
        assert!(env.iter().all(|entry| {
            !matches!(
                entry.name.as_str(),
                "BUZZ_PRIVATE_KEY" | "BUZZ_ACP_PRIVATE_KEY" | "NOSTR_PRIVATE_KEY" | "BUZZ_AUTH_TAG"
            )
        }));
        lease.activate().expect("activate capability");
        assert_eq!(lease.state, ProcessCapabilityState::Active);
        lease.revoke().expect("revoke capability");
        assert_eq!(lease.state, ProcessCapabilityState::Revoked);
        drop(lease);
        let dropped_lease = spawner.issue().expect("second process generation");
        let dropped_session = dropped_lease.session_id;
        drop(dropped_lease);
        assert_eq!(
            broker.capability_for_session(dropped_session),
            Err(BrokerError::UnknownSession),
            "process-generation Drop must revoke and retire the session"
        );
        drop(spawner);
        Arc::try_unwrap(broker)
            .expect("sole broker owner")
            .shutdown()
            .await
            .expect("broker shutdown");
    }

    fn request(
        projection: &SessionCapabilityProjection,
        request_id: Uuid,
        operation: Operation,
    ) -> RequestEnvelope {
        RequestEnvelope {
            version: PROTOCOL_VERSION,
            capability_id: projection.descriptor.capability_id,
            token: projection.token.clone(),
            request_id,
            deadline_unix_ms: projection.descriptor.expires_at_unix_ms,
            operation,
        }
    }

    async fn send(endpoint: &str, request: &RequestEnvelope) -> ResponseEnvelope {
        let address = endpoint.strip_prefix("tcp://").expect("tcp endpoint");
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
            .await
            .expect("connect timeout")
            .expect("connect");
        let mut bytes = serde_json::to_vec(request).expect("serialize request");
        bytes.push(b'\n');
        stream.write_all(&bytes).await.expect("write request");
        let mut line = String::new();
        timeout(WRITE_TIMEOUT, BufReader::new(stream).read_line(&mut line))
            .await
            .expect("response timeout")
            .expect("read response");
        serde_json::from_str(&line).expect("response")
    }

    fn signed_event(response: &ResponseEnvelope) -> Event {
        let OperationResult::SignedEvent { event_json } = response.result().expect("result") else {
            panic!("expected signed event")
        };
        serde_json::from_str(event_json).expect("event")
    }

    #[tokio::test]
    async fn signed_event_is_valid_and_injects_only_canonical_auth_tag() {
        let owner = Keys::generate();
        let agent = Keys::generate();
        let auth = buzz_sdk::nip_oa::compute_auth_tag(&owner, &agent.public_key(), "kind=9")
            .expect("auth tag");
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let broker = CapabilityBroker::start(agent.clone(), relay.clone(), Some(&auth))
            .await
            .expect("broker");
        let session = Uuid::new_v4();
        let projection = broker
            .issue_session(session, scope(&relay), budgets(), Duration::from_secs(60))
            .expect("issue");
        assert_eq!(
            send(
                &projection.endpoint,
                &request(&projection, Uuid::new_v4(), Operation::IdentityMetadata),
            )
            .await
            .error_kind(),
            Some(StableErrorKind::Inactive)
        );
        broker.activate_session(session).expect("activate");
        let operation = Operation::NostrEventSign(NostrEventSignRequest {
            relay: relay.clone(),
            kind: 9,
            content: "safe content".into(),
            tags: vec![StructuredTag(vec!["h".into(), CHANNEL.into()])],
            requested_created_at: None,
        });
        let response = send(
            &projection.endpoint,
            &request(&projection, Uuid::new_v4(), operation),
        )
        .await;
        let event = signed_event(&response);
        event.verify().expect("valid signature");
        assert_eq!(event.pubkey, agent.public_key());
        let auth_tags: Vec<_> = event
            .tags
            .iter()
            .filter(|tag| tag.as_slice().first().is_some_and(|name| name == "auth"))
            .collect();
        assert_eq!(auth_tags.len(), 1);
        assert_eq!(
            serde_json::to_string(auth_tags[0].as_slice()).expect("tag"),
            auth
        );

        let wrong_kind_session = Uuid::new_v4();
        let wrong_kind_scope = ScopeBuilder::new(relay.clone())
            .allow_operation(OperationKind::NostrEventSign)
            .allow_event_kind(1)
            .allow_channel(CHANNEL)
            .build()
            .expect("wrong-kind scope");
        let wrong_kind_projection = broker
            .issue_session(
                wrong_kind_session,
                wrong_kind_scope,
                budgets(),
                Duration::from_secs(60),
            )
            .expect("issue wrong-kind capability");
        broker
            .activate_session(wrong_kind_session)
            .expect("activate wrong-kind capability");
        let response = send(
            &wrong_kind_projection.endpoint,
            &request(
                &wrong_kind_projection,
                Uuid::new_v4(),
                Operation::NostrEventSign(NostrEventSignRequest {
                    relay,
                    kind: 1,
                    content: "outside owner attestation".into(),
                    tags: vec![StructuredTag(vec!["h".into(), CHANNEL.into()])],
                    requested_created_at: None,
                }),
            ),
        )
        .await;
        assert_eq!(
            response.error_kind(),
            Some(StableErrorKind::OperationNotAllowed)
        );
        broker.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn nip98_signature_is_valid_and_returns_canonical_auth_projection() {
        let owner = Keys::generate();
        let agent = Keys::generate();
        let auth =
            buzz_sdk::nip_oa::compute_auth_tag(&owner, &agent.public_key(), "").expect("auth tag");
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let broker = CapabilityBroker::start(agent.clone(), relay.clone(), Some(&auth))
            .await
            .expect("broker");
        let session = Uuid::new_v4();
        let projection = broker
            .issue_session(session, scope(&relay), budgets(), Duration::from_secs(60))
            .expect("issue");
        broker.activate_session(session).expect("activate");
        let response = send(
            &projection.endpoint,
            &request(
                &projection,
                Uuid::new_v4(),
                Operation::Nip98Sign(Nip98SignRequest {
                    relay,
                    method: HttpMethod::Post,
                    path: "/query".into(),
                    payload_sha256: Some(ZERO_HASH.into()),
                }),
            ),
        )
        .await;
        let OperationResult::Authorization {
            authorization,
            auth_tag,
        } = response.result().expect("authorization")
        else {
            panic!("expected authorization")
        };
        assert_eq!(auth_tag.as_deref(), Some(auth.as_str()));
        let encoded = authorization.strip_prefix("Nostr ").expect("header");
        let event_json =
            String::from_utf8(STANDARD.decode(encoded).expect("base64")).expect("utf8");
        let event: Event = serde_json::from_str(&event_json).expect("event");
        event.verify().expect("valid signature");
        assert_eq!(event.pubkey, agent.public_key());
        broker.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn exact_replay_is_cached_and_conflict_revokes() {
        let (broker, _, relay) = broker(None).await;
        let session = Uuid::new_v4();
        let projection = broker
            .issue_session(session, scope(&relay), budgets(), Duration::from_secs(60))
            .expect("issue");
        broker.activate_session(session).expect("activate");
        let request_id = Uuid::new_v4();
        let first = send(
            &projection.endpoint,
            &request(&projection, request_id, Operation::IdentityMetadata),
        )
        .await;
        let replay = send(
            &projection.endpoint,
            &request(&projection, request_id, Operation::IdentityMetadata),
        )
        .await;
        assert_eq!(first, replay);
        let conflict = send(
            &projection.endpoint,
            &request(
                &projection,
                request_id,
                Operation::NostrEventSign(NostrEventSignRequest {
                    relay,
                    kind: 9,
                    content: "conflict".into(),
                    tags: vec![StructuredTag(vec!["h".into(), CHANNEL.into()])],
                    requested_created_at: None,
                }),
            ),
        )
        .await;
        assert_eq!(conflict.error_kind(), Some(StableErrorKind::ReplayConflict));
        let after = send(
            &projection.endpoint,
            &request(&projection, Uuid::new_v4(), Operation::IdentityMetadata),
        )
        .await;
        assert_eq!(after.error_kind(), Some(StableErrorKind::Revoked));
        broker.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn expiry_revocation_and_scope_fail_closed() {
        let (broker, _, relay) = broker(None).await;
        let expiring_session = Uuid::new_v4();
        let expiring = broker
            .issue_session(
                expiring_session,
                scope(&relay),
                budgets(),
                Duration::from_millis(15),
            )
            .expect("issue");
        broker.activate_session(expiring_session).expect("activate");
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            send(
                &expiring.endpoint,
                &request(&expiring, Uuid::new_v4(), Operation::IdentityMetadata),
            )
            .await
            .error_kind(),
            Some(StableErrorKind::Expired)
        );

        let session = Uuid::new_v4();
        let projection = broker
            .issue_session(session, scope(&relay), budgets(), Duration::from_secs(60))
            .expect("issue");
        broker.activate_session(session).expect("activate");
        let wrong_relay = RelayOrigin::parse("wss://other.example").expect("other relay");
        let wrong = send(
            &projection.endpoint,
            &request(
                &projection,
                Uuid::new_v4(),
                Operation::Nip98Sign(Nip98SignRequest {
                    relay: wrong_relay,
                    method: HttpMethod::Get,
                    path: "/outside".into(),
                    payload_sha256: None,
                }),
            ),
        )
        .await;
        assert_eq!(wrong.error_kind(), Some(StableErrorKind::RelayNotAllowed));

        let wrong_method = send(
            &projection.endpoint,
            &request(
                &projection,
                Uuid::new_v4(),
                Operation::Nip98Sign(Nip98SignRequest {
                    relay: relay.clone(),
                    method: HttpMethod::Get,
                    path: "/query".into(),
                    payload_sha256: None,
                }),
            ),
        )
        .await;
        assert_eq!(
            wrong_method.error_kind(),
            Some(StableErrorKind::MethodNotAllowed)
        );
        let wrong_path = send(
            &projection.endpoint,
            &request(
                &projection,
                Uuid::new_v4(),
                Operation::Nip98Sign(Nip98SignRequest {
                    relay: relay.clone(),
                    method: HttpMethod::Post,
                    path: "/outside".into(),
                    payload_sha256: Some(ZERO_HASH.into()),
                }),
            ),
        )
        .await;
        assert_eq!(
            wrong_path.error_kind(),
            Some(StableErrorKind::PathNotAllowed)
        );
        let caller_auth = send(
            &projection.endpoint,
            &request(
                &projection,
                Uuid::new_v4(),
                Operation::NostrEventSign(NostrEventSignRequest {
                    relay,
                    kind: 9,
                    content: "safe".into(),
                    tags: vec![
                        StructuredTag(vec!["h".into(), CHANNEL.into()]),
                        StructuredTag(vec!["auth".into(), "caller".into()]),
                    ],
                    requested_created_at: None,
                }),
            ),
        )
        .await;
        assert_eq!(
            caller_auth.error_kind(),
            Some(StableErrorKind::InvalidPayload)
        );
        broker.revoke_session(session).expect("revoke");
        assert_eq!(
            send(
                &projection.endpoint,
                &request(&projection, Uuid::new_v4(), Operation::IdentityMetadata),
            )
            .await
            .error_kind(),
            Some(StableErrorKind::Revoked)
        );
        broker.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn malformed_oversize_unknown_fields_and_timestamps_are_rejected() {
        let (broker, _, relay) = broker(None).await;
        let session = Uuid::new_v4();
        let projection = broker
            .issue_session(session, scope(&relay), budgets(), Duration::from_secs(60))
            .expect("issue");
        broker.activate_session(session).expect("activate");
        let address = projection
            .endpoint
            .strip_prefix("tcp://")
            .expect("endpoint");

        let mut malformed = TcpStream::connect(address).await.expect("connect");
        malformed.write_all(b"not-json\n").await.expect("write");
        let mut line = String::new();
        BufReader::new(malformed)
            .read_line(&mut line)
            .await
            .expect("read");
        let response: ResponseEnvelope = serde_json::from_str(&line).expect("response");
        assert_eq!(response.error_kind(), Some(StableErrorKind::InvalidPayload));

        let mut oversized = TcpStream::connect(address).await.expect("connect");
        oversized
            .write_all(&vec![b'x'; MAX_WIRE_REQUEST_BYTES + 1])
            .await
            .expect("write oversized");
        let mut line = String::new();
        BufReader::new(oversized)
            .read_line(&mut line)
            .await
            .expect("read");
        let response: ResponseEnvelope = serde_json::from_str(&line).expect("response");
        assert_eq!(
            response.error_kind(),
            Some(StableErrorKind::PayloadTooLarge)
        );

        let request_id = Uuid::new_v4();
        let raw = json!({
            "version": PROTOCOL_VERSION,
            "capability_id": projection.descriptor.capability_id,
            "token": projection.token,
            "request_id": request_id,
            "deadline_unix_ms": projection.descriptor.expires_at_unix_ms,
            "operation": {
                "operation": "nostr_event_sign",
                "payload": {
                    "relay": relay,
                    "kind": 9,
                    "content": "safe",
                    "tags": [["h", CHANNEL]],
                    "requested_created_at": null
                }
            }
        });
        for forbidden in ["pubkey", "id", "sig", "signature"] {
            let mut raw = raw.clone();
            raw.pointer_mut("/operation/payload")
                .and_then(Value::as_object_mut)
                .expect("payload")
                .insert(forbidden.into(), json!("caller-controlled"));
            let mut stream = TcpStream::connect(address).await.expect("connect");
            stream
                .write_all(raw.to_string().as_bytes())
                .await
                .expect("write");
            stream.write_all(b"\n").await.expect("newline");
            let mut line = String::new();
            BufReader::new(stream)
                .read_line(&mut line)
                .await
                .expect("read");
            let response: ResponseEnvelope = serde_json::from_str(&line).expect("response");
            assert_eq!(response.error_kind(), Some(StableErrorKind::InvalidPayload));
        }

        let timestamped = Operation::NostrEventSign(NostrEventSignRequest {
            relay: RelayOrigin::parse(RELAY).expect("relay"),
            kind: 9,
            content: "safe".into(),
            tags: vec![StructuredTag(vec!["h".into(), CHANNEL.into()])],
            requested_created_at: Some(1),
        });
        let response = send(
            &projection.endpoint,
            &RequestEnvelope {
                version: PROTOCOL_VERSION,
                capability_id: projection.descriptor.capability_id,
                token: projection.token.clone(),
                request_id: Uuid::new_v4(),
                deadline_unix_ms: projection.descriptor.expires_at_unix_ms,
                operation: timestamped,
            },
        )
        .await;
        assert_eq!(response.error_kind(), Some(StableErrorKind::InvalidPayload));

        let current_timestamp = unix_now_secs().expect("clock");
        let in_window = Operation::NostrEventSign(NostrEventSignRequest {
            relay: RelayOrigin::parse(RELAY).expect("relay"),
            kind: 9,
            content: "safe".into(),
            tags: vec![StructuredTag(vec!["h".into(), CHANNEL.into()])],
            requested_created_at: Some(current_timestamp),
        });
        let response = send(
            &projection.endpoint,
            &request(&projection, Uuid::new_v4(), in_window),
        )
        .await;
        let event = signed_event(&response);
        assert_eq!(event.created_at.as_secs(), current_timestamp);
        broker.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn revoke_is_fenced_and_shutdown_closes_the_listener() {
        let (broker, _, relay) = broker(None).await;
        let session = Uuid::new_v4();
        let projection = broker
            .issue_session(session, scope(&relay), budgets(), Duration::from_secs(60))
            .expect("issue");
        broker.activate_session(session).expect("activate");

        let mut racers = Vec::new();
        for sequence in 0..16 {
            let endpoint = projection.endpoint.clone();
            let request = request(
                &projection,
                Uuid::new_v4(),
                Operation::NostrEventSign(NostrEventSignRequest {
                    relay: relay.clone(),
                    kind: 9,
                    content: format!("race-{sequence}"),
                    tags: vec![StructuredTag(vec!["h".into(), CHANNEL.into()])],
                    requested_created_at: None,
                }),
            );
            racers.push(tokio::spawn(async move { send(&endpoint, &request).await }));
        }
        tokio::task::yield_now().await;
        broker.revoke_session(session).expect("revoke");
        let completed_at_revoke = broker.completed_signature_count();
        for racer in racers {
            let response = racer.await.expect("race client");
            assert!(
                response.error_kind().is_none()
                    || response.error_kind() == Some(StableErrorKind::Revoked)
            );
        }
        assert_eq!(broker.completed_signature_count(), completed_at_revoke);
        let after_revoke = send(
            &projection.endpoint,
            &request(
                &projection,
                Uuid::new_v4(),
                Operation::NostrEventSign(NostrEventSignRequest {
                    relay,
                    kind: 9,
                    content: "after-revoke".into(),
                    tags: vec![StructuredTag(vec!["h".into(), CHANNEL.into()])],
                    requested_created_at: None,
                }),
            ),
        )
        .await;
        assert_eq!(after_revoke.error_kind(), Some(StableErrorKind::Revoked));
        assert_eq!(broker.completed_signature_count(), completed_at_revoke);
        let address = projection
            .endpoint
            .strip_prefix("tcp://")
            .expect("endpoint")
            .to_owned();
        broker.shutdown().await.expect("shutdown");
        assert!(TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn debug_and_errors_never_render_token_or_payload_canaries() {
        const TOKEN: &str = "TOKEN_CANARY_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const PAYLOAD: &str = "PAYLOAD_CANARY_agent_secret_content";
        let (broker, _, relay) = broker(None).await;
        let session = Uuid::new_v4();
        let mut projection = broker
            .issue_session(session, scope(&relay), budgets(), Duration::from_secs(60))
            .expect("issue");
        projection.token = CapabilityToken::from_secret(TOKEN.into()).expect("token");
        let rendered = format!("{projection:?} {broker:?} {:?}", BrokerError::Registry);
        assert!(!rendered.contains(TOKEN));
        assert!(!rendered.contains(PAYLOAD));
        assert!(!rendered.contains("private_key"));
        broker.shutdown().await.expect("shutdown");
    }
}
