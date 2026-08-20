//! Default-off WebSocket signing-capability broker (no mTLS for this slice).
//!
//! This module is compiled only with `signing-capability-broker`. It is not
//! connected to ACP startup by the explicit local pilot. For this slice the
//! broker owns the Nostr key, binds **localhost only** (`127.0.0.1:0`), and
//! accepts one request per WebSocket connection. Reachability is the endpoint
//! provider's concern — the broker itself is transport-agnostic beyond
//! binding localhost. See `docs/adr/0003-capability-broker-boundary.md` and
//! `docs/durable-scheduler-checkpoint-validation.md` for the ACL
//! (`tag:buzz-broker:8443 <- group:buzz-workers`), SAN/claim binding, and
//! `revoked_at` / replay-ledger reuse docs.

use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use buzz_signing_capability::{
    AuthorizationOutcome, AuthorizationPermit, BudgetLimits, CapabilityDescriptor,
    CapabilityRegistry, CapabilityScope, CapabilityState, CapabilityToken, ClockReading,
    HttpMethod, HttpPathRule, IdentityMetadata, Operation, OperationKind, OperationResult,
    RelayOrigin, RequestEnvelope, ResponseEnvelope, ScopeBuilder, StableErrorKind,
    TrustedExecutionError, TrustedOperationExecutor, MAX_REGISTRY_CAPABILITIES,
};
use futures_util::{SinkExt, StreamExt};
use nostr::{EventBuilder, Keys, Kind, Tag};
use serde::Deserialize;
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{oneshot, Mutex as AsyncMutex},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_tungstenite::{accept_async, tungstenite};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(test)]
use std::sync::atomic::AtomicU64;
#[cfg(test)]
use std::sync::Condvar;

#[cfg(test)]
type ExecutionGate = Arc<(Mutex<bool>, Condvar)>;

use crate::acp::{AcpChildCredentialProjection, EnvVar};
use crate::config::Config;

const MAX_WIRE_REQUEST_BYTES: usize = 1_100_000;
const MAX_WIRE_RESPONSE_BYTES: usize = 1_100_000;
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

/// Cloneable factory for one inactive capability per ACP process generation.
#[derive(Clone)]
pub struct BrokerChildSpawner {
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
    pub fn for_channels(
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
        match (
            config.broker_allowed_secrets.is_empty(),
            config.broker_allowed_secret_tools.is_empty(),
        ) {
            (true, true) => {}
            (false, false) => {
                builder = builder.allow_operation(OperationKind::SecretLease);
                for secret in &config.broker_allowed_secrets {
                    builder = builder.allow_secret(secret.clone());
                }
                for tool in &config.broker_allowed_secret_tools {
                    builder = builder.allow_secret_tool(tool.clone());
                }
            }
            _ => return Err(BrokerError::InvalidScope),
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
    pub fn issue(&self) -> Result<ProcessCapabilityLease, BrokerError> {
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
            let expires_at = u64::try_from(projection.descriptor.expires_at_unix_ms)
                .map_err(|_| BrokerError::InvalidIssuance)?;
            AcpChildCredentialProjection::broker_v1_zeroizing(
                &projection.endpoint,
                projection.descriptor.capability_id,
                projection.token.into_zeroizing_secret(),
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
pub struct ProcessCapabilityLease {
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
    pub fn projection(&self) -> &AcpChildCredentialProjection {
        &self.projection
    }

    pub fn mcp_env(&self) -> Vec<EnvVar> {
        self.projection.mcp_env()
    }

    pub fn activate(&mut self) -> Result<(), BrokerError> {
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

    pub fn revoke(&mut self) -> Result<(), BrokerError> {
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
pub enum BrokerError {
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
    /// The WebSocket listener could not be created.
    #[error("capability broker listener failed")]
    Bind,
    /// The broker task did not shut down cleanly.
    #[error("capability broker shutdown failed")]
    Shutdown,
    /// The trusted clock was unavailable or overflowed.
    #[error("capability broker clock is invalid")]
    Clock,
    /// The selected secret provider could not be initialized.
    #[error("capability broker secret provider is unavailable")]
    SecretProvider,
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
    secret_broker: Option<Arc<buzz_secrets::SecretBroker>>,
    shutdown: CancellationToken,
    #[cfg(test)]
    completed_signatures: AtomicU64,
    #[cfg(test)]
    ordinary_response_writes: AtomicU64,
    #[cfg(test)]
    sensitive_raw_response_writes: AtomicU64,
    #[cfg(test)]
    execution_delay: Mutex<Option<Duration>>,
    #[cfg(test)]
    execution_starts: AtomicU64,
    #[cfg(test)]
    execution_gate: Mutex<Option<ExecutionGate>>,
    #[cfg(test)]
    panic_next_execution: AtomicBool,
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
        secret_vault: Option<Arc<dyn buzz_secrets::SecretVaultProvider>>,
        secret_audit_path: Option<PathBuf>,
        shutdown: CancellationToken,
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
        // Signing-only startup has no dependency on secret-provider selection
        // or audit storage. Even when secrets are explicitly enabled, a
        // provider/audit failure degrades only SecretLease to stable Internal.
        let secret_broker = if let Some(secret_vault) = secret_vault {
            #[cfg(test)]
            let secret_audit =
                buzz_secrets::SecretAuditStore::open(secret_audit_path.unwrap_or_else(|| {
                    std::env::temp_dir()
                        .join(format!("buzz-secret-audit-test-{}.db", Uuid::new_v4()))
                }))
                .ok();
            #[cfg(not(test))]
            let secret_audit = match secret_audit_path {
                Some(path) => buzz_secrets::SecretAuditStore::open(path),
                None => buzz_secrets::SecretAuditStore::open_default(),
            }
            .ok();
            secret_audit.map(|audit| {
                Arc::new(buzz_secrets::SecretBroker::with_audit(
                    vec![secret_vault],
                    Arc::new(audit),
                ))
            })
        } else {
            None
        };
        Ok(Self {
            keys,
            relay,
            canonical_auth_tag,
            auth_tag,
            auth_conditions,
            expiries,
            secret_broker,
            shutdown,
            #[cfg(test)]
            completed_signatures: AtomicU64::new(0),
            #[cfg(test)]
            ordinary_response_writes: AtomicU64::new(0),
            #[cfg(test)]
            sensitive_raw_response_writes: AtomicU64::new(0),
            #[cfg(test)]
            execution_delay: Mutex::new(None),
            #[cfg(test)]
            execution_starts: AtomicU64::new(0),
            #[cfg(test)]
            execution_gate: Mutex::new(None),
            #[cfg(test)]
            panic_next_execution: AtomicBool::new(false),
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
        #[cfg(test)]
        {
            self.execution_starts.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = lock(&self.execution_gate).clone() {
                let (released, condition) = &*gate;
                let mut released = lock(released);
                while !*released {
                    released = condition
                        .wait(released)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
        }
        #[cfg(test)]
        if self.panic_next_execution.swap(false, Ordering::SeqCst) {
            panic!("injected executor panic");
        }
        #[cfg(test)]
        if let Some(delay) = *lock(&self.execution_delay) {
            std::thread::sleep(delay);
        }
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
            Operation::SecretLease(request) => {
                let secret_broker = Arc::clone(
                    self.secret_broker
                        .as_ref()
                        .ok_or_else(Self::stable_internal)?,
                );
                let expires_at_unix_ms = lock(&self.expiries)
                    .get(&authorized.capability_id())
                    .copied()
                    .ok_or_else(Self::stable_internal)?;
                let lease_deadline_unix_ms = expires_at_unix_ms.min(authorized.deadline_unix_ms());
                let agent_pubkey = self.keys.public_key().to_hex();
                let policy_id = authorized.capability_id().to_string();
                let tool_name = request.tool_name.clone();
                let secret_key = request.secret_key.clone();
                let mut lease = std::thread::spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(buzz_secrets::SecretError::Io)?;
                    runtime.block_on(secret_broker.acquire_lease_until_ms(
                        &policy_id,
                        &agent_pubkey,
                        &tool_name,
                        &secret_key,
                        lease_deadline_unix_ms,
                    ))
                })
                .join()
                .map_err(|_| Self::stable_internal())?
                .map_err(|error| match error {
                    buzz_secrets::SecretError::NotFound(_)
                    | buzz_secrets::SecretError::AccessDenied { .. } => {
                        TrustedExecutionError::new(StableErrorKind::ResourceNotAllowed)
                    }
                    _ => Self::stable_internal(),
                })?;
                let leased_secret_key = lease.secret_key.clone();
                let leased_secret_value = std::mem::take(&mut lease.value);
                Ok(OperationResult::SecretLease {
                    secret_key: leased_secret_key,
                    secret_value: leased_secret_value,
                    expires_at_unix_ms: lease.expires_at.timestamp_millis(),
                })
            }
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
    authority_fence: Mutex<()>,
    execution_fence: Mutex<()>,
    publication_fence: AsyncMutex<()>,
    active_secret_policies: Mutex<HashSet<Uuid>>,
    shutdown_started: AtomicBool,
    #[cfg(test)]
    shutdown_timeout_ms: AtomicU64,
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
    fn is_shutting_down(&self) -> bool {
        self.shutdown_started.load(Ordering::SeqCst)
    }

    fn remove_secret_policy(&self, capability_id: Uuid) -> Result<(), BrokerError> {
        let result = if let Some(secret_broker) = &self.executor.secret_broker {
            secret_broker
                .remove_policy(&capability_id.to_string())
                .map_err(|_| BrokerError::SecretProvider)
        } else {
            Ok(())
        };
        if result.is_ok() {
            lock(&self.active_secret_policies).remove(&capability_id);
        }
        result
    }

    fn remove_all_secret_policies(&self) -> Result<(), BrokerError> {
        let capability_ids: Vec<_> = lock(&self.active_secret_policies).iter().copied().collect();
        let mut cleanup_result = Ok(());
        for capability_id in capability_ids {
            if self.remove_secret_policy(capability_id).is_err() {
                cleanup_result = Err(BrokerError::SecretProvider);
            }
        }
        cleanup_result
    }

    /// Close the authority gate before revoking every projection. This must
    /// not take `execution_fence`: a synchronous provider may be blocked while
    /// holding it, and shutdown still has to cancel that request's transport.
    fn begin_shutdown(&self) -> Result<(), BrokerError> {
        self.shutdown_started.store(true, Ordering::SeqCst);
        self.executor.shutdown.cancel();
        let _authority = lock(&self.authority_fence);
        let capability_ids: Vec<_> = lock(&self.sessions).values().copied().collect();
        let mut cleanup_result = Ok(());
        for capability_id in capability_ids {
            if self
                .registry
                .snapshot(capability_id)
                .is_some_and(|snapshot| snapshot.state != CapabilityState::Revoked)
                && self.registry.revoke(capability_id).is_err()
            {
                cleanup_result = Err(BrokerError::Registry);
            }
        }
        if self.remove_all_secret_policies().is_err() {
            cleanup_result = Err(BrokerError::SecretProvider);
        }
        lock(&self.sessions).clear();
        lock(&self.executor.expiries).clear();
        cleanup_result
    }

    #[cfg(test)]
    fn process_request(&self, request: RequestEnvelope) -> ResponseEnvelope {
        self.process_request_for_publication(request).response
    }

    fn process_request_for_publication(&self, request: RequestEnvelope) -> ProcessedResponse {
        let request_id = request.request_id;
        let capability_id = request.capability_id;
        let deadline_unix_ms = request.deadline_unix_ms;
        if self.is_shutting_down() {
            return ProcessedResponse::unbound(ResponseEnvelope::error(
                request_id,
                StableErrorKind::Internal,
            ));
        }
        // The fence is the execution linearization boundary. Sampling the clock
        // before it would let queued work authorize against stale time.
        let _fence = lock(&self.execution_fence);
        if self.is_shutting_down() {
            return ProcessedResponse::unbound(ResponseEnvelope::error(
                request_id,
                StableErrorKind::Internal,
            ));
        }
        let now = match self.clock.now() {
            Ok(now) => now,
            Err(_) => {
                return ProcessedResponse::unbound(ResponseEnvelope::error(
                    request_id,
                    StableErrorKind::Internal,
                ));
            }
        };
        let (response, authorized) = match self.registry.authorize(request, now) {
            Ok(AuthorizationOutcome::Replay(response)) => (response, true),
            Ok(AuthorizationOutcome::Fresh(permit)) => {
                let mut cleanup = ExecutionCleanupGuard::new(self, capability_id, permit);
                let outcome = self.executor.execute(cleanup.authorized());
                let validation_failure = if self.is_shutting_down() {
                    Some(StableErrorKind::Internal)
                } else {
                    match self.clock.now() {
                        Ok(now) => cleanup
                            .permit()
                            .revalidate(now)
                            .err()
                            .map(|error| error.kind()),
                        Err(_) => Some(StableErrorKind::Internal),
                    }
                };
                let permit = cleanup.take_permit();
                let response = if let Some(kind) = validation_failure {
                    permit.fail(kind)
                } else {
                    match outcome {
                        Ok(result) => permit.complete(result).unwrap_or_else(|error| {
                            ResponseEnvelope::error(request_id, error.kind())
                        }),
                        Err(error) => permit.fail(error.kind()),
                    }
                };
                cleanup.disarm();
                (response, true)
            }
            Err(error) => {
                if error.kind() == StableErrorKind::Internal {
                    let _ = self.remove_all_secret_policies();
                } else if self
                    .registry
                    .snapshot(capability_id)
                    .is_some_and(|snapshot| snapshot.state == CapabilityState::Revoked)
                {
                    let _ = self.remove_secret_policy(capability_id);
                }
                (ResponseEnvelope::error(request_id, error.kind()), false)
            }
        };
        if authorized {
            let Some(snapshot) = self.registry.snapshot(capability_id) else {
                let _ = self.remove_all_secret_policies();
                return ProcessedResponse::unbound(ResponseEnvelope::error(
                    request_id,
                    StableErrorKind::Internal,
                ));
            };
            if snapshot.state == CapabilityState::Revoked
                && self.remove_secret_policy(capability_id).is_err()
            {
                return ProcessedResponse::unbound(ResponseEnvelope::error(
                    request_id,
                    StableErrorKind::Internal,
                ));
            }
        }
        let response = if self.is_shutting_down() {
            ResponseEnvelope::error(request_id, StableErrorKind::Internal)
        } else {
            response
        };
        let authority = response.result().is_some().then_some(PublicationAuthority {
            capability_id,
            request_id,
            deadline_unix_ms,
        });
        ProcessedResponse {
            response,
            authority,
        }
    }

    fn publication_budget(&self, authority: Option<PublicationAuthority>) -> Option<Duration> {
        if self.is_shutting_down() {
            return None;
        }
        let Some(authority) = authority else {
            return Some(WRITE_TIMEOUT);
        };
        // This is the result-publication linearization point. Activation and
        // revocation use this same synchronous fence, while request/capability
        // time is sampled only after the async publication queue is acquired.
        let _fence = lock(&self.execution_fence);
        if self.is_shutting_down() {
            return None;
        }
        let now = self.clock.now().ok()?;
        self.registry
            .revalidate_publication(
                authority.capability_id,
                authority.request_id,
                authority.deadline_unix_ms,
                now,
            )
            .ok()?;
        let remaining_ms =
            u64::try_from(authority.deadline_unix_ms.checked_sub(now.unix_ms)?).ok()?;
        Some(WRITE_TIMEOUT.min(Duration::from_millis(remaining_ms)))
    }
}

#[derive(Clone, Copy)]
struct PublicationAuthority {
    capability_id: Uuid,
    request_id: Uuid,
    deadline_unix_ms: i64,
}

struct ProcessedResponse {
    response: ResponseEnvelope,
    authority: Option<PublicationAuthority>,
}

impl ProcessedResponse {
    fn unbound(response: ResponseEnvelope) -> Self {
        Self {
            response,
            authority: None,
        }
    }
}

struct ExecutionCleanupGuard<'a> {
    state: &'a BrokerState,
    capability_id: Uuid,
    permit: Option<AuthorizationPermit>,
    armed: bool,
}

impl<'a> ExecutionCleanupGuard<'a> {
    fn new(state: &'a BrokerState, capability_id: Uuid, permit: AuthorizationPermit) -> Self {
        Self {
            state,
            capability_id,
            permit: Some(permit),
            armed: true,
        }
    }

    fn authorized(&self) -> &buzz_signing_capability::AuthorizedOperation {
        self.permit().authorized()
    }

    fn permit(&self) -> &AuthorizationPermit {
        self.permit.as_ref().expect("permit is present while armed")
    }

    fn take_permit(&mut self) -> AuthorizationPermit {
        self.permit.take().expect("permit is consumed exactly once")
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ExecutionCleanupGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Permit revocation must happen before policy removal.
            drop(self.permit.take());
            let _ = self.state.remove_secret_policy(self.capability_id);
        }
    }
}

/// Running default-off loopback broker and its trusted control API.
pub struct CapabilityBroker {
    state: Arc<BrokerState>,
    pub address: SocketAddr,
    /// Override for the IP advertised in issued endpoints. When set, the
    /// broker advertises `ws://{advertised_ip}:{port}` instead of
    /// `ws://127.0.0.1:{port}`, allowing Tailscale or other overlay networks
    /// to reach the broker from remote workers without baked-in IP logic.
    pub advertised_ip: Option<std::net::Ipv4Addr>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl fmt::Debug for CapabilityBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityBroker")
            .field("address", &self.address)
            .field("advertised_ip", &self.advertised_ip)
            .finish_non_exhaustive()
    }
}

impl CapabilityBroker {
    /// Construct and start the broker directly from validated configuration.
    ///
    /// When Tailscale is installed and running, the broker automatically
    /// discovers the Tailscale IPv4 address and uses it as the advertised
    /// endpoint IP so that remote workers can reach the broker over the
    /// Tailnet at `ws://100.x.y.z:<port>`. Set `BUZZ_ACP_BROKER_ADVERTISE_IP`
    /// to override auto-discovery.
    pub async fn from_config(
        config: &Config,
        auth_tag_json: Option<&str>,
    ) -> Result<Self, BrokerError> {
        let relay = RelayOrigin::parse(&config.relay_url).map_err(|_| BrokerError::InvalidRelay)?;
        let advertised_ip = config
            .broker_advertise_ip
            .or_else(Self::discover_tailscale_ip);
        let secrets_enabled = !config.broker_allowed_secrets.is_empty()
            && !config.broker_allowed_secret_tools.is_empty();
        let secret_vault = if secrets_enabled {
            // Secret initialization is a best-effort sidecar to signing. A
            // fixed Internal response is safer than taking signing offline.
            buzz_secrets::configured_secret_vault().await.ok()
        } else {
            None
        };
        Self::start_with_vault(
            config.keys.clone(),
            relay,
            auth_tag_json,
            advertised_ip,
            secret_vault,
        )
        .await
    }

    /// Start a broker instance with a custom secret vault provider (useful for testing and pluggable vaults).
    pub async fn start_with_vault(
        keys: Keys,
        relay: RelayOrigin,
        auth_tag_json: Option<&str>,
        advertised_ip: Option<std::net::Ipv4Addr>,
        secret_vault: Option<Arc<dyn buzz_secrets::SecretVaultProvider>>,
    ) -> Result<Self, BrokerError> {
        Self::start_with_vault_and_audit_path(
            keys,
            relay,
            auth_tag_json,
            advertised_ip,
            secret_vault,
            None,
        )
        .await
    }

    async fn start_with_vault_and_audit_path(
        keys: Keys,
        relay: RelayOrigin,
        auth_tag_json: Option<&str>,
        advertised_ip: Option<std::net::Ipv4Addr>,
        secret_vault: Option<Arc<dyn buzz_secrets::SecretVaultProvider>>,
        secret_audit_path: Option<PathBuf>,
    ) -> Result<Self, BrokerError> {
        let bind_addr = advertised_ip.unwrap_or(std::net::Ipv4Addr::LOCALHOST);
        let listener = TcpListener::bind((bind_addr, 0))
            .await
            .map_err(|_| BrokerError::Bind)?;
        let address = listener.local_addr().map_err(|_| BrokerError::Bind)?;
        let expiries = Arc::new(Mutex::new(HashMap::new()));
        let shutdown = CancellationToken::new();
        let executor = ConfigSigningExecutor::new(
            keys,
            relay.clone(),
            auth_tag_json,
            expiries,
            secret_vault,
            secret_audit_path,
            shutdown,
        )?;
        let state = Arc::new(BrokerState {
            registry: CapabilityRegistry::new(),
            executor,
            relay,
            clock: ClockAnchor::new(),
            sessions: Mutex::new(HashMap::new()),
            authority_fence: Mutex::new(()),
            execution_fence: Mutex::new(()),
            publication_fence: AsyncMutex::new(()),
            active_secret_policies: Mutex::new(HashSet::new()),
            shutdown_started: AtomicBool::new(false),
            #[cfg(test)]
            shutdown_timeout_ms: AtomicU64::new(SHUTDOWN_TIMEOUT.as_millis() as u64),
        });
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(run_listener(listener, task_state, shutdown_rx));
        Ok(Self {
            state,
            address,
            advertised_ip,
            shutdown_tx: Some(shutdown_tx),
            task,
        })
    }

    #[cfg(test)]
    async fn start(
        keys: Keys,
        relay: RelayOrigin,
        auth_tag_json: Option<&str>,
        advertised_ip: Option<std::net::Ipv4Addr>,
    ) -> Result<Self, BrokerError> {
        Self::start_with_vault(keys, relay, auth_tag_json, advertised_ip, None).await
    }

    /// Attempt to discover the Tailscale IPv4 address by running
    /// `tailscale ip -4`. Returns `None` when Tailscale is not installed,
    /// not running, or the output is not a valid IPv4 address.
    fn discover_tailscale_ip() -> Option<std::net::Ipv4Addr> {
        let output = std::process::Command::new("tailscale")
            .args(["ip", "-4"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let ip_str = std::str::from_utf8(&output.stdout).ok()?.trim();
        ip_str.parse::<std::net::Ipv4Addr>().ok()
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
        let _authority = lock(&self.state.authority_fence);
        if self.state.is_shutting_down() {
            return Err(BrokerError::Shutdown);
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
            self.state.remove_secret_policy(capability_id)?;
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
        let secret_acl = if scope.allows_operation(OperationKind::SecretLease) {
            let allowed_secrets: Vec<_> = scope.allowed_secrets().map(str::to_string).collect();
            let allowed_tools: Vec<_> = scope.allowed_secret_tools().map(str::to_string).collect();
            if allowed_secrets.is_empty() || allowed_tools.is_empty() {
                return Err(BrokerError::InvalidScope);
            }
            Some((allowed_secrets, allowed_tools))
        } else {
            None
        };
        let issued = self
            .state
            .registry
            .issue(scope, budgets, now, expires_at_unix_ms, lifetime_ms)
            .map_err(|_| BrokerError::InvalidIssuance)?;
        if let Some((allowed_secrets, allowed_tools)) = secret_acl {
            let policy = buzz_secrets::SecretPolicy {
                policy_id: issued.descriptor.capability_id.to_string(),
                agent_pubkey: self.state.executor.keys.public_key().to_hex(),
                allowed_secrets,
                allowed_tools,
                max_lease_ttl_secs: lifetime
                    .as_secs()
                    .clamp(1, buzz_secrets::MAX_SECRET_LEASE_TTL_SECS),
                expires_at: chrono::DateTime::from_timestamp_millis(expires_at_unix_ms)
                    .ok_or(BrokerError::InvalidIssuance)?,
            };
            if self
                .state
                .executor
                .secret_broker
                .as_ref()
                .is_some_and(|secret_broker| secret_broker.set_policy(policy).is_err())
            {
                let _ = self.state.registry.revoke(issued.descriptor.capability_id);
                return Err(BrokerError::SecretProvider);
            }
            if self.state.executor.secret_broker.is_some() {
                lock(&self.state.active_secret_policies).insert(issued.descriptor.capability_id);
            }
        }
        let issued_capability_id = issued.descriptor.capability_id;
        sessions.insert(session_id, issued_capability_id);
        expiries.insert(issued_capability_id, issued.descriptor.expires_at_unix_ms);
        if self.state.is_shutting_down() {
            let _ = self.state.registry.revoke(issued_capability_id);
            let _ = self.state.remove_secret_policy(issued_capability_id);
            sessions.remove(&session_id);
            expiries.remove(&issued_capability_id);
            return Err(BrokerError::Shutdown);
        }
        Ok(SessionCapabilityProjection {
            endpoint: format!(
                "ws://{}:{}",
                self.advertised_ip.unwrap_or(std::net::Ipv4Addr::LOCALHOST),
                self.address.port()
            ),
            descriptor: issued.descriptor,
            token: issued.token,
            connect_timeout_ms: CONNECT_TIMEOUT.as_millis() as u64,
            read_timeout_ms: READ_TIMEOUT.as_millis() as u64,
            write_timeout_ms: WRITE_TIMEOUT.as_millis() as u64,
        })
    }

    /// Activate the previously issued session capability.
    pub(crate) fn activate_session(&self, session_id: Uuid) -> Result<(), BrokerError> {
        let _fence = lock(&self.state.execution_fence);
        let _authority = lock(&self.state.authority_fence);
        if self.state.is_shutting_down() {
            return Err(BrokerError::Shutdown);
        }
        let capability_id = self.capability_for_session(session_id)?;
        let now = self.state.clock.now()?;
        self.state
            .registry
            .activate(capability_id, now)
            .map_err(|_| BrokerError::Registry)
    }

    /// Revoke the session capability, waiting for any already-authorized
    /// synchronous signing operation to settle before returning.
    pub(crate) fn revoke_session(&self, session_id: Uuid) -> Result<(), BrokerError> {
        let _fence = lock(&self.state.execution_fence);
        let _authority = lock(&self.state.authority_fence);
        if self.state.is_shutting_down() {
            return Err(BrokerError::Shutdown);
        }
        let capability_id = self.capability_for_session(session_id)?;
        self.state
            .registry
            .revoke(capability_id)
            .map_err(|_| BrokerError::Registry)?;
        self.state.remove_secret_policy(capability_id)?;
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

    /// Close all authority, cancel connections, and wait for bounded cleanup.
    pub async fn shutdown(mut self) -> Result<(), BrokerError> {
        let authority_cleanup = self.state.begin_shutdown();
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        #[cfg(test)]
        let shutdown_timeout =
            Duration::from_millis(self.state.shutdown_timeout_ms.load(Ordering::SeqCst));
        #[cfg(not(test))]
        let shutdown_timeout = SHUTDOWN_TIMEOUT;
        let listener_cleanup = match timeout(shutdown_timeout, &mut self.task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(BrokerError::Shutdown),
            Err(_) => {
                self.task.abort();
                let _ = (&mut self.task).await;
                Err(BrokerError::Shutdown)
            }
        };
        // A writer that crossed its pre-shutdown check owns this async fence.
        // Draining it after listener termination guarantees no secret bytes can
        // be written after `shutdown` returns, without holding a std lock over
        // an await point.
        let _publication = self.state.publication_fence.lock().await;
        authority_cleanup?;
        listener_cleanup
    }
}

impl Drop for CapabilityBroker {
    fn drop(&mut self) {
        let _ = self.state.begin_shutdown();
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        self.task.abort();
    }
}

fn scope_supported(scope: &CapabilityScope) -> bool {
    let supported = [
        OperationKind::IdentityMetadata,
        OperationKind::NostrEventSign,
        OperationKind::Nip98Sign,
        OperationKind::SecretLease,
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
            _ = &mut shutdown_rx => {
                break;
            },
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else { break };
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

async fn handle_connection(stream: TcpStream, state: Arc<BrokerState>) {
    let mut ws = tokio::select! {
        biased;
        () = state.executor.shutdown.cancelled() => return,
        accepted = accept_async(stream) => match accepted {
            Ok(ws) => ws,
            Err(_) => return,
        },
    };
    let response = tokio::select! {
        biased;
        () = state.executor.shutdown.cancelled() => return,
        request = read_request(&mut ws) => match request {
            Ok(request) => {
                let process_state = Arc::clone(&state);
                match tokio::task::spawn_blocking(move || {
                    process_state.process_request_for_publication(request)
                })
                .await
                {
                    Ok(response) => response,
                    Err(_) => ProcessedResponse::unbound(ResponseEnvelope::error(
                        Uuid::nil(),
                        StableErrorKind::Internal,
                    )),
                }
            }
            Err((request_id, kind)) => {
                ProcessedResponse::unbound(ResponseEnvelope::error(request_id, kind))
            }
        },
    };
    if !state.is_shutting_down() {
        write_response(&mut ws, &state, &response).await;
    }
}

#[derive(Deserialize)]
struct RequestIdProjection {
    request_id: Option<Uuid>,
}

async fn read_request(
    read: &mut (impl StreamExt<Item = Result<tungstenite::Message, tungstenite::Error>> + Unpin),
) -> Result<RequestEnvelope, (Uuid, StableErrorKind)> {
    let msg = timeout(READ_TIMEOUT, read.next())
        .await
        .map_err(|_| (Uuid::nil(), StableErrorKind::DeadlineExpired))?
        .ok_or((Uuid::nil(), StableErrorKind::InvalidPayload))?
        .map_err(|_| (Uuid::nil(), StableErrorKind::InvalidPayload))?;
    let tungstenite::Message::Binary(data) = msg else {
        return Err((Uuid::nil(), StableErrorKind::InvalidPayload));
    };
    if data.len() > MAX_WIRE_REQUEST_BYTES {
        return Err((Uuid::nil(), StableErrorKind::PayloadTooLarge));
    }
    let request_id = serde_json::from_slice::<RequestIdProjection>(&data)
        .ok()
        .and_then(|projection| projection.request_id)
        .unwrap_or_else(Uuid::nil);
    let request: RequestEnvelope =
        serde_json::from_slice(&data).map_err(|_| (request_id, StableErrorKind::InvalidPayload))?;
    match &request.operation {
        Operation::IdentityMetadata
        | Operation::NostrEventSign(_)
        | Operation::Nip98Sign(_)
        | Operation::SecretLease(_) => Ok(request),
        _ => Err((request_id, StableErrorKind::OperationNotAllowed)),
    }
}

async fn write_response(
    ws: &mut tokio_tungstenite::WebSocketStream<TcpStream>,
    state: &BrokerState,
    processed: &ProcessedResponse,
) {
    let _publication = state.publication_fence.lock().await;
    let Some(write_budget) = state.publication_budget(processed.authority) else {
        return;
    };
    let response = &processed.response;
    if matches!(response.result(), Some(OperationResult::SecretLease { .. })) {
        #[cfg(test)]
        state
            .executor
            .sensitive_raw_response_writes
            .fetch_add(1, Ordering::Relaxed);
        let _ = timeout(write_budget, async {
            tokio::select! {
                biased;
                () = state.executor.shutdown.cancelled() => Err(()),
                result = write_sensitive_text_frame(ws, state, response) => result,
            }
        })
        .await;
        return;
    }
    if state.is_shutting_down() {
        return;
    }
    #[cfg(test)]
    state
        .executor
        .ordinary_response_writes
        .fetch_add(1, Ordering::Relaxed);
    let _ = timeout(write_budget, async {
        let bytes = serialize_response_frame(response).map_err(|_| ())?;
        if state.is_shutting_down() {
            return Err(());
        }
        tokio::select! {
            biased;
            () = state.executor.shutdown.cancelled() => Err(()),
            result = ws.send(tungstenite::Message::Binary(bytes)) => result.map_err(|_| ()),
        }
    })
    .await;
}

/// Write a credential-bearing response without admitting its bytes to
/// Tungstenite's ordinary `out_buffer`. The WebSocket handshake and all
/// non-sensitive messages stay on Tungstenite; for a SecretLease success we
/// first flush its non-secret pending writes, then stream the sole zeroizing
/// serialization owner directly to the underlying TCP socket.
async fn write_sensitive_text_frame(
    ws: &mut tokio_tungstenite::WebSocketStream<TcpStream>,
    state: &BrokerState,
    response: &ResponseEnvelope,
) -> Result<(), ()> {
    ws.flush().await.map_err(|_| ())?;
    if state.is_shutting_down() {
        return Err(());
    }
    // Preallocate the entire bounded owner and reject overrun while serde is
    // writing. This prevents Vec growth from leaving deallocated, non-zeroized
    // copies of earlier credential-bearing prefixes in userspace memory.
    let mut payload = Zeroizing::new(Vec::with_capacity(MAX_WIRE_RESPONSE_BYTES));
    if state.is_shutting_down() {
        return Err(());
    }
    {
        let mut bounded = BoundedResponseWriter {
            bytes: &mut payload,
        };
        serde_json::to_writer(&mut bounded, response).map_err(|_| ())?;
    }
    if state.is_shutting_down() {
        return Err(());
    }
    let (header, header_len) = server_text_frame_header(payload.len()).ok_or(())?;
    let stream = ws.get_mut();
    stream
        .write_all(&header[..header_len])
        .await
        .map_err(|_| ())?;
    if state.is_shutting_down() {
        return Err(());
    }
    stream.write_all(&payload).await.map_err(|_| ())?;
    stream.flush().await.map_err(|_| ())
}

struct BoundedResponseWriter<'a> {
    bytes: &'a mut Vec<u8>,
}

impl io::Write for BoundedResponseWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= MAX_WIRE_RESPONSE_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "response exceeds bound"))?;
        debug_assert!(next_len <= self.bytes.capacity());
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn server_text_frame_header(payload_len: usize) -> Option<([u8; 10], usize)> {
    let mut header = [0_u8; 10];
    header[0] = 0x81; // FIN + text; server frames are never masked.
    if payload_len <= 125 {
        header[1] = u8::try_from(payload_len).ok()?;
        Some((header, 2))
    } else if payload_len <= usize::from(u16::MAX) {
        header[1] = 126;
        header[2..4].copy_from_slice(&u16::try_from(payload_len).ok()?.to_be_bytes());
        Some((header, 4))
    } else {
        let encoded = u64::try_from(payload_len).ok()?;
        if encoded >= (1_u64 << 63) {
            return None;
        }
        header[1] = 127;
        header[2..10].copy_from_slice(&encoded.to_be_bytes());
        Some((header, 10))
    }
}

fn serialize_response_frame(
    response: &ResponseEnvelope,
) -> Result<tungstenite::Bytes, serde_json::Error> {
    let mut owner = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *owner, response)?;
    Ok(tungstenite::Bytes::from_owner(owner))
}

fn spawn_overloaded(stream: TcpStream, connections: &mut JoinSet<()>) {
    connections.spawn(async move {
        let ws = match accept_async(stream).await {
            Ok(ws) => ws,
            Err(_) => return,
        };
        let (mut write, _read) = ws.split();
        let Ok(bytes) = serialize_response_frame(&ResponseEnvelope::error(
            Uuid::nil(),
            StableErrorKind::ConcurrencyExceeded,
        )) else {
            return;
        };
        let _ = timeout(
            WRITE_TIMEOUT,
            write.send(tungstenite::Message::Binary(bytes)),
        )
        .await;
    });
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_secrets::SecretVaultProvider as _;
    use buzz_signing_capability::{
        HttpPathRule, Nip98SignRequest, NostrEventSignRequest, ScopeBuilder, StructuredTag,
        PROTOCOL_VERSION,
    };
    use clap::Parser;
    use nostr::Event;

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

    #[test]
    fn secret_lease_wire_shape_is_accepted_without_extra_fields() {
        let request = RequestEnvelope {
            version: PROTOCOL_VERSION,
            capability_id: Uuid::new_v4(),
            token: CapabilityToken::from_secret("t".repeat(32)).expect("token"),
            request_id: Uuid::new_v4(),
            deadline_unix_ms: 1,
            operation: Operation::SecretLease(buzz_signing_capability::SecretLeaseRequest {
                secret_key: "OPENROUTER_API_KEY".into(),
                tool_name: "model_inference".into(),
            }),
        };
        let bytes = serde_json::to_vec(&request).expect("serialize request");
        let decoded: RequestEnvelope = serde_json::from_slice(&bytes).expect("decode request");
        assert_eq!(decoded.request_id, request.request_id);
    }

    #[test]
    fn response_frame_uses_secure_owner_storage() {
        let response = ResponseEnvelope::success(
            Uuid::new_v4(),
            OperationResult::SecretLease {
                secret_key: "secret-id".into(),
                secret_value: "[REDACTED]".into(),
                expires_at_unix_ms: 1,
            },
        );
        let frame = serialize_response_frame(&response).expect("serialize response");
        assert!(serde_json::from_slice::<serde_json::Value>(&frame).is_ok());
        assert!(
            frame.try_into_mut().is_err(),
            "frame must retain its secure owner"
        );
    }

    #[test]
    fn raw_server_text_frame_header_uses_rfc6455_lengths_and_no_mask() {
        let (short, short_len) = server_text_frame_header(125).expect("short header");
        assert_eq!(&short[..short_len], &[0x81, 125]);
        let (medium, medium_len) = server_text_frame_header(126).expect("medium header");
        assert_eq!(&medium[..medium_len], &[0x81, 126, 0, 126]);
        let (large, large_len) = server_text_frame_header(65_536).expect("large header");
        assert_eq!(large_len, 10);
        assert_eq!(&large[..2], &[0x81, 127]);
        assert_eq!(&large[2..], &65_536_u64.to_be_bytes());
    }

    #[tokio::test]
    async fn signing_only_from_config_never_initializes_a_secret_backend() {
        let keys = Keys::generate();
        let args = crate::config::CliArgs::try_parse_from([
            "buzz-acp",
            "--private-key",
            &keys.secret_key().to_secret_hex(),
            "--relay-url",
            RELAY,
        ])
        .expect("config args");
        let config = Config::from_args(args).expect("config");
        assert!(config.broker_allowed_secrets.is_empty());
        assert!(config.broker_allowed_secret_tools.is_empty());

        let broker = CapabilityBroker::from_config(&config, None)
            .await
            .expect("signing-only startup ignores selected/cleared secret-provider state");
        assert!(broker.state.executor.secret_broker.is_none());
        broker.shutdown().await.expect("shutdown");
    }

    async fn broker(auth_tag: Option<&str>) -> (CapabilityBroker, Keys, RelayOrigin) {
        let keys = Keys::generate();
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let broker = CapabilityBroker::start(keys.clone(), relay.clone(), auth_tag, None)
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
        assert!(!spawner.scope.allows_operation(OperationKind::SecretLease));
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

    #[tokio::test]
    async fn explicitly_scoped_process_generation_enables_secret_leases() {
        let keys = Keys::generate();
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let provider = Arc::new(buzz_secrets::InMemorySecretVault::new());
        let broker =
            CapabilityBroker::start_with_vault(keys.clone(), relay, None, None, Some(provider))
                .await
                .expect("start provider-backed broker");
        let args = crate::config::CliArgs::try_parse_from([
            "buzz-acp",
            "--private-key",
            &keys.secret_key().to_secret_hex(),
            "--relay-url",
            RELAY,
            "--broker-allowed-secret",
            "OPENROUTER_API_KEY",
            "--broker-allowed-secret-tool",
            "model_inference",
        ])
        .expect("scoped broker config args");
        let config = Config::from_args(args).expect("scoped broker config");
        let broker = Arc::new(broker);
        let spawner = BrokerChildSpawner::for_channels(
            Arc::clone(&broker),
            &config,
            [Uuid::parse_str(CHANNEL).expect("channel")],
        )
        .expect("scoped process spawner");

        assert!(spawner.scope.allows_operation(OperationKind::SecretLease));
        assert_eq!(
            spawner.scope.allowed_secrets().collect::<Vec<_>>(),
            vec!["OPENROUTER_API_KEY"]
        );
        assert_eq!(
            spawner.scope.allowed_secret_tools().collect::<Vec<_>>(),
            vec!["model_inference"]
        );
        let lease = spawner.issue().expect("issue provider-backed capability");
        let policies = broker
            .state
            .executor
            .secret_broker
            .as_ref()
            .expect("secret broker")
            .policies()
            .await
            .expect("policies");
        let capability_id = broker
            .capability_for_session(lease.session_id)
            .expect("session capability");
        let policy = policies
            .iter()
            .find(|policy| policy.policy_id == capability_id.to_string())
            .expect("capability policy");
        assert_eq!(
            policy.max_lease_ttl_secs,
            buzz_secrets::MAX_SECRET_LEASE_TTL_SECS
        );
        drop(lease);
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
        let (mut stream, _) = tokio_tungstenite::connect_async(endpoint)
            .await
            .expect("connect websocket");
        let bytes = serde_json::to_vec(request).expect("serialize request");
        stream
            .send(tungstenite::Message::Binary(bytes.into()))
            .await
            .expect("write request");
        let msg = stream.next().await.expect("no response").expect("read");
        let response_bytes = match msg {
            tungstenite::Message::Binary(data) => data.to_vec(),
            tungstenite::Message::Text(text) => text.as_bytes().to_vec(),
            _ => panic!("unexpected WS message"),
        };
        serde_json::from_slice(&response_bytes).expect("response")
    }

    async fn send_optional(endpoint: &str, request: &RequestEnvelope) -> Option<ResponseEnvelope> {
        let (mut stream, _) = tokio_tungstenite::connect_async(endpoint).await.ok()?;
        let bytes = serde_json::to_vec(request).ok()?;
        stream
            .send(tungstenite::Message::Binary(bytes.into()))
            .await
            .ok()?;
        let message = stream.next().await?.ok()?;
        let response_bytes = match message {
            tungstenite::Message::Binary(data) => data.to_vec(),
            tungstenite::Message::Text(text) => text.as_bytes().to_vec(),
            _ => return None,
        };
        serde_json::from_slice(&response_bytes).ok()
    }

    #[allow(dead_code)]
    async fn send_raw(endpoint: &str, bytes: &[u8]) -> Vec<u8> {
        let stream = tokio_tungstenite::connect_async(endpoint)
            .await
            .expect("connect websocket");
        let (mut write, mut read) = stream.0.split();
        let owned: Vec<u8> = bytes.to_vec();
        write
            .send(tungstenite::Message::Binary(owned.into()))
            .await
            .expect("write request");
        let msg = read.next().await.expect("no response").expect("read");
        match msg {
            tungstenite::Message::Binary(data) => data.to_vec(),
            tungstenite::Message::Text(text) => text.as_bytes().to_vec(),
            _ => panic!("unexpected WS message"),
        }
    }

    fn signed_event(response: &ResponseEnvelope) -> Event {
        let OperationResult::SignedEvent { event_json } = response.result().expect("result") else {
            panic!("expected signed event")
        };
        serde_json::from_str(event_json).expect("event")
    }

    #[tokio::test]
    async fn secret_lease_uses_policy_broker_and_records_value_free_audit_metadata() {
        let keys = Keys::generate();
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let vault = Arc::new(buzz_secrets::InMemorySecretVault::new());
        vault
            .set_secret("secret-id", "fixture-value", None)
            .await
            .expect("seed secret");
        let broker = CapabilityBroker::start_with_vault(
            keys.clone(),
            relay.clone(),
            None,
            None,
            Some(vault),
        )
        .await
        .expect("start broker");
        let session_id = Uuid::new_v4();
        let lease_scope = ScopeBuilder::new(relay)
            .allow_operation(OperationKind::SecretLease)
            .allow_secret("secret-id")
            .allow_secret_tool("tool-id")
            .build()
            .expect("constrained lease scope");
        let projection = broker
            .issue_session(session_id, lease_scope, budgets(), Duration::from_secs(60))
            .expect("issue session");
        broker
            .activate_session(session_id)
            .expect("activate session");

        let request_id = Uuid::new_v4();
        let lease_request = request(
            &projection,
            request_id,
            Operation::SecretLease(buzz_signing_capability::SecretLeaseRequest {
                secret_key: "secret-id".to_string(),
                tool_name: "tool-id".to_string(),
            }),
        );
        let response = send(&projection.endpoint, &lease_request).await;
        assert_eq!(
            broker
                .state
                .executor
                .ordinary_response_writes
                .load(Ordering::Relaxed),
            0,
            "sensitive success must bypass ordinary Tungstenite send"
        );
        assert_eq!(
            broker
                .state
                .executor
                .sensitive_raw_response_writes
                .load(Ordering::Relaxed),
            1
        );
        let OperationResult::SecretLease {
            secret_key,
            secret_value,
            expires_at_unix_ms,
        } = response.result().expect("lease result")
        else {
            panic!("expected secret lease result")
        };
        assert_eq!(secret_key, "secret-id");
        assert_eq!(secret_value, "fixture-value");
        assert!(*expires_at_unix_ms <= projection.descriptor.expires_at_unix_ms);
        let replay = send(&projection.endpoint, &lease_request).await;
        assert_eq!(
            broker
                .state
                .executor
                .ordinary_response_writes
                .load(Ordering::Relaxed),
            1,
            "non-sensitive errors stay on the ordinary path"
        );
        assert_eq!(
            replay.error_kind(),
            Some(StableErrorKind::SensitiveReplayDenied)
        );
        let policies = broker
            .state
            .executor
            .secret_broker
            .as_ref()
            .expect("secret broker")
            .policies()
            .await
            .expect("policy projection");
        assert_eq!(policies.len(), 1);
        assert_eq!(
            policies[0].policy_id,
            projection.descriptor.capability_id.to_string()
        );
        let active = broker
            .state
            .executor
            .secret_broker
            .as_ref()
            .expect("secret broker")
            .active_leases()
            .await
            .expect("active lease audit");
        assert!(active.iter().any(|lease| {
            lease.secret_key == "secret-id"
                && lease.tool == "tool-id"
                && lease.agent_pubkey == keys.public_key().to_hex()
        }));
        assert!(!serde_json::to_string(&active)
            .expect("serialize metadata")
            .contains("fixture-value"));
        broker.revoke_session(session_id).expect("revoke session");
        assert!(broker
            .state
            .executor
            .secret_broker
            .as_ref()
            .expect("secret broker")
            .policies()
            .await
            .expect("policy projection after revoke")
            .is_empty());
        broker.shutdown().await.expect("shutdown");
    }

    struct SlowSecretVault {
        delay: Duration,
    }

    impl buzz_secrets::SecretVaultProvider for SlowSecretVault {
        fn name(&self) -> &str {
            "slow-test"
        }

        fn get_secret<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _key: &'life1 str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<String, buzz_secrets::SecretError>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                tokio::time::sleep(self.delay).await;
                Ok("slow-fixture-value".to_string())
            })
        }

        fn set_secret<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            _key: &'life1 str,
            _value: &'life2 str,
            _description: Option<&'life3 str>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(), buzz_secrets::SecretError>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { unreachable!("slow test vault is read-only") })
        }

        fn delete_secret<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _key: &'life1 str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(), buzz_secrets::SecretError>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { unreachable!("slow test vault is read-only") })
        }

        fn list_secrets<'life0, 'async_trait>(
            &'life0 self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            Vec<buzz_secrets::SecretMetadata>,
                            buzz_secrets::SecretError,
                        >,
                    > + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { unreachable!("slow test vault does not enumerate") })
        }
    }

    struct BlockingSecretVault {
        entered: Arc<tokio::sync::Semaphore>,
        release: Arc<tokio::sync::Semaphore>,
        finished: Arc<tokio::sync::Semaphore>,
    }

    struct BlockingProviderExit(Arc<tokio::sync::Semaphore>);

    impl Drop for BlockingProviderExit {
        fn drop(&mut self) {
            self.0.add_permits(1);
        }
    }

    impl buzz_secrets::SecretVaultProvider for BlockingSecretVault {
        fn name(&self) -> &str {
            "blocking-test"
        }

        fn get_secret<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _key: &'life1 str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<String, buzz_secrets::SecretError>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                let _exit = BlockingProviderExit(Arc::clone(&self.finished));
                self.entered.add_permits(1);
                self.release
                    .acquire()
                    .await
                    .expect("blocking provider release semaphore remains open")
                    .forget();
                Ok("late-secret-value".to_string())
            })
        }

        fn set_secret<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            _key: &'life1 str,
            _value: &'life2 str,
            _description: Option<&'life3 str>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(), buzz_secrets::SecretError>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { unreachable!("blocking test vault is read-only") })
        }

        fn delete_secret<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _key: &'life1 str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(), buzz_secrets::SecretError>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { unreachable!("blocking test vault is read-only") })
        }

        fn list_secrets<'life0, 'async_trait>(
            &'life0 self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            Vec<buzz_secrets::SecretMetadata>,
                            buzz_secrets::SecretError,
                        >,
                    > + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { unreachable!("blocking test vault does not enumerate") })
        }
    }

    async fn blocking_secret_broker() -> (
        CapabilityBroker,
        SessionCapabilityProjection,
        Arc<tokio::sync::Semaphore>,
        Arc<tokio::sync::Semaphore>,
        Arc<tokio::sync::Semaphore>,
    ) {
        let keys = Keys::generate();
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let finished = Arc::new(tokio::sync::Semaphore::new(0));
        let broker = CapabilityBroker::start_with_vault(
            keys,
            relay.clone(),
            None,
            None,
            Some(Arc::new(BlockingSecretVault {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                finished: Arc::clone(&finished),
            })),
        )
        .await
        .expect("start blocking-provider broker");
        let session_id = Uuid::new_v4();
        let projection = broker
            .issue_session(
                session_id,
                ScopeBuilder::new(relay)
                    .allow_operation(OperationKind::SecretLease)
                    .allow_secret("secret-id")
                    .allow_secret_tool("tool-id")
                    .build()
                    .expect("blocking-provider scope"),
                budgets(),
                Duration::from_secs(60),
            )
            .expect("issue blocking-provider capability");
        broker
            .activate_session(session_id)
            .expect("activate blocking-provider capability");
        (broker, projection, entered, release, finished)
    }

    async fn request_blocking_secret(projection: SessionCapabilityProjection) -> Option<Vec<u8>> {
        let (mut stream, _) = tokio_tungstenite::connect_async(&projection.endpoint)
            .await
            .expect("connect blocking-provider websocket");
        let lease_request = request(
            &projection,
            Uuid::new_v4(),
            Operation::SecretLease(buzz_signing_capability::SecretLeaseRequest {
                secret_key: "secret-id".to_string(),
                tool_name: "tool-id".to_string(),
            }),
        );
        stream
            .send(tungstenite::Message::Binary(
                serde_json::to_vec(&lease_request)
                    .expect("serialize blocking-provider request")
                    .into(),
            ))
            .await
            .expect("send blocking-provider request");
        match stream.next().await {
            Some(Ok(tungstenite::Message::Binary(bytes))) => Some(bytes.to_vec()),
            Some(Ok(tungstenite::Message::Text(text))) => Some(text.as_bytes().to_vec()),
            _ => None,
        }
    }

    fn expect_provider_finished_before_return(finished: &tokio::sync::Semaphore) {
        finished
            .try_acquire()
            .expect("shutdown returned before the provider task finished")
            .forget();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_begin_revokes_authority_and_suppresses_late_secret_response() {
        let (broker, projection, entered, release, finished) = blocking_secret_broker().await;
        let state = Arc::clone(&broker.state);
        let capability_id = projection.descriptor.capability_id;
        let client = tokio::spawn(request_blocking_secret(projection));
        entered
            .acquire()
            .await
            .expect("provider entry semaphore remains open")
            .forget();

        let mut shutdown = tokio::spawn(async move { broker.shutdown().await });
        timeout(Duration::from_millis(250), async {
            loop {
                if state.is_shutting_down()
                    && state
                        .registry
                        .snapshot(capability_id)
                        .is_some_and(|snapshot| snapshot.state == CapabilityState::Revoked)
                    && state
                        .executor
                        .secret_broker
                        .as_ref()
                        .expect("secret broker")
                        .policies()
                        .await
                        .expect("policies while shutdown begins")
                        .is_empty()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown must revoke authority before provider completion");
        assert!(
            timeout(Duration::from_millis(25), &mut shutdown)
                .await
                .is_err(),
            "clean shutdown returned before the provider completed"
        );
        release.add_permits(1);
        timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("shutdown joins provider cleanup")
            .expect("shutdown task")
            .expect("authoritative shutdown");

        assert_eq!(
            state
                .registry
                .snapshot(capability_id)
                .expect("capability snapshot")
                .state,
            CapabilityState::Revoked
        );
        assert!(lock(&state.sessions).is_empty());
        assert!(state
            .executor
            .secret_broker
            .as_ref()
            .expect("secret broker")
            .policies()
            .await
            .expect("policies after shutdown begin")
            .is_empty());
        let client_result = timeout(Duration::from_millis(250), client)
            .await
            .expect("connection task terminates during shutdown")
            .expect("client task");
        assert!(
            client_result.is_none(),
            "shutdown must close without a response"
        );

        expect_provider_finished_before_return(&finished);
        assert_eq!(
            state
                .executor
                .sensitive_raw_response_writes
                .load(Ordering::SeqCst),
            0,
            "a provider result completed after shutdown must never reach the transport"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_closes_authority_before_a_blocked_provider_can_finish() {
        let (broker, projection, entered, release, finished) = blocking_secret_broker().await;
        let state = Arc::clone(&broker.state);
        let capability_id = projection.descriptor.capability_id;
        let client = tokio::spawn(request_blocking_secret(projection));
        entered
            .acquire()
            .await
            .expect("provider entry semaphore remains open")
            .forget();

        drop(broker);
        let client_result = timeout(Duration::from_millis(250), client)
            .await
            .expect("drop must terminate the active connection")
            .expect("client task");
        release.add_permits(1);
        timeout(Duration::from_secs(1), finished.acquire())
            .await
            .expect("dropped broker leaves no provider task after provider I/O returns")
            .expect("provider finish semaphore remains open")
            .forget();

        assert!(client_result.is_none(), "drop published a secret response");
        assert!(
            state.is_shutting_down(),
            "drop must close the authority gate"
        );
        assert_eq!(
            state
                .registry
                .snapshot(capability_id)
                .expect("revoked capability remains auditable")
                .state,
            CapabilityState::Revoked
        );
        assert!(lock(&state.sessions).is_empty());
        assert!(lock(&state.active_secret_policies).is_empty());
        assert_eq!(
            state
                .executor
                .sensitive_raw_response_writes
                .load(Ordering::SeqCst),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_timeout_aborts_listener_and_cannot_publish_after_return() {
        let (broker, projection, entered, release, finished) = blocking_secret_broker().await;
        let state = Arc::clone(&broker.state);
        let capability_id = projection.descriptor.capability_id;
        state.shutdown_timeout_ms.store(50, Ordering::SeqCst);
        let client = tokio::spawn(request_blocking_secret(projection));
        entered
            .acquire()
            .await
            .expect("provider entry semaphore remains open")
            .forget();

        let shutdown_result = broker.shutdown().await;
        let received_secret = timeout(Duration::from_millis(250), client)
            .await
            .expect("listener abort must terminate the connection task")
            .expect("client task must join");
        assert!(
            received_secret.is_none(),
            "timeout cleanup published a secret response"
        );

        assert!(
            finished.try_acquire().is_err(),
            "forced timeout should return while the non-cancelable provider is still blocked"
        );
        release.add_permits(1);
        timeout(Duration::from_secs(1), finished.acquire())
            .await
            .expect("provider finishes after timeout return")
            .expect("provider finish semaphore remains open")
            .forget();

        assert!(
            matches!(shutdown_result, Err(BrokerError::Shutdown)),
            "the forced listener timeout must remain observable"
        );
        assert!(
            state.is_shutting_down(),
            "timeout cannot reopen broker authority"
        );
        assert_eq!(
            state
                .registry
                .snapshot(capability_id)
                .expect("revoked capability remains auditable")
                .state,
            CapabilityState::Revoked
        );
        assert!(lock(&state.active_secret_policies).is_empty());

        assert_eq!(
            state
                .executor
                .sensitive_raw_response_writes
                .load(Ordering::SeqCst),
            0,
            "the detached provider result must not publish after timeout return"
        );
    }

    #[tokio::test]
    async fn slow_secret_provider_cannot_fulfill_after_request_deadline() {
        let keys = Keys::generate();
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let broker = CapabilityBroker::start_with_vault(
            keys,
            relay.clone(),
            None,
            None,
            Some(Arc::new(SlowSecretVault {
                delay: Duration::from_millis(75),
            })),
        )
        .await
        .expect("start broker");
        let session_id = Uuid::new_v4();
        let lease_scope = ScopeBuilder::new(relay)
            .allow_operation(OperationKind::SecretLease)
            .allow_secret("secret-id")
            .allow_secret_tool("tool-id")
            .build()
            .expect("constrained lease scope");
        let projection = broker
            .issue_session(session_id, lease_scope, budgets(), Duration::from_secs(60))
            .expect("issue session");
        broker
            .activate_session(session_id)
            .expect("activate session");

        let mut lease_request = request(
            &projection,
            Uuid::new_v4(),
            Operation::SecretLease(buzz_signing_capability::SecretLeaseRequest {
                secret_key: "secret-id".to_string(),
                tool_name: "tool-id".to_string(),
            }),
        );
        let request_deadline = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis();
        lease_request.deadline_unix_ms = i64::try_from(request_deadline).expect("clock range") + 20;
        let response = broker.state.process_request(lease_request);

        assert_eq!(
            response.error_kind(),
            Some(StableErrorKind::DeadlineExpired),
            "post-provider enforcement must reject a secret resolved after the request deadline"
        );
        broker.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn authorization_expiry_removes_capability_secret_policy() {
        let keys = Keys::generate();
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let broker = CapabilityBroker::start_with_vault(
            keys.clone(),
            relay.clone(),
            None,
            None,
            Some(Arc::new(buzz_secrets::InMemorySecretVault::new())),
        )
        .await
        .expect("start broker");
        let session_id = Uuid::new_v4();
        let lease_scope = ScopeBuilder::new(relay)
            .allow_operation(OperationKind::SecretLease)
            .allow_secret("secret-id")
            .allow_secret_tool("tool-id")
            .build()
            .expect("constrained lease scope");
        let projection = broker
            .issue_session(session_id, lease_scope, budgets(), Duration::from_secs(1))
            .expect("issue session");
        broker
            .activate_session(session_id)
            .expect("activate session");

        broker
            .state
            .executor
            .secret_broker
            .as_ref()
            .expect("secret broker")
            .set_policy(buzz_secrets::SecretPolicy {
                policy_id: projection.descriptor.capability_id.to_string(),
                agent_pubkey: keys.public_key().to_hex(),
                allowed_secrets: vec!["secret-id".into()],
                allowed_tools: vec!["tool-id".into()],
                max_lease_ttl_secs: 60,
                expires_at: chrono::Utc::now() + chrono::Duration::seconds(60),
            })
            .expect("extend policy beyond capability monotonic deadline");
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let response = broker.state.process_request(request(
            &projection,
            Uuid::new_v4(),
            Operation::SecretLease(buzz_signing_capability::SecretLeaseRequest {
                secret_key: "secret-id".into(),
                tool_name: "tool-id".into(),
            }),
        ));
        assert_eq!(response.error_kind(), Some(StableErrorKind::Expired));
        assert!(broker
            .state
            .executor
            .secret_broker
            .as_ref()
            .expect("secret broker")
            .policies()
            .await
            .expect("policy projection after authorization expiry")
            .is_empty());
        broker.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn signed_event_is_valid_and_injects_only_canonical_auth_tag() {
        let owner = Keys::generate();
        let agent = Keys::generate();
        let auth = buzz_sdk::nip_oa::compute_auth_tag(&owner, &agent.public_key(), "kind=9")
            .expect("auth tag");
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let broker = CapabilityBroker::start(agent.clone(), relay.clone(), Some(&auth), None)
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
        let broker = CapabilityBroker::start(agent.clone(), relay.clone(), Some(&auth), None)
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
    async fn audit_initialization_failure_keeps_signing_available_and_secret_stable_internal() {
        let keys = Keys::generate();
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let audit_directory = tempfile::tempdir().expect("audit directory");
        let broker = CapabilityBroker::start_with_vault_and_audit_path(
            keys,
            relay.clone(),
            None,
            None,
            Some(Arc::new(buzz_secrets::InMemorySecretVault::new())),
            Some(audit_directory.path().to_path_buf()),
        )
        .await
        .expect("signing broker starts despite audit failure");
        assert!(broker.state.executor.secret_broker.is_none());

        let signing_session = Uuid::new_v4();
        let signing = broker
            .issue_session(
                signing_session,
                ScopeBuilder::new(relay.clone())
                    .allow_operation(OperationKind::IdentityMetadata)
                    .build()
                    .expect("signing scope"),
                budgets(),
                Duration::from_secs(60),
            )
            .expect("issue signing");
        broker
            .activate_session(signing_session)
            .expect("activate signing");
        assert!(broker
            .state
            .process_request(request(
                &signing,
                Uuid::new_v4(),
                Operation::IdentityMetadata,
            ))
            .result()
            .is_some());

        let secret_session = Uuid::new_v4();
        let secret = broker
            .issue_session(
                secret_session,
                ScopeBuilder::new(relay)
                    .allow_operation(OperationKind::SecretLease)
                    .allow_secret("secret-id")
                    .allow_secret_tool("tool-id")
                    .build()
                    .expect("secret scope"),
                budgets(),
                Duration::from_secs(60),
            )
            .expect("secret capability can still be issued");
        broker
            .activate_session(secret_session)
            .expect("activate secret");
        assert_eq!(
            broker
                .state
                .process_request(request(
                    &secret,
                    Uuid::new_v4(),
                    Operation::SecretLease(buzz_signing_capability::SecretLeaseRequest {
                        secret_key: "secret-id".to_string(),
                        tool_name: "tool-id".to_string(),
                    }),
                ))
                .error_kind(),
            Some(StableErrorKind::Internal)
        );
        broker.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn executor_panic_revokes_permit_then_removes_secret_policy() {
        let keys = Keys::generate();
        let relay = RelayOrigin::parse(RELAY).expect("relay");
        let broker = CapabilityBroker::start_with_vault(
            keys,
            relay.clone(),
            None,
            None,
            Some(Arc::new(buzz_secrets::InMemorySecretVault::new())),
        )
        .await
        .expect("start broker");
        let session_id = Uuid::new_v4();
        let projection = broker
            .issue_session(
                session_id,
                ScopeBuilder::new(relay)
                    .allow_operation(OperationKind::SecretLease)
                    .allow_secret("secret-id")
                    .allow_secret_tool("tool-id")
                    .build()
                    .expect("scope"),
                budgets(),
                Duration::from_secs(60),
            )
            .expect("issue");
        broker.activate_session(session_id).expect("activate");
        broker
            .state
            .executor
            .panic_next_execution
            .store(true, Ordering::SeqCst);
        let lease_request = request(
            &projection,
            Uuid::new_v4(),
            Operation::SecretLease(buzz_signing_capability::SecretLeaseRequest {
                secret_key: "secret-id".to_string(),
                tool_name: "tool-id".to_string(),
            }),
        );

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            broker.state.process_request(lease_request)
        }));
        assert!(panic.is_err());
        assert_eq!(
            broker
                .state
                .registry
                .snapshot(projection.descriptor.capability_id)
                .expect("snapshot")
                .state,
            CapabilityState::Revoked
        );
        assert!(broker
            .state
            .executor
            .secret_broker
            .as_ref()
            .expect("secret broker")
            .policies()
            .await
            .expect("policies")
            .is_empty());
        broker.shutdown().await.expect("shutdown");
    }

    async fn wait_for_execution_start(broker: &CapabilityBroker, previous_count: u64) {
        timeout(Duration::from_secs(3), async {
            while broker
                .state
                .executor
                .execution_starts
                .load(Ordering::SeqCst)
                == previous_count
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("executor entered before deadline");
    }

    fn release_execution_gate(gate: &ExecutionGate) {
        *lock(&gate.0) = true;
        gate.1.notify_all();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_success_is_revalidated_at_publication_after_deadline_or_revocation() {
        let (broker, _, relay) = broker(None).await;
        let session_id = Uuid::new_v4();
        let projection = broker
            .issue_session(
                session_id,
                scope(&relay),
                budgets(),
                Duration::from_secs(60),
            )
            .expect("issue publication test session");
        broker
            .activate_session(session_id)
            .expect("activate publication test session");

        let publication = broker.state.publication_fence.lock().await;
        let mut expiring_request =
            request(&projection, Uuid::new_v4(), Operation::IdentityMetadata);
        expiring_request.deadline_unix_ms = broker.state.clock.now().expect("clock").unix_ms + 250;
        let execution_count = broker
            .state
            .executor
            .execution_starts
            .load(Ordering::SeqCst);
        let endpoint = projection.endpoint.clone();
        let deadline_client =
            tokio::spawn(async move { send_optional(&endpoint, &expiring_request).await });
        wait_for_execution_start(&broker, execution_count).await;
        let execution_state = Arc::clone(&broker.state);
        tokio::task::spawn_blocking(move || drop(lock(&execution_state.execution_fence)))
            .await
            .expect("execution fence synchronization");
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(publication);
        assert!(
            timeout(Duration::from_secs(1), deadline_client)
                .await
                .expect("expired publication connection closes")
                .expect("deadline client task")
                .is_none(),
            "a completed result queued past its request deadline must not publish"
        );
        assert_eq!(
            broker
                .state
                .executor
                .ordinary_response_writes
                .load(Ordering::SeqCst),
            0
        );

        let publication = broker.state.publication_fence.lock().await;
        let revocable_request = request(&projection, Uuid::new_v4(), Operation::IdentityMetadata);
        let execution_count = broker
            .state
            .executor
            .execution_starts
            .load(Ordering::SeqCst);
        let endpoint = projection.endpoint.clone();
        let revoked_client =
            tokio::spawn(async move { send_optional(&endpoint, &revocable_request).await });
        wait_for_execution_start(&broker, execution_count).await;
        let execution_state = Arc::clone(&broker.state);
        tokio::task::spawn_blocking(move || drop(lock(&execution_state.execution_fence)))
            .await
            .expect("execution fence synchronization");
        broker
            .revoke_session(session_id)
            .expect("revoke while result waits to publish");
        drop(publication);
        assert!(
            timeout(Duration::from_secs(1), revoked_client)
                .await
                .expect("revoked publication connection closes")
                .expect("revoked client task")
                .is_none(),
            "a completed result revoked while queued must not publish"
        );
        assert_eq!(
            broker
                .state
                .executor
                .ordinary_response_writes
                .load(Ordering::SeqCst),
            0
        );
        broker.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn slow_signing_result_is_not_published_after_request_or_capability_expiry() {
        let (broker, _, relay) = broker(None).await;

        let request_session = Uuid::new_v4();
        let request_projection = broker
            .issue_session(
                request_session,
                scope(&relay),
                budgets(),
                Duration::from_secs(60),
            )
            .expect("issue request-deadline session");
        broker
            .activate_session(request_session)
            .expect("activate request-deadline session");
        let mut slow_request = request(
            &request_projection,
            Uuid::new_v4(),
            Operation::NostrEventSign(NostrEventSignRequest {
                relay: relay.clone(),
                kind: 9,
                content: "slow-request".into(),
                tags: vec![StructuredTag(vec!["h".into(), CHANNEL.into()])],
                requested_created_at: None,
            }),
        );
        slow_request.deadline_unix_ms = broker.state.clock.now().expect("clock").unix_ms + 1_000;
        let request_gate = Arc::new((Mutex::new(false), Condvar::new()));
        *lock(&broker.state.executor.execution_gate) = Some(Arc::clone(&request_gate));
        let execution_count = broker
            .state
            .executor
            .execution_starts
            .load(Ordering::SeqCst);
        let request_endpoint = request_projection.endpoint.clone();
        let request_task =
            tokio::spawn(async move { send(&request_endpoint, &slow_request).await });
        wait_for_execution_start(&broker, execution_count).await;
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        release_execution_gate(&request_gate);
        assert_eq!(
            request_task
                .await
                .expect("request-deadline task")
                .error_kind(),
            Some(StableErrorKind::DeadlineExpired)
        );

        let capability_session = Uuid::new_v4();
        let capability_projection = broker
            .issue_session(
                capability_session,
                scope(&relay),
                budgets(),
                Duration::from_millis(1_000),
            )
            .expect("issue capability-deadline session");
        broker
            .activate_session(capability_session)
            .expect("activate capability-deadline session");
        let slow_capability = request(
            &capability_projection,
            Uuid::new_v4(),
            Operation::NostrEventSign(NostrEventSignRequest {
                relay,
                kind: 9,
                content: "slow-capability".into(),
                tags: vec![StructuredTag(vec!["h".into(), CHANNEL.into()])],
                requested_created_at: None,
            }),
        );
        let capability_gate = Arc::new((Mutex::new(false), Condvar::new()));
        *lock(&broker.state.executor.execution_gate) = Some(Arc::clone(&capability_gate));
        let execution_count = broker
            .state
            .executor
            .execution_starts
            .load(Ordering::SeqCst);
        let capability_endpoint = capability_projection.endpoint.clone();
        let capability_task =
            tokio::spawn(async move { send(&capability_endpoint, &slow_capability).await });
        wait_for_execution_start(&broker, execution_count).await;
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        release_execution_gate(&capability_gate);
        *lock(&broker.state.executor.execution_gate) = None;
        assert_eq!(
            capability_task
                .await
                .expect("capability-deadline task")
                .error_kind(),
            Some(StableErrorKind::Expired)
        );
        assert_eq!(
            broker.completed_signature_count(),
            2,
            "executors completed both signatures but neither became a success response"
        );
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
        let endpoint = &projection.endpoint;

        let valid_request = request(
            &projection,
            Uuid::new_v4(),
            Operation::NostrEventSign(NostrEventSignRequest {
                relay: RelayOrigin::parse(RELAY).expect("relay"),
                kind: 9,
                content: "safe".into(),
                tags: vec![StructuredTag(vec!["h".into(), CHANNEL.into()])],
                requested_created_at: None,
            }),
        );
        let serialized_valid_request =
            serde_json::to_vec(&valid_request).expect("serialize valid request");
        serde_json::from_slice::<RequestEnvelope>(&serialized_valid_request)
            .unwrap_or_else(|error| panic!("typed request round-trip failed: {error}"));
        let response = send(endpoint, &valid_request).await;
        assert_eq!(response.error_kind(), None);
        assert!(signed_event(&response).verify().is_ok());

        let valid_json =
            String::from_utf8(serde_json::to_vec(&valid_request).expect("serialize valid request"))
                .expect("request UTF-8");
        let unknown_field =
            valid_json.replacen("\"version\":1", "\"version\":1,\"unexpected\":true", 1);
        let unknown_response: ResponseEnvelope =
            serde_json::from_slice(&send_raw(endpoint, unknown_field.as_bytes()).await)
                .expect("unknown-field response");
        assert_eq!(
            unknown_response.error_kind(),
            Some(StableErrorKind::InvalidPayload)
        );

        let unknown_payload_field = valid_json.replacen(
            "\"requested_created_at\":null}",
            "\"requested_created_at\":null,\"unexpected_payload\":true}",
            1,
        );
        let unknown_payload_response: ResponseEnvelope =
            serde_json::from_slice(&send_raw(endpoint, unknown_payload_field.as_bytes()).await)
                .expect("unknown-payload-field response");
        assert_eq!(
            unknown_payload_response.error_kind(),
            Some(StableErrorKind::InvalidPayload)
        );

        let malformed_response: ResponseEnvelope =
            serde_json::from_slice(&send_raw(endpoint, b"{not-json").await)
                .expect("malformed response");
        assert_eq!(
            malformed_response.error_kind(),
            Some(StableErrorKind::InvalidPayload)
        );

        let oversized = vec![b'x'; MAX_WIRE_REQUEST_BYTES + 1];
        let oversized_response: ResponseEnvelope =
            serde_json::from_slice(&send_raw(endpoint, &oversized).await)
                .expect("oversized response");
        assert_eq!(
            oversized_response.error_kind(),
            Some(StableErrorKind::PayloadTooLarge)
        );
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
        broker.shutdown().await.expect("shutdown");
        assert!(tokio_tungstenite::connect_async(&projection.endpoint)
            .await
            .is_err());
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
