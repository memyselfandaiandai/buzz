use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    CapabilityScope, CapabilityToken, Operation, OperationKind, ProtocolError, ResponseEnvelope,
    StableErrorKind,
};

/// Hard upper bound for a capability lifetime: two hours and fifteen minutes.
pub const MAX_CAPABILITY_LIFETIME_MS: u64 = 8_100_000;

/// Hard upper bound for fresh operations authorized by one capability.
pub const MAX_CAPABILITY_OPERATIONS: u32 = 4_096;
/// Hard upper bound for cumulative canonical request bytes per capability.
pub const MAX_CAPABILITY_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;
/// Hard upper bound for simultaneous authorization permits per capability.
pub const MAX_CAPABILITY_IN_FLIGHT: u16 = 64;
/// Hard upper bound for exact retries of any one completed request.
pub const MAX_REPLAYS_PER_REQUEST: u16 = 16;
/// Hard upper bound for retained capability records in one registry.
pub const MAX_REGISTRY_CAPABILITIES: usize = 4_096;
/// Hard upper bound for pending reservations and cached response bytes.
pub const MAX_REGISTRY_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const DIGEST_DOMAIN: &[u8] = b"buzz-signing-capability/request/v1\0";

/// Trusted wall-clock and monotonic-style readings supplied by the future broker.
///
/// `monotonic_ms` is elapsed time from a broker-owned process-local epoch. The
/// registry rejects backwards movement and requires both expiry bounds to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockReading {
    /// Unix epoch milliseconds.
    pub unix_ms: i64,
    /// Milliseconds elapsed from a stable, broker-owned monotonic epoch.
    pub monotonic_ms: u64,
}

/// Bounded authorization budgets for one capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLimits {
    /// Maximum number of fresh authorized operations.
    pub max_operations: u32,
    /// Maximum cumulative canonical payload bytes for fresh operations.
    pub max_payload_bytes: u64,
    /// Maximum simultaneously outstanding authorizations.
    pub max_in_flight: u16,
    /// Maximum exact retries of one completed request.
    pub max_replays_per_request: u16,
}

impl BudgetLimits {
    /// Validate that all budgets are non-zero and within protocol hard limits.
    pub fn validate(self) -> Result<Self, IssueError> {
        if self.max_operations == 0
            || self.max_payload_bytes == 0
            || self.max_in_flight == 0
            || self.max_replays_per_request == 0
            || self.max_operations > MAX_CAPABILITY_OPERATIONS
            || self.max_payload_bytes > MAX_CAPABILITY_PAYLOAD_BYTES
            || self.max_in_flight > MAX_CAPABILITY_IN_FLIGHT
            || self.max_replays_per_request > MAX_REPLAYS_PER_REQUEST
        {
            return Err(IssueError::InvalidBudget);
        }
        Ok(self)
    }
}

/// Public capability lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// Issued but not yet activated by trusted control flow.
    Inactive,
    /// Available for authorization.
    Active,
    /// Permanently revoked.
    Revoked,
}

/// Returns true only for the CGNAT `100.64.0.0/10` Tailscale carrier behind `100.x`.
pub fn is_tailscale_ipv4(addr: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = addr.octets();
    a == 100 && b >= 64 && b <= 127
}

/// Returns true only for `tcp://100.x.y.z:<port>` — no DNS, no private LAN, no loopback.
pub fn is_tailscale_endpoint(value: &str) -> bool {
    let url = match url::Url::parse(value) {
        Ok(url) => url,
        Err(_) => return false,
    };
    if url.scheme() != "tcp"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().is_empty()
    {
        return false;
    }
    let host = match url.host_str() {
        Some(host) => host,
        None => return false,
    };
    let port = match url.port().filter(|p| *p != 0) {
        Some(port) => port,
        None => return false,
    };
    let addr: std::net::Ipv4Addr = match host.parse() {
        Ok(addr) => addr,
        Err(_) => return false,
    };
    if !is_tailscale_ipv4(addr) {
        return false;
    }
    value == format!("tcp://{addr}:{port}")
}

/// Non-secret capability metadata safe to expose to a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDescriptor {
    /// Opaque identifier.
    pub capability_id: Uuid,
    /// Capability scope.
    pub scope: CapabilityScope,
    /// Absolute expiry.
    pub expires_at_unix_ms: i64,
    /// Configured budgets.
    pub budgets: BudgetLimits,
    /// Unix-millis at which the capability was durably revoked, if any (reused by `capability_revocation` / `replay_ledger`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix_ms: Option<i64>,
}

/// Newly issued descriptor plus the only copy of its raw bearer token returned by the registry.
pub struct IssuedCapability {
    /// Non-secret descriptor.
    pub descriptor: CapabilityDescriptor,
    /// Secret token. `Debug` always redacts it.
    pub token: CapabilityToken,
}

impl fmt::Debug for IssuedCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedCapability")
            .field("descriptor", &self.descriptor)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Non-sensitive issuance failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IssueError {
    /// The absolute or monotonic lifetime is empty, inconsistent, or too large.
    #[error("capability lifetime is invalid")]
    InvalidLifetime,
    /// At least one budget is zero.
    #[error("capability budget is invalid")]
    InvalidBudget,
    /// The supplied scope is invalid.
    #[error("capability scope is invalid")]
    InvalidScope,
    /// Integer arithmetic overflowed.
    #[error("capability time bound overflowed")]
    TimeOverflow,
    /// The registry is at its hard capability or replay-cache bound.
    #[error("capability registry capacity is exhausted")]
    RegistryCapacityExceeded,
    /// A panic poisoned registry state; all existing capabilities were revoked.
    #[error("capability registry state is poisoned")]
    RegistryPoisoned,
}

/// Snapshot of one capability's non-secret state and budget counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrySnapshot {
    /// Lifecycle state.
    pub state: CapabilityState,
    /// Fresh operations authorized so far.
    pub used_operations: u32,
    /// Canonical fresh-operation bytes authorized so far.
    pub used_payload_bytes: u64,
    /// Currently outstanding authorization permits.
    pub in_flight: u16,
    /// Number of replay-ledger entries.
    pub replay_entries: usize,
}

/// In-memory, linearized capability registry for a future trusted broker.
#[derive(Clone)]
pub struct CapabilityRegistry {
    inner: Arc<Mutex<RegistryState>>,
}

impl fmt::Debug for CapabilityRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let capability_count = self
            .inner
            .lock()
            .map_or(0, |state| state.capabilities.len());
        formatter
            .debug_struct("CapabilityRegistry")
            .field("capability_count", &capability_count)
            .finish()
    }
}

#[derive(Default)]
struct RegistryState {
    capabilities: HashMap<Uuid, CapabilityRecord>,
    response_ledger_bytes: usize,
}

struct CapabilityRecord {
    descriptor: CapabilityDescriptor,
    token_hash: [u8; 32],
    state: CapabilityState,
    expires_at_monotonic_ms: u64,
    last_monotonic_ms: u64,
    used_operations: u32,
    used_payload_bytes: u64,
    in_flight: u16,
    replay: HashMap<Uuid, ReplayEntry>,
}

impl fmt::Debug for CapabilityRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityRecord")
            .field("descriptor", &self.descriptor)
            .field("token_hash", &"[REDACTED]")
            .field("state", &self.state)
            .field("expires_at_monotonic_ms", &self.expires_at_monotonic_ms)
            .field("last_monotonic_ms", &self.last_monotonic_ms)
            .field("used_operations", &self.used_operations)
            .field("used_payload_bytes", &self.used_payload_bytes)
            .field("in_flight", &self.in_flight)
            .field("replay_entries", &self.replay.len())
            .finish()
    }
}

enum ReplayEntry {
    Pending {
        payload_digest: [u8; 32],
    },
    Complete {
        payload_digest: [u8; 32],
        response: ResponseEnvelope,
        response_bytes: usize,
        replay_count: u16,
    },
}

impl CapabilityRegistry {
    /// Create an empty in-memory registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RegistryState::default())),
        }
    }

    /// Issue an inactive capability and return its one raw bearer token.
    ///
    /// Both `expires_at_unix_ms` and `lifetime_ms` are authoritative. A request
    /// expires when either its wall-clock or monotonic-style bound elapses.
    pub fn issue(
        &self,
        scope: CapabilityScope,
        budgets: BudgetLimits,
        now: ClockReading,
        expires_at_unix_ms: i64,
        lifetime_ms: u64,
    ) -> Result<IssuedCapability, IssueError> {
        scope.validate().map_err(|_| IssueError::InvalidScope)?;
        let budgets = budgets.validate()?;
        let wall_lifetime = expires_at_unix_ms
            .checked_sub(now.unix_ms)
            .ok_or(IssueError::TimeOverflow)?;
        if lifetime_ms == 0
            || lifetime_ms > MAX_CAPABILITY_LIFETIME_MS
            || wall_lifetime <= 0
            || u64::try_from(wall_lifetime).map_or(true, |value| value > MAX_CAPABILITY_LIFETIME_MS)
        {
            return Err(IssueError::InvalidLifetime);
        }
        let expires_at_monotonic_ms = now
            .monotonic_ms
            .checked_add(lifetime_ms)
            .ok_or(IssueError::TimeOverflow)?;
        let capability_id = Uuid::new_v4();
        let token = CapabilityToken::generate();
        let descriptor = CapabilityDescriptor {
            capability_id,
            scope,
            expires_at_unix_ms,
            budgets,
            revoked_at_unix_ms: None,
        };
        let record = CapabilityRecord {
            descriptor: descriptor.clone(),
            token_hash: token_hash(&token),
            state: CapabilityState::Inactive,
            expires_at_monotonic_ms,
            last_monotonic_ms: now.monotonic_ms,
            used_operations: 0,
            used_payload_bytes: 0,
            in_flight: 0,
            replay: HashMap::new(),
        };
        let mut state = try_lock_registry(&self.inner).map_err(|_| IssueError::RegistryPoisoned)?;
        prune_inactive_records(&mut state, now);
        if state.capabilities.len() >= MAX_REGISTRY_CAPABILITIES {
            return Err(IssueError::RegistryCapacityExceeded);
        }
        state.capabilities.insert(capability_id, record);
        Ok(IssuedCapability { descriptor, token })
    }

    /// Activate an issued capability through trusted broker control flow.
    pub fn activate(&self, capability_id: Uuid, now: ClockReading) -> Result<(), ProtocolError> {
        let mut state = try_lock_registry(&self.inner)
            .map_err(|_| ProtocolError::new(StableErrorKind::Internal))?;
        let record = state
            .capabilities
            .get_mut(&capability_id)
            .ok_or_else(|| ProtocolError::new(StableErrorKind::UnknownCapability))?;
        check_clock_and_expiry(record, now)?;
        match record.state {
            CapabilityState::Inactive => {
                record.state = CapabilityState::Active;
                Ok(())
            }
            CapabilityState::Active => Ok(()),
            CapabilityState::Revoked => Err(ProtocolError::new(StableErrorKind::Revoked)),
        }
    }

    /// Permanently revoke a capability.
    ///
    /// Durable reuse: store `revoked_at_unix_ms` equals `now.unix_ms` on the
    /// d...[truncated]
    pub fn revoke(&self, capability_id: Uuid) -> Result<(), ProtocolError> {
        let mut state = try_lock_registry(&self.inner)
            .map_err(|_| ProtocolError::new(StableErrorKind::Internal))?;
        let record = state
            .capabilities
            .get_mut(&capability_id)
            .ok_or_else(|| ProtocolError::new(StableErrorKind::UnknownCapability))?;
        record.state = CapabilityState::Revoked;
        Ok(())
    }

    /// Authorize a fresh structured operation or return an exact cached replay.
    pub fn authorize(
        &self,
        request: crate::RequestEnvelope,
        now: ClockReading,
    ) -> Result<AuthorizationOutcome, ProtocolError> {
        if request.version != crate::PROTOCOL_VERSION {
            return Err(ProtocolError::new(StableErrorKind::UnsupportedVersion));
        }
        let operation_bytes = request.operation.serialized_bytes()?;
        let payload_digest =
            canonical_payload_digest(request.version, request.deadline_unix_ms, &operation_bytes);
        let payload_bytes = u64::try_from(operation_bytes.len())
            .map_err(|_| ProtocolError::new(StableErrorKind::PayloadTooLarge))?;
        let mut state = try_lock_registry(&self.inner)
            .map_err(|_| ProtocolError::new(StableErrorKind::Internal))?;
        let next_response_ledger_bytes =
            state.response_ledger_bytes.checked_add(MAX_RESPONSE_BYTES);
        let record = state
            .capabilities
            .get_mut(&request.capability_id)
            .ok_or_else(|| ProtocolError::new(StableErrorKind::UnknownCapability))?;
        if !token_matches(&record.token_hash, &request.token) {
            return Err(ProtocolError::new(StableErrorKind::Unauthorized));
        }
        check_clock_and_expiry(record, now)?;
        match record.state {
            CapabilityState::Inactive => {
                return Err(ProtocolError::new(StableErrorKind::Inactive));
            }
            CapabilityState::Revoked => {
                return Err(ProtocolError::new(StableErrorKind::Revoked));
            }
            CapabilityState::Active => {}
        }
        if request.deadline_unix_ms <= now.unix_ms
            || request.deadline_unix_ms > record.descriptor.expires_at_unix_ms
        {
            return Err(ProtocolError::new(StableErrorKind::DeadlineExpired));
        }

        if let Some(entry) = record.replay.get_mut(&request.request_id) {
            return match entry {
                ReplayEntry::Pending {
                    payload_digest: prior,
                } if prior.ct_eq(&payload_digest).into() => {
                    Err(ProtocolError::new(StableErrorKind::RequestInProgress))
                }
                ReplayEntry::Complete {
                    payload_digest: prior,
                    response,
                    replay_count,
                    ..
                } if prior.ct_eq(&payload_digest).into() => {
                    if *replay_count >= record.descriptor.budgets.max_replays_per_request {
                        Err(ProtocolError::new(StableErrorKind::ReplayLimitExceeded))
                    } else {
                        *replay_count += 1;
                        Ok(AuthorizationOutcome::Replay(response.clone()))
                    }
                }
                ReplayEntry::Pending { .. } | ReplayEntry::Complete { .. } => {
                    record.state = CapabilityState::Revoked;
                    Err(ProtocolError::new(StableErrorKind::ReplayConflict))
                }
            };
        }

        record.descriptor.scope.authorize(&request.operation)?;
        if record.used_operations >= record.descriptor.budgets.max_operations {
            return Err(ProtocolError::new(StableErrorKind::RequestBudgetExceeded));
        }
        let next_bytes = record
            .used_payload_bytes
            .checked_add(payload_bytes)
            .ok_or_else(|| ProtocolError::new(StableErrorKind::ByteBudgetExceeded))?;
        if next_bytes > record.descriptor.budgets.max_payload_bytes {
            return Err(ProtocolError::new(StableErrorKind::ByteBudgetExceeded));
        }
        if record.in_flight >= record.descriptor.budgets.max_in_flight {
            return Err(ProtocolError::new(StableErrorKind::ConcurrencyExceeded));
        }
        let next_response_ledger_bytes = next_response_ledger_bytes
            .filter(|bytes| *bytes <= MAX_REGISTRY_RESPONSE_BYTES)
            .ok_or_else(|| ProtocolError::new(StableErrorKind::RegistryCapacityExceeded))?;

        record.used_operations += 1;
        record.used_payload_bytes = next_bytes;
        record.in_flight += 1;
        record
            .replay
            .insert(request.request_id, ReplayEntry::Pending { payload_digest });
        state.response_ledger_bytes = next_response_ledger_bytes;
        Ok(AuthorizationOutcome::Fresh(AuthorizationPermit {
            inner: Arc::clone(&self.inner),
            authorized: AuthorizedOperation {
                capability_id: request.capability_id,
                request_id: request.request_id,
                operation: request.operation,
                payload_bytes,
            },
            payload_digest,
            completed: false,
        }))
    }

    /// Return a non-secret snapshot for tests and operator metrics.
    pub fn snapshot(&self, capability_id: Uuid) -> Option<RegistrySnapshot> {
        let state = try_lock_registry(&self.inner).ok()?;
        state
            .capabilities
            .get(&capability_id)
            .map(|record| RegistrySnapshot {
                state: record.state,
                used_operations: record.used_operations,
                used_payload_bytes: record.used_payload_bytes,
                in_flight: record.in_flight,
                replay_entries: record.replay.len(),
            })
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of authorization: execute a fresh request or reuse an exact response.
pub enum AuthorizationOutcome {
    /// A fresh operation holding one concurrency slot.
    Fresh(AuthorizationPermit),
    /// An exact completed replay; the operation must not execute again.
    Replay(ResponseEnvelope),
}

impl fmt::Debug for AuthorizationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fresh(permit) => formatter.debug_tuple("Fresh").field(permit).finish(),
            Self::Replay(response) => formatter.debug_tuple("Replay").field(response).finish(),
        }
    }
}

/// Structured operation that passed capability authorization.
#[derive(Clone)]
pub struct AuthorizedOperation {
    capability_id: Uuid,
    request_id: Uuid,
    operation: Operation,
    payload_bytes: u64,
}

impl AuthorizedOperation {
    /// Capability identifier that authorized this operation.
    pub const fn capability_id(&self) -> Uuid {
        self.capability_id
    }

    /// Idempotency identifier.
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    /// Authorized operation kind.
    pub const fn operation_kind(&self) -> OperationKind {
        self.operation.kind()
    }

    /// Borrow the authorized structured operation.
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Canonical payload size charged to the capability.
    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }
}

impl fmt::Debug for AuthorizedOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedOperation")
            .field("capability_id", &self.capability_id)
            .field("request_id", &self.request_id)
            .field("operation_kind", &self.operation.kind())
            .field("payload_bytes", &self.payload_bytes)
            .finish()
    }
}

/// RAII authorization permit holding one concurrency slot.
///
/// A future trusted executor must call [`Self::complete`] or [`Self::fail`].
/// Dropping an unresolved permit revokes the capability because the signing
/// outcome is uncertain.
pub struct AuthorizationPermit {
    inner: Arc<Mutex<RegistryState>>,
    authorized: AuthorizedOperation,
    payload_digest: [u8; 32],
    completed: bool,
}

impl AuthorizationPermit {
    /// Borrow the already-authorized structured operation.
    pub const fn authorized(&self) -> &AuthorizedOperation {
        &self.authorized
    }

    /// Cache and return a successful response, releasing the concurrency slot.
    pub fn complete(
        mut self,
        result: crate::OperationResult,
    ) -> Result<ResponseEnvelope, ProtocolError> {
        let response = ResponseEnvelope::success(self.authorized.request_id, result);
        let response_bytes = serde_json::to_vec(&response)
            .map_err(|_| ProtocolError::new(StableErrorKind::Internal))?;
        let response = if response_bytes.len() > MAX_RESPONSE_BYTES {
            ResponseEnvelope::error(self.authorized.request_id, StableErrorKind::PayloadTooLarge)
        } else {
            response
        };
        let response_size = serde_json::to_vec(&response)
            .map_err(|_| ProtocolError::new(StableErrorKind::Internal))?
            .len();
        self.finish(response.clone(), response_size)?;
        Ok(response)
    }

    /// Cache and return a stable executor failure, releasing the concurrency slot.
    pub fn fail(mut self, kind: StableErrorKind) -> ResponseEnvelope {
        let response = ResponseEnvelope::error(self.authorized.request_id, kind);
        let response_size =
            serde_json::to_vec(&response).map_or(MAX_RESPONSE_BYTES, |bytes| bytes.len());
        if self.finish(response.clone(), response_size).is_ok() {
            response
        } else {
            ResponseEnvelope::error(self.authorized.request_id, StableErrorKind::Internal)
        }
    }

    fn finish(
        &mut self,
        response: ResponseEnvelope,
        response_bytes: usize,
    ) -> Result<(), ProtocolError> {
        let mut state = try_lock_registry(&self.inner)
            .map_err(|_| ProtocolError::new(StableErrorKind::Internal))?;
        let mut cached = false;
        if let Some(record) = state.capabilities.get_mut(&self.authorized.capability_id) {
            record.in_flight = record.in_flight.saturating_sub(1);
            if matches!(
                record.replay.get(&self.authorized.request_id),
                Some(ReplayEntry::Pending { payload_digest })
                    if payload_digest.ct_eq(&self.payload_digest).into()
            ) {
                record.replay.insert(
                    self.authorized.request_id,
                    ReplayEntry::Complete {
                        payload_digest: self.payload_digest,
                        response,
                        response_bytes,
                        replay_count: 0,
                    },
                );
                cached = true;
            } else {
                record.state = CapabilityState::Revoked;
            }
        }
        state.response_ledger_bytes = state
            .response_ledger_bytes
            .saturating_sub(MAX_RESPONSE_BYTES);
        if cached {
            state.response_ledger_bytes =
                state.response_ledger_bytes.saturating_add(response_bytes);
        }
        self.completed = true;
        Ok(())
    }
}

impl fmt::Debug for AuthorizationPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationPermit")
            .field("authorized", &self.authorized)
            .field("payload_digest", &"[REDACTED]")
            .field("completed", &self.completed)
            .finish()
    }
}

impl Drop for AuthorizationPermit {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let Ok(mut state) = try_lock_registry(&self.inner) else {
            return;
        };
        if let Some(record) = state.capabilities.get_mut(&self.authorized.capability_id) {
            record.in_flight = record.in_flight.saturating_sub(1);
            record.state = CapabilityState::Revoked;
            record.replay.remove(&self.authorized.request_id);
        }
        state.response_ledger_bytes = state
            .response_ledger_bytes
            .saturating_sub(MAX_RESPONSE_BYTES);
    }
}

fn check_clock_and_expiry(
    record: &mut CapabilityRecord,
    now: ClockReading,
) -> Result<(), ProtocolError> {
    if now.monotonic_ms < record.last_monotonic_ms {
        record.state = CapabilityState::Revoked;
        return Err(ProtocolError::new(StableErrorKind::ClockRollback));
    }
    record.last_monotonic_ms = now.monotonic_ms;
    if now.unix_ms >= record.descriptor.expires_at_unix_ms
        || now.monotonic_ms >= record.expires_at_monotonic_ms
    {
        record.state = CapabilityState::Revoked;
        return Err(ProtocolError::new(StableErrorKind::Expired));
    }
    Ok(())
}

fn token_hash(token: &CapabilityToken) -> [u8; 32] {
    Sha256::digest(token.secret_bytes()).into()
}

fn token_matches(expected: &[u8; 32], provided: &CapabilityToken) -> bool {
    let provided_hash = token_hash(provided);
    expected.ct_eq(&provided_hash).into()
}

fn canonical_payload_digest(version: u16, deadline_unix_ms: i64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(version.to_le_bytes());
    hasher.update(deadline_unix_ms.to_le_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn try_lock_registry(inner: &Mutex<RegistryState>) -> Result<MutexGuard<'_, RegistryState>, ()> {
    inner.lock().map_err(|poisoned| {
        let mut state = poisoned.into_inner();
        for record in state.capabilities.values_mut() {
            record.state = CapabilityState::Revoked;
        }
    })
}

fn prune_inactive_records(state: &mut RegistryState, now: ClockReading) {
    let removable: Vec<Uuid> = state
        .capabilities
        .iter()
        .filter_map(|(capability_id, record)| {
            let elapsed = now.unix_ms >= record.descriptor.expires_at_unix_ms
                || now.monotonic_ms >= record.expires_at_monotonic_ms;
            (record.in_flight == 0 && (record.state == CapabilityState::Revoked || elapsed))
                .then_some(*capability_id)
        })
        .collect();
    for capability_id in removable {
        if let Some(record) = state.capabilities.remove(&capability_id) {
            state.response_ledger_bytes = state
                .response_ledger_bytes
                .saturating_sub(record.accounted_response_bytes());
        }
    }
}

impl CapabilityRecord {
    fn accounted_response_bytes(&self) -> usize {
        self.replay
            .values()
            .map(|entry| match entry {
                ReplayEntry::Pending { .. } => MAX_RESPONSE_BYTES,
                ReplayEntry::Complete { response_bytes, .. } => *response_bytes,
            })
            .sum()
    }
}

#[cfg(test)]
impl CapabilityRegistry {
    pub(crate) fn poison_for_test(&self) {
        let inner = Arc::clone(&self.inner);
        let _ = std::thread::spawn(move || {
            let _guard = inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("intentional registry poison");
        })
        .join();
    }

    pub(crate) fn fill_response_ledger_for_test(&self) {
        if let Ok(mut state) = try_lock_registry(&self.inner) {
            state.response_ledger_bytes = MAX_REGISTRY_RESPONSE_BYTES;
        }
    }
}
