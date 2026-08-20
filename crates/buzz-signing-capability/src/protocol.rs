use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::registry::AuthorizedOperation;

macro_rules! structural_debug {
    ($type:ty, $name:literal, { $($field:ident $( : $value:expr )?),* $(,)? }) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut debug = formatter.debug_struct($name);
                $(
                    structural_debug_field!(debug, self, $field $(, $value)?);
                )*
                debug.finish()
            }
        }
    };
}

macro_rules! structural_debug_field {
    ($debug:ident, $self:ident, $field:ident) => {
        $debug.field(stringify!($field), &$self.$field)
    };
    ($debug:ident, $self:ident, $field:ident, $value:expr) => {
        $debug.field(stringify!($field), &$value($self))
    };
}

/// Wire protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

/// Stable, non-sensitive failure classes returned across the capability boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StableErrorKind {
    /// The request uses an unsupported protocol version.
    UnsupportedVersion,
    /// No capability with the supplied opaque identifier exists.
    UnknownCapability,
    /// Authentication failed without revealing whether the token or identifier was wrong.
    Unauthorized,
    /// The capability has not been activated by trusted control flow.
    Inactive,
    /// The capability was explicitly revoked.
    Revoked,
    /// One of the absolute or monotonic-style expiry bounds elapsed.
    Expired,
    /// The request's own deadline elapsed.
    DeadlineExpired,
    /// The trusted clock input moved backwards.
    ClockRollback,
    /// The operation is not present in the capability's allowlist.
    OperationNotAllowed,
    /// The requested relay is not the capability's bound relay.
    RelayNotAllowed,
    /// The requested HTTP method is outside the capability scope.
    MethodNotAllowed,
    /// The requested HTTP path is outside the capability scope.
    PathNotAllowed,
    /// The requested Nostr event kind is outside the capability scope.
    EventKindNotAllowed,
    /// A channel, peer, or other structured resource is outside the capability scope.
    ResourceNotAllowed,
    /// A request or structured field exceeded its byte/count bound.
    PayloadTooLarge,
    /// A structured field is malformed.
    InvalidPayload,
    /// The fresh-operation budget is exhausted.
    RequestBudgetExceeded,
    /// The cumulative fresh-operation byte budget is exhausted.
    ByteBudgetExceeded,
    /// Too many operations are currently authorized.
    ConcurrencyExceeded,
    /// The broker-wide capability or replay-cache bound is exhausted.
    RegistryCapacityExceeded,
    /// A request id was reused with different canonical payload bytes.
    ReplayConflict,
    /// An exact replay exceeded its per-request retry allowance.
    ReplayLimitExceeded,
    /// An exact request is still being executed.
    RequestInProgress,
    /// A trusted executor failed without exposing its internal message.
    Internal,
}

/// A protocol error containing only a stable, non-sensitive classification.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolError {
    kind: StableErrorKind,
}

impl ProtocolError {
    /// Construct a classified protocol error.
    pub const fn new(kind: StableErrorKind) -> Self {
        Self { kind }
    }

    /// Return the stable error classification.
    pub const fn kind(self) -> StableErrorKind {
        self.kind
    }
}

impl fmt::Debug for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capability request failed: {:?}", self.kind)
    }
}

impl std::error::Error for ProtocolError {}

/// Secret bearer token carried on the wire and redacted from `Debug` output.
pub struct CapabilityToken(String);

impl CapabilityToken {
    /// Generate a 256-bit bearer token using the operating system RNG.
    pub fn generate() -> Self {
        let bytes: [u8; 32] = rand::random();
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Construct a token from transport input.
    ///
    /// Only a coarse length bound is enforced here. Authentication always uses
    /// the SHA-256 digest and constant-time comparison in the registry.
    pub fn from_secret(secret: String) -> Result<Self, ProtocolError> {
        if !(32..=256).contains(&secret.len()) || secret.chars().any(char::is_whitespace) {
            return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
        }
        Ok(Self(secret))
    }

    pub(crate) fn secret_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Clone for CapabilityToken {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for CapabilityToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for CapabilityToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilityToken([REDACTED])")
    }
}

impl Serialize for CapabilityToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CapabilityToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secret = String::deserialize(deserializer)?;
        Self::from_secret(secret).map_err(|_| D::Error::custom("invalid capability token"))
    }
}

/// Canonical configured relay origin.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayOrigin(String);

impl RelayOrigin {
    /// Parse and canonicalize an HTTP(S) or WebSocket relay root URL.
    pub fn parse(input: &str) -> Result<Self, ProtocolError> {
        if input.len() > 2048 {
            return Err(ProtocolError::new(StableErrorKind::PayloadTooLarge));
        }
        let mut url =
            Url::parse(input).map_err(|_| ProtocolError::new(StableErrorKind::InvalidPayload))?;
        if !matches!(url.scheme(), "http" | "https" | "ws" | "wss")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
        }
        let host = url
            .host_str()
            .ok_or_else(|| ProtocolError::new(StableErrorKind::InvalidPayload))?
            .to_ascii_lowercase();
        url.set_host(Some(&host))
            .map_err(|_| ProtocolError::new(StableErrorKind::InvalidPayload))?;
        url.set_path("");
        Ok(Self(url.to_string().trim_end_matches('/').to_owned()))
    }

    /// Return the canonical relay root URL.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RelayOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("RelayOrigin").field(&self.0).finish()
    }
}

impl Serialize for RelayOrigin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelayOrigin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(|_| D::Error::custom("invalid relay origin"))
    }
}

/// HTTP methods that may be authorized by a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// DELETE.
    Delete,
}

/// A bounded Nostr tag represented as its exact ordered fields.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StructuredTag(pub Vec<String>);

impl fmt::Debug for StructuredTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StructuredTag")
            .field("field_count", &self.0.len())
            .field("serialized_bytes", &serialized_len(&self.0))
            .finish()
    }
}

/// Structured request to sign a Nostr event.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrEventSignRequest {
    /// Bound relay for which the event is intended.
    pub relay: RelayOrigin,
    /// Nostr event kind. The capability policy must explicitly allow it.
    pub kind: u32,
    /// Event content. It is bounded before authorization.
    pub content: String,
    /// Exact structured tags. Caller-supplied `auth` tags are forbidden.
    pub tags: Vec<StructuredTag>,
    /// Optional requested timestamp. The trusted broker must apply its own time policy.
    pub requested_created_at: Option<u64>,
}

structural_debug!(NostrEventSignRequest, "NostrEventSignRequest", {
    relay,
    kind,
    content_bytes: |value: &NostrEventSignRequest| value.content.len(),
    tag_count: |value: &NostrEventSignRequest| value.tags.len()
});

/// Structured request for a NIP-98 authorization event.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip98SignRequest {
    /// Bound relay.
    pub relay: RelayOrigin,
    /// HTTP method.
    pub method: HttpMethod,
    /// Root-relative path and optional query string.
    pub path: String,
    /// Optional lowercase SHA-256 body digest.
    pub payload_sha256: Option<String>,
}

structural_debug!(Nip98SignRequest, "Nip98SignRequest", { relay, method, path_bytes: |value: &Nip98SignRequest| value.path.len(), has_payload_digest: |value: &Nip98SignRequest| value.payload_sha256.is_some() });

/// Structured request for a NIP-42 AUTH event.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip42SignRequest {
    /// Bound WebSocket relay.
    pub relay: RelayOrigin,
    /// Relay-provided challenge.
    pub challenge: String,
}

structural_debug!(Nip42SignRequest, "Nip42SignRequest", { relay, challenge_bytes: |value: &Nip42SignRequest| value.challenge.len() });

/// Blossom authorization action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlossomAction {
    /// Read an existing object.
    Get,
    /// Upload an object with a known digest.
    Upload,
}

/// Structured request for a Blossom authorization event.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlossomSignRequest {
    /// Bound relay/media server.
    pub relay: RelayOrigin,
    /// Read or upload action.
    pub action: BlossomAction,
    /// Lowercase SHA-256 object digest when known.
    pub object_sha256: Option<String>,
    /// MIME type for uploads.
    pub mime_type: Option<String>,
}

structural_debug!(BlossomSignRequest, "BlossomSignRequest", { relay, action, has_object_digest: |value: &BlossomSignRequest| value.object_sha256.is_some(), mime_type_bytes: |value: &BlossomSignRequest| value.mime_type.as_ref().map_or(0, String::len) });

/// Request for the opaque coordinate of an agent engram.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngramCoordinateRequest {
    /// Bound relay.
    pub relay: RelayOrigin,
    /// Owner or peer public key in lowercase hexadecimal.
    pub peer_pubkey: String,
    /// Plaintext memory slug.
    pub slug: String,
}

structural_debug!(EngramCoordinateRequest, "EngramCoordinateRequest", { relay, peer_pubkey_bytes: |value: &EngramCoordinateRequest| value.peer_pubkey.len(), slug_bytes: |value: &EngramCoordinateRequest| value.slug.len() });

/// Request to validate and decrypt a structured agent engram event.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngramDecryptRequest {
    /// Bound relay.
    pub relay: RelayOrigin,
    /// Expected owner or peer public key.
    pub peer_pubkey: String,
    /// Serialized signed Nostr event to validate and decrypt.
    pub event_json: String,
}

structural_debug!(EngramDecryptRequest, "EngramDecryptRequest", { relay, peer_pubkey_bytes: |value: &EngramDecryptRequest| value.peer_pubkey.len(), event_bytes: |value: &EngramDecryptRequest| value.event_json.len() });

/// Request to construct, encrypt, and sign an agent engram event.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngramBuildEventRequest {
    /// Bound relay.
    pub relay: RelayOrigin,
    /// Owner public key in lowercase hexadecimal.
    pub owner_pubkey: String,
    /// Memory slug.
    pub slug: String,
    /// Memory value; `None` is a tombstone.
    pub value: Option<String>,
    /// Broker-validated requested event timestamp.
    pub requested_created_at: u64,
}

structural_debug!(EngramBuildEventRequest, "EngramBuildEventRequest", { relay, owner_pubkey_bytes: |value: &EngramBuildEventRequest| value.owner_pubkey.len(), slug_bytes: |value: &EngramBuildEventRequest| value.slug.len(), value_bytes: |value: &EngramBuildEventRequest| value.value.as_ref().map_or(0, String::len) });

/// Structured Git Smart-HTTP NIP-98 authorization request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitNip98SignRequest {
    /// Bound Buzz relay.
    pub relay: RelayOrigin,
    /// HTTP method requested by the Buzz Git challenge.
    pub method: HttpMethod,
    /// Canonical root-relative repository path.
    pub repository_path: String,
}

structural_debug!(GitNip98SignRequest, "GitNip98SignRequest", { relay, method, repository_path_bytes: |value: &GitNip98SignRequest| value.repository_path.len() });

/// Git object type accepted by NIP-GS signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitObjectKind {
    /// Commit object payload.
    Commit,
    /// Annotated tag object payload.
    Tag,
}

/// Structured request to lease a bounded secret for tool execution.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretLeaseRequest {
    /// Target secret key to lease.
    pub secret_key: String,
    /// Tool or capability requesting the secret lease.
    pub tool_name: String,
}

structural_debug!(SecretLeaseRequest, "SecretLeaseRequest", { secret_key_bytes: |value: &SecretLeaseRequest| value.secret_key.len(), tool_name_bytes: |value: &SecretLeaseRequest| value.tool_name.len() });

/// Structured request to sign one bounded Git commit or tag payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitObjectSignRequest {
    /// Bound Buzz relay identity context.
    pub relay: RelayOrigin,
    /// Commit or tag.
    pub object_kind: GitObjectKind,
    /// Exact canonical object payload, never a caller-supplied digest.
    pub payload: String,
    /// Expected public signing key identifier.
    pub key_id: String,
}

structural_debug!(GitObjectSignRequest, "GitObjectSignRequest", { relay, object_kind, payload_bytes: |value: &GitObjectSignRequest| value.payload.len(), key_id_bytes: |value: &GitObjectSignRequest| value.key_id.len() });

/// Stable operation discriminator used by capability policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Return non-secret identity metadata.
    IdentityMetadata,
    /// Sign a structured Nostr event.
    NostrEventSign,
    /// Sign a relay-bound NIP-98 request.
    Nip98Sign,
    /// Sign a relay-bound NIP-42 challenge.
    Nip42Sign,
    /// Sign a Blossom operation.
    BlossomSign,
    /// Derive an opaque engram coordinate.
    EngramCoordinate,
    /// Decrypt and validate an engram event.
    EngramDecrypt,
    /// Build and sign an engram event.
    EngramBuildEvent,
    /// Sign a Buzz Git Smart-HTTP challenge.
    GitNip98Sign,
    /// Sign a canonical Git commit or tag payload.
    GitObjectSign,
    /// Lease a bounded secret for tool execution.
    SecretLease,
}

/// Structured operations accepted by the v1 protocol.
///
/// There is intentionally no raw-key export, arbitrary digest, arbitrary URL,
/// or generic signing operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "payload", rename_all = "snake_case")]
pub enum Operation {
    /// Return public identity metadata.
    IdentityMetadata,
    /// Sign a structured Nostr event.
    NostrEventSign(NostrEventSignRequest),
    /// Sign a relay HTTP authorization event.
    Nip98Sign(Nip98SignRequest),
    /// Sign a relay WebSocket challenge.
    Nip42Sign(Nip42SignRequest),
    /// Sign a Blossom authorization event.
    BlossomSign(BlossomSignRequest),
    /// Derive an agent engram coordinate.
    EngramCoordinate(EngramCoordinateRequest),
    /// Decrypt a structured agent engram.
    EngramDecrypt(EngramDecryptRequest),
    /// Build an encrypted agent engram event.
    EngramBuildEvent(EngramBuildEventRequest),
    /// Sign a Buzz Git NIP-98 request.
    GitNip98Sign(GitNip98SignRequest),
    /// Sign a canonical Git object payload.
    GitObjectSign(GitObjectSignRequest),
    /// Lease a bounded secret for tool execution.
    SecretLease(SecretLeaseRequest),
}

impl Operation {
    /// Return the stable operation discriminator.
    pub const fn kind(&self) -> OperationKind {
        match self {
            Self::IdentityMetadata => OperationKind::IdentityMetadata,
            Self::NostrEventSign(_) => OperationKind::NostrEventSign,
            Self::Nip98Sign(_) => OperationKind::Nip98Sign,
            Self::Nip42Sign(_) => OperationKind::Nip42Sign,
            Self::BlossomSign(_) => OperationKind::BlossomSign,
            Self::EngramCoordinate(_) => OperationKind::EngramCoordinate,
            Self::EngramDecrypt(_) => OperationKind::EngramDecrypt,
            Self::EngramBuildEvent(_) => OperationKind::EngramBuildEvent,
            Self::GitNip98Sign(_) => OperationKind::GitNip98Sign,
            Self::GitObjectSign(_) => OperationKind::GitObjectSign,
            Self::SecretLease(_) => OperationKind::SecretLease,
        }
    }

    pub(crate) fn serialized_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        serde_json::to_vec(self).map_err(|_| ProtocolError::new(StableErrorKind::InvalidPayload))
    }
}

impl fmt::Debug for Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Operation")
            .field("kind", &self.kind())
            .field("serialized_bytes", &serialized_len(self))
            .finish()
    }
}

/// Versioned request envelope presented to the authorization registry.
#[derive(Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    /// Protocol version; must equal [`PROTOCOL_VERSION`].
    pub version: u16,
    /// Opaque capability identifier.
    pub capability_id: Uuid,
    /// Secret bearer token.
    pub token: CapabilityToken,
    /// Idempotency and replay-fencing identifier.
    pub request_id: Uuid,
    /// Request-specific absolute deadline in Unix milliseconds.
    pub deadline_unix_ms: i64,
    /// Narrow structured operation.
    pub operation: Operation,
}

impl fmt::Debug for RequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestEnvelope")
            .field("version", &self.version)
            .field("capability_id", &self.capability_id)
            .field("token", &"[REDACTED]")
            .field("request_id", &self.request_id)
            .field("deadline_unix_ms", &self.deadline_unix_ms)
            .field("operation_kind", &self.operation.kind())
            .field("payload_bytes", &serialized_len(&self.operation))
            .finish()
    }
}

/// Non-secret public identity metadata returned by a future broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityMetadata {
    /// Agent public key in lowercase hexadecimal.
    pub public_key: String,
    /// Capability-bound relay.
    pub relay: RelayOrigin,
    /// Capability expiry in Unix milliseconds.
    pub expires_at_unix_ms: i64,
}

/// Typed operation results returned by a future trusted broker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", content = "payload", rename_all = "snake_case")]
pub enum OperationResult {
    /// Public identity metadata.
    IdentityMetadata(IdentityMetadata),
    /// A serialized, fully signed Nostr event.
    SignedEvent { event_json: String },
    /// An authorization header and optional canonical public owner attestation.
    Authorization {
        authorization: String,
        auth_tag: Option<String>,
    },
    /// Opaque engram coordinate.
    EngramCoordinate { d_tag: String },
    /// Authorized plaintext engram body.
    EngramPlaintext { body_json: String },
    /// Armored NIP-GS Git signature.
    GitSignature { armored_signature: String },
    /// Leased secret value and expiration.
    SecretLease {
        secret_key: String,
        secret_value: String,
        expires_at_unix_ms: i64,
    },
}

impl fmt::Debug for OperationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, bytes) = match self {
            Self::IdentityMetadata(value) => ("identity_metadata", serialized_len(value)),
            Self::SignedEvent { event_json } => ("signed_event", event_json.len()),
            Self::Authorization {
                authorization,
                auth_tag,
            } => (
                "authorization",
                authorization.len() + auth_tag.as_ref().map_or(0, String::len),
            ),
            Self::EngramCoordinate { d_tag } => ("engram_coordinate", d_tag.len()),
            Self::EngramPlaintext { body_json } => ("engram_plaintext", body_json.len()),
            Self::GitSignature { armored_signature } => ("git_signature", armored_signature.len()),
            Self::SecretLease { secret_key, secret_value, .. } => (
                "secret_lease",
                secret_key.len() + secret_value.len(),
            ),
        };
        formatter
            .debug_struct("OperationResult")
            .field("kind", &kind)
            .field("serialized_content_bytes", &bytes)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResponseStatus {
    Ok,
    Error,
}

/// Versioned response envelope with only stable error classifications.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    /// Protocol version.
    pub version: u16,
    /// Correlated request identifier.
    pub request_id: Uuid,
    status: ResponseStatus,
    /// Typed successful result.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<OperationResult>,
    /// Stable error kind. Raw executor errors are never represented.
    #[serde(skip_serializing_if = "Option::is_none")]
    error_kind: Option<StableErrorKind>,
}

impl ResponseEnvelope {
    /// Construct a successful response.
    pub fn success(request_id: Uuid, result: OperationResult) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            status: ResponseStatus::Ok,
            result: Some(result),
            error_kind: None,
        }
    }

    /// Construct a classified error response.
    pub const fn error(request_id: Uuid, kind: StableErrorKind) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            status: ResponseStatus::Error,
            result: None,
            error_kind: Some(kind),
        }
    }

    /// Return the successful result, when present.
    pub const fn result(&self) -> Option<&OperationResult> {
        self.result.as_ref()
    }

    /// Return the stable error classification, when present.
    pub const fn error_kind(&self) -> Option<StableErrorKind> {
        self.error_kind
    }
}

impl fmt::Debug for ResponseEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseEnvelope")
            .field("version", &self.version)
            .field("request_id", &self.request_id)
            .field(
                "status",
                &match self.status {
                    ResponseStatus::Ok => "ok",
                    ResponseStatus::Error => "error",
                },
            )
            .field("result", &self.result)
            .field("error_kind", &self.error_kind)
            .finish()
    }
}

/// Error returned by a trusted executor without transporting an internal message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedExecutionError {
    kind: StableErrorKind,
}

impl TrustedExecutionError {
    /// Create an executor error from a stable class.
    pub const fn new(kind: StableErrorKind) -> Self {
        Self { kind }
    }

    /// Return the stable class.
    pub const fn kind(self) -> StableErrorKind {
        self.kind
    }
}

/// Cryptographic execution boundary implemented only by the future trusted broker.
///
/// The trait receives an already-authorized structured operation. It exposes no
/// API for exporting a private key or signing an arbitrary digest.
pub trait TrustedOperationExecutor {
    /// Execute one already-authorized structured operation.
    fn execute(
        &self,
        authorized: &AuthorizedOperation,
    ) -> Result<OperationResult, TrustedExecutionError>;
}

fn serialized_len<T: Serialize + ?Sized>(value: &T) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}
