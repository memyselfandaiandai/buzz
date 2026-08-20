//! Strict WebSocket client for the Buzz signing-capability broker.
//!
//! The client accepts the fixed `broker-v1` child projection and connects
//! over WebSocket (`ws://<host>:<port>`) to any reachable endpoint — local
//! loopback, LAN, or remote via Tailscale. Transport-level address
//! enforcement is the endpoint provider's concern, not this crate's. Its
//! public operation surface is deliberately narrower than the protocol
//! inventory: consumers can request identity metadata, a structured Nostr
//! event signature, or a relay-bound NIP-98 authorization.

use std::{
    ffi::OsString,
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use buzz_signing_capability::{
    CapabilityToken, IdentityMetadata, Operation, OperationResult, RequestEnvelope,
    ResponseEnvelope, PROTOCOL_VERSION,
};
pub use buzz_signing_capability::{
    HttpMethod, Nip98SignRequest, NostrEventSignRequest, RelayOrigin, StableErrorKind,
    StructuredTag,
};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use nostr::{Event, PublicKey};
use tokio::time::timeout;
use tokio_tungstenite::connect_async;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const CAPABILITY_ENDPOINT_ENV: &str = "BUZZ_CAPABILITY_ENDPOINT";
const CAPABILITY_ID_ENV: &str = "BUZZ_CAPABILITY_ID";
const CAPABILITY_TOKEN_ENV: &str = "BUZZ_CAPABILITY_TOKEN";
const PUBLIC_KEY_ENV: &str = "BUZZ_PUBLIC_KEY";
const RELAY_URL_ENV: &str = "BUZZ_RELAY_URL";
const CAPABILITY_EXPIRES_AT_ENV: &str = "BUZZ_CAPABILITY_EXPIRES_AT";
const CAPABILITY_ENV_PREFIX: &str = "BUZZ_CAPABILITY_";

const PROJECTION_ENV: [&str; 6] = [
    CAPABILITY_ENDPOINT_ENV,
    CAPABILITY_ID_ENV,
    CAPABILITY_TOKEN_ENV,
    PUBLIC_KEY_ENV,
    RELAY_URL_ENV,
    CAPABILITY_EXPIRES_AT_ENV,
];
const LONG_LIVED_CREDENTIAL_ENV: [&str; 4] = [
    "BUZZ_PRIVATE_KEY",
    "BUZZ_ACP_PRIVATE_KEY",
    "NOSTR_PRIVATE_KEY",
    "BUZZ_AUTH_TAG",
];

const MAX_WIRE_FRAME_BYTES: usize = 1_100_000;
const REQUEST_DEADLINE_MS: i64 = 6_000;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(6);

struct SecureResponseFrame(BytesMut);

impl SecureResponseFrame {
    fn try_new(bytes: tokio_tungstenite::tungstenite::Bytes) -> Result<Self, ClientError> {
        bytes
            .try_into_mut()
            .map(Self)
            .map_err(|_| ClientError::Read)
    }

    fn zeroize_now(&mut self) {
        self.0.as_mut().zeroize();
    }
}

impl AsRef<[u8]> for SecureResponseFrame {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecureResponseFrame {
    fn drop(&mut self) {
        self.zeroize_now();
    }
}

/// One stable timeout phase, without transport or credential detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutPhase {
    /// Opening the WebSocket connection.
    Connect,
    /// Writing and half-closing the single request frame.
    Write,
    /// Reading the response frame through EOF.
    Read,
    /// The complete exchange exceeded its outer deadline.
    Total,
}

impl fmt::Display for TimeoutPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self {
            Self::Connect => "connect",
            Self::Write => "write",
            Self::Read => "read",
            Self::Total => "total",
        };
        formatter.write_str(phase)
    }
}

/// Secret-safe client failure classes.
///
/// Errors intentionally contain no endpoint input, environment value, wire
/// body, operating-system error, or broker-supplied text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// None of the fixed broker projection variables was present.
    #[error("capability projection is missing")]
    MissingProjection,
    /// Only part of the fixed broker projection was present.
    #[error("capability projection is incomplete")]
    IncompleteProjection,
    /// A long-lived credential was present alongside the capability projection.
    #[error("long-lived credentials cannot be mixed with a capability projection")]
    MixedCredentials,
    /// An unrecognized or incorrectly cased capability variable was present.
    #[error("capability projection contains an unsupported variable")]
    UnsupportedEnvironment,
    /// A required environment name or value was not valid Unicode.
    #[error("capability projection contains invalid environment text")]
    InvalidEnvironment,
    /// The endpoint was not a valid WebSocket URL.
    #[error("capability endpoint must be a valid ws:// URL")]
    InvalidEndpoint,
    /// The capability identifier was not a non-nil UUID.
    #[error("capability identifier is invalid")]
    InvalidCapabilityId,
    /// The bearer token failed its coarse transport validation.
    #[error("capability token is invalid")]
    InvalidToken,
    /// The projected public key was not canonical lowercase hexadecimal.
    #[error("capability public key is invalid")]
    InvalidPublicKey,
    /// The relay was not a canonical relay origin.
    #[error("capability relay is invalid")]
    InvalidRelay,
    /// The projected absolute expiry was not a positive Unix millisecond value.
    #[error("capability expiry is invalid")]
    InvalidExpiry,
    /// The projected capability expired before a request could be made.
    #[error("capability has expired")]
    Expired,
    /// The system clock could not produce a bounded Unix millisecond value.
    #[error("capability client clock is invalid")]
    Clock,
    /// The request could not be serialized within the broker frame bound.
    #[error("capability request is invalid")]
    InvalidRequest,
    /// The request exceeded the broker frame bound.
    #[error("capability request exceeds the wire bound")]
    RequestTooLarge,
    /// A loopback connection could not be opened.
    #[error("capability broker connection failed")]
    Connect,
    /// The request could not be completely written.
    #[error("capability broker write failed")]
    Write,
    /// The response could not be completely read.
    #[error("capability broker read failed")]
    Read,
    /// A bounded transport phase elapsed.
    #[error("capability broker {0} timeout")]
    Timeout(TimeoutPhase),
    /// The response exceeded the client frame bound.
    #[error("capability response exceeds the wire bound")]
    ResponseTooLarge,
    /// The response WebSocket message did not contain a valid response envelope.
    #[error("capability response framing is invalid")]
    InvalidFrame,
    /// The response envelope or result shape was malformed.
    #[error("capability response is invalid")]
    InvalidResponse,
    /// The response used a different protocol version.
    #[error("capability response version is unsupported")]
    UnsupportedVersion,
    /// The response did not correlate to the request.
    #[error("capability response request identifier does not match")]
    RequestIdMismatch,
    /// The broker rejected the operation with a stable classification.
    #[error("capability broker rejected the request: {0:?}")]
    Broker(StableErrorKind),
    /// A typed method received a different successful result variant.
    #[error("capability broker returned an unexpected result")]
    UnexpectedResult,
    /// Broker identity metadata did not match the fixed child projection.
    #[error("capability broker identity does not match the projection")]
    IdentityMismatch,
    /// A returned event was malformed, invalidly signed, or signed by another key.
    #[error("capability broker returned an invalid signed event")]
    InvalidSignedEvent,
    /// A returned NIP-98 header was malformed.
    #[error("capability broker returned an invalid authorization")]
    InvalidAuthorization,
    /// A secret lease did not match the requested selector or bounded lifetime.
    #[error("capability broker returned an invalid secret lease")]
    InvalidSecretLease,
}

struct SecretToken(Zeroizing<String>);

impl SecretToken {
    fn new(value: String) -> Result<Self, ClientError> {
        CapabilityToken::from_secret(value.clone()).map_err(|_| ClientError::InvalidToken)?;
        Ok(Self(Zeroizing::new(value)))
    }

    fn protocol_token(&self) -> Result<CapabilityToken, ClientError> {
        CapabilityToken::from_secret(self.0.to_string()).map_err(|_| ClientError::InvalidToken)
    }
}

#[derive(Clone, Copy)]
struct ClientTimeouts {
    connect: Duration,
    write: Duration,
    read: Duration,
    total: Duration,
}

impl Default for ClientTimeouts {
    fn default() -> Self {
        Self {
            connect: DEFAULT_CONNECT_TIMEOUT,
            write: DEFAULT_WRITE_TIMEOUT,
            read: DEFAULT_READ_TIMEOUT,
            total: DEFAULT_TOTAL_TIMEOUT,
        }
    }
}

/// One validated WebSocket-client capability.
///
/// `Debug` intentionally reports only public projection metadata. The bearer
/// token is held in a zeroizing allocation and is never formatted.
pub struct CapabilityClient {
    endpoint: Url,
    capability_id: Uuid,
    token: Arc<SecretToken>,
    public_key: PublicKey,
    relay: RelayOrigin,
    expires_at_unix_ms: i64,
    timeouts: ClientTimeouts,
}

impl Clone for CapabilityClient {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            capability_id: self.capability_id,
            token: Arc::clone(&self.token),
            public_key: self.public_key,
            relay: self.relay.clone(),
            expires_at_unix_ms: self.expires_at_unix_ms,
            timeouts: self.timeouts,
        }
    }
}

impl fmt::Debug for CapabilityClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityClient")
            .field("endpoint", &self.endpoint)
            .field("capability_id", &self.capability_id)
            .field("public_key", &self.public_key)
            .field("relay", &self.relay)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish_non_exhaustive()
    }
}

/// A broker-created NIP-98 authorization and optional canonical owner tag.
///
/// The contents are intentionally omitted from `Debug`; callers can retrieve
/// them explicitly for the outbound relay request.
pub struct Nip98Authorization {
    authorization: String,
    auth_tag: Option<String>,
}

impl Nip98Authorization {
    /// Return the complete `Authorization` header value.
    pub fn authorization(&self) -> &str {
        &self.authorization
    }

    /// Return the canonical owner-attestation header value, when configured.
    pub fn auth_tag(&self) -> Option<&str> {
        self.auth_tag.as_deref()
    }
}

impl fmt::Debug for Nip98Authorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Nip98Authorization")
            .field("authorization_bytes", &self.authorization.len())
            .field(
                "auth_tag_bytes",
                &self.auth_tag.as_ref().map_or(0, String::len),
            )
            .finish()
    }
}

impl CapabilityClient {
    /// Load the fixed projection from the current process environment and
    /// verify it against live broker identity metadata.
    ///
    /// This method fails closed when the projection is absent, partial, mixed
    /// with a long-lived credential alias, expired, or unavailable.
    pub async fn from_env() -> Result<Self, ClientError> {
        Self::from_env_iter(std::env::vars_os()).await
    }

    /// Load a fixed projection from an explicit environment snapshot and
    /// verify it against live broker identity metadata.
    ///
    /// This is useful to pass a sanitized child environment without mutating
    /// process-global state. Names and values use [`OsString`] so invalid text
    /// is rejected rather than silently normalized.
    pub async fn from_env_iter<I>(variables: I) -> Result<Self, ClientError>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        let client = Self::parse_environment(variables)?;
        client.identity_metadata().await?;
        Ok(client)
    }

    /// Return the projected public signing identity.
    pub const fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Return the canonical relay origin bound to this capability.
    pub const fn relay(&self) -> &RelayOrigin {
        &self.relay
    }

    /// Return the absolute capability expiry in Unix milliseconds.
    pub const fn expires_at_unix_ms(&self) -> i64 {
        self.expires_at_unix_ms
    }

    /// Fetch and cross-check non-secret broker identity metadata.
    pub async fn identity_metadata(&self) -> Result<IdentityMetadata, ClientError> {
        let result = self.execute(Operation::IdentityMetadata).await?;
        let OperationResult::IdentityMetadata(metadata) = &result else {
            return Err(ClientError::UnexpectedResult);
        };
        if metadata.public_key != self.public_key.to_hex()
            || metadata.relay != self.relay
            || metadata.expires_at_unix_ms != self.expires_at_unix_ms
        {
            return Err(ClientError::IdentityMismatch);
        }
        Ok(metadata.clone())
    }

    /// Ask the broker to sign one structured Nostr event.
    ///
    /// The returned event is parsed, cryptographically verified, and checked
    /// against the projected public key before it is returned.
    pub async fn sign_nostr_event(
        &self,
        request: NostrEventSignRequest,
    ) -> Result<Event, ClientError> {
        let requested_kind = request.kind;
        let requested_content = request.content.clone();
        let result = self.execute(Operation::NostrEventSign(request)).await?;
        let OperationResult::SignedEvent { event_json } = &result else {
            return Err(ClientError::UnexpectedResult);
        };
        let event: Event =
            serde_json::from_str(event_json).map_err(|_| ClientError::InvalidSignedEvent)?;
        if event.verify().is_err()
            || event.pubkey != self.public_key
            || u32::from(event.kind.as_u16()) != requested_kind
            || event.content != requested_content
        {
            return Err(ClientError::InvalidSignedEvent);
        }
        Ok(event)
    }

    /// Ask the broker for one relay-bound NIP-98 authorization.
    pub async fn sign_nip98(
        &self,
        request: Nip98SignRequest,
    ) -> Result<Nip98Authorization, ClientError> {
        let result = self.execute(Operation::Nip98Sign(request)).await?;
        let OperationResult::Authorization {
            authorization,
            auth_tag,
        } = &result
        else {
            return Err(ClientError::UnexpectedResult);
        };
        if !authorization.starts_with("Nostr ")
            || authorization.len() <= "Nostr ".len()
            || contains_header_break(authorization)
            || auth_tag
                .as_ref()
                .is_some_and(|value| contains_header_break(value) || !valid_auth_tag_json(value))
        {
            return Err(ClientError::InvalidAuthorization);
        }
        Ok(Nip98Authorization {
            authorization: authorization.clone(),
            auth_tag: auth_tag.clone(),
        })
    }

    /// Ask the broker to lease a bounded secret for tool execution.
    ///
    /// Returns [`ClientError::InvalidSecretLease`] unless the typed lease matches
    /// the exact requested secret key and remains current within both the sent
    /// request deadline and the projected capability expiry.
    pub async fn acquire_secret(
        &self,
        secret_key: impl Into<String>,
        tool_name: impl Into<String>,
    ) -> Result<buzz_signing_capability::OperationResult, ClientError> {
        let expected_secret_key = secret_key.into();
        let request = buzz_signing_capability::SecretLeaseRequest {
            secret_key: expected_secret_key.clone(),
            tool_name: tool_name.into(),
        };
        let issued_at_unix_ms = unix_now_ms()?;
        let request_id = Uuid::new_v4();
        let (result, request_deadline_unix_ms) = self
            .execute_at_with_deadline(
                Operation::SecretLease(request),
                issued_at_unix_ms,
                request_id,
            )
            .await?;
        let release_at_unix_ms = unix_now_ms()?;
        // Validate through a borrow so every rejection leaves `result` as the
        // sole secret owner; `OperationResult::drop` then wipes the value.
        validate_secret_lease(
            &result,
            &expected_secret_key,
            issued_at_unix_ms,
            release_at_unix_ms,
            request_deadline_unix_ms,
            self.expires_at_unix_ms,
        )?;
        Ok(result)
    }

    fn parse_environment<I>(variables: I) -> Result<Self, ClientError>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        let mut values: [Option<OsString>; 6] = std::array::from_fn(|_| None);
        let mut saw_long_lived = false;

        for (raw_name, value) in variables {
            let Some(name) = raw_name.to_str() else {
                continue;
            };
            if LONG_LIVED_CREDENTIAL_ENV
                .iter()
                .any(|reserved| name.eq_ignore_ascii_case(reserved))
            {
                saw_long_lived = true;
                continue;
            }
            if let Some(index) = PROJECTION_ENV.iter().position(|expected| name == *expected) {
                if values[index].replace(value).is_some() {
                    return Err(ClientError::UnsupportedEnvironment);
                }
                continue;
            }
            if PROJECTION_ENV
                .iter()
                .any(|expected| name.eq_ignore_ascii_case(expected))
                || name
                    .get(..CAPABILITY_ENV_PREFIX.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(CAPABILITY_ENV_PREFIX))
            {
                return Err(ClientError::UnsupportedEnvironment);
            }
        }

        let present = values.iter().filter(|value| value.is_some()).count();
        if present == 0 {
            return Err(if saw_long_lived {
                ClientError::MixedCredentials
            } else {
                ClientError::MissingProjection
            });
        }
        if saw_long_lived {
            return Err(ClientError::MixedCredentials);
        }
        if present != values.len() {
            return Err(ClientError::IncompleteProjection);
        }

        let [endpoint, capability_id, token, public_key, relay, expires_at] = values;
        let endpoint = os_value(endpoint)?
            .into_string()
            .map_err(|_| ClientError::InvalidEnvironment)?;
        let capability_id = os_value(capability_id)?
            .into_string()
            .map_err(|_| ClientError::InvalidEnvironment)?;
        let token = os_value(token)?
            .into_string()
            .map_err(|_| ClientError::InvalidEnvironment)?;
        let public_key = os_value(public_key)?
            .into_string()
            .map_err(|_| ClientError::InvalidEnvironment)?;
        let relay = os_value(relay)?
            .into_string()
            .map_err(|_| ClientError::InvalidEnvironment)?;
        let expires_at = os_value(expires_at)?
            .into_string()
            .map_err(|_| ClientError::InvalidEnvironment)?;

        let endpoint = parse_endpoint(&endpoint)?;
        let parsed_capability_id = Uuid::parse_str(&capability_id)
            .ok()
            .filter(|value| !value.is_nil())
            .ok_or(ClientError::InvalidCapabilityId)?;
        if parsed_capability_id.to_string() != capability_id {
            return Err(ClientError::InvalidCapabilityId);
        }
        let token = Arc::new(SecretToken::new(token)?);
        let parsed_public_key =
            PublicKey::parse(&public_key).map_err(|_| ClientError::InvalidPublicKey)?;
        if parsed_public_key.to_hex() != public_key {
            return Err(ClientError::InvalidPublicKey);
        }
        let parsed_relay = RelayOrigin::parse(&relay).map_err(|_| ClientError::InvalidRelay)?;
        if parsed_relay.as_str() != relay {
            return Err(ClientError::InvalidRelay);
        }
        let expires_at_unix_ms = expires_at
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or(ClientError::InvalidExpiry)?;
        if expires_at_unix_ms.to_string() != expires_at {
            return Err(ClientError::InvalidExpiry);
        }

        Ok(Self {
            endpoint,
            capability_id: parsed_capability_id,
            token,
            public_key: parsed_public_key,
            relay: parsed_relay,
            expires_at_unix_ms,
            timeouts: ClientTimeouts::default(),
        })
    }

    async fn execute(&self, operation: Operation) -> Result<OperationResult, ClientError> {
        let now_unix_ms = unix_now_ms()?;
        self.execute_at(operation, now_unix_ms, Uuid::new_v4())
            .await
    }

    async fn execute_at(
        &self,
        operation: Operation,
        now_unix_ms: i64,
        request_id: Uuid,
    ) -> Result<OperationResult, ClientError> {
        self.execute_at_with_deadline(operation, now_unix_ms, request_id)
            .await
            .map(|(result, _)| result)
    }

    async fn execute_at_with_deadline(
        &self,
        operation: Operation,
        now_unix_ms: i64,
        request_id: Uuid,
    ) -> Result<(OperationResult, i64), ClientError> {
        let request = self.build_request(operation, now_unix_ms, request_id)?;
        let request_deadline_unix_ms = request.deadline_unix_ms;
        let result = timeout(self.timeouts.total, self.exchange(request))
            .await
            .map_err(|_| ClientError::Timeout(TimeoutPhase::Total))??;
        Ok((result, request_deadline_unix_ms))
    }

    fn build_request(
        &self,
        operation: Operation,
        now_unix_ms: i64,
        request_id: Uuid,
    ) -> Result<RequestEnvelope, ClientError> {
        if now_unix_ms >= self.expires_at_unix_ms {
            return Err(ClientError::Expired);
        }
        let local_deadline = now_unix_ms
            .checked_add(REQUEST_DEADLINE_MS)
            .ok_or(ClientError::Clock)?;
        Ok(RequestEnvelope {
            version: PROTOCOL_VERSION,
            capability_id: self.capability_id,
            token: self.token.protocol_token()?,
            request_id,
            deadline_unix_ms: local_deadline.min(self.expires_at_unix_ms),
            operation,
        })
    }

    async fn exchange(&self, request: RequestEnvelope) -> Result<OperationResult, ClientError> {
        let request_id = request.request_id;
        let frame = serde_json::to_vec(&request).map_err(|_| ClientError::InvalidRequest)?;
        let frame_len = frame.len();
        if frame_len > MAX_WIRE_FRAME_BYTES {
            return Err(ClientError::RequestTooLarge);
        }

        let (ws_stream, _) = timeout(self.timeouts.connect, connect_async(self.endpoint.as_str()))
            .await
            .map_err(|_| ClientError::Timeout(TimeoutPhase::Connect))?
            .map_err(|_| ClientError::Connect)?;

        let (mut write, mut read) = ws_stream.split();

        timeout(
            self.timeouts.write,
            write.send(tokio_tungstenite::tungstenite::Message::Binary(
                frame.into(),
            )),
        )
        .await
        .map_err(|_| ClientError::Timeout(TimeoutPhase::Write))?
        .map_err(|_| ClientError::Write)?;

        let response = timeout(self.timeouts.read, async {
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(tokio_tungstenite::tungstenite::Message::Binary(data)) => return Ok(data),
                    Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                        return Ok(text.into());
                    }
                    Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
                        return Err(ClientError::Read)
                    }
                    Ok(_) => continue,
                    Err(_) => return Err(ClientError::Read),
                }
            }
            Err(ClientError::Read)
        })
        .await
        .map_err(|_| ClientError::Timeout(TimeoutPhase::Read))?
        .map_err(|_| ClientError::Read)?;
        drop(read);
        drop(write);
        let response = SecureResponseFrame::try_new(response)?;

        if response.as_ref().len() > MAX_WIRE_FRAME_BYTES {
            return Err(ClientError::ResponseTooLarge);
        }

        parse_response(response.as_ref(), request_id)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn with_timeouts(mut self, timeouts: ClientTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }
}

fn validate_secret_lease(
    result: &OperationResult,
    expected_secret_key: &str,
    issued_at_unix_ms: i64,
    release_at_unix_ms: i64,
    request_deadline_unix_ms: i64,
    capability_expires_at_unix_ms: i64,
) -> Result<(), ClientError> {
    match result {
        OperationResult::SecretLease {
            secret_key,
            expires_at_unix_ms,
            ..
        } if secret_key == expected_secret_key
            && *expires_at_unix_ms > issued_at_unix_ms
            && *expires_at_unix_ms > release_at_unix_ms
            && *expires_at_unix_ms <= request_deadline_unix_ms
            && *expires_at_unix_ms <= capability_expires_at_unix_ms =>
        {
            Ok(())
        }
        OperationResult::SecretLease { .. } => Err(ClientError::InvalidSecretLease),
        _ => Err(ClientError::UnexpectedResult),
    }
}

fn os_value(value: Option<OsString>) -> Result<OsString, ClientError> {
    value.ok_or(ClientError::IncompleteProjection)
}

/// Validates a broker endpoint: scheme MUST be `ws`, host MUST be an IPv4
/// address (loopback, LAN, or Tailscale 100.x), port MUST be non-zero, no
/// path/query/fragment/credentials. This is deliberately permissive: address
/// enforcement is the endpoint provider's concern.
fn parse_endpoint(value: &str) -> Result<Url, ClientError> {
    let url = Url::parse(value).map_err(|_| ClientError::InvalidEndpoint)?;
    if url.scheme() != "ws"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "/" && !url.path().is_empty())
    {
        return Err(ClientError::InvalidEndpoint);
    }
    let addr: std::net::Ipv4Addr = url
        .host_str()
        .ok_or(ClientError::InvalidEndpoint)?
        .parse()
        .map_err(|_| ClientError::InvalidEndpoint)?;
    let port = url
        .port()
        .filter(|p| *p != 0)
        .ok_or(ClientError::InvalidEndpoint)?;
    let canonical = format!("ws://{addr}:{port}/");
    if url.as_str() != canonical {
        return Err(ClientError::InvalidEndpoint);
    }
    Ok(url)
}

fn unix_now_ms() -> Result<i64, ClientError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClientError::Clock)?;
    i64::try_from(duration.as_millis()).map_err(|_| ClientError::Clock)
}

fn parse_response(bytes: &[u8], request_id: Uuid) -> Result<OperationResult, ClientError> {
    if bytes.len() > MAX_WIRE_FRAME_BYTES {
        return Err(ClientError::ResponseTooLarge);
    }
    if bytes.is_empty() || bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(ClientError::InvalidFrame);
    }

    let response: ResponseEnvelope =
        serde_json::from_slice(bytes).map_err(|_| ClientError::InvalidResponse)?;
    if response.version != PROTOCOL_VERSION {
        return Err(ClientError::UnsupportedVersion);
    }
    if response.request_id != request_id {
        return Err(ClientError::RequestIdMismatch);
    }
    match response.into_result_or_error() {
        Ok(result) => Ok(result),
        Err(Some(kind)) => Err(ClientError::Broker(kind)),
        Err(None) => Err(ClientError::InvalidResponse),
    }
}

fn contains_header_break(value: &str) -> bool {
    value.contains(['\r', '\n'])
}

fn valid_auth_tag_json(value: &str) -> bool {
    serde_json::from_str::<Vec<String>>(value)
        .ok()
        .is_some_and(|fields| fields.len() == 4 && fields.first().is_some_and(|tag| tag == "auth"))
}

#[cfg(test)]
mod secure_response_frame_tests {
    use super::*;

    #[test]
    fn shared_response_storage_is_rejected_instead_of_copied() {
        let bytes = tokio_tungstenite::tungstenite::Bytes::from_static(b"secret response");
        assert!(SecureResponseFrame::try_new(bytes).is_err());
    }

    #[test]
    fn uniquely_owned_response_storage_can_be_wiped_in_place() {
        let bytes = tokio_tungstenite::tungstenite::Bytes::from(b"secret response".to_vec());
        let mut frame = SecureResponseFrame::try_new(bytes).expect("unique response storage");
        frame.zeroize_now();
        assert!(frame.as_ref().iter().all(|byte| *byte == 0));
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests;
