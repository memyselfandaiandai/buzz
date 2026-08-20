use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::{
    BlossomAction, HttpMethod, Operation, OperationKind, ProtocolError, RelayOrigin,
    StableErrorKind,
};

const MAX_OPERATION_BYTES: usize = 1024 * 1024;
const MAX_EVENT_CONTENT_BYTES: usize = 512 * 1024;
const MAX_TAGS: usize = 256;
const MAX_TAG_FIELDS: usize = 16;
const MAX_TAG_FIELD_BYTES: usize = 4096;
const MAX_PATH_BYTES: usize = 2048;
const MAX_CHALLENGE_BYTES: usize = 4096;
const MAX_MIME_BYTES: usize = 255;
const MAX_SLUG_BYTES: usize = 256;
const MAX_GIT_PAYLOAD_BYTES: usize = 768 * 1024;
const MAX_EVENT_KINDS: usize = 64;
const MAX_HTTP_RULES: usize = 64;
const MAX_CHANNEL_IDS: usize = 256;
const MAX_PEER_PUBKEYS: usize = 256;

/// Maximum UTF-8 byte length of one secret or tool policy identifier.
pub const MAX_POLICY_IDENTIFIER_BYTES: usize = 256;
/// Maximum number of explicit secret identifiers in one capability scope.
pub const MAX_SECRET_POLICY_ENTRIES: usize = 256;
/// Maximum number of explicit secret-consuming tool identifiers in one scope.
pub const MAX_SECRET_TOOL_POLICY_ENTRIES: usize = 256;

fn valid_policy_identifier(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_POLICY_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
}

/// Exact or segment-prefix path constraint for relay-bound HTTP authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "match", content = "path", rename_all = "snake_case")]
pub enum HttpPathRule {
    /// Match one exact root-relative path, including any query string.
    Exact(String),
    /// Match a root-relative path prefix on a segment boundary.
    Prefix(String),
}

impl HttpPathRule {
    fn validate(&self) -> Result<(), ScopeBuildError> {
        let path = match self {
            Self::Exact(path) | Self::Prefix(path) => path,
        };
        validate_path(path).map_err(|_| ScopeBuildError::InvalidHttpPath)?;
        if matches!(self, Self::Prefix(_)) && path.contains('?') {
            return Err(ScopeBuildError::InvalidHttpPath);
        }
        Ok(())
    }

    fn matches(&self, requested: &str) -> bool {
        match self {
            Self::Exact(path) => requested == path,
            Self::Prefix(prefix) => {
                let requested_path = requested.split('?').next().unwrap_or(requested);
                requested_path == prefix
                    || requested_path
                        .strip_prefix(prefix)
                        .is_some_and(|tail| prefix.ends_with('/') || tail.starts_with('/'))
            }
        }
    }
}

/// One allowed HTTP method/path pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpScopeRule {
    /// Allowed method.
    pub method: HttpMethod,
    /// Allowed exact path or path prefix.
    pub path: HttpPathRule,
}

/// Validated operation scope carried by one capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityScope {
    relay: RelayOrigin,
    operations: BTreeSet<OperationKind>,
    event_kinds: BTreeSet<u32>,
    http_rules: Vec<HttpScopeRule>,
    channel_ids: BTreeSet<String>,
    peer_pubkeys: BTreeSet<String>,
    allowed_secrets: BTreeSet<String>,
    allowed_secret_tools: BTreeSet<String>,
}

impl CapabilityScope {
    /// Return the capability-bound relay.
    pub const fn relay(&self) -> &RelayOrigin {
        &self.relay
    }

    /// Return whether an operation discriminator is allowed.
    pub fn allows_operation(&self, operation: OperationKind) -> bool {
        self.operations.contains(&operation)
    }

    /// Return the explicit secret identifiers authorized by this scope.
    pub fn allowed_secrets(&self) -> impl Iterator<Item = &str> {
        self.allowed_secrets.iter().map(String::as_str)
    }

    /// Return the explicit tool identifiers authorized to consume leases.
    pub fn allowed_secret_tools(&self) -> impl Iterator<Item = &str> {
        self.allowed_secret_tools.iter().map(String::as_str)
    }

    pub(crate) fn validate(&self) -> Result<(), ScopeBuildError> {
        if self.operations.is_empty() {
            return Err(ScopeBuildError::NoOperations);
        }
        if self.operations.contains(&OperationKind::SecretLease)
            && (self.allowed_secrets.is_empty()
                || self.allowed_secret_tools.is_empty()
                || self
                    .allowed_secrets
                    .iter()
                    .any(|value| value.trim().is_empty())
                || self
                    .allowed_secret_tools
                    .iter()
                    .any(|value| value.trim().is_empty()))
        {
            return Err(ScopeBuildError::UnconstrainedSecretLease);
        }
        if self
            .allowed_secrets
            .iter()
            .chain(self.allowed_secret_tools.iter())
            .any(|value| !valid_policy_identifier(value))
        {
            return Err(ScopeBuildError::InvalidResource);
        }
        if self.event_kinds.len() > MAX_EVENT_KINDS
            || self.http_rules.len() > MAX_HTTP_RULES
            || self.channel_ids.len() > MAX_CHANNEL_IDS
            || self.peer_pubkeys.len() > MAX_PEER_PUBKEYS
            || self.allowed_secrets.len() > MAX_SECRET_POLICY_ENTRIES
            || self.allowed_secret_tools.len() > MAX_SECRET_TOOL_POLICY_ENTRIES
        {
            return Err(ScopeBuildError::TooManyConstraints);
        }
        for rule in &self.http_rules {
            rule.path.validate()?;
        }
        if self
            .channel_ids
            .iter()
            .any(|value| !valid_resource_id(value))
        {
            return Err(ScopeBuildError::InvalidResource);
        }
        if self.peer_pubkeys.iter().any(|value| !valid_pubkey(value)) {
            return Err(ScopeBuildError::InvalidPublicKey);
        }
        Ok(())
    }

    pub(crate) fn authorize(&self, operation: &Operation) -> Result<(), ProtocolError> {
        let operation_bytes = operation.serialized_bytes()?.len();
        if operation_bytes > MAX_OPERATION_BYTES {
            return Err(ProtocolError::new(StableErrorKind::PayloadTooLarge));
        }
        if !self.operations.contains(&operation.kind()) {
            return Err(ProtocolError::new(StableErrorKind::OperationNotAllowed));
        }
        match operation {
            Operation::IdentityMetadata => Ok(()),
            Operation::NostrEventSign(request) => {
                self.check_relay(&request.relay)?;
                validate_event_shape(request)?;
                if !self.event_kinds.contains(&request.kind) {
                    return Err(ProtocolError::new(StableErrorKind::EventKindNotAllowed));
                }
                self.check_channel_scope(&request.tags)
            }
            Operation::Nip98Sign(request) => {
                self.check_relay(&request.relay)?;
                validate_path(&request.path)?;
                validate_optional_hash(request.payload_sha256.as_deref())?;
                if matches!(request.method, HttpMethod::Post | HttpMethod::Put)
                    && request.payload_sha256.is_none()
                {
                    return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
                }
                self.check_http(request.method, &request.path)
            }
            Operation::Nip42Sign(request) => {
                self.check_relay(&request.relay)?;
                if request.challenge.is_empty() {
                    return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
                }
                if request.challenge.len() > MAX_CHALLENGE_BYTES {
                    return Err(ProtocolError::new(StableErrorKind::PayloadTooLarge));
                }
                Ok(())
            }
            Operation::BlossomSign(request) => {
                self.check_relay(&request.relay)?;
                validate_optional_hash(request.object_sha256.as_deref())?;
                match request.action {
                    BlossomAction::Get => {
                        if request.mime_type.is_some() {
                            return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
                        }
                    }
                    BlossomAction::Upload => {
                        if request.object_sha256.is_none()
                            || request.mime_type.as_deref().is_none_or(str::is_empty)
                        {
                            return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
                        }
                    }
                }
                if request
                    .mime_type
                    .as_ref()
                    .is_some_and(|mime| mime.len() > MAX_MIME_BYTES || mime.contains(['\r', '\n']))
                {
                    return Err(ProtocolError::new(StableErrorKind::PayloadTooLarge));
                }
                Ok(())
            }
            Operation::EngramCoordinate(request) => {
                self.check_relay(&request.relay)?;
                validate_pubkey_and_slug(&request.peer_pubkey, &request.slug)?;
                self.check_peer(&request.peer_pubkey)
            }
            Operation::EngramDecrypt(request) => {
                self.check_relay(&request.relay)?;
                validate_pubkey(&request.peer_pubkey)?;
                if request.event_json.is_empty() {
                    return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
                }
                self.check_peer(&request.peer_pubkey)
            }
            Operation::EngramBuildEvent(request) => {
                self.check_relay(&request.relay)?;
                validate_pubkey_and_slug(&request.owner_pubkey, &request.slug)?;
                if request
                    .value
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_EVENT_CONTENT_BYTES)
                {
                    return Err(ProtocolError::new(StableErrorKind::PayloadTooLarge));
                }
                self.check_peer(&request.owner_pubkey)
            }
            Operation::GitNip98Sign(request) => {
                self.check_relay(&request.relay)?;
                validate_path(&request.repository_path)?;
                self.check_http(request.method, &request.repository_path)
            }
            Operation::GitObjectSign(request) => {
                self.check_relay(&request.relay)?;
                validate_pubkey(&request.key_id)?;
                if request.payload.is_empty() {
                    return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
                }
                if request.payload.len() > MAX_GIT_PAYLOAD_BYTES {
                    return Err(ProtocolError::new(StableErrorKind::PayloadTooLarge));
                }
                Ok(())
            }
            Operation::SecretLease(request) => {
                if !valid_policy_identifier(&request.secret_key)
                    || !valid_policy_identifier(&request.tool_name)
                {
                    return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
                }
                if !self.allowed_secrets.contains(&request.secret_key)
                    || !self.allowed_secret_tools.contains(&request.tool_name)
                {
                    return Err(ProtocolError::new(StableErrorKind::ResourceNotAllowed));
                }
                Ok(())
            }
        }
    }

    fn check_relay(&self, relay: &RelayOrigin) -> Result<(), ProtocolError> {
        if relay == &self.relay {
            Ok(())
        } else {
            Err(ProtocolError::new(StableErrorKind::RelayNotAllowed))
        }
    }

    fn check_http(&self, method: HttpMethod, path: &str) -> Result<(), ProtocolError> {
        let matching_method: Vec<_> = self
            .http_rules
            .iter()
            .filter(|rule| rule.method == method)
            .collect();
        if matching_method.is_empty() {
            return Err(ProtocolError::new(StableErrorKind::MethodNotAllowed));
        }
        if matching_method.iter().any(|rule| rule.path.matches(path)) {
            Ok(())
        } else {
            Err(ProtocolError::new(StableErrorKind::PathNotAllowed))
        }
    }

    fn check_channel_scope(
        &self,
        tags: &[crate::protocol::StructuredTag],
    ) -> Result<(), ProtocolError> {
        if self.channel_ids.is_empty() {
            return Ok(());
        }
        let channel_tags: Vec<_> = tags
            .iter()
            .filter(|tag| tag.0.first().is_some_and(|name| name == "h"))
            .collect();
        match channel_tags.as_slice() {
            [tag] => match tag.0.as_slice() {
                [name, value] if name == "h" && self.channel_ids.contains(value) => Ok(()),
                _ => Err(ProtocolError::new(StableErrorKind::ResourceNotAllowed)),
            },
            _ => Err(ProtocolError::new(StableErrorKind::ResourceNotAllowed)),
        }
    }

    fn check_peer(&self, peer: &str) -> Result<(), ProtocolError> {
        if self.peer_pubkeys.is_empty() || self.peer_pubkeys.contains(peer) {
            Ok(())
        } else {
            Err(ProtocolError::new(StableErrorKind::ResourceNotAllowed))
        }
    }
}

/// Builder for a validated capability scope.
pub struct ScopeBuilder {
    scope: CapabilityScope,
}

impl ScopeBuilder {
    /// Start a scope bound to one canonical relay.
    pub fn new(relay: RelayOrigin) -> Self {
        Self {
            scope: CapabilityScope {
                relay,
                operations: BTreeSet::new(),
                event_kinds: BTreeSet::new(),
                http_rules: Vec::new(),
                channel_ids: BTreeSet::new(),
                peer_pubkeys: BTreeSet::new(),
                allowed_secrets: BTreeSet::new(),
                allowed_secret_tools: BTreeSet::new(),
            },
        }
    }

    /// Allow one structured operation.
    pub fn allow_operation(mut self, operation: OperationKind) -> Self {
        self.scope.operations.insert(operation);
        self
    }

    /// Allow leasing a specific secret key.
    pub fn allow_secret(mut self, secret_key: impl Into<String>) -> Self {
        self.scope.allowed_secrets.insert(secret_key.into());
        self
    }

    /// Allow leasing secrets for a specific tool.
    pub fn allow_secret_tool(mut self, tool_name: impl Into<String>) -> Self {
        self.scope.allowed_secret_tools.insert(tool_name.into());
        self
    }

    /// Allow one Nostr event kind for `nostr_event_sign`.
    pub fn allow_event_kind(mut self, kind: u32) -> Self {
        self.scope.event_kinds.insert(kind);
        self
    }

    /// Allow one HTTP method/path rule for NIP-98 operations.
    pub fn allow_http(mut self, method: HttpMethod, path: HttpPathRule) -> Self {
        self.scope.http_rules.push(HttpScopeRule { method, path });
        self
    }

    /// Restrict channel-scoped events to one channel id.
    pub fn allow_channel(mut self, channel_id: impl Into<String>) -> Self {
        self.scope.channel_ids.insert(channel_id.into());
        self
    }

    /// Restrict engram operations to one peer/owner public key.
    pub fn allow_peer(mut self, peer_pubkey: impl Into<String>) -> Self {
        self.scope.peer_pubkeys.insert(peer_pubkey.into());
        self
    }

    /// Validate and build the scope.
    pub fn build(self) -> Result<CapabilityScope, ScopeBuildError> {
        self.scope.validate()?;
        Ok(self.scope)
    }
}

/// Non-sensitive capability-scope construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ScopeBuildError {
    /// A capability must authorize at least one operation.
    #[error("capability scope must allow at least one operation")]
    NoOperations,
    /// Secret leasing requires explicit non-empty secret and tool constraints.
    #[error("secret lease scope must constrain both secrets and tools")]
    UnconstrainedSecretLease,
    /// A scope contains more constraints than the protocol permits.
    #[error("capability scope contains too many constraints")]
    TooManyConstraints,
    /// An HTTP path constraint is malformed.
    #[error("capability scope contains an invalid HTTP path")]
    InvalidHttpPath,
    /// A resource identifier is malformed.
    #[error("capability scope contains an invalid resource identifier")]
    InvalidResource,
    /// A public key is malformed.
    #[error("capability scope contains an invalid public key")]
    InvalidPublicKey,
}

fn validate_event_shape(
    request: &crate::protocol::NostrEventSignRequest,
) -> Result<(), ProtocolError> {
    if request.content.len() > MAX_EVENT_CONTENT_BYTES
        || request.tags.len() > MAX_TAGS
        || request.tags.iter().any(|tag| {
            tag.0.is_empty()
                || tag.0.len() > MAX_TAG_FIELDS
                || tag.0.iter().any(|field| field.len() > MAX_TAG_FIELD_BYTES)
        })
    {
        return Err(ProtocolError::new(StableErrorKind::PayloadTooLarge));
    }
    if request
        .tags
        .iter()
        .any(|tag| tag.0.first().is_some_and(|name| name == "auth"))
    {
        return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), ProtocolError> {
    let bare = path.split('?').next().unwrap_or(path);
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['\r', '\n', '#', '\\'])
        || bare.split('/').any(|segment| matches!(segment, "." | ".."))
        || path.to_ascii_lowercase().contains("%2e")
        || path.to_ascii_lowercase().contains("%2f")
        || path.to_ascii_lowercase().contains("%5c")
    {
        return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
    }
    Ok(())
}

fn validate_optional_hash(value: Option<&str>) -> Result<(), ProtocolError> {
    if value.is_none_or(valid_hash) {
        Ok(())
    } else {
        Err(ProtocolError::new(StableErrorKind::InvalidPayload))
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_pubkey(value: &str) -> Result<(), ProtocolError> {
    if valid_pubkey(value) {
        Ok(())
    } else {
        Err(ProtocolError::new(StableErrorKind::InvalidPayload))
    }
}

fn valid_pubkey(value: &str) -> bool {
    valid_hash(value)
}

fn validate_pubkey_and_slug(pubkey: &str, slug: &str) -> Result<(), ProtocolError> {
    validate_pubkey(pubkey)?;
    if slug.is_empty() || slug.len() > MAX_SLUG_BYTES || slug.chars().any(char::is_control) {
        return Err(ProtocolError::new(StableErrorKind::InvalidPayload));
    }
    Ok(())
}

fn valid_resource_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_:.".contains(character))
}
