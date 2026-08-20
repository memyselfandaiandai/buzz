//! Secret-safe protocol and authorization core for a future trusted Buzz
//! signing broker.
//!
//! This crate deliberately performs no I/O and owns no long-lived key. It
//! validates narrowly structured operations and manages short-lived capability
//! state. A future trusted broker supplies cryptographic implementations through
//! [`TrustedOperationExecutor`].

mod policy;
mod protocol;
mod registry;

pub use policy::{
    CapabilityScope, HttpPathRule, HttpScopeRule, ScopeBuildError, ScopeBuilder,
    MAX_POLICY_IDENTIFIER_BYTES, MAX_SECRET_POLICY_ENTRIES, MAX_SECRET_TOOL_POLICY_ENTRIES,
};
pub use protocol::{
    BlossomAction, BlossomSignRequest, CapabilityToken, EngramBuildEventRequest,
    EngramCoordinateRequest, EngramDecryptRequest, GitNip98SignRequest, GitObjectKind,
    GitObjectSignRequest, HttpMethod, IdentityMetadata, Nip42SignRequest, Nip98SignRequest,
    NostrEventSignRequest, Operation, OperationKind, OperationResult, ProtocolError, RelayOrigin,
    RequestEnvelope, ResponseEnvelope, SecretLeaseRequest, StableErrorKind, StructuredTag,
    TrustedExecutionError, TrustedOperationExecutor, PROTOCOL_VERSION,
};
pub use registry::{
    is_tailscale_endpoint, is_tailscale_ipv4, AuthorizationOutcome, AuthorizationPermit,
    AuthorizedOperation, BudgetLimits, CapabilityDescriptor, CapabilityRegistry, CapabilityState,
    ClockReading, IssueError, IssuedCapability, RegistrySnapshot, MAX_CAPABILITY_IN_FLIGHT,
    MAX_CAPABILITY_LIFETIME_MS, MAX_CAPABILITY_OPERATIONS, MAX_CAPABILITY_PAYLOAD_BYTES,
    MAX_REGISTRY_CAPABILITIES, MAX_REGISTRY_RESPONSE_BYTES, MAX_REPLAYS_PER_REQUEST,
};

#[cfg(test)]
mod tests;
