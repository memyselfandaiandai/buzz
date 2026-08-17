use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::LifecycleError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    Normal,
    Retry,
    MergedSteer,
    MergedInterrupt,
}

impl DeliveryMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Retry => "retry",
            Self::MergedSteer => "merged_steer",
            Self::MergedInterrupt => "merged_interrupt",
        }
    }
}

impl FromStr for DeliveryMode {
    type Err = LifecycleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "normal" => Ok(Self::Normal),
            "retry" => Ok(Self::Retry),
            "merged_steer" => Ok(Self::MergedSteer),
            "merged_interrupt" => Ok(Self::MergedInterrupt),
            other => Err(LifecycleError::CorruptDeliveryMode(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchIntent {
    pub prompt_tag: String,
    pub delivery_mode: DeliveryMode,
    pub retry_count: u32,
    pub not_before_ms: i64,
    pub rule_fingerprint: Option<String>,
}

impl DispatchIntent {
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self.prompt_tag.is_empty() || self.not_before_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "dispatch intent requires a prompt tag and non-negative schedule",
            ));
        }
        if self.rule_fingerprint.as_deref().is_some_and(str::is_empty) {
            return Err(LifecycleError::InvalidRequest(
                "rule fingerprint must be absent or non-empty",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    Rehydrate,
    WaitUntilDue,
    HoldUncertain,
    MissingDispatchIntent,
}

impl RecoveryAction {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Rehydrate => "rehydrate",
            Self::WaitUntilDue => "wait_until_due",
            Self::HoldUncertain => "hold_uncertain",
            Self::MissingDispatchIntent => "missing_dispatch_intent",
        }
    }
}

impl FromStr for RecoveryAction {
    type Err = LifecycleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "rehydrate" => Ok(Self::Rehydrate),
            "wait_until_due" => Ok(Self::WaitUntilDue),
            "hold_uncertain" => Ok(Self::HoldUncertain),
            "missing_dispatch_intent" => Ok(Self::MissingDispatchIntent),
            other => Err(LifecycleError::CorruptRecoveryAction(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryItem {
    pub turn: TurnSnapshot,
    pub prior_state: TurnState,
    pub dispatch: Option<DispatchIntent>,
    pub action: RecoveryAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeLease {
    pub owner_id: String,
    pub agent_id: String,
    pub instance_id: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLeaseIdentity {
    pub owner_id: String,
    pub agent_id: String,
    pub instance_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnState {
    Accepted,
    Queued,
    Running,
    Waiting,
    Completed,
    Failed,
    Cancelled,
    Expired,
    Rejected,
}

impl TurnState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Expired | Self::Rejected
        )
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub(crate) const fn allows(self, next: Self) -> bool {
        use TurnState::{
            Accepted, Cancelled, Completed, Expired, Failed, Queued, Rejected, Running, Waiting,
        };
        matches!(
            (self, next),
            (
                Accepted,
                Queued | Running | Waiting | Completed | Failed | Cancelled | Expired | Rejected
            ) | (
                Queued,
                Running | Waiting | Completed | Failed | Cancelled | Expired | Rejected
            ) | (
                Running,
                Queued | Waiting | Completed | Failed | Cancelled | Expired | Rejected
            ) | (
                Waiting,
                Queued | Running | Completed | Failed | Cancelled | Expired | Rejected
            )
        )
    }
}

impl std::fmt::Display for TurnState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for TurnState {
    type Err = LifecycleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "accepted" => Ok(Self::Accepted),
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "waiting" => Ok(Self::Waiting),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            "rejected" => Ok(Self::Rejected),
            other => Err(LifecycleError::CorruptState(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRequest {
    pub owner_id: String,
    pub agent_id: String,
    pub requester_id: String,
    pub channel_id: String,
    pub client_nonce: String,
    pub input_digest: String,
    pub received_at_ms: i64,
    pub expires_at_ms: i64,
}

impl AdmissionRequest {
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self.owner_id.is_empty()
            || self.agent_id.is_empty()
            || self.requester_id.is_empty()
            || self.channel_id.is_empty()
            || self.client_nonce.is_empty()
            || self.input_digest.is_empty()
        {
            return Err(LifecycleError::InvalidRequest(
                "turn identifiers and digest must be non-empty",
            ));
        }
        if self.received_at_ms < 0 || self.expires_at_ms <= self.received_at_ms {
            return Err(LifecycleError::InvalidRequest(
                "expiry must be later than the non-negative receipt time",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnSnapshot {
    pub turn_id: String,
    pub owner_id: String,
    pub agent_id: String,
    pub requester_id: String,
    pub channel_id: String,
    pub client_nonce: String,
    pub input_digest: String,
    pub state: TurnState,
    pub execution_id: Option<String>,
    pub result_digest: Option<String>,
    pub version: u64,
    pub accepted_at_ms: i64,
    pub updated_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Stable keyset cursor for the bounded active-turn projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveTurnCursor {
    pub accepted_at_ms: i64,
    pub turn_id: String,
}

/// One bounded page of the authoritative active-turn projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveTurnPage {
    pub turns: Vec<TurnSnapshot>,
    pub next_cursor: Option<ActiveTurnCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOutcome {
    Accepted(TurnSnapshot),
    Duplicate(TurnSnapshot),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueAdmissionOutcome {
    Accepted(TurnSnapshot),
    Repaired(TurnSnapshot),
    Duplicate(TurnSnapshot),
}

impl QueueAdmissionOutcome {
    pub fn turn(&self) -> &TurnSnapshot {
        match self {
            Self::Accepted(turn) | Self::Repaired(turn) | Self::Duplicate(turn) => turn,
        }
    }

    pub const fn should_enqueue(&self) -> bool {
        matches!(self, Self::Accepted(_) | Self::Repaired(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionOutcome {
    Rejected(TurnSnapshot),
    Duplicate(TurnSnapshot),
}

impl RejectionOutcome {
    pub fn turn(&self) -> &TurnSnapshot {
        match self {
            Self::Rejected(turn) | Self::Duplicate(turn) => turn,
        }
    }
}

impl AdmissionOutcome {
    pub fn turn(&self) -> &TurnSnapshot {
        match self {
            Self::Accepted(turn) | Self::Duplicate(turn) => turn,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionOutcome {
    Applied(TurnSnapshot),
    Idempotent(TurnSnapshot),
}

impl TransitionOutcome {
    pub fn turn(&self) -> &TurnSnapshot {
        match self {
            Self::Applied(turn) | Self::Idempotent(turn) => turn,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalUpdate {
    pub state: TurnState,
    pub result_digest: Option<String>,
    pub payload: serde_json::Value,
    pub occurred_at_ms: i64,
}

impl TerminalUpdate {
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if !self.state.is_terminal() {
            return Err(LifecycleError::InvalidRequest(
                "terminal update requires a terminal state",
            ));
        }
        if self.occurred_at_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "terminal timestamp must be non-negative",
            ));
        }
        if matches!(self.state, TurnState::Completed | TurnState::Failed)
            && self.result_digest.as_deref().is_none_or(str::is_empty)
        {
            return Err(LifecycleError::InvalidRequest(
                "completed and failed turns require a result digest",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnEvent {
    pub sequence: u64,
    pub event_id: String,
    pub turn_id: String,
    pub owner_id: String,
    pub kind: TurnState,
    pub from_state: Option<TurnState>,
    pub to_state: TurnState,
    pub payload: serde_json::Value,
    pub occurred_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxKind {
    Receipt,
    Terminal,
}

impl OutboxKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Receipt => "receipt",
            Self::Terminal => "terminal",
        }
    }
}

impl FromStr for OutboxKind {
    type Err = LifecycleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "receipt" => Ok(Self::Receipt),
            "terminal" => Ok(Self::Terminal),
            other => Err(LifecycleError::CorruptOutboxKind(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxState {
    Pending,
    Delivered,
}

impl FromStr for OutboxState {
    type Err = LifecycleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pending" => Ok(Self::Pending),
            "delivered" => Ok(Self::Delivered),
            other => Err(LifecycleError::CorruptOutboxState(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxRecord {
    pub outbox_id: String,
    pub turn_id: String,
    pub owner_id: String,
    pub kind: OutboxKind,
    pub dedupe_key: String,
    pub payload: serde_json::Value,
    pub state: OutboxState,
    pub attempts: u32,
    pub not_before_ms: i64,
    pub created_at_ms: i64,
    pub delivered_at_ms: Option<i64>,
    pub claim_token: Option<String>,
    pub claim_expires_at_ms: Option<i64>,
    pub delivered_event_id: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub owner_id: String,
    pub agent_id: String,
    /// TTL in days, 7..=90
    pub retention_days: i64,
    /// Soft watermark bytes, 256 MiB .. 2 GiB
    pub soft_bytes: i64,
    /// Hard watermark bytes, >= soft, 256 MiB .. 2 GiB
    pub hard_bytes: i64,
    pub updated_at_ms: i64,
}

impl RetentionPolicy {
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self.owner_id.is_empty() || self.agent_id.is_empty() {
            return Err(crate::LifecycleError::InvalidRequest("retention owner/agent must be non-empty"));
        }
        if !(7..=90).contains(&self.retention_days) {
            return Err(crate::LifecycleError::InvalidRequest("retention_days must be between 7 and 90"));
        }
        const MIN: i64 = 256 * 1024 * 1024;
        const MAX: i64 = 2 * 1024 * 1024 * 1024;
        if !(MIN..=MAX).contains(&self.soft_bytes) || !(MIN..=MAX).contains(&self.hard_bytes) || self.hard_bytes < self.soft_bytes {
            return Err(crate::LifecycleError::InvalidRequest("retention bytes out of range or hard < soft"));
        }
        if self.updated_at_ms < 0 {
            return Err(crate::LifecycleError::InvalidRequest("retention updated_at must be non-negative"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionUsage {
    pub pruneable_count: i64,
    pub tombstone_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionEnforceResult {
    pub pruned: i64,
    pub ttl_pruned: i64,
    pub size_pruned: i64,
    pub vacuumed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchFence {
    pub owner_id: String,
    pub agent_id: String,
    pub launch_epoch: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationCapability {
    pub capability_id: String,
    pub owner_id: String,
    pub agent_id: String,
    pub launch_epoch: i64,
    pub consumed: bool,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelOutcome {
    Cancelled(TurnSnapshot),
    AlreadyTerminal(TurnSnapshot),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationOutcome {
    Activated(Box<TurnSnapshot>),
    AlreadyConsumed,
    NotFound,
    CancelledConflict,
}

