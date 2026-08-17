//! Provider-neutral durable turn lifecycle authority for Buzz.
//!
//! The crate owns admission, lifecycle events, receipt and terminal outboxes,
//! and active-turn projections. Transport, model execution, UI, credentials,
//! and workspace provisioning remain adapters.

mod model;
mod scheduler;
mod schema;
mod store;

#[cfg(feature = "cards-automations-skills")]
pub mod automations;
#[cfg(feature = "cards-automations-skills")]
pub mod human_cards;
#[cfg(feature = "cards-automations-skills")]
pub mod skill_curator;
#[cfg(feature = "cards-automations-skills")]
pub mod spend_guard;

pub use model::{
    ActivationCapability, ActivationOutcome, ActiveTurnCursor, ActiveTurnPage, AdmissionOutcome,
    AdmissionRequest, CancelOutcome, DeliveryMode, DispatchIntent, LaunchFence, OutboxKind,
    OutboxRecord, OutboxState, QueueAdmissionOutcome, RecoveryAction, RecoveryItem,
    RejectionOutcome, RetentionEnforceResult, RetentionPolicy, RetentionUsage, RuntimeLease,
    RuntimeLeaseIdentity, TerminalUpdate, TransitionOutcome, TurnEvent, TurnSnapshot, TurnState,
};
pub use scheduler::{
    ClaimDecision, LaneHeads, RunClaim, RunClaimIdentity, RunClaimPhase, RunLane, RunLaneCapacity,
    RunLaneDiagnostics, RunSchedulerSnapshot, ScheduleIntent, ScheduledAdmissionOutcome,
    ScheduledHead, SchedulerCounters, SchedulerPolicy, SchedulerPolicyError,
};
pub use store::{LifecycleError, LifecycleStore, Result};

#[cfg(feature = "cards-automations-skills")]
pub use automations::{
    AutomationBroker, AutomationDefinition, AutomationRun, AutomationRunState, AutomationWake,
};
#[cfg(feature = "cards-automations-skills")]
pub use human_cards::{
    CardAnswer, CardChoice, CardKind, HumanCard, HumanCardBroker, TranscriptEntry,
};
#[cfg(feature = "cards-automations-skills")]
pub use skill_curator::preflight_two_frames;
#[cfg(feature = "cards-automations-skills")]
pub use skill_curator::{
    CaptureManifest, DryRunRequest, DryRunResult, ManifestFile, PreflightCheck, PreflightFrame,
    PreflightResult, SkillCurator, SkillVersion,
};
#[cfg(feature = "cards-automations-skills")]
pub use spend_guard::{SpendGuardConfig, SpendGuardState};
