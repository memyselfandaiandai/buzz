//! Deterministic lane scheduling policy and bounded scheduler projections.

use std::str::FromStr;

use crate::LifecycleError;

/// A lane of runnable work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunLane {
    /// Direct user work, which has the normal highest priority.
    User,
    /// Work initiated by another agent.
    Agent,
    /// Deferred or maintenance work.
    Background,
}

impl RunLane {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Agent => "agent",
            Self::Background => "background",
        }
    }
}

/// Maximum pending work retained in each scheduler lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLaneCapacity {
    /// Maximum queued or waiting user turns.
    pub user: u64,
    /// Maximum queued or waiting agent turns.
    pub agent: u64,
    /// Maximum queued or waiting background turns.
    pub background: u64,
}

impl RunLaneCapacity {
    /// Returns the configured capacity for a lane.
    pub const fn for_lane(self, lane: RunLane) -> u64 {
        match lane {
            RunLane::User => self.user,
            RunLane::Agent => self.agent,
            RunLane::Background => self.background,
        }
    }
}

/// A scheduler-owned active execution identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunClaimIdentity {
    /// Monotonic epoch allocated in the owner/agent scheduler scope.
    pub epoch: u64,
    /// Caller-provided execution identifier.
    pub execution_id: String,
}

/// One turn atomically selected and bound by the durable scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunClaim {
    /// Fencing identity required for settlement.
    pub identity: RunClaimIdentity,
    /// Immutable lane selected for the turn.
    pub lane: RunLane,
    /// Immutable source selected for the turn.
    pub source: String,
    /// Dispatch parameters persisted atomically with admission.
    pub dispatch: crate::DispatchIntent,
    /// Opaque signed input envelope persisted atomically with admission.
    pub opaque_input_json: String,
    /// Claimed turn after its transition to running.
    pub turn: crate::TurnSnapshot,
}

/// Durable launch phase of an active scheduler claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunClaimPhase {
    /// Ledger reservation exists, but provider execution has not started.
    Reserved,
    /// Provider execution was launched; restart outcome is uncertain.
    Launched,
}

/// Result of atomic scheduled admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduledAdmissionOutcome {
    /// A new turn was admitted into its lane.
    Accepted(crate::TurnSnapshot),
    /// An interrupted earlier admission was repaired without changing classification.
    Repaired(crate::TurnSnapshot),
    /// An exact replay observed the already durable result.
    Duplicate(crate::TurnSnapshot),
    /// A new nonce was durably rejected because its selected lane was full.
    RejectedCapacity(crate::TurnSnapshot),
    /// A new nonce was already expired when admission was evaluated.
    RejectedExpired(crate::TurnSnapshot),
}

impl ScheduledAdmissionOutcome {
    /// Returns the durable turn for every outcome.
    pub fn turn(&self) -> &crate::TurnSnapshot {
        match self {
            Self::Accepted(turn)
            | Self::Repaired(turn)
            | Self::Duplicate(turn)
            | Self::RejectedCapacity(turn) => turn,
            Self::RejectedExpired(turn) => turn,
        }
    }

    /// Returns whether an adapter should enqueue a newly runnable item.
    pub const fn should_enqueue(&self) -> bool {
        matches!(self, Self::Accepted(_) | Self::Repaired(_))
    }
}

impl FromStr for RunLane {
    type Err = LifecycleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "user" => Ok(Self::User),
            "agent" => Ok(Self::Agent),
            "background" => Ok(Self::Background),
            other => Err(LifecycleError::CorruptRunLane(other.to_owned())),
        }
    }
}

/// Immutable scheduling classification attached to a dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleIntent {
    lane: RunLane,
    source: String,
}

impl ScheduleIntent {
    /// Builds an intent with a non-empty source of at most 64 characters.
    pub fn new(lane: RunLane, source: impl Into<String>) -> crate::Result<Self> {
        let source = source.into();
        if source.is_empty() || source.chars().count() > 64 {
            return Err(LifecycleError::InvalidRequest(
                "schedule source must contain between 1 and 64 characters",
            ));
        }
        Ok(Self { lane, source })
    }

    /// Returns the dispatch lane.
    pub const fn lane(&self) -> RunLane {
        self.lane
    }

    /// Returns the bounded dispatch source.
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Constant-cardinality diagnostics for one scheduler lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLaneDiagnostics {
    /// Lane described by this entry.
    pub lane: RunLane,
    /// Number of queued or waiting turns in the lane.
    pub depth: u64,
    /// Earliest receipt time among the pending turns.
    pub oldest_accepted_at_ms: Option<i64>,
    /// Earliest dispatch eligibility time among the pending turns.
    pub oldest_due_at_ms: Option<i64>,
}

impl RunLaneDiagnostics {
    const fn empty(lane: RunLane) -> Self {
        Self {
            lane,
            depth: 0,
            oldest_accepted_at_ms: None,
            oldest_due_at_ms: None,
        }
    }
}

/// Fixed-size projection of one owner/agent scheduler scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSchedulerSnapshot {
    /// Owner that bounds every field in this projection.
    pub owner_id: String,
    /// Agent that bounds lane and active-run state.
    pub agent_id: String,
    /// User, agent, and background diagnostics, always in that order.
    pub lanes: [RunLaneDiagnostics; 3],
    /// Epoch that the next claim will allocate.
    pub next_epoch: u64,
    /// Active claim epoch, when a run is in flight.
    pub active_epoch: Option<u64>,
    /// Active execution identifier, when a run is in flight.
    pub active_execution_id: Option<String>,
    /// Active run lane, when a run is in flight.
    pub active_lane: Option<RunLane>,
    /// Active run source, when a run is in flight.
    pub active_source: Option<String>,
    /// Time at which the active run was claimed.
    pub active_started_at_ms: Option<i64>,
    /// Durable launch phase of the active claim.
    pub active_phase: Option<RunClaimPhase>,
    /// Durable lane-fairness counters.
    pub counters: SchedulerCounters,
    /// Last scheduler-state mutation time, absent before the first claim.
    pub updated_at_ms: Option<i64>,
    /// Highest lifecycle event sequence for the owner projection.
    pub owner_event_sequence: u64,
}

impl RunSchedulerSnapshot {
    pub(crate) fn empty(owner_id: &str, agent_id: &str) -> Self {
        Self {
            owner_id: owner_id.to_owned(),
            agent_id: agent_id.to_owned(),
            lanes: [
                RunLaneDiagnostics::empty(RunLane::User),
                RunLaneDiagnostics::empty(RunLane::Agent),
                RunLaneDiagnostics::empty(RunLane::Background),
            ],
            next_epoch: 1,
            active_epoch: None,
            active_execution_id: None,
            active_lane: None,
            active_source: None,
            active_started_at_ms: None,
            active_phase: None,
            counters: SchedulerCounters::default(),
            updated_at_ms: None,
            owner_event_sequence: 0,
        }
    }

    /// Returns diagnostics for a lane without allocating or searching a map.
    pub const fn lane(&self, lane: RunLane) -> &RunLaneDiagnostics {
        match lane {
            RunLane::User => &self.lanes[0],
            RunLane::Agent => &self.lanes[1],
            RunLane::Background => &self.lanes[2],
        }
    }

    pub(crate) fn set_lane(&mut self, diagnostics: RunLaneDiagnostics) {
        let index = match diagnostics.lane {
            RunLane::User => 0,
            RunLane::Agent => 1,
            RunLane::Background => 2,
        };
        self.lanes[index] = diagnostics;
    }
}

/// The FIFO head supplied by each lane queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneHeads<T> {
    /// Oldest runnable user item, if any.
    pub user: Option<T>,
    /// Oldest runnable agent item, if any.
    pub agent: Option<T>,
    /// Oldest runnable background item, if any.
    pub background: Option<T>,
}

impl<T> LaneHeads<T> {
    /// Returns an empty set of lane heads.
    pub const fn empty() -> Self {
        Self {
            user: None,
            agent: None,
            background: None,
        }
    }
}

/// Consecutive successful claims for which each promotable lane was pending but not selected.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerCounters {
    /// Claims that bypassed a pending agent head.
    pub agent_bypasses: u64,
    /// Claims that bypassed a pending background head.
    pub background_bypasses: u64,
}

/// A selected lane and its caller-supplied FIFO head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledHead<T> {
    /// Lane selected by the policy.
    pub lane: RunLane,
    /// FIFO head supplied for that lane.
    pub head: T,
}

/// The result of applying the policy to one claim opportunity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimDecision<T> {
    /// Selected head, or `None` when every lane was empty.
    pub selected: Option<ScheduledHead<T>>,
    /// Counters to persist for the next claim opportunity.
    pub counters: SchedulerCounters,
}

/// Invalid scheduler policy configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SchedulerPolicyError {
    /// Promotion thresholds must be strictly positive.
    #[error("{lane:?} promotion threshold must be positive")]
    ZeroPromotionThreshold {
        /// Lane whose threshold was zero.
        lane: RunLane,
    },
}

/// Pure policy that chooses one of three supplied FIFO lane heads.
///
/// Normal priority is user, agent, then background. A pending background lane
/// is promoted first when its bypass counter reaches its threshold, followed by
/// an eligible agent promotion. This ordering bounds simultaneous promotions
/// ahead of a user head to background and agent, in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerPolicy {
    agent_promotion_threshold: u64,
    background_promotion_threshold: u64,
}

impl Default for SchedulerPolicy {
    fn default() -> Self {
        Self {
            agent_promotion_threshold: 8,
            background_promotion_threshold: 32,
        }
    }
}

impl SchedulerPolicy {
    /// Builds a policy with positive agent and background promotion thresholds.
    pub const fn new(
        agent_promotion_threshold: u64,
        background_promotion_threshold: u64,
    ) -> Result<Self, SchedulerPolicyError> {
        if agent_promotion_threshold == 0 {
            return Err(SchedulerPolicyError::ZeroPromotionThreshold {
                lane: RunLane::Agent,
            });
        }
        if background_promotion_threshold == 0 {
            return Err(SchedulerPolicyError::ZeroPromotionThreshold {
                lane: RunLane::Background,
            });
        }
        Ok(Self {
            agent_promotion_threshold,
            background_promotion_threshold,
        })
    }

    /// Returns the agent-lane promotion threshold.
    pub const fn agent_promotion_threshold(self) -> u64 {
        self.agent_promotion_threshold
    }

    /// Returns the background-lane promotion threshold.
    pub const fn background_promotion_threshold(self) -> u64 {
        self.background_promotion_threshold
    }

    /// Selects a supplied FIFO head and deterministically advances the counters.
    ///
    /// A counter resets when its lane is selected or absent. Otherwise it is
    /// incremented with saturation. Empty claim opportunities select nothing
    /// and reset both counters because neither promotable lane is pending.
    pub fn claim<T>(self, counters: SchedulerCounters, heads: LaneHeads<T>) -> ClaimDecision<T> {
        let user_present = heads.user.is_some();
        let agent_present = heads.agent.is_some();
        let background_present = heads.background.is_some();

        let selected_lane = if background_present
            && counters.background_bypasses >= self.background_promotion_threshold
        {
            Some(RunLane::Background)
        } else if agent_present && counters.agent_bypasses >= self.agent_promotion_threshold {
            Some(RunLane::Agent)
        } else if user_present {
            Some(RunLane::User)
        } else if agent_present {
            Some(RunLane::Agent)
        } else if background_present {
            Some(RunLane::Background)
        } else {
            None
        };

        let next_counters = SchedulerCounters {
            agent_bypasses: advance_counter(
                counters.agent_bypasses,
                agent_present,
                selected_lane == Some(RunLane::Agent),
            ),
            background_bypasses: advance_counter(
                counters.background_bypasses,
                background_present,
                selected_lane == Some(RunLane::Background),
            ),
        };

        let selected = match selected_lane {
            Some(RunLane::User) => heads.user.map(|head| ScheduledHead {
                lane: RunLane::User,
                head,
            }),
            Some(RunLane::Agent) => heads.agent.map(|head| ScheduledHead {
                lane: RunLane::Agent,
                head,
            }),
            Some(RunLane::Background) => heads.background.map(|head| ScheduledHead {
                lane: RunLane::Background,
                head,
            }),
            None => None,
        };

        ClaimDecision {
            selected,
            counters: next_counters,
        }
    }
}

const fn advance_counter(current: u64, present: bool, selected: bool) -> u64 {
    if !present || selected {
        0
    } else {
        current.saturating_add(1)
    }
}
