use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde_json::json;
use thiserror::Error;
use uuid::Uuid;

use crate::model::{
    ActiveTurnCursor, ActiveTurnPage, AdmissionOutcome,
    AdmissionRequest, DeliveryMode, DispatchIntent, OutboxKind,
    OutboxRecord, OutboxState, QueueAdmissionOutcome, RecoveryAction, RecoveryItem,
    RejectionOutcome,
    RuntimeLease, RuntimeLeaseIdentity, TerminalUpdate, TransitionOutcome, TurnEvent, TurnSnapshot,
    TurnState,
};
use crate::scheduler::{
    LaneHeads, RunClaim, RunClaimIdentity, RunClaimPhase, RunLane, RunLaneCapacity,
    RunLaneDiagnostics, RunSchedulerSnapshot, ScheduleIntent, ScheduledAdmissionOutcome,
    SchedulerCounters, SchedulerPolicy,
};
use crate::schema;

const BUSY_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PAGE_SIZE: usize = 1_000;

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("filesystem: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("turn not found")]
    TurnNotFound,
    #[error("client nonce was already used with different immutable bindings")]
    NonceConflict,
    #[error("invalid transition from {from} to {to}")]
    InvalidTransition { from: TurnState, to: TurnState },
    #[error("turn is already terminal with a conflicting result")]
    TerminalConflict,
    #[error("execution id conflicts with the active turn attempt")]
    ExecutionConflict,
    #[error("corrupt turn state: {0}")]
    CorruptState(String),
    #[error("corrupt outbox kind: {0}")]
    CorruptOutboxKind(String),
    #[error("corrupt outbox state: {0}")]
    CorruptOutboxState(String),
    #[error("stored sequence does not fit the public representation")]
    SequenceOutOfRange,
    #[error("stored attempt count does not fit the public representation")]
    AttemptOutOfRange,
    #[error("unsupported lifecycle schema version: {0}")]
    UnsupportedSchemaVersion(u32),
    #[error("outbox claim does not match the active delivery lease")]
    OutboxClaimConflict,
    #[error("runtime lease is held until {expires_at_ms}")]
    RuntimeLeaseHeld { expires_at_ms: i64 },
    #[error("runtime lease is absent, expired, or owned by another instance")]
    RuntimeLeaseConflict,
    #[error("dispatch intent conflicts with the accepted turn")]
    DispatchConflict,
    #[error("scheduler lane or source conflicts with the accepted turn")]
    ScheduleConflict,
    #[error("the owner/agent scheduler already has an active execution")]
    SchedulerBusy,
    #[error("scheduler claim does not match the active execution and epoch")]
    SchedulerClaimConflict,
    #[error("corrupt delivery mode: {0}")]
    CorruptDeliveryMode(String),
    #[error("corrupt recovery action: {0}")]
    CorruptRecoveryAction(String),
    #[error("corrupt run lane: {0}")]
    CorruptRunLane(String),
    #[error("recovery queue acknowledgement conflicts with the durable marker")]
    RecoveryMarkerConflict,
    #[error("legacy lifecycle mutation conflicts with scheduler authority for this scope")]
    SchedulerModeConflict,
    #[error("retention policy conflict")]
    RetentionPolicyConflict,
    #[error("launch capability already consumed")]
    CapabilityConsumed,
    #[error("launch capability not found")]
    CapabilityNotFound,
    #[error("launch fence conflict: cancel took the epoch")]
    LaunchFenceCancelled,
}

pub type Result<T> = std::result::Result<T, LifecycleError>;

#[derive(Debug, Clone)]
pub struct LifecycleStore {
    path: PathBuf,
}

impl LifecycleStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let store = Self { path };
        store.initialize()?;
        Ok(store)
    }

    pub fn schema_version(&self) -> Result<u32> {
        let connection = self.connection()?;
        Ok(connection.query_row(
            "SELECT version FROM lifecycle_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn journal_mode(&self) -> Result<String> {
        let connection = self.connection()?;
        Ok(connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?)
    }

    pub fn admit(&self, request: &AdmissionRequest) -> Result<AdmissionOutcome> {
        request.validate()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_request_not_scheduler(&transaction, request)?;
        let outcome = admit_in_transaction(&transaction, request)?;
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn reject_admission(
        &self,
        request: &AdmissionRequest,
        reason_code: &str,
        detail: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<RejectionOutcome> {
        request.validate()?;
        if reason_code.is_empty()
            || reason_code.len() > 64
            || !reason_code.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
            || occurred_at_ms < 0
        {
            return Err(LifecycleError::InvalidRequest(
                "rejection requires a bounded reason code and non-negative timestamp",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_request_not_scheduler(&transaction, request)?;
        let outcome = reject_admission_in_transaction(
            &transaction,
            request,
            reason_code,
            detail,
            occurred_at_ms,
        )?;
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn reject_admission_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        request: &AdmissionRequest,
        reason_code: &str,
        detail: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<RejectionOutcome> {
        validate_runtime_authority(authority, occurred_at_ms)?;
        request.validate()?;
        validate_rejection(reason_code, occurred_at_ms)?;
        if request.owner_id != authority.owner_id || request.agent_id != authority.agent_id {
            return Err(LifecycleError::RuntimeLeaseConflict);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, occurred_at_ms)?;
        assert_legacy_scope(&transaction, authority)?;
        let outcome = reject_admission_in_transaction(
            &transaction,
            request,
            reason_code,
            detail,
            occurred_at_ms,
        )?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Persists a scheduler-policy rejection under the scheduler runtime lease.
    ///
    /// This is the only rejection path allowed after scheduler authority has
    /// been activated for an owner/agent scope. It never installs a runnable
    /// dispatch or creates an active execution.
    pub fn reject_scheduled_admission_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        request: &AdmissionRequest,
        reason_code: &str,
        detail: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<RejectionOutcome> {
        validate_runtime_authority(authority, occurred_at_ms)?;
        request.validate()?;
        validate_rejection(reason_code, occurred_at_ms)?;
        if request.owner_id != authority.owner_id || request.agent_id != authority.agent_id {
            return Err(LifecycleError::RuntimeLeaseConflict);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, occurred_at_ms)?;
        assert_scheduler_activation_safe(&transaction, authority)?;
        ensure_scheduler_state(&transaction, authority, occurred_at_ms)?;
        let outcome = reject_admission_in_transaction(
            &transaction,
            request,
            reason_code,
            detail,
            occurred_at_ms,
        )?;
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn admit_queued(
        &self,
        request: &AdmissionRequest,
        dispatch: &DispatchIntent,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<AdmissionOutcome> {
        Ok(
            match self.admit_queued_decision(request, dispatch, payload, occurred_at_ms)? {
                QueueAdmissionOutcome::Accepted(turn) => AdmissionOutcome::Accepted(turn),
                QueueAdmissionOutcome::Repaired(turn) | QueueAdmissionOutcome::Duplicate(turn) => {
                    AdmissionOutcome::Duplicate(turn)
                }
            },
        )
    }

    pub fn admit_queued_decision(
        &self,
        request: &AdmissionRequest,
        dispatch: &DispatchIntent,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<QueueAdmissionOutcome> {
        request.validate()?;
        dispatch.validate()?;
        if occurred_at_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "queue timestamp must be non-negative",
            ));
        }
        let payload_json = serde_json::to_string(&payload)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_request_not_scheduler(&transaction, request)?;
        let outcome = admit_queued_in_transaction(
            &transaction,
            request,
            dispatch,
            &payload_json,
            occurred_at_ms,
        )?;
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn admit_queued_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        request: &AdmissionRequest,
        dispatch: &DispatchIntent,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<QueueAdmissionOutcome> {
        validate_runtime_authority(authority, occurred_at_ms)?;
        request.validate()?;
        dispatch.validate()?;
        if request.owner_id != authority.owner_id || request.agent_id != authority.agent_id {
            return Err(LifecycleError::RuntimeLeaseConflict);
        }
        let payload_json = serde_json::to_string(&payload)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, occurred_at_ms)?;
        assert_legacy_scope(&transaction, authority)?;
        let outcome = admit_queued_in_transaction(
            &transaction,
            request,
            dispatch,
            &payload_json,
            occurred_at_ms,
        )?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Atomically admits a classified turn under an injected per-lane capacity.
    ///
    /// Exact nonce replay is resolved before capacity is evaluated. A new turn
    /// that exceeds capacity is retained as a durable rejected tombstone; no
    /// existing turn is evicted. Lane and source are immutable after insertion.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_scheduled_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        request: &AdmissionRequest,
        dispatch: &DispatchIntent,
        schedule: &ScheduleIntent,
        opaque_input_json: &str,
        capacity: RunLaneCapacity,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<ScheduledAdmissionOutcome> {
        validate_runtime_authority(authority, occurred_at_ms)?;
        request.validate()?;
        dispatch.validate()?;
        if opaque_input_json.is_empty()
            || serde_json::from_str::<serde_json::Value>(opaque_input_json).is_err()
        {
            return Err(LifecycleError::InvalidRequest(
                "opaque input must be non-empty valid JSON",
            ));
        }
        if request.owner_id != authority.owner_id || request.agent_id != authority.agent_id {
            return Err(LifecycleError::RuntimeLeaseConflict);
        }
        let payload_json = serde_json::to_string(&payload)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, occurred_at_ms)?;

        assert_scheduler_activation_safe(&transaction, authority)?;
        if let Some(existing) = turn_by_nonce(&transaction, request)? {
            ensure_same_binding(&existing, request)?;
            ensure_dispatch_and_schedule(
                &transaction,
                &existing.turn_id,
                dispatch,
                schedule,
                opaque_input_json,
            )?;
            transaction.commit()?;
            return Ok(ScheduledAdmissionOutcome::Duplicate(existing));
        }
        ensure_scheduler_state(&transaction, authority, occurred_at_ms)?;
        if request.expires_at_ms <= occurred_at_ms {
            let outcome = admit_in_transaction(&transaction, request)?;
            insert_scheduled_dispatch(
                &transaction,
                &outcome.turn().turn_id,
                dispatch,
                schedule,
                opaque_input_json,
            )?;
            let turn = apply_terminal_update(
                &transaction,
                outcome.turn().clone(),
                &TerminalUpdate {
                    state: TurnState::Expired,
                    result_digest: None,
                    payload: json!({"reason": "deadline_elapsed_before_scheduler_admission"}),
                    occurred_at_ms,
                },
            )?
            .turn()
            .clone();
            transaction.commit()?;
            return Ok(ScheduledAdmissionOutcome::RejectedExpired(turn));
        }

        let depth: i64 = transaction.query_row(
            "SELECT COUNT(*)
             FROM turns t JOIN turn_dispatch d ON d.turn_id=t.turn_id
             WHERE t.owner_id=?1 AND t.agent_id=?2 AND t.state IN ('queued','waiting')
               AND d.lane=?3 AND t.expires_at_ms>?4",
            params![
                authority.owner_id,
                authority.agent_id,
                schedule.lane().as_str(),
                occurred_at_ms
            ],
            |row| row.get(0),
        )?;
        let depth = u64::try_from(depth).map_err(|_| LifecycleError::SequenceOutOfRange)?;
        if depth >= capacity.for_lane(schedule.lane()) {
            let outcome = reject_admission_in_transaction(
                &transaction,
                request,
                "scheduler_lane_capacity",
                json!({"lane": schedule.lane().as_str(), "capacity": capacity.for_lane(schedule.lane())}),
                occurred_at_ms,
            )?;
            insert_scheduled_dispatch(
                &transaction,
                &outcome.turn().turn_id,
                dispatch,
                schedule,
                opaque_input_json,
            )?;
            let turn = outcome.turn().clone();
            transaction.commit()?;
            return Ok(ScheduledAdmissionOutcome::RejectedCapacity(turn));
        }

        let admission = admit_in_transaction(&transaction, request)?;
        let current = admission.turn().clone();
        insert_scheduled_dispatch(
            &transaction,
            &current.turn_id,
            dispatch,
            schedule,
            opaque_input_json,
        )?;
        apply_transition(
            &transaction,
            &current,
            TurnState::Queued,
            None,
            None,
            &payload_json,
            occurred_at_ms,
        )?;
        let turn = turn_from_transaction(&transaction, &current.turn_id)?;
        transaction.commit()?;
        Ok(ScheduledAdmissionOutcome::Accepted(turn))
    }

    /// Reads the immutable lane/source classification for a turn.
    pub fn schedule_intent(&self, turn_id: &str) -> Result<Option<ScheduleIntent>> {
        if turn_id.is_empty() {
            return Err(LifecycleError::InvalidRequest("turn id must be non-empty"));
        }
        let connection = self.connection()?;
        schedule_from_connection(&connection, turn_id)
    }

    pub fn mark_queued(
        &self,
        turn_id: &str,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<TransitionOutcome> {
        self.transition(turn_id, TurnState::Queued, None, payload, occurred_at_ms)
    }

    pub fn mark_running(
        &self,
        turn_id: &str,
        execution_id: &str,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<TransitionOutcome> {
        if execution_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "execution id must be non-empty",
            ));
        }
        self.transition(
            turn_id,
            TurnState::Running,
            Some(execution_id),
            payload,
            occurred_at_ms,
        )
    }

    pub fn mark_running_many(
        &self,
        turn_ids: &[String],
        execution_id: &str,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<Vec<TransitionOutcome>> {
        if execution_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "execution id must be non-empty",
            ));
        }
        self.transition_many(
            turn_ids,
            TurnState::Running,
            Some(execution_id),
            None,
            payload,
            occurred_at_ms,
        )
    }

    pub fn mark_waiting(
        &self,
        turn_id: &str,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<TransitionOutcome> {
        self.transition(turn_id, TurnState::Waiting, None, payload, occurred_at_ms)
    }

    pub fn mark_waiting_many(
        &self,
        turn_ids: &[String],
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<Vec<TransitionOutcome>> {
        self.transition_many(
            turn_ids,
            TurnState::Waiting,
            None,
            None,
            payload,
            occurred_at_ms,
        )
    }

    pub fn mark_waiting_many_for_execution(
        &self,
        turn_ids: &[String],
        execution_id: &str,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<Vec<TransitionOutcome>> {
        if execution_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "execution id must be non-empty",
            ));
        }
        self.transition_many(
            turn_ids,
            TurnState::Waiting,
            None,
            Some(execution_id),
            payload,
            occurred_at_ms,
        )
    }

    pub fn mark_terminal(
        &self,
        turn_id: &str,
        update: &TerminalUpdate,
    ) -> Result<TransitionOutcome> {
        update.validate()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = turn_from_transaction(&transaction, turn_id)?;
        assert_turn_not_scheduler(&transaction, &current)?;
        if !current.state.is_terminal() && current.execution_id.is_some() {
            return Err(LifecycleError::ExecutionConflict);
        }
        let outcome = apply_terminal_update(&transaction, current, update)?;
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn mark_terminal_many(
        &self,
        turn_ids: &[String],
        update: &TerminalUpdate,
    ) -> Result<Vec<TransitionOutcome>> {
        self.mark_terminal_many_inner(turn_ids, None, update)
    }

    pub fn mark_terminal_many_for_execution(
        &self,
        turn_ids: &[String],
        execution_id: &str,
        update: &TerminalUpdate,
    ) -> Result<Vec<TransitionOutcome>> {
        if execution_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "execution id must be non-empty",
            ));
        }
        self.mark_terminal_many_inner(turn_ids, Some(execution_id), update)
    }

    fn mark_terminal_many_inner(
        &self,
        turn_ids: &[String],
        expected_execution_id: Option<&str>,
        update: &TerminalUpdate,
    ) -> Result<Vec<TransitionOutcome>> {
        update.validate()?;
        validate_turn_ids(turn_ids)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_turns(&transaction, turn_ids)?;
        for turn in &current {
            assert_turn_not_scheduler(&transaction, turn)?;
        }
        for turn in &current {
            if expected_execution_id.is_some()
                && turn.execution_id.as_deref() != expected_execution_id
            {
                return Err(LifecycleError::ExecutionConflict);
            }
            if expected_execution_id.is_none()
                && !turn.state.is_terminal()
                && turn.execution_id.is_some()
            {
                return Err(LifecycleError::ExecutionConflict);
            }
            if turn.state.is_terminal() {
                let same = turn.state == update.state
                    && turn.result_digest.as_deref() == update.result_digest.as_deref();
                if !same {
                    return Err(LifecycleError::TerminalConflict);
                }
            } else if !turn.state.allows(update.state) {
                return Err(LifecycleError::InvalidTransition {
                    from: turn.state,
                    to: update.state,
                });
            }
        }
        let mut outcomes = Vec::with_capacity(current.len());
        for turn in current {
            if turn.state.is_terminal() {
                outcomes.push(TransitionOutcome::Idempotent(turn));
            } else {
                outcomes.push(apply_terminal_update(&transaction, turn, update)?);
            }
        }
        transaction.commit()?;
        Ok(outcomes)
    }

    pub fn expire_due(&self, now_ms: i64, limit: usize) -> Result<Vec<TurnSnapshot>> {
        if now_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "expiry timestamp must be non-negative",
            ));
        }
        let limit = bounded_limit(limit)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let turn_ids = due_turn_ids(&transaction, now_ms, limit)?;
        let expired = expire_turn_ids_in_transaction(&transaction, turn_ids, now_ms)?;
        transaction.commit()?;
        Ok(expired)
    }

    pub fn expire_due_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<TurnSnapshot>> {
        validate_runtime_authority(authority, now_ms)?;
        let limit = bounded_limit(limit)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, now_ms)?;
        assert_legacy_scope(&transaction, authority)?;
        let turn_ids = due_turn_ids_for_agent(
            &transaction,
            &authority.owner_id,
            &authority.agent_id,
            now_ms,
            limit,
        )?;
        let expired = expire_turn_ids_in_transaction(&transaction, turn_ids, now_ms)?;
        for turn in &expired {
            let schedule = schedule_from_transaction(&transaction, &turn.turn_id)?;
            clear_recovered_active_if_classified(
                &transaction,
                &authority.owner_id,
                &authority.agent_id,
                turn.execution_id.as_deref(),
                schedule.as_ref(),
                now_ms,
            )?;
        }
        transaction.commit()?;
        Ok(expired)
    }

    pub fn turn(&self, turn_id: &str) -> Result<TurnSnapshot> {
        let connection = self.connection()?;
        turn_from_connection(&connection, turn_id)
    }

    pub fn turn_for_nonce(
        &self,
        owner_id: &str,
        agent_id: &str,
        client_nonce: &str,
    ) -> Result<Option<TurnSnapshot>> {
        if owner_id.is_empty() || agent_id.is_empty() || client_nonce.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "owner, agent, and client nonce must be non-empty",
            ));
        }
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                "SELECT turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
                        execution_id,result_digest,version,accepted_at_ms,updated_at_ms,expires_at_ms
                 FROM turns WHERE owner_id=?1 AND agent_id=?2 AND client_nonce=?3",
                params![owner_id, agent_id, client_nonce],
                turn_from_row,
            )
            .optional()?)
    }

    pub fn dispatch_intent(&self, turn_id: &str) -> Result<Option<DispatchIntent>> {
        if turn_id.is_empty() {
            return Err(LifecycleError::InvalidRequest("turn id must be non-empty"));
        }
        let connection = self.connection()?;
        dispatch_from_connection(&connection, turn_id)
    }

    pub fn acquire_runtime_lease(
        &self,
        owner_id: &str,
        agent_id: &str,
        instance_id: &str,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<RuntimeLease> {
        validate_runtime_lease_request(owner_id, agent_id, instance_id, now_ms, expires_at_ms)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = runtime_lease_from_transaction(&transaction, owner_id, agent_id)?;
        if let Some(lease) = existing {
            if lease.instance_id != instance_id && lease.expires_at_ms > now_ms {
                return Err(LifecycleError::RuntimeLeaseHeld {
                    expires_at_ms: lease.expires_at_ms,
                });
            }
            transaction.execute(
                "UPDATE runtime_leases SET instance_id=?3,expires_at_ms=?4
                 WHERE owner_id=?1 AND agent_id=?2",
                params![owner_id, agent_id, instance_id, expires_at_ms],
            )?;
        } else {
            transaction.execute(
                "INSERT INTO runtime_leases(owner_id,agent_id,instance_id,expires_at_ms)
                 VALUES (?1,?2,?3,?4)",
                params![owner_id, agent_id, instance_id, expires_at_ms],
            )?;
        }
        let lease = runtime_lease_from_transaction(&transaction, owner_id, agent_id)?
            .ok_or(LifecycleError::RuntimeLeaseConflict)?;
        transaction.commit()?;
        Ok(lease)
    }

    pub fn renew_runtime_lease(
        &self,
        owner_id: &str,
        agent_id: &str,
        instance_id: &str,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<RuntimeLease> {
        validate_runtime_lease_request(owner_id, agent_id, instance_id, now_ms, expires_at_ms)?;
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE runtime_leases SET expires_at_ms=MAX(expires_at_ms,?5)
             WHERE owner_id=?1 AND agent_id=?2 AND instance_id=?3 AND expires_at_ms>?4",
            params![owner_id, agent_id, instance_id, now_ms, expires_at_ms],
        )?;
        if changed != 1 {
            return Err(LifecycleError::RuntimeLeaseConflict);
        }
        runtime_lease_from_connection(&connection, owner_id, agent_id)?
            .ok_or(LifecycleError::RuntimeLeaseConflict)
    }

    pub fn release_runtime_lease(
        &self,
        owner_id: &str,
        agent_id: &str,
        instance_id: &str,
    ) -> Result<()> {
        if owner_id.is_empty() || agent_id.is_empty() || instance_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "runtime lease identifiers must be non-empty",
            ));
        }
        let connection = self.connection()?;
        let changed = connection.execute(
            "DELETE FROM runtime_leases
             WHERE owner_id=?1 AND agent_id=?2 AND instance_id=?3",
            params![owner_id, agent_id, instance_id],
        )?;
        if changed != 1 {
            return Err(LifecycleError::RuntimeLeaseConflict);
        }
        Ok(())
    }

    pub fn verify_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        now_ms: i64,
    ) -> Result<()> {
        validate_runtime_authority(authority, now_ms)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, now_ms)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn bind_nonces_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        client_nonces: &[String],
        execution_id: &str,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<Vec<TransitionOutcome>> {
        validate_runtime_authority(authority, occurred_at_ms)?;
        validate_client_nonces(client_nonces)?;
        if execution_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "execution id must be non-empty",
            ));
        }
        let payload_json = serde_json::to_string(&payload)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, occurred_at_ms)?;
        assert_legacy_scope(&transaction, authority)?;
        let current = load_turns_for_nonces(&transaction, authority, client_nonces)?;
        let outcomes = transition_many_in_transaction(
            &transaction,
            current,
            TurnState::Running,
            Some(execution_id),
            None,
            &payload_json,
            occurred_at_ms,
        )?;
        transaction.commit()?;
        Ok(outcomes)
    }

    pub fn mark_nonces_waiting_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        client_nonces: &[String],
        execution_id: &str,
        dispatch: &DispatchIntent,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<Vec<TransitionOutcome>> {
        validate_runtime_authority(authority, occurred_at_ms)?;
        validate_client_nonces(client_nonces)?;
        dispatch.validate()?;
        if execution_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "execution id must be non-empty",
            ));
        }
        let payload_json = serde_json::to_string(&payload)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, occurred_at_ms)?;
        assert_legacy_scope(&transaction, authority)?;
        let current = load_turns_for_nonces(&transaction, authority, client_nonces)?;
        for turn in &current {
            update_dispatch(&transaction, &turn.turn_id, dispatch)?;
        }
        let outcomes = transition_many_in_transaction(
            &transaction,
            current,
            TurnState::Waiting,
            None,
            Some(execution_id),
            &payload_json,
            occurred_at_ms,
        )?;
        transaction.commit()?;
        Ok(outcomes)
    }

    pub fn mark_nonces_terminal_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        client_nonces: &[String],
        execution_id: &str,
        update: &TerminalUpdate,
    ) -> Result<Vec<TransitionOutcome>> {
        validate_runtime_authority(authority, update.occurred_at_ms)?;
        validate_client_nonces(client_nonces)?;
        update.validate()?;
        if execution_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "execution id must be non-empty",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, update.occurred_at_ms)?;
        assert_legacy_scope(&transaction, authority)?;
        let current = load_turns_for_nonces(&transaction, authority, client_nonces)?;
        let outcomes =
            terminal_many_in_transaction(&transaction, current, Some(execution_id), update)?;
        transaction.commit()?;
        Ok(outcomes)
    }

    pub fn mark_execution_terminal_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        execution_id: &str,
        update: &TerminalUpdate,
    ) -> Result<Vec<TransitionOutcome>> {
        validate_runtime_authority(authority, update.occurred_at_ms)?;
        update.validate()?;
        if execution_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "execution id must be non-empty",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, update.occurred_at_ms)?;
        assert_legacy_scope(&transaction, authority)?;
        let current =
            active_turns_for_execution_in_transaction(&transaction, authority, execution_id)?;
        if current.is_empty() {
            return Err(LifecycleError::ExecutionConflict);
        }
        let outcomes =
            terminal_many_in_transaction(&transaction, current, Some(execution_id), update)?;
        transaction.commit()?;
        Ok(outcomes)
    }

    pub fn recover_for_restart(
        &self,
        owner_id: &str,
        agent_id: &str,
        instance_id: &str,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<RecoveryItem>> {
        if owner_id.is_empty() || agent_id.is_empty() || instance_id.is_empty() || now_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "restart recovery requires identifiers and a non-negative timestamp",
            ));
        }
        let limit = bounded_limit(limit)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = runtime_lease_from_transaction(&transaction, owner_id, agent_id)?
            .ok_or(LifecycleError::RuntimeLeaseConflict)?;
        if lease.instance_id != instance_id || lease.expires_at_ms <= now_ms {
            return Err(LifecycleError::RuntimeLeaseConflict);
        }
        let turns = active_turns_for_agent_in_transaction(
            &transaction,
            owner_id,
            agent_id,
            instance_id,
            now_ms,
            limit,
        )?;
        let mut recovery = Vec::with_capacity(turns.len());
        for current in turns {
            if current.expires_at_ms <= now_ms {
                let prior_execution_id = current.execution_id.clone();
                let schedule = schedule_from_transaction(&transaction, &current.turn_id)?;
                apply_terminal_update(
                    &transaction,
                    current,
                    &TerminalUpdate {
                        state: TurnState::Expired,
                        result_digest: None,
                        payload: json!({"reason": "deadline_elapsed_during_restart"}),
                        occurred_at_ms: now_ms,
                    },
                )?;
                clear_recovered_active_if_classified(
                    &transaction,
                    owner_id,
                    agent_id,
                    prior_execution_id.as_deref(),
                    schedule.as_ref(),
                    now_ms,
                )?;
                continue;
            }
            let prior_execution_id = current.execution_id.clone();
            let dispatch = dispatch_from_transaction(&transaction, &current.turn_id)?;
            let schedule = schedule_from_transaction(&transaction, &current.turn_id)?;
            let active_phase = scheduler_phase_for_execution(
                &transaction,
                owner_id,
                agent_id,
                prior_execution_id.as_deref(),
            )?;
            let previous_recovery =
                recovery_marker_from_transaction(&transaction, &current.turn_id)?;
            if let Some(marker) = previous_recovery.as_ref().filter(|marker| {
                marker.instance_id == instance_id
                    && marker.recovered_state == current.state
                    && marker.recovered_version == current.version
            }) {
                if marker.action == RecoveryAction::Rehydrate
                    && marker.queue_acknowledged_at_ms.is_some()
                {
                    continue;
                }
                if marker.action == RecoveryAction::WaitUntilDue
                    && dispatch
                        .as_ref()
                        .is_some_and(|intent| intent.not_before_ms <= now_ms)
                {
                    upsert_recovery_marker(
                        &transaction,
                        RecoveryMarkerWrite {
                            turn_id: &current.turn_id,
                            instance_id,
                            prior_state: marker.prior_state,
                            action: RecoveryAction::Rehydrate,
                            recovered_state: current.state,
                            recovered_version: current.version,
                            recovered_at_ms: now_ms,
                        },
                    )?;
                    recovery.push(RecoveryItem {
                        turn: current,
                        prior_state: marker.prior_state,
                        dispatch,
                        action: RecoveryAction::Rehydrate,
                    });
                    continue;
                }
                recovery.push(RecoveryItem {
                    turn: current,
                    prior_state: marker.prior_state,
                    dispatch,
                    action: marker.action,
                });
                continue;
            }
            let preserves_hold = previous_recovery.as_ref().is_some_and(|marker| {
                matches!(
                    marker.action,
                    RecoveryAction::HoldUncertain | RecoveryAction::MissingDispatchIntent
                )
            });
            let prior_state = if preserves_hold {
                previous_recovery
                    .as_ref()
                    .map_or(current.state, |marker| marker.prior_state)
            } else {
                current.state
            };
            let (next_state, action) = if previous_recovery
                .as_ref()
                .is_some_and(|marker| marker.action == RecoveryAction::HoldUncertain)
            {
                (TurnState::Waiting, RecoveryAction::HoldUncertain)
            } else if previous_recovery
                .as_ref()
                .is_some_and(|marker| marker.action == RecoveryAction::MissingDispatchIntent)
                || (current.state == TurnState::Accepted && dispatch.is_none())
            {
                (TurnState::Waiting, RecoveryAction::MissingDispatchIntent)
            } else {
                match current.state {
                    TurnState::Running if active_phase == Some(RunClaimPhase::Reserved) => {
                        (TurnState::Waiting, RecoveryAction::Rehydrate)
                    }
                    TurnState::Running => (TurnState::Waiting, RecoveryAction::HoldUncertain),
                    TurnState::Accepted | TurnState::Queued | TurnState::Waiting => {
                        let action = dispatch.as_ref().map_or(
                            RecoveryAction::MissingDispatchIntent,
                            |intent| {
                                if intent.not_before_ms <= now_ms {
                                    RecoveryAction::Rehydrate
                                } else {
                                    RecoveryAction::WaitUntilDue
                                }
                            },
                        );
                        let state = if current.state == TurnState::Accepted {
                            TurnState::Queued
                        } else {
                            current.state
                        };
                        (state, action)
                    }
                    _ => continue,
                }
            };
            let recovered_turn = if current.state != next_state || current.execution_id.is_some() {
                let payload_json = serde_json::to_string(&json!({
                    "reason": "process_restart",
                    "recoveryInstanceId": instance_id,
                    "priorState": prior_state,
                    "action": action,
                }))?;
                apply_transition(
                    &transaction,
                    &current,
                    next_state,
                    None,
                    None,
                    &payload_json,
                    now_ms,
                )?;
                turn_from_transaction(&transaction, &current.turn_id)?
            } else {
                current.clone()
            };
            upsert_recovery_marker(
                &transaction,
                RecoveryMarkerWrite {
                    turn_id: &current.turn_id,
                    instance_id,
                    prior_state,
                    action,
                    recovered_state: recovered_turn.state,
                    recovered_version: recovered_turn.version,
                    recovered_at_ms: now_ms,
                },
            )?;
            if current.state == TurnState::Running {
                clear_recovered_active_if_classified(
                    &transaction,
                    owner_id,
                    agent_id,
                    prior_execution_id.as_deref(),
                    schedule.as_ref(),
                    now_ms,
                )?;
            }
            recovery.push(RecoveryItem {
                turn: recovered_turn,
                prior_state,
                dispatch,
                action,
            });
        }
        transaction.commit()?;
        Ok(recovery)
    }

    /// Recovers the single active scheduler claim without scanning queued work.
    ///
    /// The active projection is read directly under the runtime lease, so a
    /// large backlog cannot hide a reserved or launched claim behind a bounded
    /// recovery page. Reserved work is safely requeued; launched or migrated
    /// phase-less work is quarantined as uncertain.
    pub fn recover_scheduler_active_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        now_ms: i64,
    ) -> Result<Option<RecoveryItem>> {
        validate_runtime_authority(authority, now_ms)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, now_ms)?;
        let Some(state) = transaction
            .query_row(
                "SELECT next_epoch,active_epoch,active_execution_id,active_lane,active_source,
                        active_started_at_ms,claims_since_agent,claims_since_background,updated_at_ms,active_phase
                 FROM run_scheduler_state WHERE owner_id=?1 AND agent_id=?2",
                params![authority.owner_id, authority.agent_id],
                scheduler_state_from_row,
            )
            .optional()?
        else {
            transaction.commit()?;
            return Ok(None);
        };
        let (Some(epoch), Some(execution_id), Some(active_lane), Some(active_source)) = (
            state.active_epoch,
            state.active_execution_id,
            state.active_lane,
            state.active_source,
        ) else {
            transaction.commit()?;
            return Ok(None);
        };
        let claim = RunClaimIdentity {
            epoch,
            execution_id: execution_id.clone(),
        };
        let mut turns =
            active_turns_for_execution_in_transaction(&transaction, authority, &execution_id)?;
        if turns.len() != 1 {
            return Err(LifecycleError::SchedulerClaimConflict);
        }
        let current = turns.pop().ok_or(LifecycleError::SchedulerClaimConflict)?;
        if current.state != TurnState::Running {
            return Err(LifecycleError::SchedulerClaimConflict);
        }
        let dispatch = dispatch_from_transaction(&transaction, &current.turn_id)?;
        let schedule = schedule_from_transaction(&transaction, &current.turn_id)?
            .ok_or(LifecycleError::SchedulerClaimConflict)?;
        if schedule.lane() != active_lane || schedule.source() != active_source {
            return Err(LifecycleError::SchedulerClaimConflict);
        }
        if current.expires_at_ms <= now_ms {
            apply_terminal_update(
                &transaction,
                current,
                &TerminalUpdate {
                    state: TurnState::Expired,
                    result_digest: None,
                    payload: json!({"reason":"deadline_elapsed_during_scheduler_restart"}),
                    occurred_at_ms: now_ms,
                },
            )?;
            clear_matching_active_scheduler(&transaction, authority, &claim, now_ms)?;
            transaction.commit()?;
            return Ok(None);
        }

        let action = if state.active_phase == Some(RunClaimPhase::Reserved) {
            RecoveryAction::Rehydrate
        } else {
            RecoveryAction::HoldUncertain
        };
        let prior_state = current.state;
        let payload_json = serde_json::to_string(&json!({
            "reason":"scheduler_process_restart",
            "recoveryInstanceId":authority.instance_id,
            "priorState":prior_state,
            "action":action,
        }))?;
        apply_transition(
            &transaction,
            &current,
            TurnState::Waiting,
            None,
            None,
            &payload_json,
            now_ms,
        )?;
        let recovered_turn = turn_from_transaction(&transaction, &current.turn_id)?;
        upsert_recovery_marker(
            &transaction,
            RecoveryMarkerWrite {
                turn_id: &current.turn_id,
                instance_id: &authority.instance_id,
                prior_state,
                action,
                recovered_state: recovered_turn.state,
                recovered_version: recovered_turn.version,
                recovered_at_ms: now_ms,
            },
        )?;
        clear_matching_active_scheduler(&transaction, authority, &claim, now_ms)?;
        let item = RecoveryItem {
            turn: recovered_turn,
            prior_state,
            dispatch,
            action,
        };
        transaction.commit()?;
        Ok(Some(item))
    }

    pub fn acknowledge_recovery_enqueued_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        turn_id: &str,
        recovered_version: u64,
        now_ms: i64,
    ) -> Result<()> {
        validate_runtime_authority(authority, now_ms)?;
        if turn_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "recovery acknowledgement requires a turn id",
            ));
        }
        let recovered_version_sql =
            i64::try_from(recovered_version).map_err(|_| LifecycleError::SequenceOutOfRange)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, now_ms)?;
        let marker = recovery_marker_from_transaction(&transaction, turn_id)?
            .ok_or(LifecycleError::RecoveryMarkerConflict)?;
        if marker.instance_id != authority.instance_id
            || marker.action != RecoveryAction::Rehydrate
            || marker.recovered_version != recovered_version
        {
            return Err(LifecycleError::RecoveryMarkerConflict);
        }
        let current = turn_from_transaction(&transaction, turn_id)?;
        if current.owner_id != authority.owner_id
            || current.agent_id != authority.agent_id
            || current.state != marker.recovered_state
            || current.version != marker.recovered_version
        {
            return Err(LifecycleError::RecoveryMarkerConflict);
        }
        if marker.queue_acknowledged_at_ms.is_none() {
            let changed = transaction.execute(
                "UPDATE turn_recovery SET queue_acknowledged_at_ms=?2
                 WHERE turn_id=?1 AND instance_id=?3 AND action='rehydrate'
                   AND recovered_version=?4 AND queue_acknowledged_at_ms IS NULL",
                params![
                    turn_id,
                    now_ms,
                    authority.instance_id,
                    recovered_version_sql,
                ],
            )?;
            if changed != 1 {
                return Err(LifecycleError::RecoveryMarkerConflict);
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn reconcile_pending_recovery_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<RecoveryItem>> {
        validate_runtime_authority(authority, now_ms)?;
        let limit = bounded_limit(limit)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, now_ms)?;
        let mut statement = transaction.prepare(
            "SELECT t.turn_id
             FROM turns t
             JOIN turn_recovery r ON r.turn_id=t.turn_id
             LEFT JOIN turn_dispatch d ON d.turn_id=t.turn_id
             WHERE t.owner_id=?1 AND t.agent_id=?2 AND r.instance_id=?3
               AND t.state IN ('accepted','queued','running','waiting')
               AND (
                 (r.action='rehydrate' AND r.queue_acknowledged_at_ms IS NULL)
                 OR (r.action='wait_until_due' AND d.not_before_ms<=?4)
               )
             ORDER BY t.accepted_at_ms,t.turn_id LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![
                authority.owner_id,
                authority.agent_id,
                authority.instance_id,
                now_ms,
                limit,
            ],
            |row| row.get(0),
        )?;
        let turn_ids = rows.collect::<std::result::Result<Vec<String>, _>>()?;
        drop(statement);

        let mut recovery = Vec::with_capacity(turn_ids.len());
        for turn_id in turn_ids {
            let turn = turn_from_transaction(&transaction, &turn_id)?;
            let dispatch = dispatch_from_transaction(&transaction, &turn_id)?;
            let marker = recovery_marker_from_transaction(&transaction, &turn_id)?
                .ok_or(LifecycleError::RecoveryMarkerConflict)?;
            let action = if marker.action == RecoveryAction::WaitUntilDue {
                upsert_recovery_marker(
                    &transaction,
                    RecoveryMarkerWrite {
                        turn_id: &turn_id,
                        instance_id: &authority.instance_id,
                        prior_state: marker.prior_state,
                        action: RecoveryAction::Rehydrate,
                        recovered_state: turn.state,
                        recovered_version: turn.version,
                        recovered_at_ms: now_ms,
                    },
                )?;
                RecoveryAction::Rehydrate
            } else {
                marker.action
            };
            recovery.push(RecoveryItem {
                turn,
                prior_state: marker.prior_state,
                dispatch,
                action,
            });
        }
        transaction.commit()?;
        Ok(recovery)
    }

    /// Read one bounded keyset page of active turns for an owner.
    ///
    /// Pagination happens in SQLite. Callers never need to materialize the
    /// complete lifecycle history before rendering the current projection.
    pub fn active_turns_page(
        &self,
        owner_id: &str,
        after: Option<&ActiveTurnCursor>,
        limit: usize,
    ) -> Result<ActiveTurnPage> {
        validate_projection_request(owner_id, after)?;
        let fetch_limit = bounded_fetch_limit(limit)?;
        let (after_ms, after_turn_id) = projection_cursor_parts(after);
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
                    execution_id,result_digest,version,accepted_at_ms,updated_at_ms,expires_at_ms
             FROM turns
             WHERE owner_id=?1 AND state IN ('accepted','queued','running','waiting')
               AND (?2 IS NULL OR accepted_at_ms>?2 OR (accepted_at_ms=?2 AND turn_id>?3))
             ORDER BY accepted_at_ms,turn_id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![owner_id, after_ms, after_turn_id, fetch_limit],
            turn_from_row,
        )?;
        active_turn_page(rows.collect::<std::result::Result<Vec<_>, _>>()?, limit)
    }

    /// Read one bounded keyset page of active turns for one owner/agent scope.
    pub fn active_turns_for_agent_page(
        &self,
        owner_id: &str,
        agent_id: &str,
        after: Option<&ActiveTurnCursor>,
        limit: usize,
    ) -> Result<ActiveTurnPage> {
        if owner_id.is_empty() || agent_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "owner and agent must be non-empty",
            ));
        }
        validate_projection_request(owner_id, after)?;
        let fetch_limit = bounded_fetch_limit(limit)?;
        let (after_ms, after_turn_id) = projection_cursor_parts(after);
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
                    execution_id,result_digest,version,accepted_at_ms,updated_at_ms,expires_at_ms
             FROM turns
             WHERE owner_id=?1 AND agent_id=?2
               AND state IN ('accepted','queued','running','waiting')
               AND (?3 IS NULL OR accepted_at_ms>?3 OR (accepted_at_ms=?3 AND turn_id>?4))
             ORDER BY accepted_at_ms,turn_id LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![owner_id, agent_id, after_ms, after_turn_id, fetch_limit],
            turn_from_row,
        )?;
        active_turn_page(rows.collect::<std::result::Result<Vec<_>, _>>()?, limit)
    }

    /// Atomically selects the next due FIFO head and binds it to one execution.
    ///
    /// The runtime lease, expiry reconciliation, pure policy decision, running
    /// transition, fairness counters, and active projection are committed in a
    /// single immediate transaction. At most one execution may be active for
    /// an owner/agent scheduler scope.
    pub fn claim_next_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        policy: SchedulerPolicy,
        execution_id: &str,
        payload: serde_json::Value,
        now_ms: i64,
    ) -> Result<Option<RunClaim>> {
        validate_runtime_authority(authority, now_ms)?;
        if execution_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "execution id must be non-empty",
            ));
        }
        let payload_json = serde_json::to_string(&payload)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, now_ms)?;
        assert_scheduler_activation_safe(&transaction, authority)?;
        expire_pending_scheduler_turns(&transaction, authority, now_ms)?;
        ensure_scheduler_state(&transaction, authority, now_ms)?;
        let state = scheduler_state_for_scope(&transaction, authority)?;
        if state.active_execution_id.is_some() {
            return Err(LifecycleError::SchedulerBusy);
        }

        let mut quarantined = 0;
        loop {
            let heads = LaneHeads {
                user: runnable_lane_head(&transaction, authority, RunLane::User, now_ms)?,
                agent: runnable_lane_head(&transaction, authority, RunLane::Agent, now_ms)?,
                background: runnable_lane_head(
                    &transaction,
                    authority,
                    RunLane::Background,
                    now_ms,
                )?,
            };
            let decision = policy.claim(state.counters, heads);
            let Some(selected) = decision.selected else {
                if decision.counters != state.counters {
                    update_scheduler_counters(&transaction, authority, decision.counters, now_ms)?;
                }
                transaction.commit()?;
                return Ok(None);
            };

            if !valid_opaque_input(&selected.head.opaque_input_json) {
                apply_terminal_update(
                    &transaction,
                    selected.head.turn,
                    &TerminalUpdate {
                        state: TurnState::Cancelled,
                        result_digest: None,
                        payload: json!({"reason":"corrupt_scheduler_opaque_input"}),
                        occurred_at_ms: now_ms,
                    },
                )?;
                quarantined += 1;
                if quarantined >= MAX_PAGE_SIZE {
                    transaction.commit()?;
                    return Ok(None);
                }
                continue;
            }

            let epoch = state.next_epoch;
            let next_epoch = epoch
                .checked_add(1)
                .ok_or(LifecycleError::SequenceOutOfRange)?;
            apply_transition(
                &transaction,
                &selected.head.turn,
                TurnState::Running,
                Some(execution_id),
                None,
                &payload_json,
                now_ms,
            )?;
            let changed = transaction.execute(
                "UPDATE run_scheduler_state
                 SET next_epoch=?3,active_epoch=?4,active_execution_id=?5,active_lane=?6,
                     active_source=?7,active_started_at_ms=?8,claims_since_agent=?9,
                     claims_since_background=?10,updated_at_ms=?8,active_phase='reserved'
                 WHERE owner_id=?1 AND agent_id=?2 AND active_execution_id IS NULL",
                params![
                    authority.owner_id,
                    authority.agent_id,
                    to_sql_u64(next_epoch)?,
                    to_sql_u64(epoch)?,
                    execution_id,
                    selected.lane.as_str(),
                    selected.head.source,
                    now_ms,
                    to_sql_u64(decision.counters.agent_bypasses)?,
                    to_sql_u64(decision.counters.background_bypasses)?,
                ],
            )?;
            if changed != 1 {
                return Err(LifecycleError::SchedulerBusy);
            }
            let turn = turn_from_transaction(&transaction, &selected.head.turn.turn_id)?;
            let claim = RunClaim {
                identity: RunClaimIdentity {
                    epoch,
                    execution_id: execution_id.to_owned(),
                },
                lane: selected.lane,
                source: selected.head.source,
                dispatch: selected.head.dispatch,
                opaque_input_json: selected.head.opaque_input_json,
                turn,
            };
            transaction.commit()?;
            return Ok(Some(claim));
        }
    }

    /// Advances a matching reserved claim to launched under the runtime lease.
    pub fn mark_claim_launched_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        claim: &RunClaimIdentity,
        occurred_at_ms: i64,
    ) -> Result<()> {
        validate_runtime_authority(authority, occurred_at_ms)?;
        validate_claim_identity(claim)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, occurred_at_ms)?;
        let turn = active_claim_turn(&transaction, authority, claim)?;
        if turn.state != TurnState::Running || turn.expires_at_ms <= occurred_at_ms {
            if turn.expires_at_ms <= occurred_at_ms {
                apply_terminal_update(
                    &transaction,
                    turn,
                    &TerminalUpdate {
                        state: TurnState::Expired,
                        result_digest: None,
                        payload: json!({"reason":"deadline_elapsed_before_launch"}),
                        occurred_at_ms,
                    },
                )?;
                clear_matching_active_scheduler(&transaction, authority, claim, occurred_at_ms)?;
                transaction.commit()?;
            }
            return Err(LifecycleError::SchedulerClaimConflict);
        }
        let changed=transaction.execute("UPDATE run_scheduler_state SET active_phase='launched',updated_at_ms=?5 WHERE owner_id=?1 AND agent_id=?2 AND active_epoch=?3 AND active_execution_id=?4 AND active_phase='reserved'", params![authority.owner_id,authority.agent_id,to_sql_u64(claim.epoch)?,claim.execution_id,occurred_at_ms])?;
        if changed != 1 {
            return Err(LifecycleError::SchedulerClaimConflict);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Releases the matching active claim back to waiting and clears its slot.
    pub fn release_claim_to_waiting_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        claim: &RunClaimIdentity,
        dispatch: &DispatchIntent,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<TransitionOutcome> {
        validate_runtime_authority(authority, occurred_at_ms)?;
        validate_claim_identity(claim)?;
        dispatch.validate()?;
        let payload_json = serde_json::to_string(&payload)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, occurred_at_ms)?;
        let turn = active_claim_turn(&transaction, authority, claim)?;
        update_dispatch(&transaction, &turn.turn_id, dispatch)?;
        apply_transition(
            &transaction,
            &turn,
            TurnState::Waiting,
            None,
            None,
            &payload_json,
            occurred_at_ms,
        )?;
        clear_matching_active_scheduler(&transaction, authority, claim, occurred_at_ms)?;
        let outcome =
            TransitionOutcome::Applied(turn_from_transaction(&transaction, &turn.turn_id)?);
        transaction.commit()?;
        Ok(outcome)
    }

    /// Applies a terminal update and clears only the matching active claim.
    pub fn finish_claim_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        claim: &RunClaimIdentity,
        update: &TerminalUpdate,
    ) -> Result<TransitionOutcome> {
        validate_runtime_authority(authority, update.occurred_at_ms)?;
        validate_claim_identity(claim)?;
        update.validate()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, update.occurred_at_ms)?;
        let turn = active_claim_turn(&transaction, authority, claim)?;
        let phase = active_claim_phase(&transaction, authority, claim)?;
        if matches!(update.state, TurnState::Completed | TurnState::Failed)
            && phase != RunClaimPhase::Launched
        {
            return Err(LifecycleError::SchedulerClaimConflict);
        }
        if phase == RunClaimPhase::Reserved
            && !matches!(update.state, TurnState::Cancelled | TurnState::Expired)
        {
            return Err(LifecycleError::SchedulerClaimConflict);
        }
        let outcome = apply_terminal_update(&transaction, turn, update)?;
        clear_matching_active_scheduler(&transaction, authority, claim, update.occurred_at_ms)?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Reads the constant-cardinality scheduler projection for one owner/agent.
    ///
    /// The snapshot uses indexed aggregate reads inside one SQLite read
    /// transaction. It never reconstructs scheduler state from lifecycle
    /// events, regardless of event-history size.
    pub fn run_scheduler_snapshot(
        &self,
        owner_id: &str,
        agent_id: &str,
    ) -> Result<RunSchedulerSnapshot> {
        if owner_id.is_empty() || agent_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "owner and agent must be non-empty",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let mut snapshot = RunSchedulerSnapshot::empty(owner_id, agent_id);

        {
            let mut statement = transaction.prepare(
                "SELECT d.lane,COUNT(*),MIN(t.accepted_at_ms),MIN(d.not_before_ms)
                 FROM turns t INDEXED BY turns_owner_agent_active
                 JOIN turn_dispatch d ON d.turn_id=t.turn_id
                 WHERE t.owner_id=?1 AND t.agent_id=?2 AND t.state IN ('queued','waiting')
                 GROUP BY d.lane",
            )?;
            let rows =
                statement.query_map(params![owner_id, agent_id], lane_diagnostics_from_row)?;
            for diagnostics in rows {
                snapshot.set_lane(diagnostics?);
            }
        }

        let scheduler_state = transaction
            .query_row(
                "SELECT next_epoch,active_epoch,active_execution_id,active_lane,active_source,
                        active_started_at_ms,claims_since_agent,claims_since_background,updated_at_ms,active_phase
                 FROM run_scheduler_state WHERE owner_id=?1 AND agent_id=?2",
                params![owner_id, agent_id],
                scheduler_state_from_row,
            )
            .optional()?;
        if let Some(state) = scheduler_state {
            snapshot.next_epoch = state.next_epoch;
            snapshot.active_epoch = state.active_epoch;
            snapshot.active_execution_id = state.active_execution_id;
            snapshot.active_lane = state.active_lane;
            snapshot.active_source = state.active_source;
            snapshot.active_started_at_ms = state.active_started_at_ms;
            snapshot.active_phase = state.active_phase;
            snapshot.counters = state.counters;
            snapshot.updated_at_ms = Some(state.updated_at_ms);
        }

        let maximum_sequence: Option<i64> = transaction.query_row(
            "SELECT MAX(sequence) FROM turn_events WHERE owner_id=?1",
            [owner_id],
            |row| row.get(0),
        )?;
        snapshot.owner_event_sequence = maximum_sequence.map_or(Ok(0), |sequence| {
            u64::try_from(sequence).map_err(|_| LifecycleError::SequenceOutOfRange)
        })?;
        transaction.commit()?;
        Ok(snapshot)
    }

    pub fn turns_for_execution(&self, execution_id: &str) -> Result<Vec<TurnSnapshot>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
                    execution_id,result_digest,version,accepted_at_ms,updated_at_ms,expires_at_ms
             FROM turns WHERE execution_id=?1 ORDER BY accepted_at_ms,turn_id",
        )?;
        let rows = statement.query_map([execution_id], turn_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn events_after(
        &self,
        owner_id: &str,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<TurnEvent>> {
        let limit = bounded_limit(limit)?;
        let after_sequence =
            i64::try_from(after_sequence).map_err(|_| LifecycleError::SequenceOutOfRange)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT sequence,event_id,turn_id,owner_id,kind,from_state,to_state,
                    payload_json,occurred_at_ms
             FROM turn_events
             WHERE owner_id=?1 AND sequence>?2
             ORDER BY sequence LIMIT ?3",
        )?;
        let rows = statement.query_map(params![owner_id, after_sequence, limit], event_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn pending_outbox(&self, now_ms: i64, limit: usize) -> Result<Vec<OutboxRecord>> {
        if now_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "outbox timestamp must be non-negative",
            ));
        }
        let limit = bounded_limit(limit)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT outbox_id,turn_id,owner_id,kind,dedupe_key,payload_json,state,
                    attempts,not_before_ms,created_at_ms,delivered_at_ms,
                    claim_token,claim_expires_at_ms,delivered_event_id
             FROM lifecycle_outbox
             WHERE state='pending' AND not_before_ms<=?1
               AND (claim_token IS NULL OR claim_expires_at_ms<=?1)
             ORDER BY created_at_ms,outbox_id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![now_ms, limit], outbox_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn claim_pending_outbox(
        &self,
        now_ms: i64,
        limit: usize,
        claim_token: &str,
        claim_expires_at_ms: i64,
    ) -> Result<Vec<OutboxRecord>> {
        if now_ms < 0 || claim_expires_at_ms <= now_ms || claim_token.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "outbox claim requires a token and a future expiry",
            ));
        }
        let limit = bounded_limit(limit)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut statement = transaction.prepare(
            "SELECT o.outbox_id
             FROM lifecycle_outbox o JOIN turns t ON t.turn_id=o.turn_id
             WHERE o.state='pending' AND o.not_before_ms<=?1
               AND (o.claim_token IS NULL OR o.claim_expires_at_ms<=?1)
               AND NOT EXISTS (
                 SELECT 1 FROM run_scheduler_state s
                 WHERE s.owner_id=t.owner_id AND s.agent_id=t.agent_id
               )
             ORDER BY o.created_at_ms,o.outbox_id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![now_ms, limit], |row| row.get(0))?;
        let outbox_ids = rows.collect::<std::result::Result<Vec<String>, _>>()?;
        drop(statement);
        for outbox_id in &outbox_ids {
            let changed = transaction.execute(
                "UPDATE lifecycle_outbox
                 SET claim_token=?2,claim_expires_at_ms=?3
                 WHERE outbox_id=?1 AND state='pending'
                   AND (claim_token IS NULL OR claim_expires_at_ms<=?4)",
                params![outbox_id, claim_token, claim_expires_at_ms, now_ms],
            )?;
            if changed != 1 {
                return Err(LifecycleError::OutboxClaimConflict);
            }
        }
        let claimed = outbox_ids
            .iter()
            .map(|outbox_id| outbox_from_transaction(&transaction, outbox_id))
            .collect::<Result<Vec<_>>>()?;
        transaction.commit()?;
        Ok(claimed)
    }

    pub fn claim_pending_outbox_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        now_ms: i64,
        limit: usize,
        claim_token: &str,
        claim_expires_at_ms: i64,
    ) -> Result<Vec<OutboxRecord>> {
        validate_runtime_authority(authority, now_ms)?;
        if claim_expires_at_ms <= now_ms || claim_token.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "outbox claim requires a token and a future expiry",
            ));
        }
        let limit = bounded_limit(limit)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, now_ms)?;
        let mut statement = transaction.prepare(
            "SELECT o.outbox_id
             FROM lifecycle_outbox o JOIN turns t ON t.turn_id=o.turn_id
             WHERE t.owner_id=?1 AND t.agent_id=?2
               AND o.state='pending' AND o.not_before_ms<=?3
               AND (o.claim_token IS NULL OR o.claim_expires_at_ms<=?3)
             ORDER BY o.created_at_ms,o.outbox_id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![authority.owner_id, authority.agent_id, now_ms, limit],
            |row| row.get(0),
        )?;
        let outbox_ids = rows.collect::<std::result::Result<Vec<String>, _>>()?;
        drop(statement);
        for outbox_id in &outbox_ids {
            let changed = transaction.execute(
                "UPDATE lifecycle_outbox
                 SET claim_token=?2,claim_expires_at_ms=?3
                 WHERE outbox_id=?1 AND state='pending'
                   AND (claim_token IS NULL OR claim_expires_at_ms<=?4)",
                params![outbox_id, claim_token, claim_expires_at_ms, now_ms],
            )?;
            if changed != 1 {
                return Err(LifecycleError::OutboxClaimConflict);
            }
        }
        let claimed = outbox_ids
            .iter()
            .map(|outbox_id| outbox_from_transaction(&transaction, outbox_id))
            .collect::<Result<Vec<_>>>()?;
        transaction.commit()?;
        Ok(claimed)
    }

    pub fn record_claimed_outbox_attempt_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        outbox_id: &str,
        claim_token: &str,
        now_ms: i64,
        not_before_ms: i64,
    ) -> Result<OutboxRecord> {
        validate_runtime_authority(authority, now_ms)?;
        if outbox_id.is_empty() || claim_token.is_empty() || not_before_ms < now_ms {
            return Err(LifecycleError::InvalidRequest(
                "claimed outbox retry requires identifiers and a non-past retry timestamp",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, now_ms)?;
        assert_outbox_scope(&transaction, authority, outbox_id)?;
        let changed = transaction.execute(
            "UPDATE lifecycle_outbox
             SET attempts=attempts+1,not_before_ms=MAX(not_before_ms,?3),
                 claim_token=NULL,claim_expires_at_ms=NULL
             WHERE outbox_id=?1 AND state='pending' AND claim_token=?2",
            params![outbox_id, claim_token, not_before_ms],
        )?;
        if changed != 1 {
            return Err(LifecycleError::OutboxClaimConflict);
        }
        let record = outbox_from_transaction(&transaction, outbox_id)?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn mark_claimed_outbox_delivered_for_runtime_lease(
        &self,
        authority: &RuntimeLeaseIdentity,
        outbox_id: &str,
        claim_token: &str,
        delivered_event_id: &str,
        delivered_at_ms: i64,
    ) -> Result<OutboxRecord> {
        validate_runtime_authority(authority, delivered_at_ms)?;
        if outbox_id.is_empty() || claim_token.is_empty() || delivered_event_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "claimed outbox delivery requires identifiers",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_runtime_lease(&transaction, authority, delivered_at_ms)?;
        assert_outbox_scope(&transaction, authority, outbox_id)?;
        let changed = transaction.execute(
            "UPDATE lifecycle_outbox
             SET state='delivered',delivered_at_ms=?4,delivered_event_id=?3,
                 claim_token=NULL,claim_expires_at_ms=NULL
             WHERE outbox_id=?1 AND state='pending' AND claim_token=?2",
            params![outbox_id, claim_token, delivered_event_id, delivered_at_ms],
        )?;
        if changed != 1 {
            let existing = outbox_from_transaction(&transaction, outbox_id)?;
            if existing.state != OutboxState::Delivered
                || existing.delivered_event_id.as_deref() != Some(delivered_event_id)
            {
                return Err(LifecycleError::OutboxClaimConflict);
            }
        }
        let record = outbox_from_transaction(&transaction, outbox_id)?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn record_claimed_outbox_attempt(
        &self,
        outbox_id: &str,
        claim_token: &str,
        not_before_ms: i64,
    ) -> Result<OutboxRecord> {
        if outbox_id.is_empty() || claim_token.is_empty() || not_before_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "claimed outbox retry requires identifiers and a non-negative timestamp",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_outbox_not_scheduler(&transaction, outbox_id)?;
        let changed = transaction.execute(
            "UPDATE lifecycle_outbox
             SET attempts=attempts+1,
                 not_before_ms=MAX(not_before_ms,?3),
                 claim_token=NULL,claim_expires_at_ms=NULL
             WHERE outbox_id=?1 AND state='pending' AND claim_token=?2",
            params![outbox_id, claim_token, not_before_ms],
        )?;
        if changed != 1 {
            return Err(LifecycleError::OutboxClaimConflict);
        }
        let record = outbox_from_transaction(&transaction, outbox_id)?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn mark_claimed_outbox_delivered(
        &self,
        outbox_id: &str,
        claim_token: &str,
        delivered_event_id: &str,
        delivered_at_ms: i64,
    ) -> Result<OutboxRecord> {
        if outbox_id.is_empty()
            || claim_token.is_empty()
            || delivered_event_id.is_empty()
            || delivered_at_ms < 0
        {
            return Err(LifecycleError::InvalidRequest(
                "claimed outbox delivery requires identifiers and a non-negative timestamp",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_outbox_not_scheduler(&transaction, outbox_id)?;
        let changed = transaction.execute(
            "UPDATE lifecycle_outbox
             SET state='delivered',delivered_at_ms=?4,delivered_event_id=?3,
                 claim_token=NULL,claim_expires_at_ms=NULL
             WHERE outbox_id=?1 AND state='pending' AND claim_token=?2",
            params![outbox_id, claim_token, delivered_event_id, delivered_at_ms],
        )?;
        if changed == 1 {
            let record = outbox_from_transaction(&transaction, outbox_id)?;
            transaction.commit()?;
            return Ok(record);
        }
        let existing = outbox_from_transaction(&transaction, outbox_id)?;
        if existing.state == OutboxState::Delivered
            && existing.delivered_event_id.as_deref() == Some(delivered_event_id)
        {
            transaction.commit()?;
            Ok(existing)
        } else {
            Err(LifecycleError::OutboxClaimConflict)
        }
    }

    fn transition(
        &self,
        turn_id: &str,
        next: TurnState,
        execution_id: Option<&str>,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<TransitionOutcome> {
        if occurred_at_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "transition timestamp must be non-negative",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = turn_from_transaction(&transaction, turn_id)?;
        assert_turn_not_scheduler(&transaction, &current)?;
        if current.state == next {
            if next == TurnState::Running && current.execution_id.as_deref() != execution_id {
                return Err(LifecycleError::ExecutionConflict);
            }
            transaction.commit()?;
            return Ok(TransitionOutcome::Idempotent(current));
        }
        if current.state.is_terminal() || !current.state.allows(next) {
            return Err(LifecycleError::InvalidTransition {
                from: current.state,
                to: next,
            });
        }
        let payload_json = serde_json::to_string(&payload)?;
        apply_transition(
            &transaction,
            &current,
            next,
            execution_id.or(current.execution_id.as_deref()),
            None,
            &payload_json,
            occurred_at_ms,
        )?;
        let updated = turn_from_transaction(&transaction, turn_id)?;
        transaction.commit()?;
        Ok(TransitionOutcome::Applied(updated))
    }

    fn transition_many(
        &self,
        turn_ids: &[String],
        next: TurnState,
        execution_id: Option<&str>,
        expected_execution_id: Option<&str>,
        payload: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<Vec<TransitionOutcome>> {
        if occurred_at_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "transition timestamp must be non-negative",
            ));
        }
        validate_turn_ids(turn_ids)?;
        let payload_json = serde_json::to_string(&payload)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_turns(&transaction, turn_ids)?;
        for turn in &current {
            assert_turn_not_scheduler(&transaction, turn)?;
        }
        let outcomes = transition_many_in_transaction(
            &transaction,
            current,
            next,
            execution_id,
            expected_execution_id,
            &payload_json,
            occurred_at_ms,
        )?;
        transaction.commit()?;
        Ok(outcomes)
    }

    // ------------------------------------------------------------------
    // Retention (TTL + size watermark) -- coherent with schema v8
    // ------------------------------------------------------------------
    pub fn set_retention_policy(&self, policy: &crate::RetentionPolicy) -> Result<()> {
        policy.validate()?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO retention_policies(owner_id,agent_id,retention_days,soft_bytes,hard_bytes,updated_at_ms) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(owner_id,agent_id) DO UPDATE SET retention_days=excluded.retention_days, soft_bytes=excluded.soft_bytes, hard_bytes=excluded.hard_bytes, updated_at_ms=excluded.updated_at_ms",
            params![policy.owner_id, policy.agent_id, policy.retention_days, policy.soft_bytes, policy.hard_bytes, policy.updated_at_ms],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn retention_usage(&self, owner_id: &str, agent_id: &str) -> Result<crate::RetentionUsage> {
        if owner_id.is_empty() || agent_id.is_empty() { return Err(LifecycleError::InvalidRequest("owner/agent must be non-empty")); }
        let conn = self.connection()?;
        let pruneable: i64 = conn.query_row("SELECT COUNT(*) FROM turns WHERE owner_id=?1 AND agent_id=?2 AND state IN ('completed','failed','cancelled','expired')", params![owner_id, agent_id], |r| r.get(0))?;
        let tombstone: i64 = conn.query_row("SELECT COUNT(*) FROM turns WHERE owner_id=?1 AND agent_id=?2 AND state='rejected'", params![owner_id, agent_id], |r| r.get(0))?;
        Ok(crate::RetentionUsage { pruneable_count: pruneable, tombstone_count: tombstone })
    }
    pub fn enforce_retention(&self, owner_id: &str, agent_id: &str, now_ms: i64) -> Result<crate::RetentionEnforceResult> {
        if owner_id.is_empty() || agent_id.is_empty() { return Err(LifecycleError::InvalidRequest("owner/agent must be non-empty")); }
        if now_ms < 0 { return Err(LifecycleError::InvalidRequest("now_ms must be non-negative")); }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let policy: Option<(i64,i64,i64)> = tx.query_row("SELECT retention_days, soft_bytes, hard_bytes FROM retention_policies WHERE owner_id=?1 AND agent_id=?2", params![owner_id, agent_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))).optional()?;
        let (retention_days, soft_bytes, _hard_bytes) = match policy { None => return Ok(crate::RetentionEnforceResult { pruned: 0, ttl_pruned: 0, size_pruned: 0, vacuumed: false }), Some(v) => v };
        let day_ms: i64 = 24 * 60 * 60 * 1000;
        let cutoff = now_ms - retention_days * day_ms;
        let mut ttl_pruned: i64 = 0;
        {
            let mut stmt = tx.prepare("SELECT turn_id FROM turns WHERE owner_id=?1 AND agent_id=?2 AND state IN ('completed','failed','cancelled','expired') AND updated_at_ms < ?3 ORDER BY updated_at_ms ASC, turn_id ASC")?;
            let ids: Vec<String> = stmt.query_map(params![owner_id, agent_id, cutoff], |r| r.get(0))?.collect::<std::result::Result<Vec<_>, _>>()?;
            for tid in ids { tx.execute("DELETE FROM turn_events WHERE turn_id=?1", params![tid])?; tx.execute("DELETE FROM lifecycle_outbox WHERE turn_id=?1", params![tid])?; tx.execute("DELETE FROM turn_dispatch WHERE turn_id=?1", params![tid])?; tx.execute("DELETE FROM turns WHERE turn_id=?1", params![tid])?; ttl_pruned += 1; }
        }
        let mut size_pruned: i64 = 0;
        let page_count: i64 = tx.query_row("SELECT COALESCE((SELECT page_count FROM pragma_page_count), 0)", [], |r| r.get(0)).unwrap_or(0);
        let page_size: i64 = tx.query_row("SELECT COALESCE((SELECT page_size FROM pragma_page_size), 4096)", [], |r| r.get(0)).unwrap_or(4096);
        let mut current_bytes: i64 = page_count.saturating_mul(page_size);
        if current_bytes > soft_bytes && current_bytes != 0 {
            let mut stmt = tx.prepare("SELECT turn_id FROM turns WHERE owner_id=?1 AND agent_id=?2 AND state IN ('completed','failed','cancelled','expired') ORDER BY updated_at_ms ASC, turn_id ASC")?;
            let ids: Vec<String> = stmt.query_map(params![owner_id, agent_id], |r| r.get(0))?.collect::<std::result::Result<Vec<_>, _>>()?;
            let approx_row_bytes = page_size.max(4096);
            for tid in ids { if current_bytes <= soft_bytes { break; } tx.execute("DELETE FROM turn_events WHERE turn_id=?1", params![tid])?; tx.execute("DELETE FROM lifecycle_outbox WHERE turn_id=?1", params![tid])?; tx.execute("DELETE FROM turn_dispatch WHERE turn_id=?1", params![tid])?; tx.execute("DELETE FROM turns WHERE turn_id=?1", params![tid])?; size_pruned += 1; current_bytes = current_bytes.saturating_sub(approx_row_bytes); }
        }
        let pruned = ttl_pruned + size_pruned;
        let vacuumed = pruned > 0;
        tx.commit()?;
        if vacuumed { let vac_conn = self.connection()?; let _ = vac_conn.execute("VACUUM", []); }
        Ok(crate::RetentionEnforceResult { pruned, ttl_pruned, size_pruned, vacuumed })
    }

        // ------------------------------------------------------------------
    // Launch fence: inert -> ledger -> epoch -> single-use
    // ------------------------------------------------------------------
    pub fn get_launch_fence(&self, owner_id: &str, agent_id: &str) -> Result<crate::LaunchFence> {
        if owner_id.is_empty() || agent_id.is_empty() { return Err(LifecycleError::InvalidRequest("owner/agent must be non-empty")); }
        let conn = self.connection()?;
        let row: Option<(i64,i64)> = conn.query_row("SELECT launch_epoch, updated_at_ms FROM launch_fences WHERE owner_id=?1 AND agent_id=?2", params![owner_id, agent_id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        if let Some((epoch, updated)) = row { Ok(crate::LaunchFence { owner_id: owner_id.to_owned(), agent_id: agent_id.to_owned(), launch_epoch: epoch, updated_at_ms: updated }) } else { Ok(crate::LaunchFence { owner_id: owner_id.to_owned(), agent_id: agent_id.to_owned(), launch_epoch: 0, updated_at_ms: 0 }) }
    }
    fn ensure_launch_fence_tx(tx: &Transaction<'_>, owner_id: &str, agent_id: &str) -> Result<i64> {
        let row: Option<i64> = tx.query_row("SELECT launch_epoch FROM launch_fences WHERE owner_id=?1 AND agent_id=?2", params![owner_id, agent_id], |r| r.get(0)).optional()?;
        if let Some(epoch) = row { Ok(epoch) } else { tx.execute("INSERT INTO launch_fences(owner_id,agent_id,launch_epoch,updated_at_ms) VALUES (?1,?2,0,0)", params![owner_id, agent_id])?; Ok(0) }
    }
    pub fn create_inert_turn(&self, request: &crate::AdmissionRequest) -> Result<TurnSnapshot> {
        request.validate()?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::ensure_launch_fence_tx(&tx, &request.owner_id, &request.agent_id)?;
        let outcome = admit_in_transaction(&tx, request)?;
        tx.commit()?;
        Ok(outcome.turn().clone())
    }
    pub fn mint_activation_capability(&self, owner_id: &str, agent_id: &str, now_ms: i64) -> Result<crate::ActivationCapability> {
        if owner_id.is_empty() || agent_id.is_empty() { return Err(LifecycleError::InvalidRequest("owner/agent must be non-empty")); }
        if now_ms < 0 { return Err(LifecycleError::InvalidRequest("now_ms must be non-negative")); }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_epoch = Self::ensure_launch_fence_tx(&tx, owner_id, agent_id)?;
        let next_epoch = current_epoch + 1;
        let cap_id = Uuid::new_v4().to_string();
        tx.execute("INSERT INTO activation_capabilities(capability_id,owner_id,agent_id,launch_epoch,consumed,created_at_ms) VALUES (?1,?2,?3,?4,0,?5)", params![cap_id, owner_id, agent_id, next_epoch, now_ms])?;
        // Do not bump fence on mint; fence bumps only on cancel/activate (commit point)
        tx.commit()?;
        Ok(crate::ActivationCapability { capability_id: cap_id, owner_id: owner_id.to_owned(), agent_id: agent_id.to_owned(), launch_epoch: next_epoch, consumed: false, created_at_ms: now_ms })
    }
    pub fn cancel_turn_with_fence(&self, turn_id: &str, now_ms: i64) -> Result<crate::CancelOutcome> {
        if turn_id.is_empty() { return Err(LifecycleError::InvalidRequest("turn_id must be non-empty")); }
        if now_ms < 0 { return Err(LifecycleError::InvalidRequest("now_ms must be non-negative")); }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<TurnSnapshot> = tx.query_row("SELECT turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,execution_id,result_digest,version,accepted_at_ms,updated_at_ms,expires_at_ms FROM turns WHERE turn_id=?1", params![turn_id], turn_from_row).optional().map_err(LifecycleError::Sqlite)?;
        let snap = match current { None => return Ok(crate::CancelOutcome::NotFound), Some(s) => s };
        if snap.state.is_terminal() { return Ok(crate::CancelOutcome::AlreadyTerminal(snap)); }
        let fence_epoch = Self::ensure_launch_fence_tx(&tx, &snap.owner_id, &snap.agent_id)?;
        let next_epoch = fence_epoch + 1;
        tx.execute("UPDATE launch_fences SET launch_epoch=?3, updated_at_ms=?4 WHERE owner_id=?1 AND agent_id=?2", params![snap.owner_id, snap.agent_id, next_epoch, now_ms])?;
        let payload = serde_json::to_string(&serde_json::json!({"cancelledAtMs": now_ms}))?;
        apply_transition(&tx, &snap, crate::TurnState::Cancelled, None, None, &payload, now_ms)?;
        tx.execute("UPDATE activation_capabilities SET consumed=1 WHERE owner_id=?1 AND agent_id=?2 AND launch_epoch<=?3 AND consumed=0", params![snap.owner_id, snap.agent_id, next_epoch])?;
        let updated = turn_from_transaction(&tx, turn_id)?;
        tx.commit()?;
        Ok(crate::CancelOutcome::Cancelled(updated))
    }
    pub fn activate_with_capability(&self, turn_id: &str, capability_id: &str, _expected_epoch: i64, now_ms: i64) -> Result<crate::ActivationOutcome> {
        if turn_id.is_empty() || capability_id.is_empty() { return Err(LifecycleError::InvalidRequest("turn/capability must be non-empty")); }
        if now_ms < 0 { return Err(LifecycleError::InvalidRequest("now_ms must be non-negative")); }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cap: Option<(String,String,i64,i64)> = tx.query_row("SELECT owner_id,agent_id,launch_epoch,consumed FROM activation_capabilities WHERE capability_id=?1", params![capability_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)?))).optional()?;
        let (cap_owner, cap_agent, _cap_epoch, consumed) = match cap { None => return Err(LifecycleError::CapabilityNotFound), Some(v) => v };
        if consumed != 0 { return Ok(crate::ActivationOutcome::AlreadyConsumed); }
        let snap: Option<TurnSnapshot> = tx.query_row("SELECT turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,execution_id,result_digest,version,accepted_at_ms,updated_at_ms,expires_at_ms FROM turns WHERE turn_id=?1", params![turn_id], turn_from_row).optional().map_err(LifecycleError::Sqlite)?;
        let snap = match snap { None => return Ok(crate::ActivationOutcome::NotFound), Some(s) => s };
        if snap.owner_id != cap_owner || snap.agent_id != cap_agent { return Err(LifecycleError::InvalidRequest("capability scope mismatch")); }
        if snap.state.is_terminal() {
            tx.execute("UPDATE activation_capabilities SET consumed=1 WHERE capability_id=?1", params![capability_id])?;
            let fence_epoch = Self::ensure_launch_fence_tx(&tx, &snap.owner_id, &snap.agent_id)?;
            tx.execute("UPDATE launch_fences SET launch_epoch=?3, updated_at_ms=?4 WHERE owner_id=?1 AND agent_id=?2", params![snap.owner_id, snap.agent_id, fence_epoch + 1, now_ms])?;
            tx.commit()?;
            return Ok(crate::ActivationOutcome::AlreadyConsumed);
        }
        tx.execute("UPDATE activation_capabilities SET consumed=1 WHERE capability_id=?1", params![capability_id])?;
        let fence_epoch = Self::ensure_launch_fence_tx(&tx, &snap.owner_id, &snap.agent_id)?;
        tx.execute("UPDATE launch_fences SET launch_epoch=?3, updated_at_ms=?4 WHERE owner_id=?1 AND agent_id=?2", params![snap.owner_id, snap.agent_id, fence_epoch + 1, now_ms])?;
        if snap.state != crate::TurnState::Accepted { tx.commit()?; return Ok(crate::ActivationOutcome::AlreadyConsumed); }
        let payload = serde_json::to_string(&serde_json::json!({"activatedAtMs": now_ms, "capabilityId": capability_id}))?;
        apply_transition(&tx, &snap, crate::TurnState::Queued, None, None, &payload, now_ms)?;
        let updated = turn_from_transaction(&tx, turn_id)?;
        tx.commit()?;
        Ok(crate::ActivationOutcome::Activated(Box::new(updated)))
    }
    pub fn reject_admission_by_turn_id(&self, turn_id: &str) -> Result<crate::RejectionOutcome> {
        if turn_id.is_empty() { return Err(LifecycleError::InvalidRequest("turn_id must be non-empty")); }
        let snap = self.turn(turn_id)?;
        if snap.state == crate::TurnState::Rejected { return Ok(crate::RejectionOutcome::Duplicate(snap)); }
        if snap.state.is_terminal() { return Err(LifecycleError::InvalidTransition { from: snap.state, to: crate::TurnState::Rejected }); }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = turn_from_transaction(&tx, turn_id)?;
        if current.state == crate::TurnState::Rejected { return Ok(crate::RejectionOutcome::Duplicate(current)); }
        if current.state.is_terminal() { return Err(LifecycleError::InvalidTransition { from: current.state, to: crate::TurnState::Rejected }); }
        let payload = serde_json::to_string(&serde_json::json!({"reasonCode":"rejected","detail":{}}))?;
        apply_transition(&tx, &current, crate::TurnState::Rejected, None, None, &payload, current.updated_at_ms)?;
        let updated = turn_from_transaction(&tx, turn_id)?;
        let upd = crate::TerminalUpdate { state: crate::TurnState::Rejected, result_digest: None, payload: serde_json::json!({"reasonCode":"rejected"}), occurred_at_ms: updated.updated_at_ms };
        insert_terminal_outbox(&tx, &updated, &upd)?;
        tx.commit()?;
        Ok(crate::RejectionOutcome::Rejected(turn_from_transaction(&self.connection()?.transaction_with_behavior(TransactionBehavior::Immediate)?, turn_id)?))
    }

    fn initialize(&self) -> Result<()> {
        let mut connection = self.connection()?;
        schema::initialize(&mut connection)
    }

    #[cfg(any(test, feature = "cards-automations-skills"))]
    pub fn raw_connection_for_tests(&self) -> Result<Connection> {
        self.connection()
    }

    fn connection(&self) -> Result<Connection> {
        let connection = Connection::open(&self.path)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        Ok(connection)
    }
}

fn admit_in_transaction(
    transaction: &Transaction<'_>,
    request: &AdmissionRequest,
) -> Result<AdmissionOutcome> {
    if let Some(existing) = turn_by_nonce(transaction, request)? {
        ensure_same_binding(&existing, request)?;
        return Ok(AdmissionOutcome::Duplicate(existing));
    }
    let turn_id = Uuid::new_v4().to_string();
    transaction.execute(
        "INSERT INTO turns(
            turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
            version,accepted_at_ms,updated_at_ms,expires_at_ms
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,'accepted',0,?8,?8,?9)",
        params![
            turn_id,
            request.owner_id,
            request.agent_id,
            request.requester_id,
            request.channel_id,
            request.client_nonce,
            request.input_digest,
            request.received_at_ms,
            request.expires_at_ms,
        ],
    )?;
    let payload = json!({
        "turnId": turn_id,
        "ownerId": request.owner_id,
        "agentId": request.agent_id,
        "requesterId": request.requester_id,
        "channelId": request.channel_id,
        "clientNonce": request.client_nonce,
        "state": TurnState::Accepted,
        "acceptedAtMs": request.received_at_ms,
        "expiresAtMs": request.expires_at_ms,
    });
    let payload_json = serde_json::to_string(&payload)?;
    insert_event(
        transaction,
        EventInsert {
            turn_id: &turn_id,
            owner_id: &request.owner_id,
            version: 0,
            from_state: None,
            to_state: TurnState::Accepted,
            payload_json: &payload_json,
            occurred_at_ms: request.received_at_ms,
        },
    )?;
    insert_outbox(
        transaction,
        &turn_id,
        &request.owner_id,
        OutboxKind::Receipt,
        &format!("turn:{turn_id}:receipt"),
        &payload_json,
        request.received_at_ms,
    )?;
    Ok(AdmissionOutcome::Accepted(turn_from_transaction(
        transaction,
        &turn_id,
    )?))
}

fn admit_queued_in_transaction(
    transaction: &Transaction<'_>,
    request: &AdmissionRequest,
    dispatch: &DispatchIntent,
    payload_json: &str,
    occurred_at_ms: i64,
) -> Result<QueueAdmissionOutcome> {
    let admission = admit_in_transaction(transaction, request)?;
    let was_accepted = matches!(admission, AdmissionOutcome::Accepted(_));
    let current = admission.turn().clone();
    if current.state.is_terminal() {
        return Ok(QueueAdmissionOutcome::Duplicate(current));
    }

    let dispatch_was_missing = match dispatch_from_transaction(transaction, &current.turn_id)? {
        Some(existing) if existing == *dispatch => false,
        Some(_) => return Err(LifecycleError::DispatchConflict),
        None => {
            insert_dispatch(transaction, &current.turn_id, dispatch)?;
            true
        }
    };

    let turn = if current.state == TurnState::Accepted {
        apply_transition(
            transaction,
            &current,
            TurnState::Queued,
            None,
            None,
            payload_json,
            occurred_at_ms,
        )?;
        turn_from_transaction(transaction, &current.turn_id)?
    } else {
        current
    };

    if was_accepted {
        Ok(QueueAdmissionOutcome::Accepted(turn))
    } else if dispatch_was_missing || admission.turn().state == TurnState::Accepted {
        Ok(QueueAdmissionOutcome::Repaired(turn))
    } else {
        Ok(QueueAdmissionOutcome::Duplicate(turn))
    }
}

fn validate_rejection(reason_code: &str, occurred_at_ms: i64) -> Result<()> {
    if reason_code.is_empty()
        || reason_code.len() > 64
        || !reason_code
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        || occurred_at_ms < 0
    {
        return Err(LifecycleError::InvalidRequest(
            "rejection requires a bounded reason code and non-negative timestamp",
        ));
    }
    Ok(())
}

fn reject_admission_in_transaction(
    transaction: &Transaction<'_>,
    request: &AdmissionRequest,
    reason_code: &str,
    detail: serde_json::Value,
    occurred_at_ms: i64,
) -> Result<RejectionOutcome> {
    if let Some(existing) = turn_by_nonce(transaction, request)? {
        ensure_same_binding(&existing, request)?;
        return Ok(RejectionOutcome::Duplicate(existing));
    }
    let turn_id = Uuid::new_v4().to_string();
    transaction.execute(
        "INSERT INTO turns(
            turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
            version,accepted_at_ms,updated_at_ms,expires_at_ms
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,'rejected',0,?8,?9,?10)",
        params![
            turn_id,
            request.owner_id,
            request.agent_id,
            request.requester_id,
            request.channel_id,
            request.client_nonce,
            request.input_digest,
            request.received_at_ms,
            occurred_at_ms,
            request.expires_at_ms,
        ],
    )?;
    let payload = json!({
        "reasonCode": reason_code,
        "detail": detail,
    });
    let payload_json = serde_json::to_string(&payload)?;
    insert_event(
        transaction,
        EventInsert {
            turn_id: &turn_id,
            owner_id: &request.owner_id,
            version: 0,
            from_state: None,
            to_state: TurnState::Rejected,
            payload_json: &payload_json,
            occurred_at_ms,
        },
    )?;
    let turn = turn_from_transaction(transaction, &turn_id)?;
    insert_terminal_outbox(
        transaction,
        &turn,
        &TerminalUpdate {
            state: TurnState::Rejected,
            result_digest: None,
            payload,
            occurred_at_ms,
        },
    )?;
    Ok(RejectionOutcome::Rejected(turn))
}

fn ensure_same_binding(existing: &TurnSnapshot, request: &AdmissionRequest) -> Result<()> {
    let same_binding = existing.requester_id == request.requester_id
        && existing.channel_id == request.channel_id
        && existing.input_digest == request.input_digest
        && existing.expires_at_ms == request.expires_at_ms;
    if same_binding {
        Ok(())
    } else {
        Err(LifecycleError::NonceConflict)
    }
}

fn apply_transition(
    transaction: &Transaction<'_>,
    current: &TurnSnapshot,
    next: TurnState,
    execution_id: Option<&str>,
    result_digest: Option<&str>,
    payload_json: &str,
    occurred_at_ms: i64,
) -> Result<()> {
    let next_version = current.version + 1;
    let next_version_sql =
        i64::try_from(next_version).map_err(|_| LifecycleError::SequenceOutOfRange)?;
    let current_version_sql =
        i64::try_from(current.version).map_err(|_| LifecycleError::SequenceOutOfRange)?;
    transaction.execute(
        "UPDATE turns
         SET state=?2,execution_id=?3,result_digest=COALESCE(?4,result_digest),
             version=?5,updated_at_ms=?6
         WHERE turn_id=?1 AND version=?7",
        params![
            current.turn_id,
            next.as_str(),
            execution_id,
            result_digest,
            next_version_sql,
            occurred_at_ms,
            current_version_sql,
        ],
    )?;
    insert_event(
        transaction,
        EventInsert {
            turn_id: &current.turn_id,
            owner_id: &current.owner_id,
            version: next_version,
            from_state: Some(current.state),
            to_state: next,
            payload_json,
            occurred_at_ms,
        },
    )
}

struct EventInsert<'a> {
    turn_id: &'a str,
    owner_id: &'a str,
    version: u64,
    from_state: Option<TurnState>,
    to_state: TurnState,
    payload_json: &'a str,
    occurred_at_ms: i64,
}

fn insert_event(transaction: &Transaction<'_>, event: EventInsert<'_>) -> Result<()> {
    let event_id = format!(
        "turn:{}:v:{}:{}",
        event.turn_id,
        event.version,
        event.to_state.as_str()
    );
    transaction.execute(
        "INSERT INTO turn_events(
            event_id,turn_id,owner_id,kind,from_state,to_state,payload_json,occurred_at_ms
         ) VALUES (?1,?2,?3,?4,?5,?4,?6,?7)",
        params![
            event_id,
            event.turn_id,
            event.owner_id,
            event.to_state.as_str(),
            event.from_state.map(TurnState::as_str),
            event.payload_json,
            event.occurred_at_ms,
        ],
    )?;
    Ok(())
}

fn insert_terminal_outbox(
    transaction: &Transaction<'_>,
    turn: &TurnSnapshot,
    update: &TerminalUpdate,
) -> Result<()> {
    let terminal_version = if turn.state == update.state && turn.state.is_terminal() {
        turn.version
    } else {
        turn.version + 1
    };
    let envelope = json!({
        "turnId": turn.turn_id,
        "ownerId": turn.owner_id,
        "agentId": turn.agent_id,
        "channelId": turn.channel_id,
        "requesterId": turn.requester_id,
        "inputEventId": turn.client_nonce,
        "state": update.state,
        "resultDigest": update.result_digest,
        "version": terminal_version,
        "occurredAtMs": update.occurred_at_ms,
        "detail": update.payload,
    });
    let envelope_json = serde_json::to_string(&envelope)?;
    insert_outbox(
        transaction,
        &turn.turn_id,
        &turn.owner_id,
        OutboxKind::Terminal,
        &format!("turn:{}:terminal", turn.turn_id),
        &envelope_json,
        update.occurred_at_ms,
    )
}

fn apply_terminal_update(
    transaction: &Transaction<'_>,
    current: TurnSnapshot,
    update: &TerminalUpdate,
) -> Result<TransitionOutcome> {
    if current.state.is_terminal() {
        let same = current.state == update.state
            && current.result_digest.as_deref() == update.result_digest.as_deref();
        return if same {
            Ok(TransitionOutcome::Idempotent(current))
        } else {
            Err(LifecycleError::TerminalConflict)
        };
    }
    if !current.state.allows(update.state) {
        return Err(LifecycleError::InvalidTransition {
            from: current.state,
            to: update.state,
        });
    }
    let payload_json = serde_json::to_string(&update.payload)?;
    apply_transition(
        transaction,
        &current,
        update.state,
        current.execution_id.as_deref(),
        update.result_digest.as_deref(),
        &payload_json,
        update.occurred_at_ms,
    )?;
    insert_terminal_outbox(transaction, &current, update)?;
    Ok(TransitionOutcome::Applied(turn_from_transaction(
        transaction,
        &current.turn_id,
    )?))
}

fn terminal_many_in_transaction(
    transaction: &Transaction<'_>,
    current: Vec<TurnSnapshot>,
    expected_execution_id: Option<&str>,
    update: &TerminalUpdate,
) -> Result<Vec<TransitionOutcome>> {
    for turn in &current {
        if expected_execution_id.is_some() && turn.execution_id.as_deref() != expected_execution_id
        {
            return Err(LifecycleError::ExecutionConflict);
        }
        if expected_execution_id.is_none()
            && !turn.state.is_terminal()
            && turn.execution_id.is_some()
        {
            return Err(LifecycleError::ExecutionConflict);
        }
        if turn.state.is_terminal() {
            let same = turn.state == update.state
                && turn.result_digest.as_deref() == update.result_digest.as_deref();
            if !same {
                return Err(LifecycleError::TerminalConflict);
            }
        } else if !turn.state.allows(update.state) {
            return Err(LifecycleError::InvalidTransition {
                from: turn.state,
                to: update.state,
            });
        }
    }
    current
        .into_iter()
        .map(|turn| {
            if turn.state.is_terminal() {
                Ok(TransitionOutcome::Idempotent(turn))
            } else {
                apply_terminal_update(transaction, turn, update)
            }
        })
        .collect()
}
fn transition_many_in_transaction(
    transaction: &Transaction<'_>,
    current: Vec<TurnSnapshot>,
    next: TurnState,
    execution_id: Option<&str>,
    expected_execution_id: Option<&str>,
    payload_json: &str,
    occurred_at_ms: i64,
) -> Result<Vec<TransitionOutcome>> {
    for turn in &current {
        if expected_execution_id.is_some() && turn.execution_id.as_deref() != expected_execution_id
        {
            return Err(LifecycleError::ExecutionConflict);
        }
        if turn.state == next {
            if next == TurnState::Running && turn.execution_id.as_deref() != execution_id {
                return Err(LifecycleError::ExecutionConflict);
            }
        } else if turn.state.is_terminal() || !turn.state.allows(next) {
            return Err(LifecycleError::InvalidTransition {
                from: turn.state,
                to: next,
            });
        }
    }
    let mut outcomes = Vec::with_capacity(current.len());
    for turn in current {
        if turn.state == next {
            outcomes.push(TransitionOutcome::Idempotent(turn));
        } else {
            let next_execution_id = if next == TurnState::Waiting {
                execution_id
            } else {
                execution_id.or(turn.execution_id.as_deref())
            };
            apply_transition(
                transaction,
                &turn,
                next,
                next_execution_id,
                None,
                payload_json,
                occurred_at_ms,
            )?;
            outcomes.push(TransitionOutcome::Applied(turn_from_transaction(
                transaction,
                &turn.turn_id,
            )?));
        }
    }
    Ok(outcomes)
}

fn insert_outbox(
    transaction: &Transaction<'_>,
    turn_id: &str,
    owner_id: &str,
    kind: OutboxKind,
    dedupe_key: &str,
    payload_json: &str,
    created_at_ms: i64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO lifecycle_outbox(
            outbox_id,turn_id,owner_id,kind,dedupe_key,payload_json,state,
            attempts,not_before_ms,created_at_ms
         ) VALUES (?1,?2,?3,?4,?5,?6,'pending',0,?7,?7)",
        params![
            Uuid::new_v4().to_string(),
            turn_id,
            owner_id,
            kind.as_str(),
            dedupe_key,
            payload_json,
            created_at_ms,
        ],
    )?;
    Ok(())
}

fn insert_dispatch(
    transaction: &Transaction<'_>,
    turn_id: &str,
    dispatch: &DispatchIntent,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO turn_dispatch(
            turn_id,prompt_tag,delivery_mode,retry_count,not_before_ms,rule_fingerprint
         ) VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            turn_id,
            dispatch.prompt_tag,
            dispatch.delivery_mode.as_str(),
            i64::from(dispatch.retry_count),
            dispatch.not_before_ms,
            dispatch.rule_fingerprint,
        ],
    )?;
    Ok(())
}

fn update_dispatch(
    transaction: &Transaction<'_>,
    turn_id: &str,
    dispatch: &DispatchIntent,
) -> Result<()> {
    let changed = transaction.execute(
        "UPDATE turn_dispatch
         SET prompt_tag=?2,delivery_mode=?3,retry_count=?4,not_before_ms=?5,rule_fingerprint=?6
         WHERE turn_id=?1",
        params![
            turn_id,
            dispatch.prompt_tag,
            dispatch.delivery_mode.as_str(),
            i64::from(dispatch.retry_count),
            dispatch.not_before_ms,
            dispatch.rule_fingerprint,
        ],
    )?;
    if changed != 1 {
        return Err(LifecycleError::DispatchConflict);
    }
    Ok(())
}

fn validate_turn_ids(turn_ids: &[String]) -> Result<()> {
    if turn_ids.is_empty() || turn_ids.iter().any(String::is_empty) {
        return Err(LifecycleError::InvalidRequest(
            "turn id batch must contain non-empty identifiers",
        ));
    }
    let unique: HashSet<&str> = turn_ids.iter().map(String::as_str).collect();
    if unique.len() != turn_ids.len() {
        return Err(LifecycleError::InvalidRequest(
            "turn id batch must not contain duplicates",
        ));
    }
    Ok(())
}

fn validate_client_nonces(client_nonces: &[String]) -> Result<()> {
    if client_nonces.is_empty() || client_nonces.iter().any(String::is_empty) {
        return Err(LifecycleError::InvalidRequest(
            "client nonce batch must contain non-empty identifiers",
        ));
    }
    let unique: HashSet<&str> = client_nonces.iter().map(String::as_str).collect();
    if unique.len() != client_nonces.len() {
        return Err(LifecycleError::InvalidRequest(
            "client nonce batch must not contain duplicates",
        ));
    }
    Ok(())
}

fn load_turns(transaction: &Transaction<'_>, turn_ids: &[String]) -> Result<Vec<TurnSnapshot>> {
    turn_ids
        .iter()
        .map(|turn_id| turn_from_transaction(transaction, turn_id))
        .collect()
}

fn load_turns_for_nonces(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
    client_nonces: &[String],
) -> Result<Vec<TurnSnapshot>> {
    client_nonces
        .iter()
        .map(|client_nonce| {
            transaction
                .query_row(
                    "SELECT turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
                            execution_id,result_digest,version,accepted_at_ms,updated_at_ms,expires_at_ms
                     FROM turns WHERE owner_id=?1 AND agent_id=?2 AND client_nonce=?3",
                    params![authority.owner_id, authority.agent_id, client_nonce],
                    turn_from_row,
                )
                .optional()?
                .ok_or(LifecycleError::TurnNotFound)
        })
        .collect()
}

fn turn_by_nonce(
    transaction: &Transaction<'_>,
    request: &AdmissionRequest,
) -> Result<Option<TurnSnapshot>> {
    Ok(transaction
        .query_row(
            "SELECT turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
                    execution_id,result_digest,version,accepted_at_ms,updated_at_ms,expires_at_ms
             FROM turns WHERE owner_id=?1 AND agent_id=?2 AND client_nonce=?3",
            params![request.owner_id, request.agent_id, request.client_nonce],
            turn_from_row,
        )
        .optional()?)
}

fn due_turn_ids(transaction: &Transaction<'_>, now_ms: i64, limit: i64) -> Result<Vec<String>> {
    let mut statement = transaction.prepare(
        "SELECT turn_id FROM turns
         WHERE state IN ('accepted','queued','running','waiting') AND expires_at_ms<=?1
           AND NOT EXISTS (
             SELECT 1 FROM run_scheduler_state s
             WHERE s.owner_id=turns.owner_id AND s.agent_id=turns.agent_id
           )
         ORDER BY expires_at_ms,turn_id LIMIT ?2",
    )?;
    let rows = statement.query_map(params![now_ms, limit], |row| row.get(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn due_turn_ids_for_agent(
    transaction: &Transaction<'_>,
    owner_id: &str,
    agent_id: &str,
    now_ms: i64,
    limit: i64,
) -> Result<Vec<String>> {
    let mut statement = transaction.prepare(
        "SELECT turn_id FROM turns
         WHERE owner_id=?1 AND agent_id=?2
           AND state IN ('accepted','queued','running','waiting') AND expires_at_ms<=?3
         ORDER BY expires_at_ms,turn_id LIMIT ?4",
    )?;
    let rows = statement.query_map(params![owner_id, agent_id, now_ms, limit], |row| row.get(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn expire_turn_ids_in_transaction(
    transaction: &Transaction<'_>,
    turn_ids: Vec<String>,
    now_ms: i64,
) -> Result<Vec<TurnSnapshot>> {
    let mut expired = Vec::with_capacity(turn_ids.len());
    for turn_id in turn_ids {
        let current = turn_from_transaction(transaction, &turn_id)?;
        let outcome = apply_terminal_update(
            transaction,
            current,
            &TerminalUpdate {
                state: TurnState::Expired,
                result_digest: None,
                payload: json!({"reason": "deadline_elapsed"}),
                occurred_at_ms: now_ms,
            },
        )?;
        expired.push(outcome.turn().clone());
    }
    Ok(expired)
}

fn turn_from_transaction(transaction: &Transaction<'_>, turn_id: &str) -> Result<TurnSnapshot> {
    transaction
        .query_row(
            "SELECT turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
                    execution_id,result_digest,version,accepted_at_ms,updated_at_ms,expires_at_ms
             FROM turns WHERE turn_id=?1",
            [turn_id],
            turn_from_row,
        )
        .optional()?
        .ok_or(LifecycleError::TurnNotFound)
}

fn turn_from_connection(connection: &Connection, turn_id: &str) -> Result<TurnSnapshot> {
    connection
        .query_row(
            "SELECT turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
                    execution_id,result_digest,version,accepted_at_ms,updated_at_ms,expires_at_ms
             FROM turns WHERE turn_id=?1",
            [turn_id],
            turn_from_row,
        )
        .optional()?
        .ok_or(LifecycleError::TurnNotFound)
}

fn turn_from_row(row: &Row<'_>) -> rusqlite::Result<TurnSnapshot> {
    let state: String = row.get(7)?;
    let version: i64 = row.get(10)?;
    Ok(TurnSnapshot {
        turn_id: row.get(0)?,
        owner_id: row.get(1)?,
        agent_id: row.get(2)?,
        requester_id: row.get(3)?,
        channel_id: row.get(4)?,
        client_nonce: row.get(5)?,
        input_digest: row.get(6)?,
        state: TurnState::from_str(&state).map_err(to_sql_conversion_error)?,
        execution_id: row.get(8)?,
        result_digest: row.get(9)?,
        version: u64::try_from(version).map_err(to_sql_conversion_error)?,
        accepted_at_ms: row.get(11)?,
        updated_at_ms: row.get(12)?,
        expires_at_ms: row.get(13)?,
    })
}

fn lane_diagnostics_from_row(row: &Row<'_>) -> rusqlite::Result<RunLaneDiagnostics> {
    let lane: String = row.get(0)?;
    let depth: i64 = row.get(1)?;
    Ok(RunLaneDiagnostics {
        lane: RunLane::from_str(&lane).map_err(to_sql_conversion_error)?,
        depth: u64::try_from(depth).map_err(to_sql_conversion_error)?,
        oldest_accepted_at_ms: row.get(2)?,
        oldest_due_at_ms: row.get(3)?,
    })
}

struct SchedulerStateProjection {
    next_epoch: u64,
    active_epoch: Option<u64>,
    active_execution_id: Option<String>,
    active_lane: Option<RunLane>,
    active_source: Option<String>,
    active_started_at_ms: Option<i64>,
    counters: SchedulerCounters,
    updated_at_ms: i64,
    active_phase: Option<RunClaimPhase>,
}

fn scheduler_state_from_row(row: &Row<'_>) -> rusqlite::Result<SchedulerStateProjection> {
    let next_epoch: i64 = row.get(0)?;
    let active_epoch: Option<i64> = row.get(1)?;
    let active_lane: Option<String> = row.get(3)?;
    let claims_since_agent: i64 = row.get(6)?;
    let claims_since_background: i64 = row.get(7)?;
    Ok(SchedulerStateProjection {
        next_epoch: u64::try_from(next_epoch).map_err(to_sql_conversion_error)?,
        active_epoch: active_epoch
            .map(u64::try_from)
            .transpose()
            .map_err(to_sql_conversion_error)?,
        active_execution_id: row.get(2)?,
        active_lane: active_lane
            .as_deref()
            .map(RunLane::from_str)
            .transpose()
            .map_err(to_sql_conversion_error)?,
        active_source: row.get(4)?,
        active_started_at_ms: row.get(5)?,
        counters: SchedulerCounters {
            agent_bypasses: u64::try_from(claims_since_agent).map_err(to_sql_conversion_error)?,
            background_bypasses: u64::try_from(claims_since_background)
                .map_err(to_sql_conversion_error)?,
        },
        updated_at_ms: row.get(8)?,
        active_phase: row
            .get::<_, Option<String>>(9)?
            .map(|value| match value.as_str() {
                "reserved" => Ok(RunClaimPhase::Reserved),
                "launched" => Ok(RunClaimPhase::Launched),
                _ => Err(LifecycleError::InvalidRequest("corrupt active phase")),
            })
            .transpose()
            .map_err(to_sql_conversion_error)?,
    })
}

#[derive(Debug)]
struct RunnableHead {
    turn: TurnSnapshot,
    source: String,
    dispatch: DispatchIntent,
    opaque_input_json: String,
}

fn to_sql_u64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| LifecycleError::SequenceOutOfRange)
}

fn insert_scheduled_dispatch(
    transaction: &Transaction<'_>,
    turn_id: &str,
    dispatch: &DispatchIntent,
    schedule: &ScheduleIntent,
    opaque_input_json: &str,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO turn_dispatch(
            turn_id,prompt_tag,delivery_mode,retry_count,not_before_ms,rule_fingerprint,lane,source,opaque_input_json
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            turn_id,
            dispatch.prompt_tag,
            dispatch.delivery_mode.as_str(),
            i64::from(dispatch.retry_count),
            dispatch.not_before_ms,
            dispatch.rule_fingerprint,
            schedule.lane().as_str(),
            schedule.source(),
            opaque_input_json,
        ],
    )?;
    Ok(())
}

fn ensure_dispatch_and_schedule(
    transaction: &Transaction<'_>,
    turn_id: &str,
    dispatch: &DispatchIntent,
    schedule: &ScheduleIntent,
    opaque_input_json: &str,
) -> Result<()> {
    let existing_dispatch =
        dispatch_from_transaction(transaction, turn_id)?.ok_or(LifecycleError::DispatchConflict)?;
    if existing_dispatch != *dispatch {
        return Err(LifecycleError::DispatchConflict);
    }
    let existing_schedule =
        schedule_from_transaction(transaction, turn_id)?.ok_or(LifecycleError::ScheduleConflict)?;
    if existing_schedule != *schedule {
        return Err(LifecycleError::ScheduleConflict);
    }
    let existing_input: String = transaction.query_row(
        "SELECT opaque_input_json FROM turn_dispatch WHERE turn_id=?1",
        [turn_id],
        |row| row.get(0),
    )?;
    if existing_input != opaque_input_json {
        return Err(LifecycleError::DispatchConflict);
    }
    Ok(())
}

fn schedule_from_connection(
    connection: &Connection,
    turn_id: &str,
) -> Result<Option<ScheduleIntent>> {
    Ok(connection
        .query_row(
            "SELECT lane,source FROM turn_dispatch WHERE turn_id=?1",
            [turn_id],
            schedule_from_row,
        )
        .optional()?)
}

fn schedule_from_transaction(
    transaction: &Transaction<'_>,
    turn_id: &str,
) -> Result<Option<ScheduleIntent>> {
    Ok(transaction
        .query_row(
            "SELECT lane,source FROM turn_dispatch WHERE turn_id=?1",
            [turn_id],
            schedule_from_row,
        )
        .optional()?)
}

fn schedule_from_row(row: &Row<'_>) -> rusqlite::Result<ScheduleIntent> {
    let lane: String = row.get(0)?;
    let source: String = row.get(1)?;
    ScheduleIntent::new(
        RunLane::from_str(&lane).map_err(to_sql_conversion_error)?,
        source,
    )
    .map_err(to_sql_conversion_error)
}

fn expire_pending_scheduler_turns(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
    now_ms: i64,
) -> Result<()> {
    let mut statement = transaction.prepare(
        "SELECT turn_id FROM turns
         WHERE owner_id=?1 AND agent_id=?2 AND state IN ('queued','waiting')
           AND expires_at_ms<=?3
         ORDER BY expires_at_ms,turn_id LIMIT 1000",
    )?;
    let rows = statement.query_map(
        params![authority.owner_id, authority.agent_id, now_ms],
        |row| row.get(0),
    )?;
    let turn_ids = rows.collect::<std::result::Result<Vec<String>, _>>()?;
    drop(statement);
    expire_turn_ids_in_transaction(transaction, turn_ids, now_ms)?;
    Ok(())
}

fn ensure_scheduler_state(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
    now_ms: i64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO run_scheduler_state(owner_id,agent_id,updated_at_ms)
         VALUES (?1,?2,?3) ON CONFLICT(owner_id,agent_id) DO NOTHING",
        params![authority.owner_id, authority.agent_id, now_ms],
    )?;
    Ok(())
}

fn scheduler_state_for_scope(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
) -> Result<SchedulerStateProjection> {
    transaction
        .query_row(
            "SELECT next_epoch,active_epoch,active_execution_id,active_lane,active_source,
                    active_started_at_ms,claims_since_agent,claims_since_background,updated_at_ms,active_phase
             FROM run_scheduler_state WHERE owner_id=?1 AND agent_id=?2",
            params![authority.owner_id, authority.agent_id],
            scheduler_state_from_row,
        )
        .map_err(Into::into)
}

fn runnable_lane_head(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
    lane: RunLane,
    now_ms: i64,
) -> Result<Option<RunnableHead>> {
    Ok(transaction
        .query_row(
            "SELECT t.turn_id,t.owner_id,t.agent_id,t.requester_id,t.channel_id,t.client_nonce,
                    t.input_digest,t.state,t.execution_id,t.result_digest,t.version,t.accepted_at_ms,
                    t.updated_at_ms,t.expires_at_ms,d.source,d.prompt_tag,d.delivery_mode,
                    d.retry_count,d.not_before_ms,d.rule_fingerprint,d.opaque_input_json
             FROM turns t JOIN turn_dispatch d ON d.turn_id=t.turn_id
             LEFT JOIN turn_recovery r ON r.turn_id=t.turn_id
             WHERE t.owner_id=?1 AND t.agent_id=?2 AND t.state IN ('queued','waiting')
               AND d.lane=?3 AND d.not_before_ms<=?4 AND t.expires_at_ms>?4
               AND d.opaque_input_json IS NOT NULL
               AND (r.action IS NULL OR r.action NOT IN ('hold_uncertain','missing_dispatch_intent'))
             ORDER BY t.accepted_at_ms,t.turn_id LIMIT 1",
            params![authority.owner_id, authority.agent_id, lane.as_str(), now_ms],
            |row| {
                Ok(RunnableHead {
                    turn: turn_from_row(row)?,
                    source: row.get(14)?,
                    dispatch: dispatch_from_row_offset(row, 15)?,
                    opaque_input_json: row.get(20)?,
                })
            },
        )
        .optional()?)
}

fn valid_opaque_input(input: &str) -> bool {
    !input.is_empty() && serde_json::from_str::<serde_json::Value>(input).is_ok()
}

fn update_scheduler_counters(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
    counters: SchedulerCounters,
    now_ms: i64,
) -> Result<()> {
    let changed = transaction.execute(
        "UPDATE run_scheduler_state
         SET claims_since_agent=?3,claims_since_background=?4,updated_at_ms=?5
         WHERE owner_id=?1 AND agent_id=?2 AND active_execution_id IS NULL",
        params![
            authority.owner_id,
            authority.agent_id,
            to_sql_u64(counters.agent_bypasses)?,
            to_sql_u64(counters.background_bypasses)?,
            now_ms,
        ],
    )?;
    if changed != 1 {
        return Err(LifecycleError::SchedulerBusy);
    }
    Ok(())
}

fn validate_claim_identity(claim: &RunClaimIdentity) -> Result<()> {
    if claim.epoch == 0 || claim.execution_id.is_empty() {
        return Err(LifecycleError::InvalidRequest(
            "scheduler claim requires a positive epoch and execution id",
        ));
    }
    Ok(())
}

fn active_claim_turn(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
    claim: &RunClaimIdentity,
) -> Result<TurnSnapshot> {
    let state = scheduler_state_for_scope(transaction, authority)?;
    if state.active_epoch != Some(claim.epoch)
        || state.active_execution_id.as_deref() != Some(claim.execution_id.as_str())
    {
        return Err(LifecycleError::SchedulerClaimConflict);
    }
    let turns =
        active_turns_for_execution_in_transaction(transaction, authority, &claim.execution_id)?;
    if turns.len() != 1 {
        return Err(LifecycleError::SchedulerClaimConflict);
    }
    turns
        .into_iter()
        .next()
        .ok_or(LifecycleError::SchedulerClaimConflict)
}

fn active_claim_phase(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
    claim: &RunClaimIdentity,
) -> Result<RunClaimPhase> {
    let value: Option<String> = transaction.query_row(
        "SELECT active_phase FROM run_scheduler_state WHERE owner_id=?1 AND agent_id=?2 AND active_epoch=?3 AND active_execution_id=?4",
        params![authority.owner_id, authority.agent_id, to_sql_u64(claim.epoch)?, claim.execution_id],
        |row| row.get(0),
    ).optional()?.flatten();
    match value.as_deref() {
        Some("reserved") => Ok(RunClaimPhase::Reserved),
        Some("launched") => Ok(RunClaimPhase::Launched),
        _ => Err(LifecycleError::SchedulerClaimConflict),
    }
}

fn clear_matching_active_scheduler(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
    claim: &RunClaimIdentity,
    occurred_at_ms: i64,
) -> Result<()> {
    let changed = transaction.execute(
        "UPDATE run_scheduler_state
         SET active_epoch=NULL,active_execution_id=NULL,active_lane=NULL,active_source=NULL,
             active_started_at_ms=NULL,active_phase=NULL,updated_at_ms=?5
         WHERE owner_id=?1 AND agent_id=?2 AND active_epoch=?3 AND active_execution_id=?4",
        params![
            authority.owner_id,
            authority.agent_id,
            to_sql_u64(claim.epoch)?,
            claim.execution_id,
            occurred_at_ms,
        ],
    )?;
    if changed != 1 {
        return Err(LifecycleError::SchedulerClaimConflict);
    }
    Ok(())
}

fn clear_recovered_active_if_classified(
    transaction: &Transaction<'_>,
    owner_id: &str,
    agent_id: &str,
    execution_id: Option<&str>,
    schedule: Option<&ScheduleIntent>,
    occurred_at_ms: i64,
) -> Result<()> {
    let (Some(execution_id), Some(schedule)) = (execution_id, schedule) else {
        return Ok(());
    };
    transaction.execute(
        "UPDATE run_scheduler_state
         SET active_epoch=NULL,active_execution_id=NULL,active_lane=NULL,active_source=NULL,
             active_started_at_ms=NULL,active_phase=NULL,updated_at_ms=?6
         WHERE owner_id=?1 AND agent_id=?2 AND active_execution_id=?3
           AND active_lane=?4 AND active_source=?5",
        params![
            owner_id,
            agent_id,
            execution_id,
            schedule.lane().as_str(),
            schedule.source(),
            occurred_at_ms,
        ],
    )?;
    Ok(())
}

fn scheduler_phase_for_execution(
    transaction: &Transaction<'_>,
    owner_id: &str,
    agent_id: &str,
    execution_id: Option<&str>,
) -> Result<Option<RunClaimPhase>> {
    let Some(execution_id) = execution_id else {
        return Ok(None);
    };
    let value: Option<String> = transaction.query_row(
        "SELECT active_phase FROM run_scheduler_state WHERE owner_id=?1 AND agent_id=?2 AND active_execution_id=?3",
        params![owner_id, agent_id, execution_id], |row| row.get(0)
    ).optional()?.flatten();
    match value.as_deref() {
        None => Ok(None),
        Some("reserved") => Ok(Some(RunClaimPhase::Reserved)),
        Some("launched") => Ok(Some(RunClaimPhase::Launched)),
        Some(_) => Err(LifecycleError::InvalidRequest("corrupt active phase")),
    }
}

fn dispatch_from_connection(
    connection: &Connection,
    turn_id: &str,
) -> Result<Option<DispatchIntent>> {
    Ok(connection
        .query_row(
            "SELECT prompt_tag,delivery_mode,retry_count,not_before_ms,rule_fingerprint
             FROM turn_dispatch WHERE turn_id=?1",
            [turn_id],
            dispatch_from_row,
        )
        .optional()?)
}

fn dispatch_from_transaction(
    transaction: &Transaction<'_>,
    turn_id: &str,
) -> Result<Option<DispatchIntent>> {
    Ok(transaction
        .query_row(
            "SELECT prompt_tag,delivery_mode,retry_count,not_before_ms,rule_fingerprint
             FROM turn_dispatch WHERE turn_id=?1",
            [turn_id],
            dispatch_from_row,
        )
        .optional()?)
}

fn dispatch_from_row(row: &Row<'_>) -> rusqlite::Result<DispatchIntent> {
    let delivery_mode: String = row.get(1)?;
    let retry_count: i64 = row.get(2)?;
    Ok(DispatchIntent {
        prompt_tag: row.get(0)?,
        delivery_mode: DeliveryMode::from_str(&delivery_mode).map_err(to_sql_conversion_error)?,
        retry_count: u32::try_from(retry_count).map_err(to_sql_conversion_error)?,
        not_before_ms: row.get(3)?,
        rule_fingerprint: row.get(4)?,
    })
}

fn dispatch_from_row_offset(row: &Row<'_>, offset: usize) -> rusqlite::Result<DispatchIntent> {
    let delivery_mode: String = row.get(offset + 1)?;
    let retry_count: i64 = row.get(offset + 2)?;
    Ok(DispatchIntent {
        prompt_tag: row.get(offset)?,
        delivery_mode: DeliveryMode::from_str(&delivery_mode).map_err(to_sql_conversion_error)?,
        retry_count: u32::try_from(retry_count).map_err(to_sql_conversion_error)?,
        not_before_ms: row.get(offset + 3)?,
        rule_fingerprint: row.get(offset + 4)?,
    })
}

struct RecoveryMarker {
    instance_id: String,
    prior_state: TurnState,
    action: RecoveryAction,
    recovered_state: TurnState,
    recovered_version: u64,
    queue_acknowledged_at_ms: Option<i64>,
}

fn recovery_marker_from_transaction(
    transaction: &Transaction<'_>,
    turn_id: &str,
) -> Result<Option<RecoveryMarker>> {
    Ok(transaction
        .query_row(
            "SELECT instance_id,prior_state,action,recovered_state,recovered_version,
                    queue_acknowledged_at_ms
             FROM turn_recovery WHERE turn_id=?1",
            [turn_id],
            |row| {
                let prior_state: String = row.get(1)?;
                let action: String = row.get(2)?;
                let recovered_state: String = row.get(3)?;
                let recovered_version: i64 = row.get(4)?;
                Ok(RecoveryMarker {
                    instance_id: row.get(0)?,
                    prior_state: TurnState::from_str(&prior_state)
                        .map_err(to_sql_conversion_error)?,
                    action: RecoveryAction::from_str(&action).map_err(to_sql_conversion_error)?,
                    recovered_state: TurnState::from_str(&recovered_state)
                        .map_err(to_sql_conversion_error)?,
                    recovered_version: u64::try_from(recovered_version)
                        .map_err(to_sql_conversion_error)?,
                    queue_acknowledged_at_ms: row.get(5)?,
                })
            },
        )
        .optional()?)
}

struct RecoveryMarkerWrite<'a> {
    turn_id: &'a str,
    instance_id: &'a str,
    prior_state: TurnState,
    action: RecoveryAction,
    recovered_state: TurnState,
    recovered_version: u64,
    recovered_at_ms: i64,
}

fn upsert_recovery_marker(
    transaction: &Transaction<'_>,
    marker: RecoveryMarkerWrite<'_>,
) -> Result<()> {
    let recovered_version =
        i64::try_from(marker.recovered_version).map_err(|_| LifecycleError::SequenceOutOfRange)?;
    transaction.execute(
        "INSERT INTO turn_recovery(
            turn_id,instance_id,prior_state,action,recovered_state,recovered_version,recovered_at_ms,
            queue_acknowledged_at_ms
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,NULL)
         ON CONFLICT(turn_id) DO UPDATE SET
            instance_id=excluded.instance_id,
            prior_state=excluded.prior_state,
            action=excluded.action,
            recovered_state=excluded.recovered_state,
            recovered_version=excluded.recovered_version,
            recovered_at_ms=excluded.recovered_at_ms,
            queue_acknowledged_at_ms=NULL",
        params![
            marker.turn_id,
            marker.instance_id,
            marker.prior_state.as_str(),
            marker.action.as_str(),
            marker.recovered_state.as_str(),
            recovered_version,
            marker.recovered_at_ms,
        ],
    )?;
    Ok(())
}

fn validate_runtime_lease_request(
    owner_id: &str,
    agent_id: &str,
    instance_id: &str,
    now_ms: i64,
    expires_at_ms: i64,
) -> Result<()> {
    if owner_id.is_empty()
        || agent_id.is_empty()
        || instance_id.is_empty()
        || now_ms < 0
        || expires_at_ms <= now_ms
    {
        return Err(LifecycleError::InvalidRequest(
            "runtime lease requires identifiers and a future expiry",
        ));
    }
    Ok(())
}

fn validate_runtime_authority(authority: &RuntimeLeaseIdentity, occurred_at_ms: i64) -> Result<()> {
    if authority.owner_id.is_empty()
        || authority.agent_id.is_empty()
        || authority.instance_id.is_empty()
        || occurred_at_ms < 0
    {
        return Err(LifecycleError::InvalidRequest(
            "runtime authority requires identifiers and a non-negative timestamp",
        ));
    }
    Ok(())
}

fn assert_runtime_lease(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
    now_ms: i64,
) -> Result<()> {
    let lease =
        runtime_lease_from_transaction(transaction, &authority.owner_id, &authority.agent_id)?
            .ok_or(LifecycleError::RuntimeLeaseConflict)?;
    if lease.instance_id != authority.instance_id || lease.expires_at_ms <= now_ms {
        return Err(LifecycleError::RuntimeLeaseConflict);
    }
    Ok(())
}

fn assert_legacy_scope(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
) -> Result<()> {
    let exists = transaction
        .query_row(
            "SELECT 1 FROM run_scheduler_state WHERE owner_id=?1 AND agent_id=?2",
            params![authority.owner_id, authority.agent_id],
            |_| Ok(()),
        )
        .optional()?;
    if exists.is_some() {
        Err(LifecycleError::SchedulerModeConflict)
    } else {
        Ok(())
    }
}

fn assert_scheduler_activation_safe(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
) -> Result<()> {
    let scheduler_exists = transaction
        .query_row(
            "SELECT 1 FROM run_scheduler_state WHERE owner_id=?1 AND agent_id=?2",
            params![authority.owner_id, authority.agent_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if scheduler_exists {
        return Ok(());
    }
    let legacy_active: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM turns
         WHERE owner_id=?1 AND agent_id=?2
           AND state IN ('accepted','queued','running','waiting')",
        params![authority.owner_id, authority.agent_id],
        |row| row.get(0),
    )?;
    if legacy_active == 0 {
        Ok(())
    } else {
        Err(LifecycleError::SchedulerModeConflict)
    }
}

fn assert_request_not_scheduler(
    transaction: &Transaction<'_>,
    request: &AdmissionRequest,
) -> Result<()> {
    let authority = RuntimeLeaseIdentity {
        owner_id: request.owner_id.clone(),
        agent_id: request.agent_id.clone(),
        instance_id: "scope-check".into(),
    };
    assert_legacy_scope(transaction, &authority)
}

fn assert_turn_not_scheduler(transaction: &Transaction<'_>, turn: &TurnSnapshot) -> Result<()> {
    let authority = RuntimeLeaseIdentity {
        owner_id: turn.owner_id.clone(),
        agent_id: turn.agent_id.clone(),
        instance_id: "scope-check".into(),
    };
    assert_legacy_scope(transaction, &authority)
}

fn assert_outbox_scope(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
    outbox_id: &str,
) -> Result<()> {
    let scoped = transaction
        .query_row(
            "SELECT 1
             FROM lifecycle_outbox o JOIN turns t ON t.turn_id=o.turn_id
             WHERE o.outbox_id=?1 AND t.owner_id=?2 AND t.agent_id=?3",
            params![outbox_id, authority.owner_id, authority.agent_id],
            |_| Ok(()),
        )
        .optional()?;
    if scoped.is_some() {
        Ok(())
    } else {
        Err(LifecycleError::OutboxClaimConflict)
    }
}

fn assert_outbox_not_scheduler(transaction: &Transaction<'_>, outbox_id: &str) -> Result<()> {
    let authority = transaction
        .query_row(
            "SELECT t.owner_id,t.agent_id
             FROM lifecycle_outbox o JOIN turns t ON t.turn_id=o.turn_id
             WHERE o.outbox_id=?1",
            [outbox_id],
            |row| {
                Ok(RuntimeLeaseIdentity {
                    owner_id: row.get(0)?,
                    agent_id: row.get(1)?,
                    instance_id: "scope-check".into(),
                })
            },
        )
        .optional()?
        .ok_or(LifecycleError::OutboxClaimConflict)?;
    assert_legacy_scope(transaction, &authority)
}

fn runtime_lease_from_connection(
    connection: &Connection,
    owner_id: &str,
    agent_id: &str,
) -> Result<Option<RuntimeLease>> {
    Ok(connection
        .query_row(
            "SELECT owner_id,agent_id,instance_id,expires_at_ms
             FROM runtime_leases WHERE owner_id=?1 AND agent_id=?2",
            params![owner_id, agent_id],
            runtime_lease_from_row,
        )
        .optional()?)
}

fn runtime_lease_from_transaction(
    transaction: &Transaction<'_>,
    owner_id: &str,
    agent_id: &str,
) -> Result<Option<RuntimeLease>> {
    Ok(transaction
        .query_row(
            "SELECT owner_id,agent_id,instance_id,expires_at_ms
             FROM runtime_leases WHERE owner_id=?1 AND agent_id=?2",
            params![owner_id, agent_id],
            runtime_lease_from_row,
        )
        .optional()?)
}

fn runtime_lease_from_row(row: &Row<'_>) -> rusqlite::Result<RuntimeLease> {
    Ok(RuntimeLease {
        owner_id: row.get(0)?,
        agent_id: row.get(1)?,
        instance_id: row.get(2)?,
        expires_at_ms: row.get(3)?,
    })
}

fn active_turns_for_agent_in_transaction(
    transaction: &Transaction<'_>,
    owner_id: &str,
    agent_id: &str,
    instance_id: &str,
    now_ms: i64,
    limit: i64,
) -> Result<Vec<TurnSnapshot>> {
    let mut statement = transaction.prepare(
        "SELECT t.turn_id,t.owner_id,t.agent_id,t.requester_id,t.channel_id,t.client_nonce,
                t.input_digest,t.state,t.execution_id,t.result_digest,t.version,t.accepted_at_ms,
                t.updated_at_ms,t.expires_at_ms
         FROM turns t
         LEFT JOIN turn_recovery r ON r.turn_id=t.turn_id
         LEFT JOIN turn_dispatch d ON d.turn_id=t.turn_id
         WHERE t.owner_id=?1 AND t.agent_id=?2
           AND t.state IN ('accepted','queued','running','waiting')
           AND (
               r.instance_id IS NULL OR r.instance_id<>?3 OR r.action<>'rehydrate'
               OR r.queue_acknowledged_at_ms IS NULL
           )
         ORDER BY
           CASE WHEN r.instance_id=?3 AND (
               r.action IN ('hold_uncertain','missing_dispatch_intent')
               OR (r.action='wait_until_due' AND d.not_before_ms>?4)
           ) THEN 1 ELSE 0 END,
           t.accepted_at_ms,t.turn_id
         LIMIT ?5",
    )?;
    let rows = statement.query_map(
        params![owner_id, agent_id, instance_id, now_ms, limit],
        turn_from_row,
    )?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn active_turns_for_execution_in_transaction(
    transaction: &Transaction<'_>,
    authority: &RuntimeLeaseIdentity,
    execution_id: &str,
) -> Result<Vec<TurnSnapshot>> {
    let mut statement = transaction.prepare(
        "SELECT turn_id,owner_id,agent_id,requester_id,channel_id,client_nonce,input_digest,state,
                execution_id,result_digest,version,accepted_at_ms,updated_at_ms,expires_at_ms
         FROM turns
         WHERE owner_id=?1 AND agent_id=?2 AND execution_id=?3
           AND state IN ('accepted','queued','running','waiting')
         ORDER BY accepted_at_ms,turn_id",
    )?;
    let rows = statement.query_map(
        params![authority.owner_id, authority.agent_id, execution_id],
        turn_from_row,
    )?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn event_from_row(row: &Row<'_>) -> rusqlite::Result<TurnEvent> {
    let sequence: i64 = row.get(0)?;
    let kind: String = row.get(4)?;
    let from_state: Option<String> = row.get(5)?;
    let to_state: String = row.get(6)?;
    let payload_json: String = row.get(7)?;
    Ok(TurnEvent {
        sequence: u64::try_from(sequence).map_err(to_sql_conversion_error)?,
        event_id: row.get(1)?,
        turn_id: row.get(2)?,
        owner_id: row.get(3)?,
        kind: TurnState::from_str(&kind).map_err(to_sql_conversion_error)?,
        from_state: from_state
            .map(|value| TurnState::from_str(&value))
            .transpose()
            .map_err(to_sql_conversion_error)?,
        to_state: TurnState::from_str(&to_state).map_err(to_sql_conversion_error)?,
        payload: serde_json::from_str(&payload_json).map_err(to_sql_conversion_error)?,
        occurred_at_ms: row.get(8)?,
    })
}

fn outbox_from_transaction(transaction: &Transaction<'_>, outbox_id: &str) -> Result<OutboxRecord> {
    transaction
        .query_row(
            "SELECT outbox_id,turn_id,owner_id,kind,dedupe_key,payload_json,state,
                    attempts,not_before_ms,created_at_ms,delivered_at_ms,
                    claim_token,claim_expires_at_ms,delivered_event_id
             FROM lifecycle_outbox WHERE outbox_id=?1",
            [outbox_id],
            outbox_from_row,
        )
        .optional()?
        .ok_or(LifecycleError::InvalidRequest("outbox record not found"))
}

fn outbox_from_row(row: &Row<'_>) -> rusqlite::Result<OutboxRecord> {
    let kind: String = row.get(3)?;
    let payload_json: String = row.get(5)?;
    let state: String = row.get(6)?;
    let attempts: i64 = row.get(7)?;
    Ok(OutboxRecord {
        outbox_id: row.get(0)?,
        turn_id: row.get(1)?,
        owner_id: row.get(2)?,
        kind: OutboxKind::from_str(&kind).map_err(to_sql_conversion_error)?,
        dedupe_key: row.get(4)?,
        payload: serde_json::from_str(&payload_json).map_err(to_sql_conversion_error)?,
        state: OutboxState::from_str(&state).map_err(to_sql_conversion_error)?,
        attempts: u32::try_from(attempts).map_err(to_sql_conversion_error)?,
        not_before_ms: row.get(8)?,
        created_at_ms: row.get(9)?,
        delivered_at_ms: row.get(10)?,
        claim_token: row.get(11)?,
        claim_expires_at_ms: row.get(12)?,
        delivered_event_id: row.get(13)?,
    })
}

fn bounded_limit(limit: usize) -> Result<i64> {
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(LifecycleError::InvalidRequest(
            "page limit must be between 1 and 1000",
        ));
    }
    i64::try_from(limit).map_err(|_| LifecycleError::SequenceOutOfRange)
}

fn bounded_fetch_limit(limit: usize) -> Result<i64> {
    bounded_limit(limit)?;
    i64::try_from(limit.saturating_add(1)).map_err(|_| LifecycleError::SequenceOutOfRange)
}

fn validate_projection_request(owner_id: &str, after: Option<&ActiveTurnCursor>) -> Result<()> {
    if owner_id.is_empty() {
        return Err(LifecycleError::InvalidRequest("owner must be non-empty"));
    }
    if after.is_some_and(|cursor| cursor.accepted_at_ms < 0 || cursor.turn_id.is_empty()) {
        return Err(LifecycleError::InvalidRequest(
            "active-turn cursor requires a non-negative timestamp and turn id",
        ));
    }
    Ok(())
}

fn projection_cursor_parts(after: Option<&ActiveTurnCursor>) -> (Option<i64>, Option<&str>) {
    match after {
        Some(cursor) => (Some(cursor.accepted_at_ms), Some(cursor.turn_id.as_str())),
        None => (None, None),
    }
}

fn active_turn_page(mut turns: Vec<TurnSnapshot>, limit: usize) -> Result<ActiveTurnPage> {
    let has_more = turns.len() > limit;
    let next_cursor = if has_more {
        turns
            .get(limit.saturating_sub(1))
            .map(|last| ActiveTurnCursor {
                accepted_at_ms: last.accepted_at_ms,
                turn_id: last.turn_id.clone(),
            })
    } else {
        None
    };
    if has_more {
        turns.truncate(limit);
    }
    Ok(ActiveTurnPage { turns, next_cursor })
}

fn to_sql_conversion_error(
    error: impl std::error::Error + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_constant_matches_database() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = LifecycleStore::open(directory.path().join("lifecycle.sqlite3"))?;
        assert_eq!(store.schema_version()?, schema::SCHEMA_VERSION);
        assert_eq!(store.journal_mode()?.to_ascii_lowercase(), "wal");
        Ok(())
    }

    #[test]
    fn schema_v1_migrates_atomically_to_current() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("lifecycle.sqlite3");
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            r#"
            CREATE TABLE lifecycle_schema (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                version INTEGER NOT NULL CHECK(version > 0)
            );
            INSERT INTO lifecycle_schema(singleton, version) VALUES (1, 1);
            CREATE TABLE turns (
                turn_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                requester_id TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                client_nonce TEXT NOT NULL,
                input_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                execution_id TEXT,
                result_digest TEXT,
                version INTEGER NOT NULL DEFAULT 0,
                accepted_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER NOT NULL,
                UNIQUE(owner_id, agent_id, client_nonce)
            );
            CREATE TABLE turn_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                turn_id TEXT NOT NULL REFERENCES turns(turn_id) ON DELETE RESTRICT,
                owner_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                occurred_at_ms INTEGER NOT NULL
            );
            CREATE TABLE lifecycle_outbox (
                outbox_id TEXT PRIMARY KEY,
                turn_id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                dedupe_key TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL,
                state TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                not_before_ms INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                delivered_at_ms INTEGER
            );
            "#,
        )?;
        drop(connection);

        let store = LifecycleStore::open(&path)?;
        assert_eq!(store.schema_version()?, schema::SCHEMA_VERSION);
        let connection = store.connection()?;
        let claim_column: i64 = connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('lifecycle_outbox') WHERE name='claim_token'",
            [],
            |row| row.get(0),
        )?;
        let recovery_table: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='turn_recovery'",
            [],
            |row| row.get(0),
        )?;
        let lane_column: i64 = connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('turn_dispatch') WHERE name='lane'",
            [],
            |row| row.get(0),
        )?;
        let scheduler_table: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='run_scheduler_state'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(claim_column, 1);
        assert_eq!(recovery_table, 1);
        assert_eq!(lane_column, 1);
        assert_eq!(scheduler_table, 1);
        Ok(())
    }
}
