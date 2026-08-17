//! Default-off adapter between signed Buzz/Nostr events and the durable turn ledger.
//!
//! This module deliberately does not alter the live ACP queue. It establishes the
//! translation and async boundary that the Slice 2 integration will use.

use std::path::Path;

use buzz_lifecycle::{
    ActiveTurnCursor, ActiveTurnPage, AdmissionOutcome, AdmissionRequest, DeliveryMode,
    DispatchIntent, LifecycleError, LifecycleStore, OutboxKind, OutboxRecord,
    QueueAdmissionOutcome, RecoveryAction, RecoveryItem, RejectionOutcome, RunClaim,
    RunClaimIdentity, RunLane, RunLaneCapacity, RuntimeLease, RuntimeLeaseIdentity, ScheduleIntent,
    ScheduledAdmissionOutcome, SchedulerPolicy, TerminalUpdate, TransitionOutcome, TurnSnapshot,
};
use nostr::{Alphabet, Event, Kind, SingleLetterTag, Timestamp};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

/// Stable pilot retention used to derive replay-safe expiry from signed event time.
pub const PILOT_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1_000;

#[derive(Debug, Error)]
pub enum DurableLifecycleAdapterError {
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
    #[error("lifecycle blocking task failed: {0}")]
    BlockingTask(#[from] tokio::task::JoinError),
    #[error("owner and agent identities must be non-empty")]
    InvalidIdentity,
    #[error("signed event timestamp cannot be represented in milliseconds")]
    TimestampOutOfRange,
    #[error("signed input event was not admitted: {0}")]
    EventNotAdmitted(String),
    #[error("signed input event failed Nostr verification: {0}")]
    InvalidSignedEvent(String),
    #[error("restart recovery input is invalid or unavailable: {0}")]
    RecoveryInputUnavailable(String),
    #[error(transparent)]
    Relay(#[from] crate::relay::RelayError),
    #[error("durable outbox record cannot be published: {0}")]
    OutboxDelivery(String),
}

fn required_outbox_string(payload: &Value, key: &str) -> Result<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            DurableLifecycleAdapterError::OutboxDelivery(format!("outbox payload is missing {key}"))
        })
}

fn outbox_delivery_plan(record: &OutboxRecord) -> Result<OutboxDeliveryPlan> {
    let turn_id = required_outbox_string(&record.payload, "turnId")?;
    let channel_id = Uuid::parse_str(&required_outbox_string(&record.payload, "channelId")?)
        .map_err(|error| DurableLifecycleAdapterError::OutboxDelivery(error.to_string()))?;
    let requester_id = required_outbox_string(&record.payload, "requesterId")?;
    let input_event_id = required_outbox_string(
        &record.payload,
        if record.kind == OutboxKind::Receipt {
            "clientNonce"
        } else {
            "inputEventId"
        },
    )?;
    let input_event_id = nostr::EventId::from_hex(&input_event_id)
        .map_err(|error| DurableLifecycleAdapterError::OutboxDelivery(error.to_string()))?;

    let (content, marker) = match record.kind {
        OutboxKind::Receipt => (
            "On it.".to_owned(),
            format!("buzz.acp.turn.v1:{turn_id}:receipt"),
        ),
        OutboxKind::Terminal => {
            let state = required_outbox_string(&record.payload, "state")?;
            let detail = record.payload.get("detail").ok_or_else(|| {
                DurableLifecycleAdapterError::OutboxDelivery(
                    "terminal outbox payload is missing detail".to_owned(),
                )
            })?;
            let execution_id = detail
                .get("executionId")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or(&turn_id);
            if state == "completed" {
                if detail.get("harnessOwnsFinalReply").and_then(Value::as_bool) != Some(true) {
                    return Err(DurableLifecycleAdapterError::OutboxDelivery(
                        "legacy completed turn has no harness-owned final".to_owned(),
                    ));
                }
                let content = required_outbox_string(detail, "visibleFinalText")?;
                (
                    content,
                    format!("buzz.acp.execution.v1:{execution_id}:final"),
                )
            } else {
                let content = match state.as_str() {
                    "rejected" => {
                        "I couldn't start that request because this agent is at capacity."
                    }
                    "cancelled" => "That request was cancelled.",
                    "expired" => "That request expired before it could be completed.",
                    _ => "I couldn't complete that request.",
                };
                (
                    content.to_owned(),
                    format!("buzz.acp.execution.v1:{execution_id}:failure"),
                )
            }
        }
    };
    Ok(OutboxDeliveryPlan {
        channel_id,
        input_event_id,
        requester_id,
        content,
        marker,
    })
}

fn event_has_client_marker(event: &Event, marker: &str) -> bool {
    event.tags.iter().any(|tag| {
        let parts = tag.as_slice();
        parts.len() >= 2 && parts[0] == "client" && parts[1] == marker
    })
}

async fn find_marked_event(
    rest: &crate::relay::RestClient,
    plan: &OutboxDeliveryPlan,
) -> Result<Option<Event>> {
    let channel = plan.channel_id.to_string();
    let mut until = None;
    for _ in 0..10 {
        let mut filter = nostr::Filter::new()
            .kind(Kind::Custom(9))
            .author(rest.keys.public_key())
            .custom_tags(SingleLetterTag::lowercase(Alphabet::H), [channel.as_str()])
            .limit(500);
        if let Some(timestamp) = until {
            filter = filter.until(Timestamp::from(timestamp));
        }
        let response = rest.query(&[filter]).await?;
        let values = response.as_array().ok_or_else(|| {
            DurableLifecycleAdapterError::OutboxDelivery(
                "relay marker query returned a non-array response".to_owned(),
            )
        })?;
        let mut events = Vec::with_capacity(values.len());
        for value in values {
            let event: Event = serde_json::from_value(value.clone()).map_err(|error| {
                DurableLifecycleAdapterError::OutboxDelivery(format!(
                    "relay marker event is malformed: {error}"
                ))
            })?;
            if event_has_client_marker(&event, &plan.marker) {
                event.verify().map_err(|error| {
                    DurableLifecycleAdapterError::OutboxDelivery(format!(
                        "marked relay event failed signature verification: {error}"
                    ))
                })?;
                let has_channel = event.tags.iter().any(|tag| {
                    let parts = tag.as_slice();
                    parts.len() >= 2 && parts[0] == "h" && parts[1] == channel
                });
                let input_event_id = plan.input_event_id.to_hex();
                let has_reply = event.tags.iter().any(|tag| {
                    let parts = tag.as_slice();
                    parts.len() >= 4
                        && parts[0] == "e"
                        && parts[1] == input_event_id
                        && parts[3] == "reply"
                });
                let has_requester = event.tags.iter().any(|tag| {
                    let parts = tag.as_slice();
                    parts.len() >= 2 && parts[0] == "p" && parts[1] == plan.requester_id
                });
                if event.pubkey != rest.keys.public_key()
                    || event.kind != Kind::Custom(9)
                    || !has_channel
                    || !has_reply
                    || !has_requester
                    || event.content != plan.content
                {
                    return Err(DurableLifecycleAdapterError::OutboxDelivery(
                        "marked relay event does not match the durable delivery plan".to_owned(),
                    ));
                }
                return Ok(Some(event));
            }
            events.push(event);
        }
        if events.len() < 500 {
            break;
        }
        until = events
            .iter()
            .map(|event| event.created_at.as_secs())
            .min()
            .map(|timestamp| timestamp.saturating_sub(1));
        if until.is_none() {
            break;
        }
    }
    Ok(None)
}

pub type Result<T> = std::result::Result<T, DurableLifecycleAdapterError>;

/// Async-safe ACP facade over the synchronous, transaction-scoped lifecycle store.
#[derive(Debug, Clone)]
pub struct DurableLifecycleAdapter {
    store: LifecycleStore,
    owner_id: String,
    agent_id: String,
}

#[derive(Debug, Clone)]
pub struct RehydratedInput {
    pub turn_id: String,
    pub channel_id: Uuid,
    pub event: Event,
    pub prompt_tag: String,
}

#[derive(Debug, Clone)]
struct OutboxDeliveryPlan {
    channel_id: Uuid,
    input_event_id: nostr::EventId,
    requester_id: String,
    content: String,
    marker: String,
}

impl DurableLifecycleAdapter {
    pub async fn open(
        path: impl AsRef<Path>,
        owner_id: impl Into<String>,
        agent_id: impl Into<String>,
    ) -> Result<Self> {
        let owner_id = owner_id.into();
        let agent_id = agent_id.into();
        if owner_id.is_empty() || agent_id.is_empty() {
            return Err(DurableLifecycleAdapterError::InvalidIdentity);
        }
        let path = path.as_ref().to_path_buf();
        let store = tokio::task::spawn_blocking(move || LifecycleStore::open(path)).await??;
        Ok(Self {
            store,
            owner_id,
            agent_id,
        })
    }

    /// Derive immutable admission identity from the signed Nostr envelope.
    ///
    /// The Nostr event ID is both the delivery nonce and input digest: it commits
    /// to the signed content and metadata while making relay replay idempotent.
    pub fn admission_request(&self, channel_id: Uuid, event: &Event) -> Result<AdmissionRequest> {
        event
            .verify()
            .map_err(|error| DurableLifecycleAdapterError::InvalidSignedEvent(error.to_string()))?;
        let received_at_ms = event
            .created_at
            .as_secs()
            .checked_mul(1_000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(DurableLifecycleAdapterError::TimestampOutOfRange)?;
        let expires_at_ms = received_at_ms
            .checked_add(PILOT_RETENTION_MS)
            .ok_or(DurableLifecycleAdapterError::TimestampOutOfRange)?;
        let event_id = event.id.to_hex();
        Ok(AdmissionRequest {
            owner_id: self.owner_id.clone(),
            agent_id: self.agent_id.clone(),
            requester_id: event.pubkey.to_hex(),
            channel_id: channel_id.to_string(),
            client_nonce: event_id.clone(),
            input_digest: event_id,
            received_at_ms,
            expires_at_ms,
        })
    }

    pub async fn admit_event(&self, channel_id: Uuid, event: &Event) -> Result<AdmissionOutcome> {
        let request = self.admission_request(channel_id, event)?;
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || store.admit(&request)).await??)
    }

    pub async fn admit_queued_event(
        &self,
        channel_id: Uuid,
        event: &Event,
        prompt_tag: impl Into<String>,
        occurred_at_ms: i64,
    ) -> Result<AdmissionOutcome> {
        let request = self.admission_request(channel_id, event)?;
        let dispatch = DispatchIntent {
            prompt_tag: prompt_tag.into(),
            delivery_mode: DeliveryMode::Normal,
            retry_count: 0,
            not_before_ms: occurred_at_ms,
            rule_fingerprint: None,
        };
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.admit_queued(
                &request,
                &dispatch,
                serde_json::json!({"adapter": "buzz-acp-shadow"}),
                occurred_at_ms,
            )
        })
        .await??)
    }

    pub async fn admit_queued_event_decision(
        &self,
        channel_id: Uuid,
        event: &Event,
        prompt_tag: impl Into<String>,
        occurred_at_ms: i64,
    ) -> Result<QueueAdmissionOutcome> {
        let request = self.admission_request(channel_id, event)?;
        let dispatch = DispatchIntent {
            prompt_tag: prompt_tag.into(),
            delivery_mode: DeliveryMode::Normal,
            retry_count: 0,
            not_before_ms: occurred_at_ms,
            rule_fingerprint: None,
        };
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.admit_queued_decision(
                &request,
                &dispatch,
                serde_json::json!({"adapter": "buzz-acp-authoritative"}),
                occurred_at_ms,
            )
        })
        .await??)
    }

    pub async fn admit_queued_event_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        channel_id: Uuid,
        event: &Event,
        prompt_tag: impl Into<String>,
        occurred_at_ms: i64,
    ) -> Result<QueueAdmissionOutcome> {
        let authority = self.runtime_identity(instance_id.into());
        let request = self.admission_request(channel_id, event)?;
        let dispatch = DispatchIntent {
            prompt_tag: prompt_tag.into(),
            delivery_mode: DeliveryMode::Normal,
            retry_count: 0,
            not_before_ms: occurred_at_ms,
            rule_fingerprint: None,
        };
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.admit_queued_for_runtime_lease(
                &authority,
                &request,
                &dispatch,
                serde_json::json!({"adapter": "buzz-acp-authoritative"}),
                occurred_at_ms,
            )
        })
        .await??)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn admit_scheduled_event_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        channel_id: Uuid,
        event: &Event,
        prompt_tag: impl Into<String>,
        lane: RunLane,
        source: impl Into<String>,
        capacity: RunLaneCapacity,
        occurred_at_ms: i64,
    ) -> Result<ScheduledAdmissionOutcome> {
        let authority = self.runtime_identity(instance_id.into());
        let request = self.admission_request(channel_id, event)?;
        let dispatch = DispatchIntent {
            prompt_tag: prompt_tag.into(),
            delivery_mode: DeliveryMode::Normal,
            retry_count: 0,
            not_before_ms: occurred_at_ms,
            rule_fingerprint: None,
        };
        let schedule = ScheduleIntent::new(lane, source.into())?;
        let opaque_input_json = serde_json::to_string(event)
            .map_err(|error| DurableLifecycleAdapterError::InvalidSignedEvent(error.to_string()))?;
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.admit_scheduled_for_runtime_lease(
                &authority,
                &request,
                &dispatch,
                &schedule,
                &opaque_input_json,
                capacity,
                serde_json::json!({"adapter": "buzz-acp-scheduler"}),
                occurred_at_ms,
            )
        })
        .await??)
    }

    pub async fn claim_next_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        execution_id: impl Into<String>,
        occurred_at_ms: i64,
    ) -> Result<Option<RunClaim>> {
        let authority = self.runtime_identity(instance_id.into());
        let execution_id = execution_id.into();
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.claim_next_for_runtime_lease(
                &authority,
                SchedulerPolicy::default(),
                &execution_id,
                serde_json::json!({"adapter": "buzz-acp-scheduler", "executionId": execution_id}),
                occurred_at_ms,
            )
        })
        .await??)
    }

    /// Reconstructs and verifies the exact signed event carried by a scheduler claim.
    ///
    /// The durable opaque envelope is accepted only when its signature and all
    /// admission identities still bind to the claimed turn. This is the final
    /// fail-closed boundary before a provider launch.
    pub fn claimed_input(&self, claim: &RunClaim) -> Result<RehydratedInput> {
        let event: Event = serde_json::from_str(&claim.opaque_input_json).map_err(|error| {
            DurableLifecycleAdapterError::RecoveryInputUnavailable(format!(
                "scheduled opaque input is malformed: {error}"
            ))
        })?;
        let channel_id = Uuid::parse_str(&claim.turn.channel_id).map_err(|error| {
            DurableLifecycleAdapterError::RecoveryInputUnavailable(format!(
                "scheduled channel id is invalid: {error}"
            ))
        })?;
        validate_signed_event_binding(&claim.turn, channel_id, &event)?;
        if matches!(
            claim.dispatch.delivery_mode,
            DeliveryMode::MergedSteer | DeliveryMode::MergedInterrupt
        ) {
            return Err(DurableLifecycleAdapterError::RecoveryInputUnavailable(
                "scheduler pilot does not execute merged dispatches".to_owned(),
            ));
        }
        Ok(RehydratedInput {
            turn_id: claim.turn.turn_id.clone(),
            channel_id,
            event,
            prompt_tag: claim.dispatch.prompt_tag.clone(),
        })
    }

    /// Advances a matching scheduler reservation to launched under the lease.
    pub async fn mark_claim_launched_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        claim: RunClaimIdentity,
        occurred_at_ms: i64,
    ) -> Result<()> {
        let authority = self.runtime_identity(instance_id.into());
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_claim_launched_for_runtime_lease(&authority, &claim, occurred_at_ms)
        })
        .await??)
    }

    pub async fn release_claim_to_waiting_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        claim: RunClaimIdentity,
        dispatch: DispatchIntent,
        payload: Value,
        occurred_at_ms: i64,
    ) -> Result<TransitionOutcome> {
        let authority = self.runtime_identity(instance_id.into());
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.release_claim_to_waiting_for_runtime_lease(
                &authority,
                &claim,
                &dispatch,
                payload,
                occurred_at_ms,
            )
        })
        .await??)
    }

    pub async fn finish_claim_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        claim: RunClaimIdentity,
        update: TerminalUpdate,
    ) -> Result<TransitionOutcome> {
        let authority = self.runtime_identity(instance_id.into());
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.finish_claim_for_runtime_lease(&authority, &claim, &update)
        })
        .await??)
    }

    pub async fn reject_event(
        &self,
        channel_id: Uuid,
        event: &Event,
        reason_code: impl Into<String>,
        detail: Value,
        occurred_at_ms: i64,
    ) -> Result<RejectionOutcome> {
        let request = self.admission_request(channel_id, event)?;
        let reason_code = reason_code.into();
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.reject_admission(&request, &reason_code, detail, occurred_at_ms)
        })
        .await??)
    }

    pub async fn reject_event_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        channel_id: Uuid,
        event: &Event,
        reason_code: impl Into<String>,
        detail: Value,
        occurred_at_ms: i64,
    ) -> Result<RejectionOutcome> {
        let authority = self.runtime_identity(instance_id.into());
        let request = self.admission_request(channel_id, event)?;
        let reason_code = reason_code.into();
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.reject_admission_for_runtime_lease(
                &authority,
                &request,
                &reason_code,
                detail,
                occurred_at_ms,
            )
        })
        .await??)
    }

    pub async fn reject_scheduled_event_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        channel_id: Uuid,
        event: &Event,
        reason_code: impl Into<String>,
        detail: Value,
        occurred_at_ms: i64,
    ) -> Result<RejectionOutcome> {
        let authority = self.runtime_identity(instance_id.into());
        let request = self.admission_request(channel_id, event)?;
        let reason_code = reason_code.into();
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.reject_scheduled_admission_for_runtime_lease(
                &authority,
                &request,
                &reason_code,
                detail,
                occurred_at_ms,
            )
        })
        .await??)
    }

    pub async fn mark_queued(
        &self,
        turn_id: impl Into<String>,
        payload: Value,
        occurred_at_ms: i64,
    ) -> Result<TransitionOutcome> {
        let store = self.store.clone();
        let turn_id = turn_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_queued(&turn_id, payload, occurred_at_ms)
        })
        .await??)
    }

    pub async fn mark_running(
        &self,
        turn_id: impl Into<String>,
        execution_id: impl Into<String>,
        payload: Value,
        occurred_at_ms: i64,
    ) -> Result<TransitionOutcome> {
        let store = self.store.clone();
        let turn_id = turn_id.into();
        let execution_id = execution_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_running(&turn_id, &execution_id, payload, occurred_at_ms)
        })
        .await??)
    }

    pub async fn mark_waiting(
        &self,
        turn_id: impl Into<String>,
        payload: Value,
        occurred_at_ms: i64,
    ) -> Result<TransitionOutcome> {
        let store = self.store.clone();
        let turn_id = turn_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_waiting(&turn_id, payload, occurred_at_ms)
        })
        .await??)
    }

    pub async fn mark_terminal(
        &self,
        turn_id: impl Into<String>,
        update: TerminalUpdate,
    ) -> Result<TransitionOutcome> {
        let store = self.store.clone();
        let turn_id = turn_id.into();
        Ok(tokio::task::spawn_blocking(move || store.mark_terminal(&turn_id, &update)).await??)
    }

    pub async fn active_turns_page(
        &self,
        after: Option<ActiveTurnCursor>,
        limit: usize,
    ) -> Result<ActiveTurnPage> {
        let store = self.store.clone();
        let owner_id = self.owner_id.clone();
        let agent_id = self.agent_id.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.active_turns_for_agent_page(&owner_id, &agent_id, after.as_ref(), limit)
        })
        .await??)
    }

    pub async fn turn_for_event_id(
        &self,
        event_id: impl Into<String>,
    ) -> Result<Option<TurnSnapshot>> {
        let store = self.store.clone();
        let owner_id = self.owner_id.clone();
        let agent_id = self.agent_id.clone();
        let event_id = event_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.turn_for_nonce(&owner_id, &agent_id, &event_id)
        })
        .await??)
    }

    pub async fn mark_events_running(
        &self,
        event_ids: Vec<String>,
        execution_id: impl Into<String>,
        payload: Value,
        occurred_at_ms: i64,
    ) -> Result<Vec<TransitionOutcome>> {
        let turn_ids = self.turn_ids_for_events(event_ids).await?;
        let store = self.store.clone();
        let execution_id = execution_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_running_many(&turn_ids, &execution_id, payload, occurred_at_ms)
        })
        .await??)
    }

    pub async fn mark_events_waiting(
        &self,
        event_ids: Vec<String>,
        payload: Value,
        occurred_at_ms: i64,
    ) -> Result<Vec<TransitionOutcome>> {
        let turn_ids = self.turn_ids_for_events(event_ids).await?;
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_waiting_many(&turn_ids, payload, occurred_at_ms)
        })
        .await??)
    }

    pub async fn mark_events_waiting_for_execution(
        &self,
        event_ids: Vec<String>,
        execution_id: impl Into<String>,
        payload: Value,
        occurred_at_ms: i64,
    ) -> Result<Vec<TransitionOutcome>> {
        let turn_ids = self.turn_ids_for_events(event_ids).await?;
        let store = self.store.clone();
        let execution_id = execution_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_waiting_many_for_execution(&turn_ids, &execution_id, payload, occurred_at_ms)
        })
        .await??)
    }

    pub async fn mark_events_terminal(
        &self,
        event_ids: Vec<String>,
        update: TerminalUpdate,
    ) -> Result<Vec<TransitionOutcome>> {
        let turn_ids = self.turn_ids_for_events(event_ids).await?;
        let store = self.store.clone();
        Ok(
            tokio::task::spawn_blocking(move || store.mark_terminal_many(&turn_ids, &update))
                .await??,
        )
    }

    pub async fn mark_events_terminal_for_execution(
        &self,
        event_ids: Vec<String>,
        execution_id: impl Into<String>,
        update: TerminalUpdate,
    ) -> Result<Vec<TransitionOutcome>> {
        let turn_ids = self.turn_ids_for_events(event_ids).await?;
        let store = self.store.clone();
        let execution_id = execution_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_terminal_many_for_execution(&turn_ids, &execution_id, &update)
        })
        .await??)
    }

    pub async fn expire_due(&self, now_ms: i64, limit: usize) -> Result<Vec<TurnSnapshot>> {
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || store.expire_due(now_ms, limit)).await??)
    }

    pub async fn expire_due_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<TurnSnapshot>> {
        let authority = self.runtime_identity(instance_id.into());
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.expire_due_for_runtime_lease(&authority, now_ms, limit)
        })
        .await??)
    }

    pub async fn claim_pending_outbox(
        &self,
        instance_id: impl Into<String>,
        now_ms: i64,
        limit: usize,
        claim_token: impl Into<String>,
        claim_expires_at_ms: i64,
    ) -> Result<Vec<OutboxRecord>> {
        let authority = self.runtime_identity(instance_id.into());
        let claim_token = claim_token.into();
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.claim_pending_outbox_for_runtime_lease(
                &authority,
                now_ms,
                limit,
                &claim_token,
                claim_expires_at_ms,
            )
        })
        .await??)
    }

    pub async fn retry_claimed_outbox(
        &self,
        instance_id: impl Into<String>,
        outbox_id: impl Into<String>,
        claim_token: impl Into<String>,
        now_ms: i64,
        not_before_ms: i64,
    ) -> Result<OutboxRecord> {
        let authority = self.runtime_identity(instance_id.into());
        let outbox_id = outbox_id.into();
        let claim_token = claim_token.into();
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.record_claimed_outbox_attempt_for_runtime_lease(
                &authority,
                &outbox_id,
                &claim_token,
                now_ms,
                not_before_ms,
            )
        })
        .await??)
    }

    pub async fn mark_claimed_outbox_delivered(
        &self,
        instance_id: impl Into<String>,
        outbox_id: impl Into<String>,
        claim_token: impl Into<String>,
        delivered_event_id: impl Into<String>,
        delivered_at_ms: i64,
    ) -> Result<OutboxRecord> {
        let authority = self.runtime_identity(instance_id.into());
        let outbox_id = outbox_id.into();
        let claim_token = claim_token.into();
        let delivered_event_id = delivered_event_id.into();
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_claimed_outbox_delivered_for_runtime_lease(
                &authority,
                &outbox_id,
                &claim_token,
                &delivered_event_id,
                delivered_at_ms,
            )
        })
        .await??)
    }

    pub async fn deliver_claimed_outbox(
        &self,
        instance_id: impl Into<String>,
        rest: &crate::relay::RestClient,
        record: &OutboxRecord,
        claim_token: impl Into<String>,
    ) -> Result<OutboxRecord> {
        use nostr::event::builder::Error as EventBuilderError;

        let instance_id = instance_id.into();
        let claim_token = claim_token.into();
        let plan = outbox_delivery_plan(record)?;
        let event_id = if let Some(existing) = find_marked_event(rest, &plan).await? {
            existing.id.to_hex()
        } else {
            self.verify_runtime_lease(instance_id.clone(), chrono::Utc::now().timestamp_millis())
                .await?;
            let thread = buzz_sdk::ThreadRef {
                root_event_id: plan.input_event_id,
                parent_event_id: plan.input_event_id,
            };
            let builder = buzz_sdk::build_message_with_client_marker(
                plan.channel_id,
                &plan.content,
                Some(&thread),
                &[plan.requester_id.as_str()],
                &plan.marker,
            )
            .map_err(|error| DurableLifecycleAdapterError::OutboxDelivery(error.to_string()))?;
            let event =
                builder
                    .sign_with_keys(&rest.keys)
                    .map_err(|error: EventBuilderError| {
                        DurableLifecycleAdapterError::OutboxDelivery(error.to_string())
                    })?;
            rest.submit_event_verified(&event).await?
        };
        self.mark_claimed_outbox_delivered(
            instance_id,
            record.outbox_id.clone(),
            claim_token,
            event_id,
            chrono::Utc::now().timestamp_millis(),
        )
        .await
    }

    pub async fn acquire_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<RuntimeLease> {
        let store = self.store.clone();
        let owner_id = self.owner_id.clone();
        let agent_id = self.agent_id.clone();
        let instance_id = instance_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.acquire_runtime_lease(&owner_id, &agent_id, &instance_id, now_ms, expires_at_ms)
        })
        .await??)
    }

    pub async fn renew_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<RuntimeLease> {
        let store = self.store.clone();
        let owner_id = self.owner_id.clone();
        let agent_id = self.agent_id.clone();
        let instance_id = instance_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.renew_runtime_lease(&owner_id, &agent_id, &instance_id, now_ms, expires_at_ms)
        })
        .await??)
    }

    pub async fn release_runtime_lease(&self, instance_id: impl Into<String>) -> Result<()> {
        let store = self.store.clone();
        let owner_id = self.owner_id.clone();
        let agent_id = self.agent_id.clone();
        let instance_id = instance_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.release_runtime_lease(&owner_id, &agent_id, &instance_id)
        })
        .await??)
    }

    pub async fn verify_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        now_ms: i64,
    ) -> Result<()> {
        let authority = self.runtime_identity(instance_id.into());
        let store = self.store.clone();
        Ok(
            tokio::task::spawn_blocking(move || store.verify_runtime_lease(&authority, now_ms))
                .await??,
        )
    }

    pub async fn bind_events_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        event_ids: Vec<String>,
        execution_id: impl Into<String>,
        payload: Value,
        occurred_at_ms: i64,
    ) -> Result<Vec<TransitionOutcome>> {
        let store = self.store.clone();
        let authority = self.runtime_identity(instance_id.into());
        let execution_id = execution_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.bind_nonces_for_runtime_lease(
                &authority,
                &event_ids,
                &execution_id,
                payload,
                occurred_at_ms,
            )
        })
        .await??)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn mark_events_waiting_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        event_ids: Vec<String>,
        execution_id: impl Into<String>,
        dispatch: DispatchIntent,
        payload: Value,
        occurred_at_ms: i64,
    ) -> Result<Vec<TransitionOutcome>> {
        let store = self.store.clone();
        let authority = self.runtime_identity(instance_id.into());
        let execution_id = execution_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_nonces_waiting_for_runtime_lease(
                &authority,
                &event_ids,
                &execution_id,
                &dispatch,
                payload,
                occurred_at_ms,
            )
        })
        .await??)
    }

    pub async fn mark_events_terminal_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        event_ids: Vec<String>,
        execution_id: impl Into<String>,
        update: TerminalUpdate,
    ) -> Result<Vec<TransitionOutcome>> {
        let store = self.store.clone();
        let authority = self.runtime_identity(instance_id.into());
        let execution_id = execution_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_nonces_terminal_for_runtime_lease(
                &authority,
                &event_ids,
                &execution_id,
                &update,
            )
        })
        .await??)
    }

    pub async fn mark_execution_terminal_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        execution_id: impl Into<String>,
        update: TerminalUpdate,
    ) -> Result<Vec<TransitionOutcome>> {
        let store = self.store.clone();
        let authority = self.runtime_identity(instance_id.into());
        let execution_id = execution_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.mark_execution_terminal_for_runtime_lease(&authority, &execution_id, &update)
        })
        .await??)
    }

    pub async fn recover_for_restart(
        &self,
        instance_id: impl Into<String>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<RecoveryItem>> {
        let store = self.store.clone();
        let owner_id = self.owner_id.clone();
        let agent_id = self.agent_id.clone();
        let instance_id = instance_id.into();
        Ok(tokio::task::spawn_blocking(move || {
            store.recover_for_restart(&owner_id, &agent_id, &instance_id, now_ms, limit)
        })
        .await??)
    }

    pub async fn recover_scheduler_active_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        now_ms: i64,
    ) -> Result<Option<RecoveryItem>> {
        let authority = self.runtime_identity(instance_id.into());
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.recover_scheduler_active_for_runtime_lease(&authority, now_ms)
        })
        .await??)
    }

    pub async fn acknowledge_recovery_enqueued_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        turn_id: impl Into<String>,
        recovered_version: u64,
        now_ms: i64,
    ) -> Result<()> {
        let authority = self.runtime_identity(instance_id.into());
        let turn_id = turn_id.into();
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.acknowledge_recovery_enqueued_for_runtime_lease(
                &authority,
                &turn_id,
                recovered_version,
                now_ms,
            )
        })
        .await??)
    }

    pub async fn reconcile_pending_recovery_for_runtime_lease(
        &self,
        instance_id: impl Into<String>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<RecoveryItem>> {
        let authority = self.runtime_identity(instance_id.into());
        let store = self.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.reconcile_pending_recovery_for_runtime_lease(&authority, now_ms, limit)
        })
        .await??)
    }

    pub async fn rehydrate_recovery_input(
        &self,
        rest: &crate::relay::RestClient,
        recovery: &RecoveryItem,
    ) -> Result<RehydratedInput> {
        use nostr::{Alphabet, SingleLetterTag};

        if recovery.action != RecoveryAction::Rehydrate {
            return Err(DurableLifecycleAdapterError::RecoveryInputUnavailable(
                "recovery item is not eligible for automatic rehydration".to_owned(),
            ));
        }
        let event_id = nostr::EventId::from_hex(&recovery.turn.client_nonce).map_err(|error| {
            DurableLifecycleAdapterError::RecoveryInputUnavailable(format!(
                "stored event id is invalid: {error}"
            ))
        })?;
        let requester =
            nostr::PublicKey::from_hex(&recovery.turn.requester_id).map_err(|error| {
                DurableLifecycleAdapterError::RecoveryInputUnavailable(format!(
                    "stored requester key is invalid: {error}"
                ))
            })?;
        let channel_id = Uuid::parse_str(&recovery.turn.channel_id).map_err(|error| {
            DurableLifecycleAdapterError::RecoveryInputUnavailable(format!(
                "stored channel id is invalid: {error}"
            ))
        })?;
        let channel = channel_id.to_string();
        let filter = nostr::Filter::new()
            .id(event_id)
            .author(requester)
            .custom_tags(SingleLetterTag::lowercase(Alphabet::H), [channel.as_str()])
            .limit(2);
        let response = rest.query(&[filter]).await?;
        let values = response.as_array().ok_or_else(|| {
            DurableLifecycleAdapterError::RecoveryInputUnavailable(
                "relay query returned a non-array response".to_owned(),
            )
        })?;
        if values.len() != 1 {
            return Err(DurableLifecycleAdapterError::RecoveryInputUnavailable(
                format!("expected one relay event, found {}", values.len()),
            ));
        }
        let event: Event = serde_json::from_value(values[0].clone()).map_err(|error| {
            DurableLifecycleAdapterError::RecoveryInputUnavailable(format!(
                "relay event is malformed: {error}"
            ))
        })?;
        validate_rehydrated_event(recovery, channel_id, &event)?;
        let dispatch = recovery.dispatch.as_ref().ok_or_else(|| {
            DurableLifecycleAdapterError::RecoveryInputUnavailable(
                "dispatch intent is missing".to_owned(),
            )
        })?;
        if dispatch.delivery_mode != DeliveryMode::Normal || dispatch.retry_count != 0 {
            return Err(DurableLifecycleAdapterError::RecoveryInputUnavailable(
                "retry and merged dispatch recovery requires the due-queue reconciler".to_owned(),
            ));
        }
        let prompt_tag = dispatch.prompt_tag.clone();
        Ok(RehydratedInput {
            turn_id: recovery.turn.turn_id.clone(),
            channel_id,
            event,
            prompt_tag,
        })
    }

    async fn turn_ids_for_events(&self, event_ids: Vec<String>) -> Result<Vec<String>> {
        if event_ids.is_empty() {
            return Err(LifecycleError::InvalidRequest("event id batch must not be empty").into());
        }
        let store = self.store.clone();
        let owner_id = self.owner_id.clone();
        let agent_id = self.agent_id.clone();
        tokio::task::spawn_blocking(move || {
            event_ids
                .into_iter()
                .map(|event_id| {
                    store
                        .turn_for_nonce(&owner_id, &agent_id, &event_id)?
                        .map(|turn| turn.turn_id)
                        .ok_or(DurableLifecycleAdapterError::EventNotAdmitted(event_id))
                })
                .collect()
        })
        .await?
    }

    fn runtime_identity(&self, instance_id: String) -> RuntimeLeaseIdentity {
        RuntimeLeaseIdentity {
            owner_id: self.owner_id.clone(),
            agent_id: self.agent_id.clone(),
            instance_id,
        }
    }
}

fn validate_rehydrated_event(
    recovery: &RecoveryItem,
    channel_id: Uuid,
    event: &Event,
) -> Result<()> {
    validate_signed_event_binding(&recovery.turn, channel_id, event)
}

fn validate_signed_event_binding(
    turn: &TurnSnapshot,
    channel_id: Uuid,
    event: &Event,
) -> Result<()> {
    event
        .verify()
        .map_err(|error| DurableLifecycleAdapterError::InvalidSignedEvent(error.to_string()))?;
    if event.id.to_hex() != turn.client_nonce
        || event.id.to_hex() != turn.input_digest
        || event.pubkey.to_hex() != turn.requester_id
    {
        return Err(DurableLifecycleAdapterError::RecoveryInputUnavailable(
            "signed event identity does not match the durable turn".to_owned(),
        ));
    }
    let channel = channel_id.to_string();
    let has_channel = event.tags.iter().any(|tag| {
        let values = tag.as_slice();
        values.first().map(String::as_str) == Some("h")
            && values.get(1).map(String::as_str) == Some(channel.as_str())
    });
    if !has_channel {
        return Err(DurableLifecycleAdapterError::RecoveryInputUnavailable(
            "signed event channel does not match the durable turn".to_owned(),
        ));
    }
    let created_at_ms = event
        .created_at
        .as_secs()
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(DurableLifecycleAdapterError::TimestampOutOfRange)?;
    if created_at_ms != turn.accepted_at_ms {
        return Err(DurableLifecycleAdapterError::RecoveryInputUnavailable(
            "signed event timestamp does not match the durable turn".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{routing::post, Json, Router};
    use buzz_lifecycle::{
        AdmissionOutcome, LifecycleError, OutboxState, RunLane, RunLaneCapacity, TerminalUpdate,
        TurnState,
    };
    use nostr::{EventBuilder, Keys, Kind, Timestamp};

    use super::*;

    fn signed_event(
        created_at_secs: u64,
    ) -> std::result::Result<Event, nostr::event::builder::Error> {
        EventBuilder::new(Kind::Custom(9), "durable turn")
            .custom_created_at(Timestamp::from(created_at_secs))
            .sign_with_keys(&Keys::generate())
    }

    fn signed_channel_event(
        keys: &Keys,
        channel_id: Uuid,
        created_at_secs: u64,
    ) -> std::result::Result<Event, nostr::event::builder::Error> {
        let channel_tag =
            nostr::Tag::parse(["h", &channel_id.to_string()]).expect("valid channel tag");
        EventBuilder::new(Kind::Custom(9), "durable turn")
            .tags([channel_tag])
            .custom_created_at(Timestamp::from(created_at_secs))
            .sign_with_keys(keys)
    }

    fn outbox_record(kind: OutboxKind, payload: Value) -> OutboxRecord {
        OutboxRecord {
            outbox_id: "outbox-a".to_owned(),
            turn_id: "turn-a".to_owned(),
            owner_id: "owner-a".to_owned(),
            kind,
            dedupe_key: "dedupe-a".to_owned(),
            payload,
            state: OutboxState::Pending,
            attempts: 0,
            not_before_ms: 1,
            created_at_ms: 1,
            delivered_at_ms: None,
            claim_token: Some("claim-a".to_owned()),
            claim_expires_at_ms: Some(10),
            delivered_event_id: None,
        }
    }

    async fn empty_query() -> Json<Value> {
        Json(serde_json::json!([]))
    }

    async fn accept_submitted_event(Json(event): Json<Event>) -> Json<Value> {
        Json(serde_json::json!({
            "accepted": true,
            "event_id": event.id.to_hex(),
        }))
    }

    #[tokio::test]
    async fn claimed_receipt_is_submitted_and_marked_delivered_through_rest(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let router = Router::new()
            .route("/query", post(empty_query))
            .route("/events", post(accept_submitted_event));
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("test relay server");
        });

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("outbox.sqlite3");
        let adapter = DurableLifecycleAdapter::open(&path, "owner-a", "agent-a").await?;
        let channel_id = Uuid::new_v4();
        let input = signed_channel_event(&Keys::generate(), channel_id, 1_700_000_000)?;
        adapter
            .admit_queued_event(channel_id, &input, "@mention", 1_700_000_000_100)
            .await?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        adapter
            .acquire_runtime_lease("instance-a", now_ms, now_ms + 10_000)
            .await?;
        let claim = adapter
            .claim_pending_outbox("instance-a", now_ms + 1, 10, "claim-a", now_ms + 5_000)
            .await?;
        assert_eq!(claim.len(), 1);
        let rest = crate::relay::RestClient {
            http: reqwest::Client::new(),
            base_url: format!("http://{address}"),
            keys: Keys::generate(),
            auth_tag_json: None,
        };
        let delivered = adapter
            .deliver_claimed_outbox("instance-a", &rest, &claim[0], "claim-a")
            .await?;
        assert_eq!(delivered.state, OutboxState::Delivered);
        assert!(delivered.delivered_event_id.is_some());
        assert!(LifecycleStore::open(path)?
            .pending_outbox(now_ms + 2, 10)?
            .is_empty());
        server.abort();
        Ok(())
    }

    #[test]
    fn outbox_delivery_plan_is_marked_and_never_exposes_failure_detail(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let event = signed_event(1_700_000_000)?;
        let channel_id = Uuid::new_v4();
        let receipt = outbox_record(
            OutboxKind::Receipt,
            serde_json::json!({
                "turnId": "turn-a",
                "channelId": channel_id,
                "requesterId": event.pubkey.to_hex(),
                "clientNonce": event.id.to_hex(),
            }),
        );
        let receipt_plan = outbox_delivery_plan(&receipt)?;
        assert_eq!(receipt_plan.content, "On it.");
        assert_eq!(receipt_plan.marker, "buzz.acp.turn.v1:turn-a:receipt");

        let completed = outbox_record(
            OutboxKind::Terminal,
            serde_json::json!({
                "turnId": "turn-a",
                "channelId": channel_id,
                "requesterId": event.pubkey.to_hex(),
                "inputEventId": event.id.to_hex(),
                "state": "completed",
                "detail": {
                    "executionId": "execution-a",
                    "harnessOwnsFinalReply": true,
                    "visibleFinalText": "Durable answer",
                },
            }),
        );
        let completed_plan = outbox_delivery_plan(&completed)?;
        assert_eq!(completed_plan.content, "Durable answer");
        assert_eq!(
            completed_plan.marker,
            "buzz.acp.execution.v1:execution-a:final"
        );

        let failed = outbox_record(
            OutboxKind::Terminal,
            serde_json::json!({
                "turnId": "turn-a",
                "channelId": channel_id,
                "requesterId": event.pubkey.to_hex(),
                "inputEventId": event.id.to_hex(),
                "state": "failed",
                "detail": {
                    "executionId": "execution-a",
                    "providerError": "secret internal failure",
                },
            }),
        );
        let failed_plan = outbox_delivery_plan(&failed)?;
        assert_eq!(failed_plan.content, "I couldn't complete that request.");
        assert!(!failed_plan.content.contains("secret"));
        assert_eq!(
            failed_plan.marker,
            "buzz.acp.execution.v1:execution-a:failure"
        );
        Ok(())
    }

    #[tokio::test]
    async fn signed_event_translation_is_stable_and_replay_safe(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let adapter = DurableLifecycleAdapter::open(
            directory.path().join("lifecycle.sqlite3"),
            "owner-a",
            "agent-a",
        )
        .await?;
        let channel_id = Uuid::new_v4();
        let event = signed_event(1_700_000_000)?;

        let request = adapter.admission_request(channel_id, &event)?;
        assert_eq!(request.client_nonce, event.id.to_hex());
        assert_eq!(request.input_digest, event.id.to_hex());
        assert_eq!(request.requester_id, event.pubkey.to_hex());
        assert_eq!(request.channel_id, channel_id.to_string());
        assert_eq!(request.received_at_ms, 1_700_000_000_000);
        assert_eq!(
            request.expires_at_ms,
            request.received_at_ms + PILOT_RETENTION_MS
        );

        let first = adapter.admit_event(channel_id, &event).await?;
        let replay = adapter.admit_event(channel_id, &event).await?;
        assert!(matches!(first, AdmissionOutcome::Accepted(_)));
        assert!(matches!(replay, AdmissionOutcome::Duplicate(_)));
        assert_eq!(first.turn().turn_id, replay.turn().turn_id);
        assert_eq!(
            adapter
                .turn_for_event_id(event.id.to_hex())
                .await?
                .map(|turn| turn.turn_id),
            Some(first.turn().turn_id.clone())
        );
        assert_eq!(
            adapter.active_turns_page(None, 1_000).await?.turns[0].state,
            TurnState::Accepted
        );
        Ok(())
    }

    #[tokio::test]
    async fn tampered_signed_event_is_rejected_before_admission(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let adapter = DurableLifecycleAdapter::open(
            directory.path().join("lifecycle.sqlite3"),
            "owner-a",
            "agent-a",
        )
        .await?;
        let event = signed_event(1_700_000_000)?;
        let mut value = serde_json::to_value(event)?;
        value["content"] = serde_json::Value::String("tampered".to_owned());
        let tampered: Event = serde_json::from_value(value)?;

        assert!(matches!(
            adapter.admit_event(Uuid::new_v4(), &tampered).await,
            Err(DurableLifecycleAdapterError::InvalidSignedEvent(_))
        ));
        assert!(adapter
            .active_turns_page(None, 1_000)
            .await?
            .turns
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_work_runs_off_the_async_reactor(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let adapter = DurableLifecycleAdapter::open(
            directory.path().join("lifecycle.sqlite3"),
            "owner-a",
            "agent-a",
        )
        .await?;
        let event = signed_event(1_700_000_000)?;
        let admitted = adapter
            .admit_queued_event(Uuid::new_v4(), &event, "@mention", 1_700_000_000_001)
            .await?;
        assert_eq!(admitted.turn().state, TurnState::Queued);
        adapter
            .acquire_runtime_lease("instance-a", 1_700_000_000_002, 1_700_000_010_000)
            .await?;
        let recovered = adapter
            .recover_for_restart("instance-a", 1_700_000_000_003, 10)
            .await?;
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].turn.state, TurnState::Queued);
        Ok(())
    }

    #[tokio::test]
    async fn recovery_input_validation_requires_exact_signed_identity_and_channel(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let adapter = DurableLifecycleAdapter::open(
            directory.path().join("lifecycle.sqlite3"),
            "owner-a",
            "agent-a",
        )
        .await?;
        let channel_id = Uuid::new_v4();
        let keys = Keys::generate();
        let event = signed_channel_event(&keys, channel_id, 1_700_000_000)?;
        adapter
            .admit_queued_event(channel_id, &event, "@mention", 1_700_000_000_001)
            .await?;
        adapter
            .acquire_runtime_lease("instance-a", 1_700_000_000_002, 1_700_000_010_000)
            .await?;
        let recovery = adapter
            .recover_for_restart("instance-a", 1_700_000_000_003, 10)
            .await?
            .remove(0);
        validate_rehydrated_event(&recovery, channel_id, &event)?;

        let wrong_author = signed_channel_event(&Keys::generate(), channel_id, 1_700_000_000)?;
        assert!(matches!(
            validate_rehydrated_event(&recovery, channel_id, &wrong_author),
            Err(DurableLifecycleAdapterError::RecoveryInputUnavailable(_))
        ));
        let wrong_channel = signed_channel_event(&keys, Uuid::new_v4(), 1_700_000_000)?;
        assert!(matches!(
            validate_rehydrated_event(&recovery, channel_id, &wrong_channel),
            Err(DurableLifecycleAdapterError::RecoveryInputUnavailable(_))
        ));
        let mut tampered_value = serde_json::to_value(&event)?;
        tampered_value["content"] = serde_json::Value::String("tampered".to_owned());
        let tampered: Event = serde_json::from_value(tampered_value)?;
        assert!(matches!(
            validate_rehydrated_event(&recovery, channel_id, &tampered),
            Err(DurableLifecycleAdapterError::InvalidSignedEvent(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn merged_event_attempt_updates_all_rows_as_one_batch(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let adapter = DurableLifecycleAdapter::open(
            directory.path().join("lifecycle.sqlite3"),
            "owner-a",
            "agent-a",
        )
        .await?;
        let channel_id = Uuid::new_v4();
        let first = signed_event(1_700_000_000)?;
        let second = signed_event(1_700_000_001)?;
        adapter.admit_event(channel_id, &first).await?;
        adapter.admit_event(channel_id, &second).await?;
        let event_ids = vec![first.id.to_hex(), second.id.to_hex()];

        let running = adapter
            .mark_events_running(
                event_ids.clone(),
                "execution-a",
                serde_json::json!({"batchSize": 2}),
                1_700_000_001_001,
            )
            .await?;
        assert!(running
            .iter()
            .all(|outcome| outcome.turn().state == TurnState::Running));

        let completed = adapter
            .mark_events_terminal_for_execution(
                event_ids,
                "execution-a",
                TerminalUpdate {
                    state: TurnState::Completed,
                    result_digest: Some("sha256:result-a".to_owned()),
                    payload: serde_json::json!({"executionId": "execution-a"}),
                    occurred_at_ms: 1_700_000_001_500,
                },
            )
            .await?;
        assert!(completed
            .iter()
            .all(|outcome| outcome.turn().state == TurnState::Completed));
        assert!(adapter
            .active_turns_page(None, 1_000)
            .await?
            .turns
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn scheduler_policy_rejection_replays_without_queue_or_claim(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let adapter = DurableLifecycleAdapter::open(
            directory.path().join("scheduler.sqlite3"),
            "owner-a",
            "agent-a",
        )
        .await?;
        let now_ms = 1_700_000_000_100;
        adapter
            .acquire_runtime_lease("instance-a", now_ms, now_ms + 10_000)
            .await?;
        let channel_id = Uuid::new_v4();
        let event = signed_channel_event(&Keys::generate(), channel_id, 1_700_000_000)?;
        let queue = crate::queue::EventQueue::new(crate::config::DedupMode::Queue);

        let rejected = adapter
            .reject_scheduled_event_for_runtime_lease(
                "instance-a",
                channel_id,
                &event,
                "scheduler_sender_unclassified",
                serde_json::json!({"policy":"test"}),
                now_ms + 1,
            )
            .await?;
        assert!(matches!(rejected, RejectionOutcome::Rejected(_)));
        let replay = adapter
            .reject_scheduled_event_for_runtime_lease(
                "instance-a",
                channel_id,
                &event,
                "scheduler_sender_unclassified",
                serde_json::json!({"policy":"test"}),
                now_ms + 2,
            )
            .await?;
        assert!(matches!(replay, RejectionOutcome::Duplicate(_)));
        assert_eq!(queue.pending_channels(), 0);
        assert!(adapter
            .claim_next_for_runtime_lease("instance-a", "must-not-launch", now_ms + 3)
            .await?
            .is_none());
        assert_eq!(queue.pending_channels(), 0);
        assert!(matches!(
            adapter
                .reject_event_for_runtime_lease(
                    "instance-a",
                    channel_id,
                    &signed_channel_event(&Keys::generate(), channel_id, 1_700_000_001)?,
                    "legacy_path",
                    serde_json::json!({}),
                    now_ms + 3,
                )
                .await,
            Err(DurableLifecycleAdapterError::Lifecycle(
                LifecycleError::SchedulerModeConflict
            ))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn scheduler_claim_round_trip_is_fenced_and_never_uses_event_queue(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let adapter = DurableLifecycleAdapter::open(
            directory.path().join("scheduler.sqlite3"),
            "owner-a",
            "agent-a",
        )
        .await?;
        let now_ms = 1_700_000_000_100;
        adapter
            .acquire_runtime_lease("instance-a", now_ms, now_ms + 10_000)
            .await?;
        let channel_id = Uuid::new_v4();
        let event = signed_channel_event(&Keys::generate(), channel_id, 1_700_000_000)?;
        let queue = crate::queue::EventQueue::new(crate::config::DedupMode::Queue);

        let admitted = adapter
            .admit_scheduled_event_for_runtime_lease(
                "instance-a",
                channel_id,
                &event,
                "@mention",
                RunLane::User,
                "human",
                RunLaneCapacity {
                    user: 8,
                    agent: 8,
                    background: 8,
                },
                now_ms + 1,
            )
            .await?;
        assert!(admitted.should_enqueue());
        assert_eq!(queue.pending_channels(), 0);

        let claim = adapter
            .claim_next_for_runtime_lease("instance-a", "execution-a", now_ms + 2)
            .await?
            .ok_or("expected scheduler claim")?;
        let input = adapter.claimed_input(&claim)?;
        assert_eq!(input.channel_id, channel_id);
        assert_eq!(input.event.id, event.id);
        adapter
            .mark_claim_launched_for_runtime_lease("instance-a", claim.identity.clone(), now_ms + 3)
            .await?;
        adapter
            .finish_claim_for_runtime_lease(
                "instance-a",
                claim.identity.clone(),
                TerminalUpdate {
                    state: TurnState::Completed,
                    result_digest: Some("sha256:result-a".to_owned()),
                    payload: serde_json::json!({"adapter": "test"}),
                    occurred_at_ms: now_ms + 4,
                },
            )
            .await?;
        let stale = adapter
            .finish_claim_for_runtime_lease(
                "instance-a",
                claim.identity,
                TerminalUpdate {
                    state: TurnState::Failed,
                    result_digest: Some("sha256:stale".to_owned()),
                    payload: serde_json::json!({"adapter": "stale"}),
                    occurred_at_ms: now_ms + 5,
                },
            )
            .await;
        assert!(matches!(
            stale,
            Err(DurableLifecycleAdapterError::Lifecycle(
                LifecycleError::SchedulerClaimConflict
            ))
        ));
        assert_eq!(queue.pending_channels(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn corrupt_migrated_opaque_input_is_quarantined_once_without_launch_or_queue(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("scheduler.sqlite3");
        let adapter = DurableLifecycleAdapter::open(&path, "owner-a", "agent-a").await?;
        let now_ms = 1_700_000_000_100;
        adapter
            .acquire_runtime_lease("instance-a", now_ms, now_ms + 10_000)
            .await?;
        let channel_id = Uuid::new_v4();
        let event = signed_channel_event(&Keys::generate(), channel_id, 1_700_000_000)?;
        let admitted = adapter
            .admit_scheduled_event_for_runtime_lease(
                "instance-a",
                channel_id,
                &event,
                "@mention",
                RunLane::User,
                "human",
                RunLaneCapacity {
                    user: 8,
                    agent: 8,
                    background: 8,
                },
                now_ms + 1,
            )
            .await?;
        assert!(admitted.should_enqueue());
        let queue = crate::queue::EventQueue::new(crate::config::DedupMode::Queue);
        let claim = adapter
            .claim_next_for_runtime_lease("instance-a", "execution-corrupt", now_ms + 2)
            .await?
            .ok_or("expected corrupt scheduler claim")?;
        // Models a pre-v6/fabricated claim payload at the ACP boundary without
        // teaching this crate to mutate lifecycle-owned schema directly.
        let mut corrupt_claim = claim.clone();
        corrupt_claim.opaque_input_json = "{}".to_owned();
        assert!(matches!(
            adapter.claimed_input(&corrupt_claim),
            Err(DurableLifecycleAdapterError::RecoveryInputUnavailable(_))
        ));
        adapter
            .finish_claim_for_runtime_lease(
                "instance-a",
                claim.identity.clone(),
                TerminalUpdate {
                    state: TurnState::Cancelled,
                    result_digest: None,
                    payload: serde_json::json!({"reason": "invalid_opaque_input_quarantined"}),
                    occurred_at_ms: now_ms + 3,
                },
            )
            .await?;
        assert!(adapter
            .claim_next_for_runtime_lease("instance-a", "execution-next", now_ms + 4)
            .await?
            .is_none());
        assert!(matches!(
            adapter
                .finish_claim_for_runtime_lease(
                    "instance-a",
                    claim.identity,
                    TerminalUpdate {
                        state: TurnState::Failed,
                        result_digest: Some("sha256:duplicate".to_owned()),
                        payload: serde_json::json!({"reason": "duplicate"}),
                        occurred_at_ms: now_ms + 5,
                    },
                )
                .await,
            Err(DurableLifecycleAdapterError::Lifecycle(
                LifecycleError::SchedulerClaimConflict
            ))
        ));
        assert_eq!(queue.pending_channels(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn pre_launch_failure_releases_reserved_claim_for_a_fresh_fenced_retry(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let adapter = DurableLifecycleAdapter::open(
            directory.path().join("scheduler.sqlite3"),
            "owner-a",
            "agent-a",
        )
        .await?;
        let now_ms = 1_700_000_000_100;
        adapter
            .acquire_runtime_lease("instance-a", now_ms, now_ms + 10_000)
            .await?;
        let channel_id = Uuid::new_v4();
        let event = signed_channel_event(&Keys::generate(), channel_id, 1_700_000_000)?;
        adapter
            .admit_scheduled_event_for_runtime_lease(
                "instance-a",
                channel_id,
                &event,
                "@mention",
                RunLane::User,
                "human",
                RunLaneCapacity {
                    user: 8,
                    agent: 8,
                    background: 8,
                },
                now_ms + 1,
            )
            .await?;
        let queue = crate::queue::EventQueue::new(crate::config::DedupMode::Queue);
        let first = adapter
            .claim_next_for_runtime_lease("instance-a", "execution-first", now_ms + 2)
            .await?
            .ok_or("expected first claim")?;
        adapter
            .release_claim_to_waiting_for_runtime_lease(
                "instance-a",
                first.identity.clone(),
                first.dispatch,
                serde_json::json!({"reason": "pre_launch_failure"}),
                now_ms + 3,
            )
            .await?;
        let second = adapter
            .claim_next_for_runtime_lease("instance-a", "execution-second", now_ms + 4)
            .await?
            .ok_or("expected reclaimed turn")?;
        assert_eq!(first.turn.turn_id, second.turn.turn_id);
        assert!(second.identity.epoch > first.identity.epoch);
        assert_ne!(second.identity.execution_id, first.identity.execution_id);
        adapter
            .finish_claim_for_runtime_lease(
                "instance-a",
                second.identity,
                TerminalUpdate {
                    state: TurnState::Cancelled,
                    result_digest: None,
                    payload: serde_json::json!({"reason": "test_cleanup"}),
                    occurred_at_ms: now_ms + 5,
                },
            )
            .await?;
        assert_eq!(queue.pending_channels(), 0);
        Ok(())
    }
}
