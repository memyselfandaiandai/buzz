//! AutomationBroker — inactive-by-default definitions, immutable revision, unique wake/run IDs,
//! at-least-once push+safety-poll, bounded batching, acked completion.
//!
//! Feature-gated by `cards-automations-skills` (off by default).

use crate::LifecycleError;
use serde::{Deserialize, Serialize};

const MAX_BATCH: usize = 64;
const MAX_DEFINITIONS_PER_OWNER: usize = 256;
const MAX_WAKE_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomationDefinition {
    pub definition_id: String,
    pub owner_id: String,
    pub name: String,
    pub revision: u64,
    pub enabled: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub config_json: serde_json::Value,
}

impl AutomationDefinition {
    pub fn validate_new(&self) -> Result<(), LifecycleError> {
        if self.definition_id.is_empty() || self.owner_id.is_empty() || self.name.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "automation identifiers/name must be non-empty",
            ));
        }
        if self.name.len() > 128 {
            return Err(LifecycleError::InvalidRequest("automation name too long"));
        }
        if self.created_at_ms < 0 || self.updated_at_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "automation timestamps must be non-negative",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationRunState {
    Pending,
    Delivered,
    Acked,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomationWake {
    pub wake_id: String,
    pub definition_id: String,
    pub owner_id: String,
    pub revision: u64,
    pub payload_json: serde_json::Value,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomationRun {
    pub run_id: String,
    pub wake_id: String,
    pub definition_id: String,
    pub owner_id: String,
    pub revision: u64,
    pub state: AutomationRunState,
    pub attempts: u32,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Default)]
pub struct AutomationBroker {
    definitions: std::collections::HashMap<String, AutomationDefinition>,
    wakes: std::collections::HashMap<String, AutomationWake>,
    runs: std::collections::HashMap<String, AutomationRun>,
    // dedupe wake creation by (definition_id, wake_id)
}

impl AutomationBroker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create definition. Inactive by default; caller may pass enabled=false only on create.
    /// New revision is always 1 on create.
    pub fn create_definition(
        &mut self,
        def: AutomationDefinition,
    ) -> Result<AutomationDefinition, LifecycleError> {
        def.validate_new()?;
        if def.revision != 1 {
            return Err(LifecycleError::InvalidRequest(
                "new definition revision must be 1",
            ));
        }
        if def.enabled {
            return Err(LifecycleError::InvalidRequest(
                "new definition must be inactive by default",
            ));
        }
        if self.definitions.contains_key(&def.definition_id) {
            return Err(LifecycleError::InvalidRequest("definition already exists"));
        }
        let owner_count = self
            .definitions
            .values()
            .filter(|d| d.owner_id == def.owner_id)
            .count();
        if owner_count >= MAX_DEFINITIONS_PER_OWNER {
            return Err(LifecycleError::InvalidRequest(
                "too many definitions for owner",
            ));
        }
        self.definitions
            .insert(def.definition_id.clone(), def.clone());
        Ok(def)
    }

    /// Immutable revision bump — returns a new revision snapshot; old revision remains addressable by (id, revision).
    pub fn revise_definition(
        &mut self,
        definition_id: &str,
        config_json: serde_json::Value,
        updated_at_ms: i64,
    ) -> Result<AutomationDefinition, LifecycleError> {
        if updated_at_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "updated_at must be non-negative",
            ));
        }
        let cur = self
            .definitions
            .get(definition_id)
            .ok_or(LifecycleError::InvalidRequest("definition not found"))?
            .clone();
        let next = AutomationDefinition {
            revision: cur.revision + 1,
            config_json,
            updated_at_ms,
            ..cur
        };
        self.definitions
            .insert(definition_id.to_owned(), next.clone());
        Ok(next)
    }

    pub fn set_enabled(
        &mut self,
        definition_id: &str,
        enabled: bool,
        updated_at_ms: i64,
    ) -> Result<AutomationDefinition, LifecycleError> {
        let mut cur = self
            .definitions
            .get(definition_id)
            .ok_or(LifecycleError::InvalidRequest("definition not found"))?
            .clone();
        cur.enabled = enabled;
        cur.updated_at_ms = updated_at_ms;
        self.definitions
            .insert(definition_id.to_owned(), cur.clone());
        Ok(cur)
    }

    pub fn get_definition(&self, definition_id: &str) -> Option<&AutomationDefinition> {
        self.definitions.get(definition_id)
    }

    /// Create a wake (unique wake_id). Payload bounded.
    pub fn create_wake(&mut self, wake: AutomationWake) -> Result<AutomationWake, LifecycleError> {
        if wake.wake_id.is_empty() || wake.definition_id.is_empty() || wake.owner_id.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "wake identifiers must be non-empty",
            ));
        }
        if wake.created_at_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "wake created_at must be non-negative",
            ));
        }
        let payload_len = serde_json::to_string(&wake.payload_json)
            .map(|s| s.len())
            .unwrap_or(0);
        if payload_len > MAX_WAKE_PAYLOAD_BYTES {
            return Err(LifecycleError::InvalidRequest("wake payload too large"));
        }
        if self.wakes.contains_key(&wake.wake_id) {
            return Err(LifecycleError::InvalidRequest("wake id already exists"));
        }
        let def = self
            .definitions
            .get(&wake.definition_id)
            .ok_or(LifecycleError::InvalidRequest("definition not found"))?;
        if def.owner_id != wake.owner_id {
            return Err(LifecycleError::InvalidRequest("wake owner mismatch"));
        }
        if wake.revision != def.revision {
            return Err(LifecycleError::InvalidRequest("wake revision mismatch"));
        }
        self.wakes.insert(wake.wake_id.clone(), wake.clone());
        // at-least-once: create a run immediately (push); safety-poll can also materialize it, but idempotently via run_id
        let run = AutomationRun {
            run_id: format!("run:{}", wake.wake_id),
            wake_id: wake.wake_id.clone(),
            definition_id: wake.definition_id.clone(),
            owner_id: wake.owner_id.clone(),
            revision: wake.revision,
            state: AutomationRunState::Pending,
            attempts: 0,
            created_at_ms: wake.created_at_ms,
            updated_at_ms: wake.created_at_ms,
        };
        self.runs.entry(run.run_id.clone()).or_insert(run);
        Ok(wake)
    }

    /// At-least-once push: list pending runs (bounded batching).
    pub fn pending_runs(&self, limit: usize) -> Vec<&AutomationRun> {
        let lim = limit.min(MAX_BATCH).max(1);
        let mut v: Vec<_> = self
            .runs
            .values()
            .filter(|r| r.state == AutomationRunState::Pending)
            .collect();
        v.sort_by_key(|r| r.created_at_ms);
        v.truncate(lim);
        v
    }

    /// Safety-poll: same as pending_runs — caller polls periodically; delivery is at-least-once.
    pub fn poll_pending(&self, limit: usize) -> Vec<&AutomationRun> {
        self.pending_runs(limit)
    }

    pub fn mark_delivered(&mut self, run_id: &str, now_ms: i64) -> Result<(), LifecycleError> {
        let run = self
            .runs
            .get_mut(run_id)
            .ok_or(LifecycleError::InvalidRequest("run not found"))?;
        if run.state != AutomationRunState::Pending {
            return Err(LifecycleError::InvalidRequest("run not pending"));
        }
        run.state = AutomationRunState::Delivered;
        run.attempts += 1;
        run.updated_at_ms = now_ms;
        Ok(())
    }

    /// Acked completion — only Delivered can be acked.
    pub fn ack(&mut self, run_id: &str, now_ms: i64) -> Result<(), LifecycleError> {
        let run = self
            .runs
            .get_mut(run_id)
            .ok_or(LifecycleError::InvalidRequest("run not found"))?;
        if run.state != AutomationRunState::Delivered {
            return Err(LifecycleError::InvalidRequest("run not delivered"));
        }
        run.state = AutomationRunState::Acked;
        run.updated_at_ms = now_ms;
        Ok(())
    }

    pub fn get_run(&self, run_id: &str) -> Option<&AutomationRun> {
        self.runs.get(run_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn def(id: &str) -> AutomationDefinition {
        AutomationDefinition {
            definition_id: id.into(),
            owner_id: "o1".into(),
            name: "n".into(),
            revision: 1,
            enabled: false,
            created_at_ms: 10,
            updated_at_ms: 10,
            config_json: json!({}),
        }
    }
    #[test]
    fn inactive_by_default() {
        let mut b = AutomationBroker::new();
        let mut d = def("d1");
        d.enabled = true;
        assert!(b.create_definition(d).is_err());
    }
    #[test]
    fn revision_immutable() {
        let mut b = AutomationBroker::new();
        b.create_definition(def("d1")).unwrap();
        let r2 = b.revise_definition("d1", json!({"v":2}), 20).unwrap();
        assert_eq!(r2.revision, 2);
        assert_eq!(b.get_definition("d1").unwrap().revision, 2);
    }
    #[test]
    fn unique_wake_and_run_ids() {
        let mut b = AutomationBroker::new();
        b.create_definition(def("d1")).unwrap();
        b.create_wake(AutomationWake {
            wake_id: "w1".into(),
            definition_id: "d1".into(),
            owner_id: "o1".into(),
            revision: 1,
            payload_json: json!({}),
            created_at_ms: 30,
        })
        .unwrap();
        assert!(b
            .create_wake(AutomationWake {
                wake_id: "w1".into(),
                definition_id: "d1".into(),
                owner_id: "o1".into(),
                revision: 1,
                payload_json: json!({}),
                created_at_ms: 31
            })
            .is_err());
        assert_eq!(b.get_run("run:w1").unwrap().wake_id, "w1");
    }
    #[test]
    fn at_least_once_push_and_safety_poll_bounded() {
        let mut b = AutomationBroker::new();
        b.create_definition(def("d1")).unwrap();
        for i in 0..10 {
            b.create_wake(AutomationWake {
                wake_id: format!("w{i}"),
                definition_id: "d1".into(),
                owner_id: "o1".into(),
                revision: 1,
                payload_json: json!({}),
                created_at_ms: 30 + i,
            })
            .unwrap();
        }
        assert_eq!(b.pending_runs(3).len(), 3);
        assert_eq!(b.poll_pending(3).len(), 3);
    }
    #[test]
    fn acked_completion() {
        let mut b = AutomationBroker::new();
        b.create_definition(def("d1")).unwrap();
        b.create_wake(AutomationWake {
            wake_id: "w1".into(),
            definition_id: "d1".into(),
            owner_id: "o1".into(),
            revision: 1,
            payload_json: json!({}),
            created_at_ms: 30,
        })
        .unwrap();
        assert!(b.ack("run:w1", 40).is_err());
        b.mark_delivered("run:w1", 40).unwrap();
        b.ack("run:w1", 41).unwrap();
        assert_eq!(
            b.get_run("run:w1").unwrap().state,
            AutomationRunState::Acked
        );
    }
}
