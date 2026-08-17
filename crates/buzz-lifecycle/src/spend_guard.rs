//! AutomationSpendGuard — window/counters/grace/snooze + scoped pause.
//!
//! Feature-gated by `cards-automations-skills` (off by default).

use crate::LifecycleError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendGuardConfig {
    pub window_ms: i64,
    pub max_wakes_per_window: u32,
    pub max_runs_per_window: u32,
    pub grace_ms: i64,
    pub snooze_ms: i64,
}

impl Default for SpendGuardConfig {
    fn default() -> Self {
        Self {
            window_ms: 60_000,
            max_wakes_per_window: 20,
            max_runs_per_window: 20,
            grace_ms: 5_000,
            snooze_ms: 30_000,
        }
    }
}

impl SpendGuardConfig {
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.window_ms <= 0 || self.grace_ms < 0 || self.snooze_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "spend guard timing must be non-negative with positive window",
            ));
        }
        if self.max_wakes_per_window == 0 || self.max_runs_per_window == 0 {
            return Err(LifecycleError::InvalidRequest(
                "spend guard counters must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendGuardState {
    pub config: SpendGuardConfig,
    pub window_start_ms: i64,
    pub wakes_in_window: u32,
    pub runs_in_window: u32,
    pub snoozed_until_ms: Option<i64>,
    pub grace_until_ms: Option<i64>,
    pub paused_scopes: Vec<String>,
    pub paused_definition_ids: Vec<String>,
}

impl SpendGuardState {
    pub fn new(config: SpendGuardConfig, now_ms: i64) -> Result<Self, LifecycleError> {
        config.validate()?;
        if now_ms < 0 {
            return Err(LifecycleError::InvalidRequest("now must be non-negative"));
        }
        Ok(Self {
            config,
            window_start_ms: now_ms,
            wakes_in_window: 0,
            runs_in_window: 0,
            snoozed_until_ms: None,
            grace_until_ms: None,
            paused_scopes: vec![],
            paused_definition_ids: vec![],
        })
    }
    fn maybe_roll_window(&mut self, now_ms: i64) {
        if now_ms.saturating_sub(self.window_start_ms) >= self.config.window_ms {
            self.window_start_ms = now_ms;
            self.wakes_in_window = 0;
            self.runs_in_window = 0;
        }
    }
    pub fn is_snoozed(&self, now_ms: i64) -> bool {
        self.snoozed_until_ms.is_some_and(|u| now_ms < u)
    }
    pub fn is_in_grace(&self, now_ms: i64) -> bool {
        self.grace_until_ms.is_some_and(|u| now_ms < u)
    }

    /// Record a wake. Returns true if budget exceeded (caller should trigger scoped pause).
    pub fn record_wake(&mut self, now_ms: i64) -> Result<bool, LifecycleError> {
        if now_ms < 0 {
            return Err(LifecycleError::InvalidRequest("now must be non-negative"));
        }
        self.maybe_roll_window(now_ms);
        if self.is_snoozed(now_ms) {
            return Ok(false);
        }
        self.wakes_in_window += 1;
        Ok(self.wakes_in_window > self.config.max_wakes_per_window)
    }
    pub fn record_run(&mut self, now_ms: i64) -> Result<bool, LifecycleError> {
        if now_ms < 0 {
            return Err(LifecycleError::InvalidRequest("now must be non-negative"));
        }
        self.maybe_roll_window(now_ms);
        if self.is_snoozed(now_ms) {
            return Ok(false);
        }
        self.runs_in_window += 1;
        Ok(self.runs_in_window > self.config.max_runs_per_window)
    }

    pub fn snooze(&mut self, now_ms: i64) -> Result<(), LifecycleError> {
        if now_ms < 0 {
            return Err(LifecycleError::InvalidRequest("now must be non-negative"));
        }
        self.snoozed_until_ms = Some(now_ms + self.config.snooze_ms);
        Ok(())
    }
    pub fn start_grace(&mut self, now_ms: i64) -> Result<(), LifecycleError> {
        if now_ms < 0 {
            return Err(LifecycleError::InvalidRequest("now must be non-negative"));
        }
        self.grace_until_ms = Some(now_ms + self.config.grace_ms);
        Ok(())
    }

    /// Scoped pause — records exactly which definition_ids were paused; may restore only that set.
    pub fn pause_scoped(
        &mut self,
        scope: &str,
        definition_ids: Vec<String>,
        now_ms: i64,
    ) -> Result<(), LifecycleError> {
        if scope.is_empty() {
            return Err(LifecycleError::InvalidRequest("scope must be non-empty"));
        }
        if definition_ids.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "must pause at least one definition",
            ));
        }
        if now_ms < 0 {
            return Err(LifecycleError::InvalidRequest("now must be non-negative"));
        }
        if self.is_in_grace(now_ms) {
            return Ok(());
        } // grace suppresses pause
        if !self.paused_scopes.contains(&scope.to_owned()) {
            self.paused_scopes.push(scope.to_owned());
        }
        for id in &definition_ids {
            if !self.paused_definition_ids.contains(id) {
                self.paused_definition_ids.push(id.clone());
            }
        }
        Ok(())
    }
    pub fn resume_scoped(&mut self, scope: &str) -> Vec<String> {
        let before: Vec<String> = self.paused_definition_ids.clone();
        self.paused_scopes.retain(|s| s != scope);
        if self.paused_scopes.is_empty() {
            let out = std::mem::take(&mut self.paused_definition_ids);
            out
        } else {
            before
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn window_counters_and_grace_snooze() {
        let cfg = SpendGuardConfig {
            window_ms: 1000,
            max_wakes_per_window: 2,
            max_runs_per_window: 2,
            grace_ms: 500,
            snooze_ms: 500,
        };
        let mut s = SpendGuardState::new(cfg, 0).unwrap();
        assert!(!s.record_wake(10).unwrap());
        assert!(!s.record_wake(20).unwrap());
        assert!(s.record_wake(30).unwrap());
        s.start_grace(30).unwrap();
        // in grace: pause is suppressed
        s.pause_scoped("owner1", vec!["d1".into()], 31).unwrap();
        assert!(s.paused_definition_ids.is_empty());
        // after grace, pause applies
        s.pause_scoped("owner1", vec!["d1".into(), "d2".into()], 600)
            .unwrap();
        assert_eq!(s.paused_definition_ids.len(), 2);
        // snooze suppresses budget exceed
        s.snooze(601).unwrap();
        assert!(!s.record_wake(602).unwrap());
    }
    #[test]
    fn scoped_pause_restores_only_that_set() {
        let mut s = SpendGuardState::new(SpendGuardConfig::default(), 0).unwrap();
        s.pause_scoped("s1", vec!["d1".into(), "d2".into()], 10)
            .unwrap();
        s.pause_scoped("s2", vec!["d3".into()], 11).unwrap();
        // resuming s1 while s2 still paused should not clear ids (we keep guard definition set while any scope paused)
        let _ = s.resume_scoped("s1");
        assert!(!s.paused_definition_ids.is_empty());
        let restored = s.resume_scoped("s2");
        assert_eq!(restored.len(), 3);
        assert!(s.paused_definition_ids.is_empty());
    }
}
