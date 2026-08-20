use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceLifecycleState {
    Prepared,
    Admitted,
    Creating,
    Active,
    Terminating,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewerPresence {
    pub viewer_id: String,
    pub last_seen_unix_ms: i64,
    pub active_view: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceFrameUpdate {
    pub frame_seq: u64,
    pub payload_bytes: usize,
    pub timestamp_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceObserverContract {
    pub workspace_id: String,
    pub lifecycle: WorkspaceLifecycleState,
    pub viewers: Vec<ViewerPresence>,
    pub frame_updates: Vec<WorkspaceFrameUpdate>,
    pub recording_enabled: bool,
    pub scheduled_input_json: Option<String>,
}

impl WorkspaceObserverContract {
    pub fn new(workspace_id: impl Into<String>) -> Self {
        Self {
            workspace_id: workspace_id.into(),
            lifecycle: WorkspaceLifecycleState::Prepared,
            viewers: Vec::new(),
            frame_updates: Vec::new(),
            recording_enabled: false, // OFF by default
            scheduled_input_json: None,
        }
    }

    pub fn set_lifecycle(&mut self, state: WorkspaceLifecycleState) {
        self.lifecycle = state;
    }

    pub fn update_presence(&mut self, viewer_id: impl Into<String>, active_view: impl Into<String>, now_ms: i64) {
        let viewer_id = viewer_id.into();
        let active_view = active_view.into();
        if let Some(existing) = self.viewers.iter_mut().find(|v| v.viewer_id == viewer_id) {
            existing.last_seen_unix_ms = now_ms;
            existing.active_view = active_view;
        } else {
            self.viewers.push(ViewerPresence {
                viewer_id,
                last_seen_unix_ms: now_ms,
                active_view,
            });
        }
    }

    pub fn push_frame(&mut self, frame_seq: u64, payload_bytes: usize, now_ms: i64) {
        self.frame_updates.push(WorkspaceFrameUpdate {
            frame_seq,
            payload_bytes,
            timestamp_unix_ms: now_ms,
        });
    }

    pub fn bind_scheduled_input(&mut self, json_str: impl Into<String>) {
        self.scheduled_input_json = Some(json_str.into());
    }

    pub fn set_recording(&mut self, enabled: bool) {
        self.recording_enabled = enabled;
    }
}

#[derive(Debug, Default)]
pub struct WorkspaceObserverRegistry {
    observers: std::collections::HashMap<String, WorkspaceObserverContract>,
}

impl WorkspaceObserverRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create(&mut self, workspace_id: &str) -> &mut WorkspaceObserverContract {
        self.observers
            .entry(workspace_id.to_string())
            .or_insert_with(|| WorkspaceObserverContract::new(workspace_id))
    }

    pub fn get(&self, workspace_id: &str) -> Option<&WorkspaceObserverContract> {
        self.observers.get(workspace_id)
    }

    pub fn all(&self) -> Vec<WorkspaceObserverContract> {
        self.observers.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observer_defaults_and_contracts() {
        let mut obs = WorkspaceObserverContract::new("ws-123");
        assert_eq!(obs.workspace_id, "ws-123");
        assert_eq!(obs.lifecycle, WorkspaceLifecycleState::Prepared);
        assert!(!obs.recording_enabled);
        assert!(obs.scheduled_input_json.is_none());

        obs.set_lifecycle(WorkspaceLifecycleState::Active);
        assert_eq!(obs.lifecycle, WorkspaceLifecycleState::Active);

        obs.update_presence("user:cory", "terminal", 1000);
        assert_eq!(obs.viewers.len(), 1);
        assert_eq!(obs.viewers[0].viewer_id, "user:cory");

        obs.push_frame(1, 1024, 1005);
        assert_eq!(obs.frame_updates.len(), 1);

        obs.bind_scheduled_input(r#"{"turn_id":"t-1"}"#);
        assert_eq!(obs.scheduled_input_json.as_deref(), Some(r#"{"turn_id":"t-1"}"#));
    }
}
