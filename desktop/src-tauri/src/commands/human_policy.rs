use serde::{Deserialize, Serialize};
use tauri::State;
use crate::app_state::AppState;
use buzz_lifecycle::{
    CardAnswer, CardChoice, CardKind, CaptureManifest, DryRunRequest, DryRunResult,
    HumanCard, ManifestFile, PreflightCheck, PreflightFrame, SkillCurator, SkillVersion,
    SpendGuardConfig,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanCardWire {
    pub card_id: String,
    pub turn_id: String,
    pub owner_id: String,
    pub agent_id: String,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub choices: Vec<CardChoiceWire>,
    pub created_at_ms: i64,
    pub answered: Option<CardAnswerWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardChoiceWire {
    pub choice_id: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardAnswerWire {
    pub choice_id: String,
    pub answered_at_ms: i64,
    pub resumed: bool,
}

impl From<HumanCard> for HumanCardWire {
    fn from(c: HumanCard) -> Self {
        Self {
            card_id: c.card_id,
            turn_id: c.turn_id,
            owner_id: c.owner_id,
            agent_id: c.agent_id,
            kind: "action_request".to_string(),
            title: c.title,
            body: c.body,
            choices: c
                .choices
                .into_iter()
                .map(|ch| CardChoiceWire {
                    choice_id: ch.choice_id,
                    label: ch.label,
                })
                .collect(),
            created_at_ms: c.created_at_ms,
            answered: c.answered.map(|a| CardAnswerWire {
                choice_id: a.choice_id,
                answered_at_ms: a.answered_at_ms,
                resumed: a.resumed,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateHumanCardInput {
    pub card_id: String,
    pub turn_id: String,
    pub owner_id: String,
    pub agent_id: String,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub choices: Vec<CardChoiceWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendGuardStatusWire {
    pub window_ms: i64,
    pub max_wakes_per_window: u32,
    pub max_runs_per_window: u32,
    pub grace_ms: i64,
    pub snooze_ms: i64,
    pub wakes_in_window: u32,
    pub runs_in_window: u32,
    pub paused: bool,
    pub snoozed: bool,
    pub in_grace: bool,
}

#[tauri::command]
pub async fn list_human_cards(
    state: State<'_, AppState>,
) -> Result<Vec<HumanCardWire>, String> {
    let broker = state.human_card_broker.lock().map_err(|e| e.to_string())?;
    Ok(broker.all_cards().into_iter().map(HumanCardWire::from).collect())
}

#[tauri::command]
pub async fn create_human_card(
    input: CreateHumanCardInput,
    state: State<'_, AppState>,
) -> Result<HumanCardWire, String> {
    let mut broker = state.human_card_broker.lock().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp_millis();
    let card = HumanCard {
        card_id: input.card_id,
        turn_id: input.turn_id,
        owner_id: input.owner_id,
        agent_id: input.agent_id,
        kind: CardKind::ActionRequest,
        title: input.title,
        body: input.body,
        choices: input
            .choices
            .into_iter()
            .map(|c| CardChoice {
                choice_id: c.choice_id,
                label: c.label,
            })
            .collect(),
        created_at_ms: now,
        answered: None,
    };
    let created = broker.create(card).map_err(|e| format!("{:?}", e))?;
    Ok(HumanCardWire::from(created))
}

#[tauri::command]
pub async fn answer_human_card(
    card_id: String,
    choice_id: String,
    state: State<'_, AppState>,
) -> Result<HumanCardWire, String> {
    let mut broker = state.human_card_broker.lock().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp_millis();
    let answered = broker
        .answer(&card_id, &choice_id, now)
        .map_err(|e| format!("{:?}", e))?;
    Ok(HumanCardWire::from(answered))
}

#[tauri::command]
pub async fn get_spend_guard_status(
    state: State<'_, AppState>,
) -> Result<SpendGuardStatusWire, String> {
    let guard = state.spend_guard_state.lock().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp_millis();
    Ok(SpendGuardStatusWire {
        window_ms: guard.config.window_ms,
        max_wakes_per_window: guard.config.max_wakes_per_window,
        max_runs_per_window: guard.config.max_runs_per_window,
        grace_ms: guard.config.grace_ms,
        snooze_ms: guard.config.snooze_ms,
        wakes_in_window: guard.wakes_in_window,
        runs_in_window: guard.runs_in_window,
        paused: guard.is_paused(),
        snoozed: guard.is_snoozed(now),
        in_grace: guard.is_in_grace(now),
    })
}

#[tauri::command]
pub async fn update_spend_guard_config(
    config: SpendGuardConfig,
    state: State<'_, AppState>,
) -> Result<SpendGuardStatusWire, String> {
    let mut guard = state.spend_guard_state.lock().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp_millis();
    config.validate().map_err(|e| format!("{:?}", e))?;
    guard.config = config;
    Ok(SpendGuardStatusWire {
        window_ms: guard.config.window_ms,
        max_wakes_per_window: guard.config.max_wakes_per_window,
        max_runs_per_window: guard.config.max_runs_per_window,
        grace_ms: guard.config.grace_ms,
        snooze_ms: guard.config.snooze_ms,
        wakes_in_window: guard.wakes_in_window,
        runs_in_window: guard.runs_in_window,
        paused: guard.is_paused(),
        snoozed: guard.is_snoozed(now),
        in_grace: guard.is_in_grace(now),
    })
}

#[tauri::command]
pub async fn toggle_spend_guard_pause(
    paused: bool,
    state: State<'_, AppState>,
) -> Result<SpendGuardStatusWire, String> {
    let mut guard = state.spend_guard_state.lock().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp_millis();
    guard.toggle_global_pause(paused);
    Ok(SpendGuardStatusWire {
        window_ms: guard.config.window_ms,
        max_wakes_per_window: guard.config.max_wakes_per_window,
        max_runs_per_window: guard.config.max_runs_per_window,
        grace_ms: guard.config.grace_ms,
        snooze_ms: guard.config.snooze_ms,
        wakes_in_window: guard.wakes_in_window,
        runs_in_window: guard.runs_in_window,
        paused: guard.is_paused(),
        snoozed: guard.is_snoozed(now),
        in_grace: guard.is_in_grace(now),
    })
}

#[tauri::command]
pub async fn list_curated_skills(
    state: State<'_, AppState>,
) -> Result<Vec<SkillVersion>, String> {
    let curator = state.skill_curator.lock().map_err(|e| e.to_string())?;
    Ok(curator.all_skills())
}

#[tauri::command]
pub async fn preflight_skill_capture(
    owner_id: String,
    manifest: CaptureManifest,
    frame_a: PreflightFrame,
    frame_b: PreflightFrame,
    state: State<'_, AppState>,
) -> Result<SkillVersion, String> {
    let mut curator = state.skill_curator.lock().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp_millis();
    let manifest_id = manifest.manifest_id.clone();
    curator.capture(manifest).map_err(|e| format!("{:?}", e))?;
    curator
        .create_private_skill(&owner_id, &manifest_id, (&frame_a, &frame_b), now)
        .map_err(|e| format!("{:?}", e))
}

#[tauri::command]
pub async fn dry_run_skill_capability(
    req: DryRunRequest,
    state: State<'_, AppState>,
) -> Result<DryRunResult, String> {
    let curator = state.skill_curator.lock().map_err(|e| e.to_string())?;
    curator.dry_run(&req).map_err(|e| format!("{:?}", e))
}

#[tauri::command]
pub async fn get_workspace_observer(
    workspace_id: String,
    state: State<'_, AppState>,
) -> Result<buzz_workspace_controller::WorkspaceObserverContract, String> {
    let mut registry = state.workspace_observers.lock().map_err(|e| e.to_string())?;
    Ok(registry.get_or_create(&workspace_id).clone())
}

#[tauri::command]
pub async fn set_workspace_observer_presence(
    workspace_id: String,
    viewer_id: String,
    active_view: String,
    state: State<'_, AppState>,
) -> Result<buzz_workspace_controller::WorkspaceObserverContract, String> {
    let mut registry = state.workspace_observers.lock().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp_millis();
    let obs = registry.get_or_create(&workspace_id);
    obs.update_presence(viewer_id, active_view, now);
    Ok(obs.clone())
}

#[tauri::command]
pub async fn toggle_workspace_recording(
    workspace_id: String,
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<buzz_workspace_controller::WorkspaceObserverContract, String> {
    let mut registry = state.workspace_observers.lock().map_err(|e| e.to_string())?;
    let obs = registry.get_or_create(&workspace_id);
    obs.set_recording(enabled);
    Ok(obs.clone())
}
