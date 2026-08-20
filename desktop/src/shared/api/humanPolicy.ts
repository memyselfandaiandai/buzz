import { invokeTauri } from "@/shared/api/tauri";

export interface CardChoice {
  choice_id: string;
  label: string;
}

export interface CardAnswer {
  choice_id: string;
  answered_at_ms: number;
  resumed: boolean;
}

export interface HumanCard {
  card_id: string;
  turn_id: string;
  owner_id: string;
  agent_id: string;
  kind: "clarify" | "approval" | "choice";
  title: string;
  body: string;
  choices: CardChoice[];
  created_at_ms: number;
  answered: CardAnswer | null;
}

export interface CreateHumanCardInput {
  card_id: string;
  turn_id: string;
  owner_id: string;
  agent_id: string;
  kind: string;
  title: string;
  body: string;
  choices: CardChoice[];
}

export interface SpendGuardStatus {
  window_ms: number;
  max_wakes_per_window: number;
  max_runs_per_window: number;
  grace_ms: number;
  snooze_ms: number;
  wakes_in_window: number;
  runs_in_window: number;
  paused: boolean;
}

export interface SpendGuardConfig {
  window_ms: number;
  max_wakes_per_window: number;
  max_runs_per_window: number;
  grace_ms: number;
  snooze_ms: number;
}

export async function listHumanCards(): Promise<HumanCard[]> {
  return invokeTauri<HumanCard[]>("list_human_cards");
}

export async function createHumanCard(input: CreateHumanCardInput): Promise<HumanCard> {
  return invokeTauri<HumanCard>("create_human_card", { input });
}

export async function answerHumanCard(card_id: string, choice_id: string): Promise<HumanCard> {
  return invokeTauri<HumanCard>("answer_human_card", { input: { card_id, choice_id } });
}

export async function getSpendGuardStatus(): Promise<SpendGuardStatus> {
  return invokeTauri<SpendGuardStatus>("get_spend_guard_status");
}

export async function updateSpendGuardConfig(config: SpendGuardConfig): Promise<SpendGuardStatus> {
  return invokeTauri<SpendGuardStatus>("update_spend_guard_config", { config });
}

export async function toggleSpendGuardPause(paused: boolean): Promise<SpendGuardStatus> {
  return invokeTauri<SpendGuardStatus>("toggle_spend_guard_pause", { paused });
}

export interface SkillVersion {
  skill_id: string;
  owner_id: string;
  version: number;
  manifest_id: string;
  created_at_ms: number;
  private: boolean;
}

export interface ManifestFile {
  path: string;
  sha256: string;
}

export interface CaptureManifest {
  manifest_id: string;
  owner_id: string;
  title: string;
  summary: string;
  files: ManifestFile[];
}

export interface PreflightCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface PreflightFrame {
  frame_id: string;
  checks: PreflightCheck[];
}

export interface DryRunRequest {
  skill_id: string;
  version: number;
  capabilities: string[];
}

export interface DryRunResult {
  skill_id: string;
  version: number;
  allowed: boolean;
  detail: string;
}

export async function listCuratedSkills(): Promise<SkillVersion[]> {
  return invokeTauri<SkillVersion[]>("list_curated_skills");
}

export async function preflightSkillCapture(params: {
  owner_id: string;
  manifest: CaptureManifest;
  frame_a: PreflightFrame;
  frame_b: PreflightFrame;
}): Promise<SkillVersion> {
  return invokeTauri<SkillVersion>("preflight_skill_capture", params);
}

export async function dryRunSkillCapability(req: DryRunRequest): Promise<DryRunResult> {
  return invokeTauri<DryRunResult>("dry_run_skill_capability", { req });
}
