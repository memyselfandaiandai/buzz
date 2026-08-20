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

export async function toggleSpendGuardPause(pause: boolean): Promise<SpendGuardStatus> {
  return invokeTauri<SpendGuardStatus>("toggle_spend_guard_pause", { pause });
}
