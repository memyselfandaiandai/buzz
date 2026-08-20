import { AgentDefaultsSettingsCard } from "./AgentDefaultsSettingsCard";
import { HarnessesSettingsPanel } from "./HarnessesSettingsPanel";
import { PreventSleepSettingsCard } from "./PreventSleepSettingsCard";
import { SpendGuardSettingsCard } from "./SpendGuardSettingsCard";
import { SkillCuratorSettingsCard } from "./SkillCuratorSettingsCard";
import { SettingsSectionHeader } from "./SettingsSectionHeader";

export function AgentsSettingsPanel() {
  return (
    <section className="min-w-0" data-testid="settings-agents">
      <SettingsSectionHeader
        title="Agents & Automation Policy"
        description="Control how agents behave, enforce spend fences, and supervise local executions."
      />

      <div className="space-y-6">
        <SpendGuardSettingsCard />
        <SkillCuratorSettingsCard />
        <PreventSleepSettingsCard />
        <HarnessesSettingsPanel />
        <AgentDefaultsSettingsCard />
      </div>
    </section>
  );
}
