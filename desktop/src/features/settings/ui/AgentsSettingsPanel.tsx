import { AgentDefaultsSettingsCard } from "./AgentDefaultsSettingsCard";
import { HarnessesSettingsPanel } from "./HarnessesSettingsPanel";
import { PreventSleepSettingsCard } from "./PreventSleepSettingsCard";
import { SpendGuardSettingsCard } from "./SpendGuardSettingsCard";
import { SettingsOptionGroupList } from "./SettingsOptionGroup";
import { SettingsSectionHeader } from "./SettingsSectionHeader";

export function AgentsSettingsPanel() {
  return (
    <section className="min-w-0" data-testid="settings-agents">
      <SettingsSectionHeader
        title="Agents & Automation Policy"
        description="Control how agents behave, enforce spend fences, and supervise local executions."
      />

      <SettingsOptionGroupList>
        <SpendGuardSettingsCard />
        <PreventSleepSettingsCard />
        <HarnessesSettingsPanel />
        <AgentDefaultsSettingsCard />
      </SettingsOptionGroupList>
    </section>
  );
}
