import { useCallback, useEffect, useState } from "react";
import {
  listAutomationDefinitions,
  toggleAutomationEnabled,
  listAutomationRuns,
  createAutomationDefinition,
  type AutomationDefinition,
  type AutomationRun,
} from "@/shared/api/humanPolicy";

export function AutomationsSettingsCard() {
  const [definitions, setDefinitions] = useState<AutomationDefinition[]>([]);
  const [runs, setRuns] = useState<AutomationRun[]>([]);
  const [loading, setLoading] = useState(false);
  const [newName, setNewName] = useState("");
  const [newId, setNewId] = useState("");

  const loadData = useCallback(async () => {
    try {
      const [defs, r] = await Promise.all([
        listAutomationDefinitions(),
        listAutomationRuns(),
      ]);
      setDefinitions(defs);
      setRuns(r);
    } catch (err) {
      console.error("Failed to load automations:", err);
    }
  }, []);

  useEffect(() => {
    loadData();
    const timer = setInterval(loadData, 5000);
    return () => clearInterval(timer);
  }, [loadData]);

  const handleToggle = async (def: AutomationDefinition) => {
    try {
      setLoading(true);
      await toggleAutomationEnabled({
        definitionId: def.definition_id,
        enabled: !def.enabled,
      });
      await loadData();
    } catch (err) {
      console.error("Failed to toggle automation:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newId.trim() || !newName.trim()) return;
    try {
      setLoading(true);
      await createAutomationDefinition({
        definitionId: newId.trim(),
        name: newName.trim(),
        ownerId: "buzz-desktop",
        configJson: {},
      });
      setNewId("");
      setNewName("");
      await loadData();
    } catch (err) {
      console.error("Failed to create automation:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded-xl border border-border bg-card p-6 shadow-sm">
      <div className="flex items-center justify-between pb-4 border-b border-border">
        <div>
          <h3 className="text-lg font-semibold text-foreground">
            Automations & Scheduled Triggers
          </h3>
          <p className="text-sm text-muted-foreground">
            Inactive-by-default scheduled jobs with immutable revision fences
            and wake/run accounting.
          </p>
        </div>
        <button
          type="button"
          onClick={loadData}
          className="px-3 py-1 text-xs font-medium rounded-md border border-border hover:bg-muted text-muted-foreground"
        >
          Refresh
        </button>
      </div>

      {/* Create Definition Form */}
      <form onSubmit={handleCreate} className="mt-4 flex gap-2 items-center">
        <input
          type="text"
          placeholder="Job ID (e.g. daily-summary)"
          value={newId}
          onChange={(e) => setNewId(e.target.value)}
          className="flex-1 px-3 py-1.5 text-sm rounded-md border border-border bg-background text-foreground"
        />
        <input
          type="text"
          placeholder="Friendly Name"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          className="flex-1 px-3 py-1.5 text-sm rounded-md border border-border bg-background text-foreground"
        />
        <button
          type="submit"
          disabled={loading || !newId || !newName}
          className="px-4 py-1.5 text-sm font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          + Add Inactive Job
        </button>
      </form>

      {/* Definitions Table */}
      <div className="mt-6">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
          Configured Jobs ({definitions.length})
        </h4>
        {definitions.length === 0 ? (
          <div className="rounded-lg border border-dashed border-border p-6 text-center text-sm text-muted-foreground">
            No automations configured. New jobs are created inactive by default
            to protect against unvetted runs.
          </div>
        ) : (
          <div className="space-y-2">
            {definitions.map((def) => (
              <div
                key={def.definition_id}
                className="flex items-center justify-between rounded-lg border border-border bg-muted/40 p-3 text-sm"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-foreground">
                      {def.name}
                    </span>
                    <span className="text-xs font-mono text-muted-foreground">
                      ({def.definition_id})
                    </span>
                    <span className="rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
                      rev {def.revision}
                    </span>
                  </div>
                  <div className="text-xs text-muted-foreground mt-0.5">
                    Updated {new Date(def.updated_at_ms).toLocaleTimeString()}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span
                    className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                      def.enabled
                        ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                        : "bg-amber-500/10 text-amber-600 dark:text-amber-400"
                    }`}
                  >
                    {def.enabled ? "Active" : "Inactive (Safe)"}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleToggle(def)}
                    disabled={loading}
                    className={`px-3 py-1 text-xs font-medium rounded-md border ${
                      def.enabled
                        ? "border-amber-500/30 text-amber-600 hover:bg-amber-500/10"
                        : "border-emerald-500/30 text-emerald-600 hover:bg-emerald-500/10"
                    }`}
                  >
                    {def.enabled ? "Disable" : "Enable"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent Runs */}
      {runs.length > 0 && (
        <div className="mt-6 pt-4 border-t border-border">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
            Recent Runs ({runs.length})
          </h4>
          <div className="space-y-1.5">
            {runs.slice(0, 5).map((r) => (
              <div
                key={r.run_id}
                className="flex items-center justify-between text-xs py-1.5 px-2 rounded bg-muted/20 border border-border/50"
              >
                <div className="flex items-center gap-2 font-mono">
                  <span className="text-foreground">{r.definition_id}</span>
                  <span className="text-muted-foreground">
                    [{r.run_id.slice(0, 8)}]
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">
                    {new Date(r.created_at_ms).toLocaleTimeString()}
                  </span>
                  <span
                    className={`font-semibold uppercase text-2xs px-1.5 py-0.5 rounded ${
                      r.state === "acked"
                        ? "bg-emerald-500/10 text-emerald-600"
                        : r.state === "delivered"
                          ? "bg-blue-500/10 text-blue-600"
                          : r.state === "failed"
                            ? "bg-red-500/10 text-red-600"
                            : "bg-muted text-muted-foreground"
                    }`}
                  >
                    {r.state}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
