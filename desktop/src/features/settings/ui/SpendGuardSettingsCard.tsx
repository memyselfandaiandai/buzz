import { useState, useEffect } from "react";
import {
  getSpendGuardStatus,
  updateSpendGuardConfig,
  toggleSpendGuardPause,
  type SpendGuardStatus,
} from "@/shared/api/humanPolicy";

export function SpendGuardSettingsCard() {
  const [status, setStatus] = useState<SpendGuardStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [windowSecs, setWindowSecs] = useState("60");
  const [maxWakes, setMaxWakes] = useState("20");
  const [maxRuns, setMaxRuns] = useState("20");

  useEffect(() => {
    loadStatus();
  }, []);

  const loadStatus = async () => {
    try {
      const s = await getSpendGuardStatus();
      setStatus(s);
      setWindowSecs(String(Math.round(s.window_ms / 1000)));
      setMaxWakes(String(s.max_wakes_per_window));
      setMaxRuns(String(s.max_runs_per_window));
    } catch (e) {
      console.error("Failed to load spend guard status:", e);
    }
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      const updated = await updateSpendGuardConfig({
        window_ms: Number(windowSecs) * 1000,
        max_wakes_per_window: Number(maxWakes),
        max_runs_per_window: Number(maxRuns),
        grace_ms: 5000,
        snooze_ms: 30000,
      });
      setStatus(updated);
    } catch (e) {
      console.error("Failed to update spend guard:", e);
    } finally {
      setLoading(false);
    }
  };

  const handleTogglePause = async () => {
    if (!status) return;
    setLoading(true);
    try {
      const updated = await toggleSpendGuardPause(!status.paused);
      setStatus(updated);
    } catch (e) {
      console.error("Failed to toggle spend guard pause:", e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded-xl border bg-card p-6 shadow-sm space-y-6" data-testid="spend-guard-settings">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-semibold text-card-foreground">
            Automation Spend Guard & Rate Fences
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Hard budget fences preventing runaway agent wake loops and API spend.
          </p>
        </div>
        {status && (
          <button
            onClick={handleTogglePause}
            disabled={loading}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition ${
              status.paused
                ? "bg-amber-600 hover:bg-amber-500 text-white"
                : "bg-red-600/20 text-red-400 hover:bg-red-600/30 border border-red-500/30"
            }`}
          >
            {status.paused ? "▶ Resume Automations" : "⏸ Emergency Pause All"}
          </button>
        )}
      </div>

      {status && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-muted/30 p-3 rounded-lg border text-xs">
          <div>
            <span className="text-muted-foreground block text-[11px]">Wakes (Window)</span>
            <span className="font-semibold text-foreground">
              {status.wakes_in_window} / {status.max_wakes_per_window}
            </span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px]">Runs (Window)</span>
            <span className="font-semibold text-foreground">
              {status.runs_in_window} / {status.max_runs_per_window}
            </span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px]">Window Duration</span>
            <span className="font-semibold text-foreground">{status.window_ms / 1000}s</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px]">Status</span>
            <span
              className={`font-semibold ${
                status.paused ? "text-amber-400" : "text-green-400"
              }`}
            >
              {status.paused ? "Paused" : "Active & Guarded"}
            </span>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="block text-xs font-medium text-foreground mb-1">
            Window Length (seconds)
          </label>
          <input
            type="number"
            value={windowSecs}
            onChange={(e) => setWindowSecs(e.target.value)}
            className="w-full rounded-md border bg-background px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-foreground mb-1">
            Max Wakes per Window
          </label>
          <input
            type="number"
            value={maxWakes}
            onChange={(e) => setMaxWakes(e.target.value)}
            className="w-full rounded-md border bg-background px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-foreground mb-1">
            Max Runs per Window
          </label>
          <input
            type="number"
            value={maxRuns}
            onChange={(e) => setMaxRuns(e.target.value)}
            className="w-full rounded-md border bg-background px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
      </div>

      <div className="flex justify-end">
        <button
          onClick={handleSave}
          disabled={loading}
          className="px-4 py-2 bg-primary text-primary-foreground text-xs font-medium rounded-lg hover:opacity-90 transition disabled:opacity-50"
        >
          {loading ? "Updating..." : "Save Rate Limits"}
        </button>
      </div>
    </div>
  );
}
