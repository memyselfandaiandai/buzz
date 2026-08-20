import { useState, useEffect } from "react";
import {
  getWorkspaceObserver,
  toggleWorkspaceRecording,
  type WorkspaceObserverContract,
} from "@/shared/api/humanPolicy";

export function WorkspaceObserverCard() {
  const [observer, setObserver] = useState<WorkspaceObserverContract | null>(null);
  const [workspaceId] = useState("local-default");
  const [loading, setLoading] = useState(false);

  const loadObserver = async (id: string) => {
    try {
      const obs = await getWorkspaceObserver(id);
      setObserver(obs);
    } catch (e) {
      console.error("Failed to load workspace observer:", e);
    }
  };

  useEffect(() => {
    loadObserver(workspaceId);
    const interval = setInterval(() => loadObserver(workspaceId), 3000);
    return () => clearInterval(interval);
  }, [workspaceId]);

  const handleToggleRecording = async () => {
    if (!observer) return;
    setLoading(true);
    try {
      const updated = await toggleWorkspaceRecording({
        workspaceId,
        enabled: !observer.recording_enabled,
      });
      setObserver(updated);
    } catch (e) {
      console.error("Failed to toggle workspace recording:", e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded-xl border border-border bg-card p-5 shadow-sm space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <span>🖥️</span> Workspace Observer & Live Telemetry
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Normalized contract for viewer presence, streaming frames, lifecycle states, and scheduled turns.
          </p>
        </div>
        <button
          onClick={handleToggleRecording}
          disabled={loading || !observer}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors ${
            observer?.recording_enabled
              ? "bg-red-500/10 text-red-600 border-red-500/30 hover:bg-red-500/20"
              : "bg-muted text-muted-foreground border-border hover:bg-accent"
          }`}
        >
          {observer?.recording_enabled ? "⏺ Recording Active" : "⭘ Recording Off (Default)"}
        </button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-muted/40 p-3 rounded-lg border border-border/50 text-xs">
        <div>
          <span className="text-muted-foreground block text-[11px]">Lifecycle</span>
          <span className="font-semibold text-foreground capitalize">
            {observer?.lifecycle || "Prepared"}
          </span>
        </div>
        <div>
          <span className="text-muted-foreground block text-[11px]">Active Viewers</span>
          <span className="font-semibold text-foreground">
            {observer?.viewers.length || 0} Connected
          </span>
        </div>
        <div>
          <span className="text-muted-foreground block text-[11px]">Frame Updates</span>
          <span className="font-semibold text-foreground">
            {observer?.frame_updates.length || 0} Frames
          </span>
        </div>
        <div>
          <span className="text-muted-foreground block text-[11px]">Scheduled Input</span>
          <span className="font-semibold text-foreground">
            {observer?.scheduled_input_json ? "Bound ✓" : "None"}
          </span>
        </div>
      </div>
    </div>
  );
}
