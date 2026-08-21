import { useCallback, useEffect, useState } from "react";
import { listCuratedSkills, type SkillVersion } from "@/shared/api/humanPolicy";

export function SkillCuratorSettingsCard() {
  const [skills, setSkills] = useState<SkillVersion[]>([]);
  const [loading, setLoading] = useState(false);

  const loadSkills = useCallback(async () => {
    setLoading(true);
    try {
      const list = await listCuratedSkills();
      setSkills(list);
    } catch (e) {
      console.error("Failed to load curated skills:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSkills();
  }, [loadSkills]);

  return (
    <div className="rounded-xl border border-border/80 bg-card/60 p-5 shadow-xs backdrop-blur-xs">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold tracking-tight text-foreground">
            Skill Curator & Preflight Engine
          </h3>
          <p className="text-muted-foreground mt-1 text-xs">
            Autonomous procedural skills curated from live sessions. Enforces
            two-frame preflight diffing and air-gapped capability verification.
          </p>
        </div>
        <button
          type="button"
          onClick={loadSkills}
          disabled={loading}
          className="rounded-lg border border-border/80 bg-background/80 px-2.5 py-1 text-xs font-medium text-foreground hover:bg-accent disabled:opacity-50"
        >
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      <div className="mt-4 space-y-2">
        {skills.length === 0 ? (
          <div className="rounded-lg border border-dashed border-border/60 p-4 text-center">
            <p className="text-xs text-muted-foreground">
              No curated procedural skills recorded yet. Skills captured via
              agent turns will appear here after two-frame preflight passing.
            </p>
          </div>
        ) : (
          skills.map((skill) => (
            <div
              key={skill.skill_id}
              className="flex items-center justify-between rounded-lg border border-border/60 bg-background/40 p-3"
            >
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-semibold text-foreground">
                    {skill.skill_id}
                  </span>
                  <span className="rounded-full bg-primary/10 px-2 py-0.5 text-2xs font-medium text-primary">
                    v{skill.version}
                  </span>
                  {skill.private && (
                    <span className="rounded-full bg-muted px-2 py-0.5 text-2xs text-muted-foreground">
                      Private
                    </span>
                  )}
                </div>
                <p className="mt-1 font-mono text-2xs text-muted-foreground">
                  Manifest: {skill.manifest_id}
                </p>
              </div>
              <div className="text-right">
                <span className="text-2xs text-muted-foreground">
                  {new Date(skill.created_at_ms).toLocaleDateString()}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
