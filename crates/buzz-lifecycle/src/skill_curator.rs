//! SkillCurator — capture manifest → two-frame preflight → private versioned skill → capability-bounded dry-run.
//!
//! Feature-gated by `cards-automations-skills` (off by default). No publish/share surface.

use crate::LifecycleError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureManifest {
    pub manifest_id: String,
    pub owner_id: String,
    pub source: String,
    pub files: Vec<ManifestFile>,
    pub created_at_ms: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    pub path: String,
    pub sha256_hex: String,
    pub bytes: u64,
}

impl CaptureManifest {
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.manifest_id.is_empty() || self.owner_id.is_empty() || self.source.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "manifest identifiers/source must be non-empty",
            ));
        }
        if self.files.is_empty() || self.files.len() > 256 {
            return Err(LifecycleError::InvalidRequest(
                "manifest must have 1..=256 files",
            ));
        }
        if self.created_at_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "manifest created_at must be non-negative",
            ));
        }
        for f in &self.files {
            if f.path.is_empty() || f.path.len() > 512 {
                return Err(LifecycleError::InvalidRequest("manifest file path invalid"));
            }
            if f.sha256_hex.len() != 64 || !f.sha256_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(LifecycleError::InvalidRequest(
                    "sha256 must be 64 hex chars",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightFrame {
    pub frame_id: String,
    pub checks: Vec<PreflightCheck>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightResult {
    pub frame: PreflightFrame,
    pub passed: bool,
}

fn run_frame(frame: &PreflightFrame) -> PreflightResult {
    let passed = frame.checks.iter().all(|c| c.passed);
    PreflightResult {
        frame: frame.clone(),
        passed,
    }
}

/// Two-frame preflight: both frames must pass.
pub fn preflight_two_frames(
    a: &PreflightFrame,
    b: &PreflightFrame,
) -> Result<(PreflightResult, PreflightResult), LifecycleError> {
    if a.frame_id.is_empty() || b.frame_id.is_empty() {
        return Err(LifecycleError::InvalidRequest("frame_id must be non-empty"));
    }
    if a.frame_id == b.frame_id {
        return Err(LifecycleError::InvalidRequest("frame ids must be distinct"));
    }
    let ra = run_frame(a);
    let rb = run_frame(b);
    if !ra.passed || !rb.passed {
        return Err(LifecycleError::InvalidRequest("preflight failed"));
    }
    Ok((ra, rb))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillVersion {
    pub skill_id: String,
    pub owner_id: String,
    pub version: u64,
    pub manifest_id: String,
    pub created_at_ms: i64,
    pub private: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunRequest {
    pub skill_id: String,
    pub version: u64,
    pub capabilities: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunResult {
    pub skill_id: String,
    pub version: u64,
    pub allowed: bool,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct SkillCurator {
    manifests: std::collections::HashMap<String, CaptureManifest>,
    skills: std::collections::HashMap<String, Vec<SkillVersion>>,
    allowed_capabilities: std::collections::HashSet<String>,
}

impl SkillCurator {
    pub fn new(allowed_capabilities: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed_capabilities: allowed_capabilities.into_iter().collect(),
            ..Default::default()
        }
    }
    pub fn capture(
        &mut self,
        manifest: CaptureManifest,
    ) -> Result<CaptureManifest, LifecycleError> {
        manifest.validate()?;
        if self.manifests.contains_key(&manifest.manifest_id) {
            return Err(LifecycleError::InvalidRequest("manifest already captured"));
        }
        self.manifests
            .insert(manifest.manifest_id.clone(), manifest.clone());
        Ok(manifest)
    }
    pub fn get_manifest(&self, id: &str) -> Option<&CaptureManifest> {
        self.manifests.get(id)
    }

    /// After two-frame preflight, create a private versioned skill (no publish/share).
    pub fn create_private_skill(
        &mut self,
        owner_id: &str,
        manifest_id: &str,
        frames: (&PreflightFrame, &PreflightFrame),
        now_ms: i64,
    ) -> Result<SkillVersion, LifecycleError> {
        if owner_id.is_empty() {
            return Err(LifecycleError::InvalidRequest("owner must be non-empty"));
        }
        if now_ms < 0 {
            return Err(LifecycleError::InvalidRequest("now must be non-negative"));
        }
        let manifest = self
            .manifests
            .get(manifest_id)
            .ok_or(LifecycleError::InvalidRequest("manifest not found"))?;
        if manifest.owner_id != owner_id {
            return Err(LifecycleError::InvalidRequest("manifest owner mismatch"));
        }
        preflight_two_frames(frames.0, frames.1)?;
        let skill_id = format!("skill:{}", manifest_id);
        let entry = self.skills.entry(skill_id.clone()).or_default();
        let version = entry.last().map(|s| s.version + 1).unwrap_or(1);
        let skill = SkillVersion {
            skill_id: skill_id.clone(),
            owner_id: owner_id.to_owned(),
            version,
            manifest_id: manifest_id.to_owned(),
            created_at_ms: now_ms,
            private: true,
        };
        entry.push(skill.clone());
        Ok(skill)
    }

    pub fn latest(&self, skill_id: &str) -> Option<&SkillVersion> {
        self.skills.get(skill_id).and_then(|v| v.last())
    }
    pub fn versions(&self, skill_id: &str) -> Option<&[SkillVersion]> {
        self.skills.get(skill_id).map(|v| v.as_slice())
    }

    /// Capability-bounded dry-run: all requested capabilities must be in the allowlist.
    pub fn dry_run(&self, req: &DryRunRequest) -> Result<DryRunResult, LifecycleError> {
        if req.skill_id.is_empty() {
            return Err(LifecycleError::InvalidRequest("skill_id must be non-empty"));
        }
        let versions = self
            .skills
            .get(&req.skill_id)
            .ok_or(LifecycleError::InvalidRequest("skill not found"))?;
        if !versions.iter().any(|s| s.version == req.version) {
            return Err(LifecycleError::InvalidRequest("skill version not found"));
        }
        for cap in &req.capabilities {
            if !self.allowed_capabilities.contains(cap) {
                return Ok(DryRunResult {
                    skill_id: req.skill_id.clone(),
                    version: req.version,
                    allowed: false,
                    detail: format!("capability denied: {cap}"),
                });
            }
        }
        Ok(DryRunResult {
            skill_id: req.skill_id.clone(),
            version: req.version,
            allowed: true,
            detail: "dry-run allowed".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest(id: &str) -> CaptureManifest {
        CaptureManifest {
            manifest_id: id.into(),
            owner_id: "o1".into(),
            source: "capture".into(),
            files: vec![ManifestFile {
                path: "a.txt".into(),
                sha256_hex: "a".repeat(64),
                bytes: 3,
            }],
            created_at_ms: 10,
        }
    }
    fn frame(id: &str, pass: bool) -> PreflightFrame {
        PreflightFrame {
            frame_id: id.into(),
            checks: vec![PreflightCheck {
                name: "c".into(),
                passed: pass,
                detail: "".into(),
            }],
        }
    }
    #[test]
    fn capture_then_two_frame_then_private_versioned() {
        let mut c = SkillCurator::new(["read".into()]);
        c.capture(manifest("m1")).unwrap();
        let s1 = c
            .create_private_skill("o1", "m1", (&frame("f1", true), &frame("f2", true)), 20)
            .unwrap();
        assert_eq!(s1.version, 1);
        assert!(s1.private);
        let s2 = c
            .create_private_skill("o1", "m1", (&frame("f3", true), &frame("f4", true)), 21)
            .unwrap();
        assert_eq!(s2.version, 2);
        assert_eq!(c.versions(&s1.skill_id).unwrap().len(), 2);
    }
    #[test]
    fn preflight_must_pass_both_frames() {
        let mut c = SkillCurator::new(["read".into()]);
        c.capture(manifest("m1")).unwrap();
        assert!(c
            .create_private_skill("o1", "m1", (&frame("f1", true), &frame("f2", false)), 20)
            .is_err());
    }
    #[test]
    fn dry_run_capability_bounded() {
        let mut c = SkillCurator::new(["read".into()]);
        c.capture(manifest("m1")).unwrap();
        let s = c
            .create_private_skill("o1", "m1", (&frame("f1", true), &frame("f2", true)), 20)
            .unwrap();
        assert!(
            c.dry_run(&DryRunRequest {
                skill_id: s.skill_id.clone(),
                version: s.version,
                capabilities: vec!["read".into()]
            })
            .unwrap()
            .allowed
        );
        assert!(
            !c.dry_run(&DryRunRequest {
                skill_id: s.skill_id.clone(),
                version: s.version,
                capabilities: vec!["write".into()]
            })
            .unwrap()
            .allowed
        );
    }
    #[test]
    fn no_publish_share_surface() {
        let mut c = SkillCurator::new(["read".into()]);
        c.capture(manifest("m1")).unwrap();
        let s = c
            .create_private_skill("o1", "m1", (&frame("f1", true), &frame("f2", true)), 20)
            .unwrap();
        assert!(s.private);
    }
}
