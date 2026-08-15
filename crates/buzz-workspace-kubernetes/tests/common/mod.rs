use serde_json::Value;
use sha2::{Digest, Sha256};

pub const JOB_SPEC_DIGEST: &str =
    "c4996da7a6cc5893c798ee55c4ab4568182186409d6baaee90e637a12836c377";

pub fn provider_job(mut job: Value) -> Value {
    job["metadata"]["namespace"] = Value::String("workspaces".into());
    job["metadata"]["annotations"]["buzz.final-form/delete-operation-key"] =
        Value::String("delete-op-1".into());
    let spec = serde_json::to_vec(&job["spec"]).expect("serialize mock Job spec");
    job["metadata"]["annotations"]["buzz.final-form/job-spec-digest"] =
        Value::String(hex::encode(Sha256::digest(spec)));
    job
}
