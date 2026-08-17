use buzz_lifecycle::AdmissionRequest;

pub fn request(nonce: &str, digest: &str) -> AdmissionRequest {
    AdmissionRequest {
        owner_id: "owner-a".to_owned(),
        agent_id: "agent-a".to_owned(),
        requester_id: "requester-a".to_owned(),
        channel_id: "channel-a".to_owned(),
        client_nonce: nonce.to_owned(),
        input_digest: digest.to_owned(),
        received_at_ms: 0,
        expires_at_ms: 61_000,
    }
}

pub fn request_at(nonce: &str, digest: &str, at: i64) -> AdmissionRequest {
    let mut r = request(nonce, digest);
    r.received_at_ms = at;
    r.expires_at_ms = at + 61_000;
    r
}
