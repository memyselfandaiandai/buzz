use std::{
    sync::{Arc, Barrier},
    thread,
};

use uuid::Uuid;

use crate::*;

const NOW: ClockReading = ClockReading {
    unix_ms: 1_700_000_000_000,
    monotonic_ms: 50_000,
};
const RELAY: &str = "wss://relay.example";
const OTHER_RELAY: &str = "wss://other.example";
const CHANNEL: &str = "channel-a";
const PEER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn relay() -> RelayOrigin {
    RelayOrigin::parse(RELAY).expect("test relay")
}

fn budgets() -> BudgetLimits {
    BudgetLimits {
        max_operations: 1000,
        max_payload_bytes: 16 * 1024 * 1024,
        max_in_flight: 8,
        max_replays_per_request: 3,
    }
}

fn event_scope() -> CapabilityScope {
    ScopeBuilder::new(relay())
        .allow_operation(OperationKind::IdentityMetadata)
        .allow_operation(OperationKind::NostrEventSign)
        .allow_operation(OperationKind::Nip98Sign)
        .allow_operation(OperationKind::Nip42Sign)
        .allow_operation(OperationKind::EngramCoordinate)
        .allow_event_kind(9)
        .allow_http(HttpMethod::Post, HttpPathRule::Exact("/query".into()))
        .allow_channel(CHANNEL)
        .allow_peer(PEER)
        .build()
        .expect("valid scope")
}

fn issue(
    scope: CapabilityScope,
    limits: BudgetLimits,
    active: bool,
) -> (CapabilityRegistry, IssuedCapability) {
    let registry = CapabilityRegistry::new();
    let issued = registry
        .issue(scope, limits, NOW, NOW.unix_ms + 60_000, 60_000)
        .expect("issue capability");
    if active {
        registry
            .activate(issued.descriptor.capability_id, NOW)
            .expect("activate capability");
    }
    (registry, issued)
}

fn request(issued: &IssuedCapability, request_id: Uuid, operation: Operation) -> RequestEnvelope {
    RequestEnvelope {
        version: PROTOCOL_VERSION,
        capability_id: issued.descriptor.capability_id,
        token: issued.token.clone(),
        request_id,
        deadline_unix_ms: NOW.unix_ms + 30_000,
        operation,
    }
}

fn event(relay: RelayOrigin, kind: u32, channel: &str, content: &str) -> Operation {
    Operation::NostrEventSign(NostrEventSignRequest {
        relay,
        kind,
        content: content.into(),
        tags: vec![StructuredTag(vec!["h".into(), channel.into()])],
        requested_created_at: None,
    })
}

fn complete(outcome: AuthorizationOutcome, request_id: Uuid) -> ResponseEnvelope {
    match outcome {
        AuthorizationOutcome::Fresh(permit) => permit
            .complete(OperationResult::SignedEvent {
                event_json: format!("signed-{request_id}"),
            })
            .expect("complete authorization"),
        AuthorizationOutcome::Replay(_) => panic!("expected fresh authorization"),
    }
}

fn error_kind(result: Result<AuthorizationOutcome, ProtocolError>) -> StableErrorKind {
    result.expect_err("authorization should fail").kind()
}

#[test]
fn wrong_identifier_and_token_are_rejected_without_secret_echo() {
    let (registry, issued) = issue(event_scope(), budgets(), true);
    let operation = Operation::IdentityMetadata;
    let mut wrong_id = request(&issued, Uuid::new_v4(), operation.clone());
    wrong_id.capability_id = Uuid::new_v4();
    assert_eq!(
        error_kind(registry.authorize(wrong_id, NOW)),
        StableErrorKind::UnknownCapability
    );

    let mut wrong_token = request(&issued, Uuid::new_v4(), operation);
    wrong_token.token = CapabilityToken::generate();
    assert_eq!(
        error_kind(registry.authorize(wrong_token, NOW)),
        StableErrorKind::Unauthorized
    );
}

#[test]
fn authorized_operation_retains_the_request_deadline() {
    let (registry, issued) = issue(event_scope(), budgets(), true);
    let mut request = request(&issued, Uuid::new_v4(), Operation::IdentityMetadata);
    request.deadline_unix_ms = NOW.unix_ms + 12_345;

    let outcome = registry.authorize(request, NOW).expect("authorize request");
    let AuthorizationOutcome::Fresh(permit) = outcome else {
        panic!("new request must produce a fresh permit");
    };
    assert_eq!(permit.authorized().deadline_unix_ms(), NOW.unix_ms + 12_345);
}

#[test]
fn inactive_revoked_and_both_expiry_clocks_fail_closed() {
    let (inactive_registry, inactive) = issue(event_scope(), budgets(), false);
    assert_eq!(
        error_kind(inactive_registry.authorize(
            request(&inactive, Uuid::new_v4(), Operation::IdentityMetadata),
            NOW,
        )),
        StableErrorKind::Inactive
    );

    let (revoked_registry, revoked) = issue(event_scope(), budgets(), true);
    revoked_registry
        .revoke(revoked.descriptor.capability_id)
        .expect("revoke");
    assert_eq!(
        error_kind(revoked_registry.authorize(
            request(&revoked, Uuid::new_v4(), Operation::IdentityMetadata),
            NOW,
        )),
        StableErrorKind::Revoked
    );

    let (wall_registry, wall) = issue(event_scope(), budgets(), true);
    let wall_expired = ClockReading {
        unix_ms: NOW.unix_ms + 60_000,
        monotonic_ms: NOW.monotonic_ms + 1,
    };
    assert_eq!(
        error_kind(wall_registry.authorize(
            request(&wall, Uuid::new_v4(), Operation::IdentityMetadata),
            wall_expired,
        )),
        StableErrorKind::Expired
    );

    let (mono_registry, mono) = issue(event_scope(), budgets(), true);
    let mono_expired = ClockReading {
        unix_ms: NOW.unix_ms + 1,
        monotonic_ms: NOW.monotonic_ms + 60_000,
    };
    assert_eq!(
        error_kind(mono_registry.authorize(
            request(&mono, Uuid::new_v4(), Operation::IdentityMetadata),
            mono_expired,
        )),
        StableErrorKind::Expired
    );
}

#[test]
fn secret_lease_scope_requires_both_constraint_sets() {
    let no_constraints = ScopeBuilder::new(relay())
        .allow_operation(OperationKind::SecretLease)
        .build();
    assert_eq!(
        no_constraints.unwrap_err(),
        ScopeBuildError::UnconstrainedSecretLease
    );

    let only_secret = ScopeBuilder::new(relay())
        .allow_operation(OperationKind::SecretLease)
        .allow_secret("secret-id")
        .build();
    assert_eq!(
        only_secret.unwrap_err(),
        ScopeBuildError::UnconstrainedSecretLease
    );

    ScopeBuilder::new(relay())
        .allow_operation(OperationKind::SecretLease)
        .allow_secret("secret-id")
        .allow_secret_tool("tool-id")
        .build()
        .expect("fully constrained secret scope");

    for invalid_secret in ["", " ", "\t\r\n"] {
        assert_eq!(
            ScopeBuilder::new(relay())
                .allow_operation(OperationKind::SecretLease)
                .allow_secret(invalid_secret)
                .allow_secret_tool("tool-id")
                .build()
                .unwrap_err(),
            ScopeBuildError::UnconstrainedSecretLease
        );
    }
    for invalid_tool in ["", " ", "\t\r\n"] {
        assert_eq!(
            ScopeBuilder::new(relay())
                .allow_operation(OperationKind::SecretLease)
                .allow_secret("secret-id")
                .allow_secret_tool(invalid_tool)
                .build()
                .unwrap_err(),
            ScopeBuildError::UnconstrainedSecretLease
        );
    }
}

#[test]
fn secret_scope_identifiers_and_cardinality_are_bounded_in_the_core() {
    for invalid in ["secret\nname".to_owned(), "x".repeat(257)] {
        assert_eq!(
            ScopeBuilder::new(relay())
                .allow_operation(OperationKind::SecretLease)
                .allow_secret(invalid)
                .allow_secret_tool("tool-id")
                .build(),
            Err(ScopeBuildError::InvalidResource)
        );
    }
    for invalid in ["tool\u{7f}name".to_owned(), "x".repeat(257)] {
        assert_eq!(
            ScopeBuilder::new(relay())
                .allow_operation(OperationKind::SecretLease)
                .allow_secret("secret-id")
                .allow_secret_tool(invalid)
                .build(),
            Err(ScopeBuildError::InvalidResource)
        );
    }

    let mut secrets = ScopeBuilder::new(relay())
        .allow_operation(OperationKind::SecretLease)
        .allow_secret_tool("tool-id");
    for index in 0..257 {
        secrets = secrets.allow_secret(format!("secret-{index}"));
    }
    assert_eq!(secrets.build(), Err(ScopeBuildError::TooManyConstraints));

    let mut tools = ScopeBuilder::new(relay())
        .allow_operation(OperationKind::SecretLease)
        .allow_secret("secret-id");
    for index in 0..257 {
        tools = tools.allow_secret_tool(format!("tool-{index}"));
    }
    assert_eq!(tools.build(), Err(ScopeBuildError::TooManyConstraints));
}

#[test]
fn completion_revalidation_rejects_elapsed_request_and_capability_deadlines() {
    let (request_registry, request_capability) = issue(event_scope(), budgets(), true);
    let mut expiring_request = request(
        &request_capability,
        Uuid::new_v4(),
        Operation::IdentityMetadata,
    );
    expiring_request.deadline_unix_ms = NOW.unix_ms + 5;
    let AuthorizationOutcome::Fresh(request_permit) = request_registry
        .authorize(expiring_request, NOW)
        .expect("authorize short request")
    else {
        panic!("expected fresh permit")
    };
    assert_eq!(
        request_permit
            .revalidate(ClockReading {
                unix_ms: NOW.unix_ms + 5,
                monotonic_ms: NOW.monotonic_ms + 5,
            })
            .expect_err("elapsed request deadline")
            .kind(),
        StableErrorKind::DeadlineExpired
    );

    let (capability_registry, capability) = issue(event_scope(), budgets(), true);
    let AuthorizationOutcome::Fresh(capability_permit) = capability_registry
        .authorize(
            request(&capability, Uuid::new_v4(), Operation::IdentityMetadata),
            NOW,
        )
        .expect("authorize capability")
    else {
        panic!("expected fresh permit")
    };
    assert_eq!(
        capability_permit
            .revalidate(ClockReading {
                unix_ms: NOW.unix_ms + 60_000,
                monotonic_ms: NOW.monotonic_ms + 60_000,
            })
            .expect_err("elapsed capability deadline")
            .kind(),
        StableErrorKind::Expired
    );
}

#[test]
fn publication_revalidation_rejects_elapsed_or_revoked_completed_results() {
    let (deadline_registry, deadline_capability) = issue(event_scope(), budgets(), true);
    let request_id = Uuid::new_v4();
    let deadline = NOW.unix_ms + 5;
    let mut expiring_request = request(
        &deadline_capability,
        request_id,
        Operation::IdentityMetadata,
    );
    expiring_request.deadline_unix_ms = deadline;
    complete(
        deadline_registry
            .authorize(expiring_request, NOW)
            .expect("authorize publication-bound result"),
        request_id,
    );
    assert_eq!(
        deadline_registry
            .revalidate_publication(
                deadline_capability.descriptor.capability_id,
                request_id,
                deadline,
                ClockReading {
                    unix_ms: deadline,
                    monotonic_ms: NOW.monotonic_ms + 5,
                },
            )
            .expect_err("publication cannot occur at the request deadline")
            .kind(),
        StableErrorKind::DeadlineExpired
    );

    let (revoked_registry, revoked_capability) = issue(event_scope(), budgets(), true);
    let request_id = Uuid::new_v4();
    complete(
        revoked_registry
            .authorize(
                request(&revoked_capability, request_id, Operation::IdentityMetadata),
                NOW,
            )
            .expect("authorize result before revocation"),
        request_id,
    );
    revoked_registry
        .revoke(revoked_capability.descriptor.capability_id)
        .expect("revoke capability");
    assert_eq!(
        revoked_registry
            .revalidate_publication(
                revoked_capability.descriptor.capability_id,
                request_id,
                NOW.unix_ms + 30_000,
                ClockReading {
                    unix_ms: NOW.unix_ms + 1,
                    monotonic_ms: NOW.monotonic_ms + 1,
                },
            )
            .expect_err("revoked result cannot publish")
            .kind(),
        StableErrorKind::Revoked
    );
}

#[test]
fn secret_lease_requests_reject_blank_resource_names() {
    let scope = ScopeBuilder::new(relay())
        .allow_operation(OperationKind::SecretLease)
        .allow_secret("secret-id")
        .allow_secret_tool("tool-id")
        .build()
        .expect("secret scope");
    let (registry, issued) = issue(scope, budgets(), true);

    for (secret_key, tool_name) in [
        ("", "tool-id"),
        (" \t", "tool-id"),
        ("secret-id", ""),
        ("secret-id", "\r\n"),
    ] {
        assert_eq!(
            error_kind(registry.authorize(
                request(
                    &issued,
                    Uuid::new_v4(),
                    Operation::SecretLease(SecretLeaseRequest {
                        secret_key: secret_key.into(),
                        tool_name: tool_name.into(),
                    }),
                ),
                NOW,
            )),
            StableErrorKind::InvalidPayload
        );
    }
}

#[test]
fn secret_bearing_responses_are_never_cached_for_replay() {
    let scope = ScopeBuilder::new(relay())
        .allow_operation(OperationKind::SecretLease)
        .allow_secret("secret-id")
        .allow_secret_tool("tool-id")
        .build()
        .expect("secret scope");
    let (registry, issued) = issue(scope, budgets(), true);
    let request_id = Uuid::new_v4();
    let operation = Operation::SecretLease(SecretLeaseRequest {
        secret_key: "secret-id".into(),
        tool_name: "tool-id".into(),
    });
    let request = request(&issued, request_id, operation);
    let permit = match registry.authorize(request.clone(), NOW).unwrap() {
        AuthorizationOutcome::Fresh(permit) => permit,
        AuthorizationOutcome::Replay(_) => panic!("expected fresh authorization"),
    };
    let response = permit
        .complete(OperationResult::SecretLease {
            secret_key: "secret-id".into(),
            secret_value: "secret-fixture-value".into(),
            expires_at_unix_ms: NOW.unix_ms + 1_000,
        })
        .unwrap();
    assert!(serde_json::to_string(&response)
        .unwrap()
        .contains("secret-fixture-value"));
    drop(response);

    assert_eq!(
        error_kind(registry.authorize(request, NOW)),
        StableErrorKind::SensitiveReplayDenied
    );
}

#[test]
fn oversized_secret_completion_is_rejected_without_cacheable_replay() {
    let scope = ScopeBuilder::new(relay())
        .allow_operation(OperationKind::SecretLease)
        .allow_secret("secret-id")
        .allow_secret_tool("tool-id")
        .build()
        .expect("secret scope");
    let (registry, issued) = issue(scope, budgets(), true);
    let request_id = Uuid::new_v4();
    let operation = Operation::SecretLease(SecretLeaseRequest {
        secret_key: "secret-id".into(),
        tool_name: "tool-id".into(),
    });
    let request = request(&issued, request_id, operation);
    let permit = match registry.authorize(request.clone(), NOW).unwrap() {
        AuthorizationOutcome::Fresh(permit) => permit,
        AuthorizationOutcome::Replay(_) => panic!("expected fresh authorization"),
    };

    let response = permit
        .complete(OperationResult::SecretLease {
            secret_key: "secret-id".into(),
            secret_value: "x".repeat(1024 * 1024),
            expires_at_unix_ms: NOW.unix_ms + 1_000,
        })
        .expect("oversized completion returns a stable response");
    assert_eq!(
        response.error_kind(),
        Some(StableErrorKind::PayloadTooLarge)
    );
    assert_eq!(
        error_kind(registry.authorize(request, NOW)),
        StableErrorKind::SensitiveReplayDenied
    );
}

#[test]
fn escaped_secret_completion_honors_serialized_limit_without_cacheable_replay() {
    const RESPONSE_LIMIT: usize = 1024 * 1024;

    let scope = ScopeBuilder::new(relay())
        .allow_operation(OperationKind::SecretLease)
        .allow_secret("secret-id")
        .allow_secret_tool("tool-id")
        .build()
        .expect("secret scope");
    let (registry, issued) = issue(scope, budgets(), true);
    let request_id = Uuid::new_v4();
    let operation = Operation::SecretLease(SecretLeaseRequest {
        secret_key: "secret-id".into(),
        tool_name: "tool-id".into(),
    });
    let request = request(&issued, request_id, operation);
    let permit = match registry.authorize(request.clone(), NOW).unwrap() {
        AuthorizationOutcome::Fresh(permit) => permit,
        AuthorizationOutcome::Replay(_) => panic!("expected fresh authorization"),
    };
    let secret_value = "\"".repeat(600 * 1024);
    assert!(secret_value.len() < RESPONSE_LIMIT);
    assert!(secret_value.len() * 2 > RESPONSE_LIMIT);

    let response = permit
        .complete(OperationResult::SecretLease {
            secret_key: "secret-id".into(),
            secret_value,
            expires_at_unix_ms: NOW.unix_ms + 1_000,
        })
        .expect("escaped oversized completion returns a stable response");
    assert_eq!(
        response.error_kind(),
        Some(StableErrorKind::PayloadTooLarge)
    );
    assert_eq!(
        error_kind(registry.authorize(request, NOW)),
        StableErrorKind::SensitiveReplayDenied
    );
}

#[test]
fn operation_relay_and_resource_scopes_are_enforced() {
    let identity_only = ScopeBuilder::new(relay())
        .allow_operation(OperationKind::IdentityMetadata)
        .build()
        .expect("scope");
    let (registry, issued) = issue(identity_only, budgets(), true);
    assert_eq!(
        error_kind(registry.authorize(
            request(
                &issued,
                Uuid::new_v4(),
                Operation::Nip42Sign(Nip42SignRequest {
                    relay: relay(),
                    challenge: "challenge".into(),
                }),
            ),
            NOW,
        )),
        StableErrorKind::OperationNotAllowed
    );

    let (registry, issued) = issue(event_scope(), budgets(), true);
    assert_eq!(
        error_kind(registry.authorize(
            request(
                &issued,
                Uuid::new_v4(),
                event(
                    RelayOrigin::parse(OTHER_RELAY).expect("other relay"),
                    9,
                    CHANNEL,
                    "hello",
                ),
            ),
            NOW,
        )),
        StableErrorKind::RelayNotAllowed
    );
    assert_eq!(
        error_kind(registry.authorize(
            request(
                &issued,
                Uuid::new_v4(),
                event(relay(), 9, "channel-b", "hello"),
            ),
            NOW,
        )),
        StableErrorKind::ResourceNotAllowed
    );

    let wrong_peer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    assert_eq!(
        error_kind(registry.authorize(
            request(
                &issued,
                Uuid::new_v4(),
                Operation::EngramCoordinate(EngramCoordinateRequest {
                    relay: relay(),
                    peer_pubkey: wrong_peer.into(),
                    slug: "core".into(),
                }),
            ),
            NOW,
        )),
        StableErrorKind::ResourceNotAllowed
    );
}

#[test]
fn method_path_and_event_kind_scopes_are_independent() {
    let (registry, issued) = issue(event_scope(), budgets(), true);
    let nip98 = |method, path: &str| {
        Operation::Nip98Sign(Nip98SignRequest {
            relay: relay(),
            method,
            path: path.into(),
            payload_sha256: Some(ZERO_HASH.into()),
        })
    };
    assert_eq!(
        error_kind(registry.authorize(
            request(&issued, Uuid::new_v4(), nip98(HttpMethod::Get, "/query")),
            NOW,
        )),
        StableErrorKind::MethodNotAllowed
    );
    assert_eq!(
        error_kind(registry.authorize(
            request(&issued, Uuid::new_v4(), nip98(HttpMethod::Post, "/events"),),
            NOW,
        )),
        StableErrorKind::PathNotAllowed
    );
    assert_eq!(
        error_kind(registry.authorize(
            request(&issued, Uuid::new_v4(), event(relay(), 1, CHANNEL, "hello"),),
            NOW,
        )),
        StableErrorKind::EventKindNotAllowed
    );
}

#[test]
fn malformed_or_oversized_structured_payloads_are_refused() {
    let (registry, issued) = issue(event_scope(), budgets(), true);
    assert_eq!(
        error_kind(registry.authorize(
            request(
                &issued,
                Uuid::new_v4(),
                event(relay(), 9, CHANNEL, &"x".repeat(512 * 1024 + 1)),
            ),
            NOW,
        )),
        StableErrorKind::PayloadTooLarge
    );
    let with_auth = Operation::NostrEventSign(NostrEventSignRequest {
        relay: relay(),
        kind: 9,
        content: "hello".into(),
        tags: vec![
            StructuredTag(vec!["h".into(), CHANNEL.into()]),
            StructuredTag(vec!["auth".into(), "caller-controlled".into()]),
        ],
        requested_created_at: None,
    });
    assert_eq!(
        error_kind(registry.authorize(request(&issued, Uuid::new_v4(), with_auth), NOW,)),
        StableErrorKind::InvalidPayload
    );

    for tags in [
        vec![StructuredTag(vec![
            "h".into(),
            CHANNEL.into(),
            "hidden".into(),
        ])],
        vec![
            StructuredTag(vec!["h".into(), CHANNEL.into()]),
            StructuredTag(vec!["h".into(), "unauthorized".into(), "hidden".into()]),
        ],
    ] {
        let malformed_channel = Operation::NostrEventSign(NostrEventSignRequest {
            relay: relay(),
            kind: 9,
            content: "hello".into(),
            tags,
            requested_created_at: None,
        });
        assert_eq!(
            error_kind(
                registry.authorize(request(&issued, Uuid::new_v4(), malformed_channel), NOW,)
            ),
            StableErrorKind::ResourceNotAllowed
        );
    }

    let missing_post_digest = Operation::Nip98Sign(Nip98SignRequest {
        relay: relay(),
        method: HttpMethod::Post,
        path: "/query".into(),
        payload_sha256: None,
    });
    assert_eq!(
        error_kind(registry.authorize(request(&issued, Uuid::new_v4(), missing_post_digest), NOW,)),
        StableErrorKind::InvalidPayload
    );
}

#[test]
fn operation_byte_and_concurrency_budgets_are_bounded() {
    let one_operation = BudgetLimits {
        max_operations: 1,
        ..budgets()
    };
    let (registry, issued) = issue(event_scope(), one_operation, true);
    let first_id = Uuid::new_v4();
    let first = registry
        .authorize(request(&issued, first_id, Operation::IdentityMetadata), NOW)
        .expect("first authorization");
    complete(first, first_id);
    assert_eq!(
        error_kind(registry.authorize(
            request(&issued, Uuid::new_v4(), Operation::IdentityMetadata),
            NOW,
        )),
        StableErrorKind::RequestBudgetExceeded
    );

    let tiny_bytes = BudgetLimits {
        max_payload_bytes: 1,
        ..budgets()
    };
    let (registry, issued) = issue(event_scope(), tiny_bytes, true);
    assert_eq!(
        error_kind(registry.authorize(
            request(&issued, Uuid::new_v4(), Operation::IdentityMetadata),
            NOW,
        )),
        StableErrorKind::ByteBudgetExceeded
    );

    let single_flight = BudgetLimits {
        max_in_flight: 1,
        ..budgets()
    };
    let (registry, issued) = issue(event_scope(), single_flight, true);
    let held = registry
        .authorize(
            request(&issued, Uuid::new_v4(), Operation::IdentityMetadata),
            NOW,
        )
        .expect("held authorization");
    assert_eq!(
        error_kind(registry.authorize(
            request(&issued, Uuid::new_v4(), Operation::IdentityMetadata),
            NOW,
        )),
        StableErrorKind::ConcurrencyExceeded
    );
    match held {
        AuthorizationOutcome::Fresh(permit) => {
            permit.fail(StableErrorKind::Internal);
        }
        AuthorizationOutcome::Replay(_) => panic!("expected fresh permit"),
    }
}

#[test]
fn exact_request_replay_returns_cached_response_without_reexecution() {
    let (registry, issued) = issue(event_scope(), budgets(), true);
    let request_id = Uuid::new_v4();
    let operation = event(relay(), 9, CHANNEL, "hello");
    let first = registry
        .authorize(request(&issued, request_id, operation.clone()), NOW)
        .expect("fresh request");
    let response = complete(first, request_id);
    let replay = registry
        .authorize(request(&issued, request_id, operation), NOW)
        .expect("exact replay");
    match replay {
        AuthorizationOutcome::Replay(cached) => assert_eq!(cached, response),
        AuthorizationOutcome::Fresh(_) => panic!("exact replay must not execute again"),
    }
    let snapshot = registry
        .snapshot(issued.descriptor.capability_id)
        .expect("snapshot");
    assert_eq!(snapshot.used_operations, 1);
    assert_eq!(snapshot.in_flight, 0);
}

#[test]
fn conflicting_request_id_replay_revokes_capability() {
    let (registry, issued) = issue(event_scope(), budgets(), true);
    let request_id = Uuid::new_v4();
    let first = registry
        .authorize(
            request(&issued, request_id, event(relay(), 9, CHANNEL, "first")),
            NOW,
        )
        .expect("first request");
    complete(first, request_id);
    assert_eq!(
        error_kind(registry.authorize(
            request(&issued, request_id, event(relay(), 9, CHANNEL, "conflict"),),
            NOW,
        )),
        StableErrorKind::ReplayConflict
    );
    assert_eq!(
        registry
            .snapshot(issued.descriptor.capability_id)
            .expect("snapshot")
            .state,
        CapabilityState::Revoked
    );
}

#[test]
fn unresolved_authorization_revokes_on_drop() {
    let (registry, issued) = issue(event_scope(), budgets(), true);
    let permit = registry
        .authorize(
            request(&issued, Uuid::new_v4(), Operation::IdentityMetadata),
            NOW,
        )
        .expect("authorization");
    drop(permit);
    assert_eq!(
        registry
            .snapshot(issued.descriptor.capability_id)
            .expect("snapshot")
            .state,
        CapabilityState::Revoked
    );
}

#[test]
fn authorize_and_revoke_are_linearized_across_threads() {
    let (registry, issued) = issue(event_scope(), budgets(), true);
    let registry = Arc::new(registry);
    let issued = Arc::new(issued);
    let barrier = Arc::new(Barrier::new(9));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let registry = Arc::clone(&registry);
        let issued = Arc::clone(&issued);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            let result = registry.authorize(
                request(&issued, Uuid::new_v4(), Operation::IdentityMetadata),
                NOW,
            );
            if let Ok(AuthorizationOutcome::Fresh(permit)) = result {
                permit.fail(StableErrorKind::Internal);
            }
        }));
    }
    barrier.wait();
    registry
        .revoke(issued.descriptor.capability_id)
        .expect("linearized revoke");
    for worker in workers {
        worker.join().expect("authorization worker");
    }

    for _ in 0..128 {
        assert_eq!(
            error_kind(registry.authorize(
                request(&issued, Uuid::new_v4(), Operation::IdentityMetadata),
                NOW,
            )),
            StableErrorKind::Revoked,
            "no authorization may succeed after revoke returns"
        );
    }
}

#[test]
fn debug_and_error_serialization_do_not_expose_tokens_or_payloads() {
    const TOKEN_CANARY: &str = "TOKEN_CANARY_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const PAYLOAD_CANARY: &str = "PAYLOAD_CANARY_super_secret_model_content";
    let token = CapabilityToken::from_secret(TOKEN_CANARY.into()).expect("valid token");
    let request_id = Uuid::new_v4();
    let envelope = RequestEnvelope {
        version: PROTOCOL_VERSION,
        capability_id: Uuid::new_v4(),
        token,
        request_id,
        deadline_unix_ms: NOW.unix_ms + 1,
        operation: event(relay(), 9, CHANNEL, PAYLOAD_CANARY),
    };
    let request_debug = format!("{envelope:?}");
    let operation_debug = format!("{:?}", envelope.operation);
    assert!(!request_debug.contains(TOKEN_CANARY));
    assert!(!request_debug.contains(PAYLOAD_CANARY));
    assert!(!operation_debug.contains(PAYLOAD_CANARY));

    let error = ProtocolError::new(StableErrorKind::Unauthorized);
    let error_debug = format!("{error:?}");
    let error_display = error.to_string();
    let error_json = serde_json::to_string(&error).expect("serialize protocol error");
    let response_json = serde_json::to_string(&ResponseEnvelope::error(
        request_id,
        StableErrorKind::Unauthorized,
    ))
    .expect("serialize error response");
    for rendered in [error_debug, error_display, error_json, response_json] {
        assert!(!rendered.contains(TOKEN_CANARY));
        assert!(!rendered.contains(PAYLOAD_CANARY));
        assert!(!rendered.contains("private_key"));
    }
}

#[test]
fn lifetime_clock_rollback_and_replay_limits_are_bounded() {
    let registry = CapabilityRegistry::new();
    assert_eq!(
        registry
            .issue(
                event_scope(),
                budgets(),
                NOW,
                NOW.unix_ms + MAX_CAPABILITY_LIFETIME_MS as i64 + 1,
                MAX_CAPABILITY_LIFETIME_MS + 1,
            )
            .expect_err("oversized lifetime"),
        IssueError::InvalidLifetime
    );

    let replay_once = BudgetLimits {
        max_replays_per_request: 1,
        ..budgets()
    };
    let (registry, issued) = issue(event_scope(), replay_once, true);
    let request_id = Uuid::new_v4();
    let operation = Operation::IdentityMetadata;
    let first = registry
        .authorize(request(&issued, request_id, operation.clone()), NOW)
        .expect("fresh");
    complete(first, request_id);
    assert!(matches!(
        registry
            .authorize(request(&issued, request_id, operation.clone()), NOW)
            .expect("one replay"),
        AuthorizationOutcome::Replay(_)
    ));
    assert_eq!(
        error_kind(registry.authorize(request(&issued, request_id, operation), NOW)),
        StableErrorKind::ReplayLimitExceeded
    );

    let (registry, issued) = issue(event_scope(), budgets(), true);
    let forward = ClockReading {
        unix_ms: NOW.unix_ms + 5,
        monotonic_ms: NOW.monotonic_ms + 5,
    };
    let request_id = Uuid::new_v4();
    let first = registry
        .authorize(
            request(&issued, request_id, Operation::IdentityMetadata),
            forward,
        )
        .expect("forward clock");
    complete(first, request_id);
    assert_eq!(
        error_kind(registry.authorize(
            request(&issued, Uuid::new_v4(), Operation::IdentityMetadata),
            NOW,
        )),
        StableErrorKind::ClockRollback
    );
}

#[test]
fn wire_tokens_budgets_relays_and_scope_collections_have_hard_bounds() {
    let invalid_token = serde_json::from_str::<CapabilityToken>("\"short\"")
        .expect_err("wire deserialization must enforce token bounds");
    assert!(!invalid_token.to_string().contains("short"));

    assert_eq!(
        RelayOrigin::parse(&format!("wss://{}", "a".repeat(2048))).expect_err("oversized relay"),
        ProtocolError::new(StableErrorKind::PayloadTooLarge)
    );

    for invalid in [
        BudgetLimits {
            max_operations: MAX_CAPABILITY_OPERATIONS + 1,
            ..budgets()
        },
        BudgetLimits {
            max_payload_bytes: MAX_CAPABILITY_PAYLOAD_BYTES + 1,
            ..budgets()
        },
        BudgetLimits {
            max_in_flight: MAX_CAPABILITY_IN_FLIGHT + 1,
            ..budgets()
        },
        BudgetLimits {
            max_replays_per_request: MAX_REPLAYS_PER_REQUEST + 1,
            ..budgets()
        },
    ] {
        assert_eq!(invalid.validate(), Err(IssueError::InvalidBudget));
    }

    let mut builder = ScopeBuilder::new(relay()).allow_operation(OperationKind::NostrEventSign);
    for kind in 0..=64 {
        builder = builder.allow_event_kind(kind);
    }
    assert_eq!(builder.build(), Err(ScopeBuildError::TooManyConstraints));
}

#[test]
fn replay_digest_binds_deadline_and_conflict_revokes() {
    let (registry, issued) = issue(event_scope(), budgets(), true);
    let request_id = Uuid::new_v4();
    let operation = Operation::IdentityMetadata;
    let first_request = request(&issued, request_id, operation.clone());
    let first = registry
        .authorize(first_request.clone(), NOW)
        .expect("fresh request");
    complete(first, request_id);

    let mut conflicting_deadline = first_request;
    conflicting_deadline.deadline_unix_ms -= 1;
    assert_eq!(
        error_kind(registry.authorize(conflicting_deadline, NOW)),
        StableErrorKind::ReplayConflict
    );
    assert_eq!(
        registry
            .snapshot(issued.descriptor.capability_id)
            .expect("snapshot")
            .state,
        CapabilityState::Revoked
    );
}

#[test]
fn registry_capacity_pruning_and_poisoning_fail_closed() {
    let registry = CapabilityRegistry::new();
    for _ in 0..MAX_REGISTRY_CAPABILITIES {
        registry
            .issue(event_scope(), budgets(), NOW, NOW.unix_ms + 60_000, 60_000)
            .expect("within registry bound");
    }
    assert_eq!(
        registry
            .issue(event_scope(), budgets(), NOW, NOW.unix_ms + 60_000, 60_000,)
            .expect_err("registry hard bound"),
        IssueError::RegistryCapacityExceeded
    );

    let prune_registry = CapabilityRegistry::new();
    let retired = prune_registry
        .issue(event_scope(), budgets(), NOW, NOW.unix_ms + 60_000, 60_000)
        .expect("retired capability");
    prune_registry
        .revoke(retired.descriptor.capability_id)
        .expect("revoke");
    prune_registry
        .issue(event_scope(), budgets(), NOW, NOW.unix_ms + 60_000, 60_000)
        .expect("issue prunes revoked record");
    assert!(
        prune_registry
            .snapshot(retired.descriptor.capability_id)
            .is_none(),
        "revoked record without a permit is pruned during issuance"
    );

    let (ledger_registry, ledger_capability) = issue(event_scope(), budgets(), true);
    ledger_registry.fill_response_ledger_for_test();
    assert_eq!(
        error_kind(ledger_registry.authorize(
            request(
                &ledger_capability,
                Uuid::new_v4(),
                Operation::IdentityMetadata,
            ),
            NOW,
        )),
        StableErrorKind::RegistryCapacityExceeded
    );

    let poisoned = CapabilityRegistry::new();
    poisoned.poison_for_test();
    assert_eq!(
        poisoned
            .issue(event_scope(), budgets(), NOW, NOW.unix_ms + 60_000, 60_000,)
            .expect_err("poisoned issuance must fail explicitly"),
        IssueError::RegistryPoisoned
    );
}

#[test]
fn registry_poison_fails_closed_during_authorize_and_post_execution_revalidation() {
    let (authorize_registry, authorize_capability) = issue(event_scope(), budgets(), true);
    authorize_registry.poison_for_test();
    assert_eq!(
        error_kind(authorize_registry.authorize(
            request(
                &authorize_capability,
                Uuid::new_v4(),
                Operation::IdentityMetadata,
            ),
            NOW,
        )),
        StableErrorKind::Internal
    );
    assert!(authorize_registry
        .snapshot(authorize_capability.descriptor.capability_id)
        .is_none());

    let (completion_registry, completion_capability) = issue(event_scope(), budgets(), true);
    let AuthorizationOutcome::Fresh(permit) = completion_registry
        .authorize(
            request(
                &completion_capability,
                Uuid::new_v4(),
                Operation::IdentityMetadata,
            ),
            NOW,
        )
        .expect("authorize before poison")
    else {
        panic!("expected fresh permit")
    };
    completion_registry.poison_for_test();
    assert_eq!(
        permit
            .revalidate(NOW)
            .expect_err("post-execution poison must fail closed")
            .kind(),
        StableErrorKind::Internal
    );
    assert!(completion_registry
        .snapshot(completion_capability.descriptor.capability_id)
        .is_none());
}
