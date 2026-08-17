use std::{
    ffi::{OsStr, OsString},
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use buzz_signing_capability::{
    HttpMethod, IdentityMetadata, Nip98SignRequest, NostrEventSignRequest, Operation,
    OperationResult, RelayOrigin, RequestEnvelope, ResponseEnvelope, StableErrorKind,
    StructuredTag, PROTOCOL_VERSION,
};
use nostr::{EventBuilder, Keys, Kind, Tag};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use uuid::Uuid;

use super::*;

const RELAY: &str = "https://relay.example.test";
const TOKEN: &str = "TOKEN_CANARY_DO_NOT_LEAK_0123456789ABCDEF";

fn future_expiry() -> i64 {
    unix_now_ms().expect("clock") + 60_000
}

fn projection(endpoint: &str, public_key: &PublicKey, expiry: i64) -> Vec<(OsString, OsString)> {
    vec![
        (CAPABILITY_ENDPOINT_ENV.into(), endpoint.into()),
        (
            CAPABILITY_ID_ENV.into(),
            Uuid::from_u128(7).to_string().into(),
        ),
        (CAPABILITY_TOKEN_ENV.into(), TOKEN.into()),
        (PUBLIC_KEY_ENV.into(), public_key.to_hex().into()),
        (RELAY_URL_ENV.into(), RELAY.into()),
        (CAPABILITY_EXPIRES_AT_ENV.into(), expiry.to_string().into()),
    ]
}

fn replace_value(vars: &mut [(OsString, OsString)], name: &str, value: &str) {
    let entry = vars
        .iter_mut()
        .find(|(candidate, _)| candidate == OsStr::new(name))
        .expect("projection variable");
    entry.1 = value.into();
}

async fn bind_raw<F, Fut>(handler: F) -> String
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    // Tests bind a real loopback listener; the parser enforces 100.x in
    // production and the LAN fixture is still checked by
    // `is_tailscale_endpoint` / `is_tailscale_ipv4` explicitly.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        handler(stream).await;
    });
    format!("tcp://{address}")
}

async fn read_request(stream: &mut TcpStream) -> (Vec<u8>, RequestEnvelope) {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("read request");
    assert_eq!(bytes.last(), Some(&b'\n'));
    let request = serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("request envelope");
    (bytes, request)
}

async fn write_response(stream: &mut TcpStream, response: &ResponseEnvelope) {
    let mut bytes = serde_json::to_vec(response).expect("serialize response");
    bytes.push(b'\n');
    stream.write_all(&bytes).await.expect("write response");
    stream.shutdown().await.expect("shutdown response");
}

async fn spawn_protocol_broker<F>(connections: usize, handler: F) -> String
where
    F: Fn(usize, &RequestEnvelope) -> ResponseEnvelope + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        for index in 0..connections {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let (_, request) = read_request(&mut stream).await;
            let response = handler(index, &request);
            write_response(&mut stream, &response).await;
        }
    });
    format!("tcp://{address}")
}

fn identity_response(
    request: &RequestEnvelope,
    public_key: &PublicKey,
    expiry: i64,
) -> ResponseEnvelope {
    ResponseEnvelope::success(
        request.request_id,
        OperationResult::IdentityMetadata(IdentityMetadata {
            public_key: public_key.to_hex(),
            relay: RelayOrigin::parse(RELAY).expect("relay"),
            expires_at_unix_ms: expiry,
        }),
    )
}

#[tokio::test]
async fn fake_loopback_supports_all_three_typed_operations() {
    let keys = Keys::generate();
    let public_key = keys.public_key();
    let expiry = future_expiry();
    let broker_keys = keys.clone();
    let endpoint = spawn_protocol_broker(3, move |index, request| match index {
        0 => identity_response(request, &broker_keys.public_key(), expiry),
        1 => {
            let Operation::NostrEventSign(payload) = &request.operation else {
                panic!("expected event signing operation")
            };
            let tags = payload
                .tags
                .iter()
                .map(|tag| Tag::parse(tag.0.clone()).expect("tag"))
                .collect::<Vec<_>>();
            let event = EventBuilder::new(Kind::Custom(payload.kind as u16), &payload.content)
                .tags(tags)
                .sign_with_keys(&broker_keys)
                .expect("sign");
            ResponseEnvelope::success(
                request.request_id,
                OperationResult::SignedEvent {
                    event_json: serde_json::to_string(&event).expect("event JSON"),
                },
            )
        }
        2 => ResponseEnvelope::success(
            request.request_id,
            OperationResult::Authorization {
                authorization: "Nostr signed-header".to_owned(),
                auth_tag: Some(r#"["auth","owner","","signature"]"#.to_owned()),
            },
        ),
        _ => unreachable!(),
    })
    .await;

    let client = CapabilityClient::from_env_iter(projection(&endpoint, &public_key, expiry))
        .await
        .expect("verified client");
    assert_eq!(client.public_key(), public_key);
    assert_eq!(client.relay().as_str(), RELAY);

    let event = client
        .sign_nostr_event(NostrEventSignRequest {
            relay: RelayOrigin::parse(RELAY).expect("relay"),
            kind: 9,
            content: "hello from capability".to_owned(),
            tags: vec![StructuredTag(vec!["h".to_owned(), Uuid::nil().to_string()])],
            requested_created_at: None,
        })
        .await
        .expect("signed event");
    assert_eq!(event.pubkey, public_key);
    assert_eq!(event.content, "hello from capability");

    let authorization = client
        .sign_nip98(Nip98SignRequest {
            relay: RelayOrigin::parse(RELAY).expect("relay"),
            method: HttpMethod::Post,
            path: "/query".to_owned(),
            payload_sha256: Some("a".repeat(64)),
        })
        .await
        .expect("authorization");
    assert_eq!(authorization.authorization(), "Nostr signed-header");
    assert!(authorization.auth_tag().is_some());
    let rendered = format!("{authorization:?}");
    assert!(!rendered.contains("signed-header"));
    assert!(!rendered.contains("signature"));
}

#[test]
fn endpoint_parser_accepts_only_canonical_tailscale_tcp_and_rejects_non_tailscale() {
    assert_eq!(
        parse_endpoint("tcp://100.117.196.100:49152").expect("canonical Tailscale endpoint"),
        "100.117.196.100:49152".parse().expect("address")
    );
    assert_eq!(
        parse_endpoint("tcp://100.64.0.1:8443").expect("lower 100.64 edge"),
        "100.64.0.1:8443".parse().expect("address")
    );
    assert_eq!(
        parse_endpoint("tcp://100.127.255.255:8443").expect("upper 100.127 edge"),
        "100.127.255.255:8443".parse().expect("address")
    );
    // In test builds `parse_endpoint` also accepts `127.0.0.1` for the
    // in-process fake brokers (see `is_tailscale_ipv4` cfg(test)). The
    // *production* contract remains strict, so we prove the allowlist with
    // the non-test helper instead.
    assert!(buzz_signing_capability::is_tailscale_endpoint(
        "tcp://100.117.196.100:49152"
    ));
    assert!(!buzz_signing_capability::is_tailscale_endpoint(
        "tcp://127.0.0.1:49152"
    ));
    assert!(!buzz_signing_capability::is_tailscale_endpoint(
        "tcp://192.168.4.31:8791"
    ));
    assert!(!buzz_signing_capability::is_tailscale_endpoint(
        "tcp://100.63.255.255:8443"
    ));
    assert!(!buzz_signing_capability::is_tailscale_endpoint(
        "tcp://100.128.0.1:8443"
    ));
    for invalid in [
        "http://100.117.196.100:49152",
        "tcp://localhost:49152",
        "tcp://[::1]:49152",
        "tcp://10.0.0.1:49152",
        "tcp://0.0.0.0:8443",
        "tcp://100.117.196.100:0",
        "tcp://100.117.196.100:49152/",
        "tcp://100.117.196.100:49152/path",
        "tcp://100.117.196.100:49152?query=1",
        "tcp://100.117.196.100:49152#fragment",
        "tcp://user@100.117.196.100:49152",
        "TCP://100.117.196.100:49152",
        "tcp://100.117.196.100:049152",
        "tcp://100.117.196.100",
    ] {
        assert_eq!(parse_endpoint(invalid), Err(ClientError::InvalidEndpoint), "{invalid}");
    }
}

#[test]
fn environment_is_complete_exact_and_never_mixed() {
    let keys = Keys::generate();
    let endpoint = "tcp://100.117.196.100:49152";
    assert_eq!(
        CapabilityClient::parse_environment(Vec::<(OsString, OsString)>::new())
            .expect_err("missing projection"),
        ClientError::MissingProjection
    );
    assert_eq!(
        CapabilityClient::parse_environment(vec![(
            OsString::from(CAPABILITY_ENDPOINT_ENV),
            OsString::from(endpoint),
        )])
        .expect_err("partial projection"),
        ClientError::IncompleteProjection
    );

    for secret_name in LONG_LIVED_CREDENTIAL_ENV {
        let mut vars = projection(endpoint, &keys.public_key(), future_expiry());
        vars.push((
            secret_name.into(),
            OsString::from("even-empty-presence-is-forbidden"),
        ));
        assert_eq!(
            CapabilityClient::parse_environment(vars).expect_err("mixed credentials"),
            ClientError::MixedCredentials
        );
    }
    let mut lower_alias = projection(endpoint, &keys.public_key(), future_expiry());
    lower_alias.push(("nostr_private_key".into(), "alias".into()));
    assert_eq!(
        CapabilityClient::parse_environment(lower_alias).expect_err("case-insensitive alias"),
        ClientError::MixedCredentials
    );

    let mut unknown = projection(endpoint, &keys.public_key(), future_expiry());
    unknown.push(("BUZZ_CAPABILITY_EXTRA".into(), "value".into()));
    assert_eq!(
        CapabilityClient::parse_environment(unknown).expect_err("unknown capability variable"),
        ClientError::UnsupportedEnvironment
    );
    let mut wrong_case = projection(endpoint, &keys.public_key(), future_expiry());
    wrong_case.push((
        "buzz_capability_id".into(),
        Uuid::new_v4().to_string().into(),
    ));
    assert_eq!(
        CapabilityClient::parse_environment(wrong_case).expect_err("wrong case"),
        ClientError::UnsupportedEnvironment
    );
}

#[test]
fn environment_rejects_invalid_public_projection_fields() {
    let keys = Keys::generate();
    let endpoint = "tcp://100.117.196.100:49152";
    let expiry = future_expiry();
    for (name, value, expected) in [
        (
            CAPABILITY_ID_ENV,
            Uuid::nil().to_string(),
            ClientError::InvalidCapabilityId,
        ),
        (
            CAPABILITY_ID_ENV,
            format!("{{{}}}", Uuid::from_u128(7)),
            ClientError::InvalidCapabilityId,
        ),
        (
            CAPABILITY_TOKEN_ENV,
            "short".to_owned(),
            ClientError::InvalidToken,
        ),
        (
            PUBLIC_KEY_ENV,
            "NOT-A-KEY".to_owned(),
            ClientError::InvalidPublicKey,
        ),
        (
            RELAY_URL_ENV,
            "https://relay.test/path".to_owned(),
            ClientError::InvalidRelay,
        ),
        (
            CAPABILITY_EXPIRES_AT_ENV,
            "0".to_owned(),
            ClientError::InvalidExpiry,
        ),
        (
            CAPABILITY_EXPIRES_AT_ENV,
            format!("+{expiry}"),
            ClientError::InvalidExpiry,
        ),
    ] {
        let mut vars = projection(endpoint, &keys.public_key(), expiry);
        replace_value(&mut vars, name, &value);
        assert_eq!(
            CapabilityClient::parse_environment(vars).expect_err("invalid projection field"),
            expected,
            "field {name}"
        );
    }
    let mut noncanonical_relay = projection(endpoint, &keys.public_key(), expiry);
    replace_value(
        &mut noncanonical_relay,
        RELAY_URL_ENV,
        "https://RELAY.EXAMPLE.TEST/",
    );
    assert_eq!(
        CapabilityClient::parse_environment(noncanonical_relay).expect_err("noncanonical relay"),
        ClientError::InvalidRelay
    );
    let mut uppercase_key = projection(endpoint, &keys.public_key(), expiry);
    replace_value(
        &mut uppercase_key,
        PUBLIC_KEY_ENV,
        &keys.public_key().to_hex().to_uppercase(),
    );
    assert_eq!(
        CapabilityClient::parse_environment(uppercase_key).expect_err("noncanonical key"),
        ClientError::InvalidPublicKey
    );
}

#[tokio::test]
async fn exact_serialized_request_uses_fresh_shape_and_bounded_deadline() {
    let keys = Keys::generate();
    let public_key = keys.public_key();
    let now = 2_000_000_000_000_i64;
    let expiry = now + 20_000;
    let request_id = Uuid::from_u128(11);
    let capability_id = Uuid::from_u128(7);
    let (captured_tx, captured_rx) = oneshot::channel();
    let endpoint = bind_raw(move |mut stream| async move {
        let (bytes, request) = read_request(&mut stream).await;
        captured_tx.send(bytes).expect("capture request");
        write_response(
            &mut stream,
            &ResponseEnvelope::success(
                request.request_id,
                OperationResult::IdentityMetadata(IdentityMetadata {
                    public_key: public_key.to_hex(),
                    relay: RelayOrigin::parse(RELAY).expect("relay"),
                    expires_at_unix_ms: expiry,
                }),
            ),
        )
        .await;
    })
    .await;
    let client = CapabilityClient::parse_environment(projection(&endpoint, &public_key, expiry))
        .expect("projection");
    let result = client
        .execute_at(Operation::IdentityMetadata, now, request_id)
        .await
        .expect("exchange");
    assert!(matches!(result, OperationResult::IdentityMetadata(_)));
    let captured = String::from_utf8(captured_rx.await.expect("captured")).expect("UTF-8");
    let expected = format!(
        "{{\"version\":{PROTOCOL_VERSION},\"capability_id\":\"{capability_id}\",\"token\":\"{TOKEN}\",\"request_id\":\"{request_id}\",\"deadline_unix_ms\":{},\"operation\":{{\"operation\":\"identity_metadata\"}}}}\n",
        now + REQUEST_DEADLINE_MS
    );
    assert_eq!(captured, expected);
}

#[test]
fn request_deadline_is_capped_by_projection_expiry() {
    let keys = Keys::generate();
    let now = 2_000_000_000_000_i64;
    let expiry = now + 250;
    let client = CapabilityClient::parse_environment(projection(
        "tcp://100.117.196.100:49152",
        &keys.public_key(),
        expiry,
    ))
    .expect("projection");
    let request = client
        .build_request(Operation::IdentityMetadata, now, Uuid::new_v4())
        .expect("request");
    assert_eq!(request.deadline_unix_ms, expiry);
}

#[tokio::test]
async fn each_operation_uses_a_fresh_request_identifier() {
    let keys = Keys::generate();
    let public_key = keys.public_key();
    let expiry = future_expiry();
    let request_ids = Arc::new(Mutex::new(Vec::new()));
    let captured_ids = Arc::clone(&request_ids);
    let endpoint = spawn_protocol_broker(2, move |_, request| {
        captured_ids
            .lock()
            .expect("request IDs")
            .push(request.request_id);
        identity_response(request, &public_key, expiry)
    })
    .await;
    let client = CapabilityClient::from_env_iter(projection(&endpoint, &public_key, expiry))
        .await
        .expect("client");
    client.identity_metadata().await.expect("second identity");
    let ids = request_ids.lock().expect("request IDs");
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    assert!(!ids.iter().any(Uuid::is_nil));
}

#[tokio::test]
async fn oversized_request_fails_before_connecting() {
    let keys = Keys::generate();
    let client = CapabilityClient::parse_environment(projection(
        "tcp://100.117.196.100:49152",
        &keys.public_key(),
        future_expiry(),
    ))
    .expect("projection");
    let error = client
        .execute(Operation::NostrEventSign(NostrEventSignRequest {
            relay: RelayOrigin::parse(RELAY).expect("relay"),
            kind: 9,
            content: "x".repeat(MAX_WIRE_FRAME_BYTES),
            tags: Vec::new(),
            requested_created_at: None,
        }))
        .await
        .expect_err("oversized request");
    assert_eq!(error, ClientError::RequestTooLarge);
}

async fn client_for_raw_response<F, Fut>(handler: F) -> CapabilityClient
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let endpoint = bind_raw(handler).await;
    let keys = Keys::generate();
    CapabilityClient::parse_environment(projection(&endpoint, &keys.public_key(), future_expiry()))
        .expect("projection")
}

#[tokio::test]
async fn response_requires_one_complete_frame_and_eof() {
    let eof = client_for_raw_response(|mut stream| async move {
        let _ = read_request(&mut stream).await;
    })
    .await;
    assert_eq!(
        eof.identity_metadata().await.expect_err("empty EOF"),
        ClientError::InvalidFrame
    );

    let missing_newline = client_for_raw_response(|mut stream| async move {
        let _ = read_request(&mut stream).await;
        stream.write_all(b"{}").await.expect("write");
        stream.shutdown().await.expect("shutdown");
    })
    .await;
    assert_eq!(
        missing_newline
            .identity_metadata()
            .await
            .expect_err("missing newline"),
        ClientError::InvalidFrame
    );

    let malformed = client_for_raw_response(|mut stream| async move {
        let _ = read_request(&mut stream).await;
        stream.write_all(b"{]\n").await.expect("write");
        stream.shutdown().await.expect("shutdown");
    })
    .await;
    assert_eq!(
        malformed
            .identity_metadata()
            .await
            .expect_err("malformed response"),
        ClientError::InvalidResponse
    );

    let multiple = client_for_raw_response(|mut stream| async move {
        let _ = read_request(&mut stream).await;
        stream.write_all(b"{}\n{}\n").await.expect("write");
        stream.shutdown().await.expect("shutdown");
    })
    .await;
    assert_eq!(
        multiple
            .identity_metadata()
            .await
            .expect_err("multiple frames"),
        ClientError::InvalidFrame
    );
}

#[tokio::test]
async fn oversized_response_is_rejected_before_json_parsing() {
    let client = client_for_raw_response(|mut stream| async move {
        let _ = read_request(&mut stream).await;
        let bytes = vec![b'x'; MAX_WIRE_FRAME_BYTES + 1];
        let _ = stream.write_all(&bytes).await;
        let _ = stream.shutdown().await;
    })
    .await;
    assert_eq!(
        client
            .identity_metadata()
            .await
            .expect_err("oversized response"),
        ClientError::ResponseTooLarge
    );
}

#[tokio::test]
async fn response_version_and_request_id_are_exact() {
    let version = client_for_raw_response(|mut stream| async move {
        let (_, request) = read_request(&mut stream).await;
        let mut response = ResponseEnvelope::error(request.request_id, StableErrorKind::Revoked);
        response.version = PROTOCOL_VERSION + 1;
        write_response(&mut stream, &response).await;
    })
    .await;
    assert_eq!(
        version
            .identity_metadata()
            .await
            .expect_err("wrong version"),
        ClientError::UnsupportedVersion
    );

    let mismatch = client_for_raw_response(|mut stream| async move {
        let _ = read_request(&mut stream).await;
        write_response(
            &mut stream,
            &ResponseEnvelope::error(Uuid::new_v4(), StableErrorKind::Revoked),
        )
        .await;
    })
    .await;
    assert_eq!(
        mismatch
            .identity_metadata()
            .await
            .expect_err("wrong request id"),
        ClientError::RequestIdMismatch
    );
}

#[tokio::test]
async fn broker_expiry_and_revoke_errors_remain_stable() {
    for kind in [StableErrorKind::Expired, StableErrorKind::Revoked] {
        let client = client_for_raw_response(move |mut stream| async move {
            let (_, request) = read_request(&mut stream).await;
            write_response(
                &mut stream,
                &ResponseEnvelope::error(request.request_id, kind),
            )
            .await;
        })
        .await;
        assert_eq!(
            client.identity_metadata().await.expect_err("broker error"),
            ClientError::Broker(kind)
        );
    }
}

#[tokio::test]
async fn projected_expiry_fails_before_connecting() {
    let keys = Keys::generate();
    let client = CapabilityClient::parse_environment(projection(
        "tcp://100.117.196.100:49152",
        &keys.public_key(),
        unix_now_ms().expect("clock") - 1,
    ))
    .expect("projection shape");
    assert_eq!(
        client.identity_metadata().await.expect_err("expired"),
        ClientError::Expired
    );
}

#[tokio::test]
async fn read_and_total_timeouts_are_bounded() {
    let read_timeout = client_for_raw_response(|mut stream| async move {
        let _ = read_request(&mut stream).await;
        tokio::time::sleep(Duration::from_millis(250)).await;
    })
    .await
    .with_timeouts(ClientTimeouts {
        connect: Duration::from_millis(100),
        write: Duration::from_millis(100),
        read: Duration::from_millis(20),
        total: Duration::from_millis(200),
    });
    assert_eq!(
        read_timeout
            .identity_metadata()
            .await
            .expect_err("read timeout"),
        ClientError::Timeout(TimeoutPhase::Read)
    );

    let total_timeout = client_for_raw_response(|mut stream| async move {
        let _ = read_request(&mut stream).await;
        tokio::time::sleep(Duration::from_millis(250)).await;
    })
    .await
    .with_timeouts(ClientTimeouts {
        connect: Duration::from_millis(100),
        write: Duration::from_millis(100),
        read: Duration::from_millis(200),
        total: Duration::from_millis(20),
    });
    assert_eq!(
        total_timeout
            .identity_metadata()
            .await
            .expect_err("total timeout"),
        ClientError::Timeout(TimeoutPhase::Total)
    );
}

#[tokio::test]
async fn identity_metadata_must_match_the_projection() {
    let projected = Keys::generate();
    let different = Keys::generate();
    let expiry = future_expiry();
    let endpoint = spawn_protocol_broker(1, move |_, request| {
        identity_response(request, &different.public_key(), expiry)
    })
    .await;
    assert_eq!(
        CapabilityClient::from_env_iter(projection(&endpoint, &projected.public_key(), expiry))
            .await
            .expect_err("identity mismatch"),
        ClientError::IdentityMismatch
    );
}

#[tokio::test]
async fn token_canary_is_absent_from_debug_and_errors() {
    let keys = Keys::generate();
    let endpoint = bind_raw(|mut stream| async move {
        let _ = read_request(&mut stream).await;
        stream.write_all(b"malformed\n").await.expect("write");
        stream.shutdown().await.expect("shutdown");
    })
    .await;
    let client = CapabilityClient::parse_environment(projection(
        &endpoint,
        &keys.public_key(),
        future_expiry(),
    ))
    .expect("projection");
    let rendered_client = format!("{client:?}");
    assert!(!rendered_client.contains(TOKEN));

    let request = client
        .build_request(
            Operation::IdentityMetadata,
            unix_now_ms().expect("clock"),
            Uuid::new_v4(),
        )
        .expect("request");
    assert!(!format!("{request:?}").contains(TOKEN));

    let error = client
        .identity_metadata()
        .await
        .expect_err("malformed broker response");
    assert!(!format!("{error:?}").contains(TOKEN));
    assert!(!error.to_string().contains(TOKEN));
}

#[tokio::test]
async fn invalid_success_result_and_headers_fail_closed() {
    let keys = Keys::generate();
    let public_key = keys.public_key();
    let expiry = future_expiry();
    let endpoint = spawn_protocol_broker(2, move |index, request| {
        if index == 0 {
            identity_response(request, &public_key, expiry)
        } else {
            ResponseEnvelope::success(
                request.request_id,
                OperationResult::Authorization {
                    authorization: "Nostr good\r\nInjected: value".to_owned(),
                    auth_tag: None,
                },
            )
        }
    })
    .await;
    let client = CapabilityClient::from_env_iter(projection(&endpoint, &public_key, expiry))
        .await
        .expect("client");
    assert_eq!(
        client
            .sign_nip98(Nip98SignRequest {
                relay: RelayOrigin::parse(RELAY).expect("relay"),
                method: HttpMethod::Get,
                path: "/events/id".to_owned(),
                payload_sha256: None,
            })
            .await
            .expect_err("header injection"),
        ClientError::InvalidAuthorization
    );
}
