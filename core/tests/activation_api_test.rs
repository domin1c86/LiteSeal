use liteseal_core::trusted_devices::activation::ActivationApi;
use liteseal_shared::{
    crypto,
    device_activation::{
        ActivationCancel, ActivationCancelResult, Enable, EnableCancel, EnableCancelResult, Start,
    },
    trusted_device::*,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
async fn setup() -> (TcpListener, String, DeviceState, crypto::KeyPair) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let keys = crypto::generate_keypair().unwrap();
    let state = DeviceState::pin(Anchor {
        origin: url.clone(),
        account: uuid::Uuid::new_v4().to_string(),
        root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &keys),
    })
    .unwrap();
    (listener, url, state, keys)
}
async fn reply(listener: TcpListener, wire: Vec<u8>) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut chunk = [0; 4096];
    let mut request = vec![];
    loop {
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        request.extend_from_slice(&chunk[..n]);
        if request.windows(4).any(|v| v == b"\r\n\r\n") {
            break;
        }
    }
    socket.write_all(&wire).await.unwrap();
}
fn response(body: &[u8]) -> Vec<u8> {
    let mut wire=format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n",body.len()).into_bytes();
    wire.extend_from_slice(body);
    wire
}
#[tokio::test]
async fn refresh_sdk_recovers_bound_encrypted_session_and_rejects_invalid_replies() {
    use liteseal_shared::device_activation::{refresh as r, Challenge, Session};
    for case in 0..5 {
        let (listener, url, state, keys) = setup().await;
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let original = Session {
            id: uuid::Uuid::new_v4().to_string(),
            account: state.anchor().account.clone(),
            device: state.anchor().root.device_id.clone(),
            authorization: state.anchor().hash().try_into().unwrap(),
            mode: mode.digest().unwrap(),
            access_token: "synthetic-original-access".into(),
            refresh_token: "synthetic-original-refresh".into(),
            expires_at: now - 1,
            refresh_expires_at: now + 120_000,
        };
        let request = r::Start::make(
            &state,
            &mode,
            &original,
            &uuid::Uuid::new_v4().to_string(),
            now,
            &keys,
        )
        .unwrap();
        let challenge = Challenge::make(&state, &mode, &request.id, &original.device, now).unwrap();
        let next = Session {
            id: uuid::Uuid::new_v4().to_string(),
            account: original.account.clone(),
            device: original.device.clone(),
            authorization: original.authorization,
            mode: original.mode,
            access_token: "synthetic-next-access".into(),
            refresh_token: "synthetic-next-refresh".into(),
            expires_at: now + 60_000,
            refresh_expires_at: now + 120_000,
        };
        let envelope = r::Envelope::seal(&request, &challenge, &next).unwrap();
        let accepted = r::Reply::Accepted {
            request: request.digest().unwrap(),
            challenge: Box::new(challenge),
            envelope,
        };
        let mut body = serde_json::to_value(&accepted).unwrap();
        match case {
            1 => body["request"] = serde_json::json!(vec![0; 32]),
            2 => body["envelope"]["encrypted"][30] = serde_json::json!(256),
            3 => body["unknown"] = true.into(),
            4 => {
                body["challenge"]["device"]["device_id"] =
                    serde_json::json!(uuid::Uuid::new_v4().to_string())
            }
            _ => {}
        }
        let expected_request = request.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut wire = Vec::new();
            let mut chunk = [0; 4096];
            let (start, len) = loop {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                wire.extend_from_slice(&chunk[..n]);
                if let Some(end) = wire.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&wire[..end]).to_lowercase();
                    assert!(header.starts_with("post /auth/v3/refresh/begin "));
                    assert!(header.contains("authorization: bearer synthetic-original-refresh"));
                    let len = header
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse::<usize>()
                        .unwrap();
                    break (end + 4, len);
                }
            };
            while wire.len() < start + len {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                wire.extend_from_slice(&chunk[..n]);
            }
            assert_eq!(
                serde_json::from_slice::<r::Start>(&wire[start..start + len]).unwrap(),
                expected_request
            );
            socket
                .write_all(&response(&serde_json::to_vec(&body).unwrap()))
                .await
                .unwrap();
        });
        let result = ActivationApi::new(&url)
            .unwrap()
            .begin_refresh(&request, &original, &state, &mode, &keys)
            .await;
        if case == 0 {
            let observation = result.unwrap();
            assert_eq!(observation.request(), &request);
            let session = observation.into_session().unwrap();
            assert_eq!(session.id, next.id);
            assert_eq!(session.access_token, next.access_token);
        } else {
            assert!(result.is_err());
        }
        server.await.unwrap();
    }
}
#[tokio::test]
async fn refresh_sdk_rejects_wrong_origin_capability_and_private_keys_before_network() {
    use liteseal_shared::device_activation::{refresh as r, Session};
    let (listener, url, state, keys) = setup().await;
    let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let mut original = Session {
        id: uuid::Uuid::new_v4().to_string(),
        account: state.anchor().account.clone(),
        device: state.anchor().root.device_id.clone(),
        authorization: state.anchor().hash().try_into().unwrap(),
        mode: mode.digest().unwrap(),
        access_token: "synthetic-old-access".into(),
        refresh_token: "synthetic-old-refresh".into(),
        expires_at: now - 1,
        refresh_expires_at: now + 120_000,
    };
    let request = r::Start::make(
        &state,
        &mode,
        &original,
        &uuid::Uuid::new_v4().to_string(),
        now,
        &keys,
    )
    .unwrap();
    let api = ActivationApi::new(&url).unwrap();
    let other = crypto::generate_keypair().unwrap();
    assert!(api
        .begin_refresh(&request, &original, &state, &mode, &other)
        .await
        .is_err());
    let wrong_origin = ActivationApi::new("http://127.0.0.1:1").unwrap();
    assert!(wrong_origin
        .begin_refresh(&request, &original, &state, &mode, &keys)
        .await
        .is_err());
    original.refresh_token = "wrong-refresh".into();
    assert!(api
        .begin_refresh(&request, &original, &state, &mode, &keys)
        .await
        .is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn refresh_proof_transport_requires_exact_saved_challenge_and_accepted_ciphertext() {
    use liteseal_shared::device_activation::{refresh as r, Challenge, Session};
    for case in 0..3 {
        let (listener, url, state, keys) = setup().await;
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
        let at = chrono::Utc::now().timestamp_millis();
        let original = Session {
            id: uuid::Uuid::new_v4().to_string(),
            account: state.anchor().account.clone(),
            device: state.anchor().root.device_id.clone(),
            authorization: state.anchor().hash().try_into().unwrap(),
            mode: mode.digest().unwrap(),
            access_token: "synthetic-old-access".into(),
            refresh_token: "synthetic-old-refresh".into(),
            expires_at: at - 1,
            refresh_expires_at: at + 120_000,
        };
        let request = r::Start::make(
            &state,
            &mode,
            &original,
            &uuid::Uuid::new_v4().to_string(),
            at,
            &keys,
        )
        .unwrap();
        let challenge = Challenge::make(&state, &mode, &request.id, &original.device, at).unwrap();
        let proof = challenge.answer(&state, &mode, at, &keys).unwrap();
        let returned = if case == 1 {
            Challenge::make(&state, &mode, &request.id, &original.device, at).unwrap()
        } else {
            challenge.clone()
        };
        let next = Session {
            id: uuid::Uuid::new_v4().to_string(),
            account: original.account.clone(),
            device: original.device.clone(),
            authorization: original.authorization,
            mode: original.mode,
            access_token: "synthetic-next-access".into(),
            refresh_token: "synthetic-next-refresh".into(),
            expires_at: at + 60_000,
            refresh_expires_at: at + 120_000,
        };
        let envelope = r::Envelope::seal(&request, &returned, &next).unwrap();
        let refresh_reply = if case == 2 {
            r::Reply::Pending {
                request: request.digest().unwrap(),
                challenge: Box::new(returned),
            }
        } else {
            r::Reply::Accepted {
                request: request.digest().unwrap(),
                challenge: Box::new(returned),
                envelope,
            }
        };
        let server = tokio::spawn(reply(
            listener,
            response(&serde_json::to_vec(&refresh_reply).unwrap()),
        ));
        let result = ActivationApi::new(&url)
            .unwrap()
            .prove_refresh(
                &request, &proof, &challenge, &original, &state, &mode, &keys,
            )
            .await;
        assert_eq!(result.is_ok(), case == 0);
        if case == 0 {
            assert_eq!(result.unwrap().into_session().unwrap().id, next.id);
        }
        server.await.unwrap();
    }
}
#[tokio::test]
async fn mode_status_requires_exact_boolean_root_signature_and_known_fields() {
    for case in 0..4 {
        let (listener, url, state, keys) = setup().await;
        let mut mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
        if case == 1 {
            mode.signature[0] ^= 1;
        }
        let mut body = serde_json::json!({"enabled":true,"event":mode});
        if case == 2 {
            body["enabled"] = serde_json::json!(false);
        }
        if case == 3 {
            body["unknown"] = serde_json::json!(true);
        }
        let server = tokio::spawn(reply(
            listener,
            response(&serde_json::to_vec(&body).unwrap()),
        ));
        let result = ActivationApi::new(&url)
            .unwrap()
            .status("synthetic-token", state.anchor())
            .await;
        assert_eq!(result.is_ok(), case == 0);
        server.await.unwrap();
    }
}
#[tokio::test]
async fn activation_credentials_are_not_sent_for_wrong_local_identity_or_origin() {
    let (listener, url, state, keys) = setup().await;
    let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
    let input = Start {
        id: uuid::Uuid::new_v4().to_string(),
        request_token: "synthetic-token-at-least-thirty-two-characters".into(),
        username: "synthetic-user".into(),
        password: "synthetic-password".into(),
        device: uuid::Uuid::new_v4().to_string(),
        authorization: state.anchor().hash().try_into().unwrap(),
    };
    assert!(ActivationApi::new(&url)
        .unwrap()
        .begin(&input, &state, &mode)
        .await
        .is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn redirect_and_oversized_mode_response_fail_without_followup_request() {
    for oversized in [false, true] {
        let (listener, url, state, _keys) = setup().await;
        let other = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let wire = if oversized {
            response(&vec![b' '; 16385])
        } else {
            format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{}/capture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",other.local_addr().unwrap()).into_bytes()
        };
        let server = tokio::spawn(reply(listener, wire));
        assert!(ActivationApi::new(&url)
            .unwrap()
            .status("synthetic-token", state.anchor())
            .await
            .is_err());
        server.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), other.accept())
                .await
                .is_err()
        );
    }
}
#[tokio::test]
async fn cancel_response_requires_original_digest_and_known_fields() {
    for case in 0..4 {
        let (listener, url, state, keys) = setup().await;
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
        let token = "synthetic-cancel-credential-at-least-thirty-two";
        let packet = ActivationCancel::make(
            &state,
            &mode,
            &uuid::Uuid::new_v4().to_string(),
            token,
            &state.anchor().root.device_id,
            &keys,
        )
        .unwrap();
        let mut body = serde_json::to_value(ActivationCancelResult::Cancelled {
            cancellation: packet.digest().unwrap(),
        })
        .unwrap();
        if case == 1 {
            body["cancellation"][0] =
                serde_json::json!((body["cancellation"][0].as_u64().unwrap() + 1) % 256);
        }
        if case == 2 {
            body["unexpected"] = serde_json::json!(true);
        }
        if case == 3 {
            body["status"] = serde_json::json!("unknown");
        }
        let server = tokio::spawn(reply(
            listener,
            response(&serde_json::to_vec(&body).unwrap()),
        ));
        let result = ActivationApi::new(&url)
            .unwrap()
            .cancel(token, &packet, &state, &mode, &keys)
            .await;
        assert_eq!(result.is_ok(), case == 0);
        server.await.unwrap();
    }
}
#[tokio::test]
async fn enable_cancel_response_cannot_claim_another_event_or_unbound_fence() {
    for case in 0..3 {
        let (listener, url, state, keys) = setup().await;
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
        let packet = EnableCancel::make(mode.clone(), state.anchor(), &keys).unwrap();
        let result = match case {
            0 => EnableCancelResult::Accepted { event: mode },
            1 => EnableCancelResult::Accepted {
                event: Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap(),
            },
            _ => EnableCancelResult::Cancelled { event: [1; 32] },
        };
        let server = tokio::spawn(reply(
            listener,
            response(&serde_json::to_vec(&result).unwrap()),
        ));
        assert_eq!(
            ActivationApi::new(&url)
                .unwrap()
                .cancel_enable("synthetic-token", &packet, state.anchor())
                .await
                .is_ok(),
            case == 0
        );
        server.await.unwrap();
    }
}
#[tokio::test]
async fn accepted_cancel_result_requires_exact_challenge_and_authentic_session_ciphertext() {
    use liteseal_shared::device_activation::{Challenge, Envelope, Session};
    for case in 0..3 {
        let (listener, url, state, keys) = setup().await;
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
        let token = "synthetic-cancel-credential-at-least-thirty-two";
        let id = uuid::Uuid::new_v4().to_string();
        let packet = ActivationCancel::make(
            &state,
            &mode,
            &id,
            token,
            &state.anchor().root.device_id,
            &keys,
        )
        .unwrap();
        let challenge = Challenge::make(
            &state,
            &mode,
            if case == 2 { &mode.id } else { &id },
            &packet.device.device_id,
            1000,
        )
        .unwrap();
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            account: packet.account.clone(),
            device: packet.device.device_id.clone(),
            authorization: packet.authorization,
            mode: packet.mode,
            access_token: "synthetic-access".into(),
            refresh_token: "synthetic-refresh".into(),
            expires_at: 300000,
            refresh_expires_at: 3000000,
        };
        let mut envelope = Envelope::seal(&challenge, &session).unwrap();
        if case == 1 {
            envelope.encrypted[40] ^= 1;
        }
        let body = ActivationCancelResult::Accepted {
            challenge: Box::new(challenge),
            envelope,
        };
        let server = tokio::spawn(reply(
            listener,
            response(&serde_json::to_vec(&body).unwrap()),
        ));
        assert_eq!(
            ActivationApi::new(&url)
                .unwrap()
                .cancel(token, &packet, &state, &mode, &keys)
                .await
                .is_ok(),
            case == 0
        );
        server.await.unwrap();
    }
}
#[tokio::test]
async fn structured_inspection_rejects_wrong_digest_and_impossible_terminal_facts() {
    use liteseal_shared::device_activation::{ClosedReason, Closure, Inspection, InspectionResult};
    for case in 0..4 {
        let (listener, url, state, keys) = setup().await;
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
        let token = "synthetic-inspection-credential-at-least-thirty-two";
        let request = Inspection::make(
            &state,
            &mode,
            &uuid::Uuid::new_v4().to_string(),
            token,
            &state.anchor().root.device_id,
            &keys,
        )
        .unwrap();
        let mut closed =
            Closure::make(&request, Some([1; 32]), false, ClosedReason::Expired).unwrap();
        if case == 1 {
            closed.request[0] ^= 1;
        }
        if case == 2 {
            closed.accepted = true;
        }
        if case == 3 {
            closed.version = 2;
        }
        let body = InspectionResult::Closed {
            closure: Box::new(closed),
        };
        let server = tokio::spawn(reply(
            listener,
            response(&serde_json::to_vec(&body).unwrap()),
        ));
        assert_eq!(
            ActivationApi::new(&url)
                .unwrap()
                .inspect(token, &request, &state, &mode, &keys)
                .await
                .is_ok(),
            case == 0
        );
        server.await.unwrap();
    }
}
#[tokio::test]
async fn unknown_inspection_requires_the_original_request_digest() {
    use liteseal_shared::device_activation::{Inspection, InspectionResult};
    for wrong in [false, true] {
        let (listener, url, state, keys) = setup().await;
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
        let token = "synthetic-inspection-credential-at-least-thirty-two";
        let request = Inspection::make(
            &state,
            &mode,
            &uuid::Uuid::new_v4().to_string(),
            token,
            &state.anchor().root.device_id,
            &keys,
        )
        .unwrap();
        let body = InspectionResult::Unknown {
            request: if wrong {
                [0; 32]
            } else {
                request.digest().unwrap()
            },
        };
        let server = tokio::spawn(reply(
            listener,
            response(&serde_json::to_vec(&body).unwrap()),
        ));
        assert_eq!(
            ActivationApi::new(&url)
                .unwrap()
                .inspect(token, &request, &state, &mode, &keys)
                .await
                .is_ok(),
            !wrong
        );
        server.await.unwrap();
    }
}
#[tokio::test]
async fn session_check_rejects_wrong_scope_expiry_and_unknown_fields() {
    use liteseal_shared::device_activation::SessionInfo;
    for case in 0..6 {
        let (listener, url, state, keys) = setup().await;
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let info = SessionInfo {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            account: state.anchor().account.clone(),
            device: state.anchor().root.clone(),
            authorization: state.anchor().hash().try_into().unwrap(),
            mode: mode.digest().unwrap(),
            expires_at: now + 60000,
            refresh_expires_at: now + 120000,
            refresh_hash: [1; 32],
        };
        let mut body = serde_json::to_value(info).unwrap();
        match case {
            1 => body["device"]["device_id"] = serde_json::json!(uuid::Uuid::new_v4().to_string()),
            2 => body["authorization"][0] = serde_json::json!(256),
            3 => body["expires_at"] = serde_json::json!(now - 1),
            4 => body["mode"] = serde_json::json!(vec![0; 32]),
            5 => body["unknown"] = serde_json::json!(true),
            _ => {}
        }
        let server = tokio::spawn(reply(
            listener,
            response(&serde_json::to_vec(&body).unwrap()),
        ));
        assert_eq!(
            ActivationApi::new(&url)
                .unwrap()
                .check_session(
                    "synthetic-token",
                    &state,
                    &mode,
                    &state.anchor().root,
                    &keys
                )
                .await
                .is_ok(),
            case == 0
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn checked_session_binding_requires_both_credentials_and_exact_original_session() {
    use liteseal_shared::device_activation::{Session, SessionInfo};
    use sha2::{Digest, Sha256};
    for case in 0..8 {
        let (listener, url, state, keys) = setup().await;
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let mut session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            account: state.anchor().account.clone(),
            device: state.anchor().root.device_id.clone(),
            authorization: state.anchor().hash().try_into().unwrap(),
            mode: mode.digest().unwrap(),
            access_token: "synthetic-original-access".into(),
            refresh_token: "synthetic-original-refresh".into(),
            expires_at: now + 30000,
            refresh_expires_at: now + 90000,
        };
        let info = SessionInfo {
            version: 1,
            id: session.id.clone(),
            account: session.account.clone(),
            device: state.anchor().root.clone(),
            authorization: session.authorization,
            mode: session.mode,
            expires_at: now + 60000,
            refresh_expires_at: now + 120000,
            refresh_hash: Sha256::digest(session.refresh_token.as_bytes()).into(),
        };
        let server = tokio::spawn(reply(
            listener,
            response(&serde_json::to_vec(&info).unwrap()),
        ));
        let checked = ActivationApi::new(&url)
            .unwrap()
            .check_session(
                &session.access_token,
                &state,
                &mode,
                &state.anchor().root,
                &keys,
            )
            .await
            .unwrap();
        server.await.unwrap();
        match case {
            1 => session.access_token = "other-access".into(),
            2 => session.refresh_token = "other-refresh".into(),
            3 => session.id = uuid::Uuid::new_v4().to_string(),
            4 => session.account = uuid::Uuid::new_v4().to_string(),
            5 => session.device = uuid::Uuid::new_v4().to_string(),
            6 => session.authorization = [0; 32],
            7 => session.mode = [0; 32],
            _ => {}
        }
        let result = checked.bind(session);
        if case == 0 {
            let bound = result.unwrap();
            assert_eq!(bound.expires_at, info.expires_at);
            assert_eq!(bound.refresh_expires_at, info.refresh_expires_at);
        } else {
            assert!(result.is_err());
        }
    }
}
#[tokio::test]
async fn bootstrap_mode_needs_no_bearer_and_accepts_only_bound_root_configuration() {
    use liteseal_shared::device_activation::{ModeQuery, ModeReply};
    for case in 0..7 {
        let (listener, url, state, keys) = setup().await;
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut wire = Vec::new();
            let mut chunk = [0; 4096];
            let (start, length) = loop {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                wire.extend_from_slice(&chunk[..n]);
                if let Some(start) = wire.windows(4).position(|v| v == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&wire[..start]).to_lowercase();
                    assert!(header.starts_with("post /auth/v3/mode "));
                    assert!(!header.contains("authorization:"));
                    let length = header
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse::<usize>()
                        .unwrap();
                    break (start + 4, length);
                }
            };
            while wire.len() < start + length {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                wire.extend_from_slice(&chunk[..n]);
            }
            let query: ModeQuery = serde_json::from_slice(&wire[start..start + length]).unwrap();
            query
                .verify_current(&server_state, chrono::Utc::now().timestamp_millis())
                .unwrap();
            let mut reply = ModeReply {
                version: 1,
                request: query.digest().unwrap(),
                event: if case == 1 { None } else { Some(mode) },
            };
            if case == 2 {
                reply.request[0] ^= 1;
            }
            if case == 3 {
                reply.event.as_mut().unwrap().signature[0] ^= 1;
            }
            if case == 4 {
                reply.version = 2;
            }
            let mut body = serde_json::to_value(reply).unwrap();
            if case == 5 {
                body["access_token"] = serde_json::json!("synthetic-secret");
            }
            if case == 6 {
                body["event"]["account"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
            }
            socket
                .write_all(&response(&serde_json::to_vec(&body).unwrap()))
                .await
                .unwrap();
        });
        let result = ActivationApi::new(&url)
            .unwrap()
            .discover_mode(&state, &state.anchor().root.device_id, &keys)
            .await;
        assert_eq!(result.is_ok(), case < 2);
        if let Ok(mode) = result {
            assert_eq!(mode.is_none(), case == 1);
        }
        server.await.unwrap();
    }
}
#[tokio::test]
async fn bootstrap_rejects_mismatched_local_keys_before_any_network_request() {
    let (listener, url, state, keys) = setup().await;
    let other = crypto::generate_keypair().unwrap();
    let wrong = crypto::KeyPair {
        secret_key: other.secret_key,
        ..keys
    };
    assert!(ActivationApi::new(&url)
        .unwrap()
        .discover_mode(&state, &state.anchor().root.device_id, &wrong)
        .await
        .is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}
