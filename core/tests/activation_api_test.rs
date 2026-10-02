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
