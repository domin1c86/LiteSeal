use liteseal_core::trusted_devices::activation::ActivationApi;
use liteseal_shared::{
    crypto,
    device_activation::{Enable, Start},
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
