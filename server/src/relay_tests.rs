//! Opt-in black-box tests against a dedicated, disposable Postgres database.
use super::*;
use futures_util::{SinkExt, StreamExt};
use liteseal_shared::{
    crypto,
    protocol::{ClientMessage, ServerMessage, SignedEnvelopeV2, PROTOCOL_V2},
};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct TestServer {
    url: String,
    task: tokio::task::JoinHandle<()>,
    db: Db,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    async fn start() -> Self {
        let database_url = std::env::var("LITESEAL_TEST_DATABASE_URL")
            .expect("set LITESEAL_TEST_DATABASE_URL to a dedicated test database");
        let db = Db::connect(&database_url).await.unwrap();
        let app = build_router(
            AppState::new(db.clone()),
            HeaderValue::from_static("http://localhost:1420"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self { url, task, db }
    }

    async fn register(&self) -> TestUser {
        let invite = uuid::Uuid::new_v4().to_string();
        self.db
            .seed_invite_code(&auth::service::hash_token(&invite))
            .await
            .unwrap();
        let keys = crypto::generate_keypair().unwrap();
        let response = http_client()
            .post(format!("{}/auth/register", self.url))
            .json(&serde_json::json!({
                "username": format!("beta{}", uuid::Uuid::new_v4().simple()),
                "password": "Test-only-password-2026!",
                "invite_code": invite,
                "device_name": "test desktop",
                "public_key": keys.public_key.to_vec(),
                "ed25519_pk": keys.ed25519_pk.to_vec(),
            }))
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "register: {}",
            response.status()
        );
        let body: serde_json::Value = response.json().await.unwrap();
        TestUser {
            user_id: body["user_id"].as_str().unwrap().to_string(),
            device_id: body["device_id"].as_str().unwrap().to_string(),
            token: body["access_token"].as_str().unwrap().to_string(),
            keys,
        }
    }

    async fn connect(&self, user: &TestUser) -> Socket {
        let (mut socket, _) = connect_async(format!("{}/ws", self.url.replacen("http", "ws", 1)))
            .await
            .unwrap();
        send(
            &mut socket,
            ClientMessage::Auth {
                user_id: user.user_id.clone(),
                token: user.token.clone(),
                device_id: user.device_id.clone(),
            },
        )
        .await;
        assert!(matches!(receive(&mut socket).await, ServerMessage::AuthOk));
        socket
    }
}

struct TestUser {
    user_id: String,
    device_id: String,
    token: String,
    keys: crypto::KeyPair,
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

fn envelope(sender: &TestUser, recipient: &TestUser) -> SignedEnvelopeV2 {
    let (lo, hi) = if sender.user_id < recipient.user_id {
        (&sender.user_id, &recipient.user_id)
    } else {
        (&recipient.user_id, &sender.user_id)
    };
    let mut envelope = SignedEnvelopeV2 {
        protocol_version: PROTOCOL_V2,
        message_id: uuid::Uuid::new_v4().to_string(),
        conversation_id: format!("dm:{lo}:{hi}"),
        sender_user_id: sender.user_id.clone(),
        sender_device_id: sender.device_id.clone(),
        recipient_user_id: recipient.user_id.clone(),
        recipient_device_id: recipient.device_id.clone(),
        sender_seq: 1,
        prev_hash: Vec::new(),
        sent_at: 1,
        message_type: "text".to_string(),
        ciphertext: crypto::encrypt(
            b"durable test",
            &recipient.keys.public_key,
            &sender.keys.secret_key,
        )
        .unwrap(),
        signature: Vec::new(),
    };
    envelope.signature =
        crypto::sign(&envelope.signing_bytes().unwrap(), &sender.keys.ed25519_sk).unwrap();
    envelope
}

async fn send(socket: &mut Socket, message: ClientMessage) {
    socket
        .send(Message::Text(serde_json::to_string(&message).unwrap()))
        .await
        .unwrap();
}

async fn receive(socket: &mut Socket) -> ServerMessage {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Message::Text(text) = socket.next().await.expect("socket ended").unwrap() {
                return serde_json::from_str(&text).unwrap();
            }
        }
    })
    .await
    .expect("timed out waiting for relay")
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn online_delivery_survives_disconnect_until_authenticated_recipient_ack() {
    let server = TestServer::start().await;
    let alice = server.register().await;
    let bob = server.register().await;
    let mut alice_socket = server.connect(&alice).await;
    let mut bob_socket = server.connect(&bob).await;
    let original = envelope(&alice, &bob);
    send(
        &mut alice_socket,
        ClientMessage::SendV2 {
            envelopes: vec![original.clone()],
        },
    )
    .await;
    assert!(matches!(receive(&mut alice_socket).await,
        ServerMessage::DeliveryUpdate { updates } if updates[0].status == "stored"));
    assert!(matches!(receive(&mut bob_socket).await,
        ServerMessage::MessageV2 { envelope, .. } if envelope == original));
    assert_eq!(
        server
            .db
            .drain_offline_messages(&bob.device_id)
            .await
            .unwrap()
            .len(),
        1
    );

    // A different authenticated device cannot acknowledge Bob's message,
    // even through the old ACK shape with Bob's id supplied in its body.
    send(
        &mut alice_socket,
        ClientMessage::Ack {
            message_id: original.message_id.clone(),
            recipient_device_id: bob.device_id.clone(),
        },
    )
    .await;
    assert!(matches!(receive(&mut alice_socket).await,
        ServerMessage::Error { code, .. } if code == "ack_not_found"));
    assert_eq!(
        server
            .db
            .drain_offline_messages(&bob.device_id)
            .await
            .unwrap()
            .len(),
        1
    );

    bob_socket.close(None).await.unwrap();
    let mut reconnected = server.connect(&bob).await;
    assert!(matches!(receive(&mut reconnected).await,
        ServerMessage::MessageV2 { envelope, .. } if envelope == original));
    send(
        &mut reconnected,
        ClientMessage::AckV2 {
            message_id: original.message_id.clone(),
        },
    )
    .await;
    assert!(matches!(receive(&mut alice_socket).await,
        ServerMessage::DeliveryUpdate { updates } if updates[0].status == "delivered"));
    assert!(server
        .db
        .drain_offline_messages(&bob.device_id)
        .await
        .unwrap()
        .is_empty());
}
