use futures_util::{SinkExt, StreamExt};
use liteseal_desktop::{
    protocol::{dispatch, Request},
    AppState,
};
use liteseal_shared::{
    crypto,
    protocol::{EncryptedPayload, SignedEnvelopeV2},
};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::{accept_async, tungstenite::Message};

async fn call(state: &AppState, name: &str, args: Value) -> Value {
    let request: Request =
        serde_json::from_value(json!({"id":1,"command":{"name":name,"args":args}})).unwrap();
    dispatch(request.command, state).await.unwrap()
}

#[tokio::test]
async fn desktop_sends_signed_envelopes_and_persists_relay_receipts() {
    tokio::time::timeout(Duration::from_secs(10), async {
        // Test-only keys: the real keystore is never touched.
        let keys = crypto::generate_keypair().unwrap();
        let signing_public_key = keys.ed25519_pk;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let relay = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            let auth: Value =
                serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            assert_eq!(auth["type"], "auth");
            assert_eq!(auth["device_id"], "device-a");
            socket
                .send(Message::Text(json!({"type":"auth_ok"}).to_string()))
                .await
                .unwrap();
            let sent: Value =
                serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            assert_eq!(sent["type"], "send_v2");
            let envelope: SignedEnvelopeV2 =
                serde_json::from_value(sent["envelopes"][0].clone()).unwrap();
            assert_eq!(envelope.conversation_id, "dm:alice:bob");
            assert_eq!(envelope.recipient_device_id, "device-b");
            assert_eq!((envelope.sender_seq, envelope.prev_hash.len()), (1, 0));
            assert!(crypto::verify_with_public_key(
                &envelope.signing_bytes().unwrap(),
                &envelope.signature,
                &signing_public_key
            )
            .unwrap());
            socket
                .send(Message::Text(
                    json!({"type":"delivery_update","updates":[{
                        "message_id": envelope.message_id, "recipient_user_id": "bob",
                        "recipient_device_id": "device-b", "status": "delivered"
                    }]})
                    .to_string(),
                ))
                .await
                .unwrap();
            while let Some(message) = socket.next().await {
                if message.unwrap().is_close() {
                    break;
                }
            }
        });
        let state = AppState::new(":memory:").unwrap();
        assert_eq!(
            call(
                &state,
                "connect_relay",
                json!({"serverUrl":url,"userId":"alice","token":"token","deviceId":"device-a"})
            )
            .await["connected"],
            true
        );
        let payload = EncryptedPayload {
            recipient_user_id: "bob".into(),
            recipient_device_id: "device-b".into(),
            ciphertext: vec![1, 2],
            signature: vec![3],
        };
        let sent = state
            .client
            .send_message_with_id(
                "alice".into(),
                vec![1, 2],
                vec![3],
                "device-a".into(),
                vec![payload],
                None,
                Some(&keys.ed25519_sk),
            )
            .await
            .unwrap();
        loop {
            let batch = call(&state, "poll_messages", json!({})).await;
            if !batch["events"].as_array().unwrap().is_empty() {
                assert_eq!(batch["events"][0]["message_id"], sent.message_id);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let messages = call(
            &state,
            "get_local_messages",
            json!({"conversationId":"dm:alice:bob","limit":50,"offset":0}),
        )
        .await;
        assert_eq!(messages[0]["local_state"], "received");
        call(&state, "disconnect", json!({})).await;
        relay.await.unwrap();
    })
    .await
    .expect("Desktop relay test timed out");
}
