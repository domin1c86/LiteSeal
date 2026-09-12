use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use liteseal_shared::protocol::{ClientMessage, DeliveryStatus, ServerMessage};
use tokio::sync::mpsc;

use crate::state::AppState;

const MAX_WS_MESSAGE_BYTES: usize = 256 * 1024;

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    let mut authenticated_user: Option<String> = None;
    let mut authenticated_device: Option<String> = None;

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(msg)) = StreamExt::next(&mut ws_receiver).await {
        match msg {
            Message::Text(text) => {
                let text_str: &str = &text;
                match serde_json::from_str::<ClientMessage>(text_str) {
                    Ok(ClientMessage::Auth {
                        user_id: _,
                        token,
                        device_id,
                    }) => {
                        if let Some(user_id) = state.validate_auth(&token, &device_id).await {
                            authenticated_user = Some(user_id.clone());
                            authenticated_device = Some(device_id.clone());
                            state.register(device_id.clone(), tx.clone());
                            let resp = serde_json::to_string(&ServerMessage::AuthOk).unwrap();
                            let _ = tx.send(resp);
                            if let Ok(messages) = state.db.drain_offline_messages(&device_id).await
                            {
                                for msg in messages {
                                    let relay_msg =
                                        serde_json::to_string(&ServerMessage::Message {
                                            message_id: msg.message_id,
                                            from: msg.from_user_id,
                                            conversation_id: msg.conversation_id,
                                            ciphertext: msg.ciphertext,
                                            signature: msg.signature,
                                            sender_device_id: msg.sender_device_id,
                                            sender_seq: msg.sender_seq,
                                            prev_hash: msg.prev_hash,
                                            recipient_device_id: msg.recipient_device_id,
                                            timestamp: msg.timestamp,
                                        })
                                        .unwrap();
                                    let _ = tx.send(relay_msg);
                                }
                            }
                        } else {
                            let resp = serde_json::to_string(&ServerMessage::AuthFail {
                                reason: "Invalid credentials".into(),
                            })
                            .unwrap();
                            let _ = tx.send(resp);
                        }
                    }
                    Ok(ClientMessage::Send {
                        message_id,
                        conversation_id,
                        ciphertext: _,
                        signature: _,
                        // The claimed sender device is untrusted; the relay
                        // stamps the authenticated device instead.
                        sender_device_id: _,
                        sender_seq,
                        prev_hash,
                        payloads,
                    }) => {
                        let (from, sender_device_id) =
                            match (&authenticated_user, &authenticated_device) {
                                (Some(uid), Some(did)) => (uid.clone(), did.clone()),
                                _ => {
                                    let resp = serde_json::to_string(&ServerMessage::Error {
                                        code: "unauthorized".into(),
                                        message: "Not authenticated".into(),
                                    })
                                    .unwrap();
                                    let _ = tx.send(resp);
                                    continue;
                                }
                            };

                        if payloads.is_empty() {
                            let resp = serde_json::to_string(&ServerMessage::Error {
                                code: "no_payloads".into(),
                                message: "Send requires at least one recipient payload".into(),
                            })
                            .unwrap();
                            let _ = tx.send(resp);
                            continue;
                        }

                        let timestamp = chrono_now();
                        let mut updates = Vec::new();
                        for payload in payloads {
                            let relay_msg = serde_json::to_string(&ServerMessage::Message {
                                message_id: message_id.clone(),
                                from: from.clone(),
                                conversation_id: conversation_id.clone(),
                                ciphertext: payload.ciphertext.clone(),
                                signature: payload.signature.clone(),
                                sender_device_id: sender_device_id.clone(),
                                sender_seq,
                                prev_hash: prev_hash.clone(),
                                recipient_device_id: payload.recipient_device_id.clone(),
                                timestamp,
                            })
                            .unwrap();

                            if state.send_to(&payload.recipient_device_id, relay_msg) {
                                updates.push(DeliveryStatus {
                                    message_id: message_id.clone(),
                                    recipient_user_id: payload.recipient_user_id,
                                    recipient_device_id: payload.recipient_device_id,
                                    status: "delivered".to_string(),
                                });
                            } else {
                                let stored = state
                                    .db
                                    .store_offline_message(&crate::db::OfflineMessageRecord {
                                        message_id: message_id.clone(),
                                        conversation_id: conversation_id.clone(),
                                        from_user_id: from.clone(),
                                        sender_device_id: sender_device_id.clone(),
                                        sender_seq,
                                        prev_hash: prev_hash.clone(),
                                        recipient_device_id: payload.recipient_device_id.clone(),
                                        ciphertext: payload.ciphertext,
                                        signature: payload.signature,
                                        timestamp,
                                    })
                                    .await;
                                if stored.is_err() {
                                    tracing::error!("Failed to persist an offline message");
                                    let _ = tx.send(serde_json::to_string(&ServerMessage::Error {
                                        code: "storage_failed".into(),
                                        message: "服务器未能保存离线消息，请稍后重试；部分设备可能已收到消息".into(),
                                    }).unwrap());
                                }
                                updates.push(DeliveryStatus {
                                    message_id: message_id.clone(),
                                    recipient_user_id: payload.recipient_user_id,
                                    recipient_device_id: payload.recipient_device_id,
                                    status: if stored.is_ok() {
                                        "stored_offline"
                                    } else {
                                        "failed"
                                    }
                                    .to_string(),
                                });
                            }
                        }
                        let update =
                            serde_json::to_string(&ServerMessage::DeliveryUpdate { updates })
                                .unwrap();
                        let _ = tx.send(update);
                    }
                    Ok(ClientMessage::Ack {
                        message_id,
                        recipient_device_id,
                    }) => {
                        let _ = state
                            .db
                            .ack_message(&message_id, &recipient_device_id)
                            .await;
                        tracing::debug!("Received ack for message: {}", message_id);
                    }
                    Err(_) => {
                        let resp = serde_json::to_string(&ServerMessage::Error {
                            code: "parse_error".into(),
                            message: "Invalid message format".into(),
                        })
                        .unwrap();
                        let _ = tx.send(resp);
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    if let Some(device_id) = &authenticated_device {
        state.unregister(device_id);
        tracing::info!("Device disconnected: {}", device_id);
    }

    send_task.abort();
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
