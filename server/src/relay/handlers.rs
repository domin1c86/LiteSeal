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

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
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
                        ciphertext,
                        signature,
                        sender_device_id,
                        sender_seq,
                        prev_hash,
                        payloads,
                    }) => {
                        let from = match &authenticated_user {
                            Some(uid) => uid.clone(),
                            None => {
                                let resp = serde_json::to_string(&ServerMessage::Error {
                                    code: "unauthorized".into(),
                                    message: "Not authenticated".into(),
                                })
                                .unwrap();
                                let _ = tx.send(resp);
                                continue;
                            }
                        };

                        let timestamp = chrono_now();
                        let mut updates = Vec::new();
                        let effective_payloads = if payloads.is_empty() {
                            vec![liteseal_shared::protocol::EncryptedPayload {
                                recipient_user_id: from.clone(),
                                recipient_device_id: from.clone(),
                                ciphertext,
                                signature,
                            }]
                        } else {
                            payloads
                        };
                        for payload in effective_payloads {
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
                                let _ = state
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
                                updates.push(DeliveryStatus {
                                    message_id: message_id.clone(),
                                    recipient_user_id: payload.recipient_user_id,
                                    recipient_device_id: payload.recipient_device_id,
                                    status: "stored_offline".to_string(),
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
