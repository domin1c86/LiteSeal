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
                let parsed = serde_json::from_str::<ClientMessage>(text_str);
                let chains = match &parsed {
                    Ok(ClientMessage::SendV2 {
                        recipient_chains, ..
                    }) => Some(recipient_chains.clone()),
                    _ => None,
                };
                match parsed {
                    Ok(ClientMessage::Auth {
                        user_id: _,
                        token,
                        device_id,
                    }) => {
                        if authenticated_device.is_some() {
                            let _ = tx.send(
                                serde_json::to_string(&ServerMessage::Error {
                                    code: "already_authenticated".into(),
                                    message: "Connection is already authenticated".into(),
                                })
                                .unwrap(),
                            );
                            continue;
                        }
                        if let Some(user_id) = state.validate_auth(&token, &device_id).await {
                            authenticated_user = Some(user_id.clone());
                            authenticated_device = Some(device_id.clone());
                            state.register(device_id.clone(), tx.clone());
                            let resp = serde_json::to_string(&ServerMessage::AuthOk).unwrap();
                            let _ = tx.send(resp);
                            match state.db.drain_offline_messages(&device_id).await {
                                Ok(messages) => {
                                    for msg in messages {
                                        let _ = tx.send(delivery_frame(msg));
                                    }
                                }
                                Err(_) => {
                                    tracing::error!("Cannot load pending deliveries; closing connection for retry");
                                    break;
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
                    })
                    | Ok(ClientMessage::SendV2 {
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
                        recipient_chains: _,
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
                            let chain_version = if chains.is_some() { 2 } else { 0 };
                            let (sequence, previous_hash) = if let Some(chains) = &chains {
                                match chains.get(&payload.recipient_device_id) {
                                    Some(chain)
                                        if (chain.sender_seq > 1
                                            && chain.prev_hash.len() == 32)
                                            || (chain.sender_seq == 1
                                                && chain.prev_hash.is_empty()) =>
                                    {
                                        (chain.sender_seq, chain.prev_hash.clone())
                                    }
                                    _ => {
                                        let _ = tx.send(
                                            serde_json::to_string(&ServerMessage::Error {
                                                code: "invalid_chain".into(),
                                                message: "Missing or invalid recipient chain"
                                                    .into(),
                                            })
                                            .unwrap(),
                                        );
                                        continue;
                                    }
                                }
                            } else {
                                (sender_seq, prev_hash.clone())
                            };
                            let record = crate::db::OfflineMessageRecord {
                                chain_version,
                                message_id: message_id.clone(),
                                conversation_id: conversation_id.clone(),
                                from_user_id: from.clone(),
                                sender_device_id: sender_device_id.clone(),
                                sender_seq: sequence,
                                prev_hash: previous_hash,
                                recipient_device_id: payload.recipient_device_id.clone(),
                                ciphertext: payload.ciphertext.clone(),
                                signature: payload.signature.clone(),
                                timestamp,
                            };
                            let relay_msg = delivery_frame(record.clone());
                            let valid_device = state
                                .db
                                .get_user_device(
                                    &payload.recipient_user_id,
                                    &payload.recipient_device_id,
                                )
                                .await;
                            let stored = match valid_device {
                                Ok(Some(device)) if !device.revoked => {
                                    state.db.store_offline_message(&record).await
                                }
                                _ => Err(sqlx::Error::Protocol(
                                    "Recipient device is unavailable".into(),
                                )),
                            };
                            let status = match stored {
                                Ok(true) => "received",
                                Ok(false) => {
                                    if state.send_to(&payload.recipient_device_id, relay_msg) {
                                        "queued"
                                    } else {
                                        "stored_offline"
                                    }
                                }
                                Err(_) => {
                                    tracing::error!(
                                        "Cannot persist relay message or validate recipient device"
                                    );
                                    let _ = tx.send(serde_json::to_string(&ServerMessage::Error {
                                        code: "storage_failed".into(), message: "消息未能保存或收件设备不可用，请重试原消息；部分设备可能已收到".into()
                                    }).unwrap());
                                    "failed"
                                }
                            };
                            updates.push(DeliveryStatus {
                                message_id: message_id.clone(),
                                recipient_user_id: payload.recipient_user_id,
                                recipient_device_id: payload.recipient_device_id,
                                status: status.into(),
                            });
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
                        if authenticated_device.as_deref() != Some(recipient_device_id.as_str()) {
                            continue;
                        }
                        match state
                            .db
                            .ack_message(&message_id, &recipient_device_id)
                            .await
                        {
                            Ok(Some(sender_device)) => {
                                let update = ServerMessage::DeliveryUpdate {
                                    updates: vec![DeliveryStatus {
                                        message_id,
                                        recipient_user_id: authenticated_user
                                            .clone()
                                            .unwrap_or_default(),
                                        recipient_device_id,
                                        status: "received".into(),
                                    }],
                                };
                                state.send_to(
                                    &sender_device,
                                    serde_json::to_string(&update).unwrap(),
                                );
                            }
                            Ok(None) => {}
                            Err(_) => {
                                // Closing the stream forces replay of unacknowledged durable rows.
                                break;
                            }
                        }
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
        state.unregister_connection(device_id, &tx);
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

fn delivery_frame(msg: crate::db::OfflineMessageRecord) -> String {
    let frame = if msg.chain_version == 2 {
        ServerMessage::MessageV2 {
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
        }
    } else {
        ServerMessage::Message {
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
        }
    };
    serde_json::to_string(&frame).expect("Relay frame is serializable")
}
