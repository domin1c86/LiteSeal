use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::state::AppState;

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientMessage {
    #[serde(rename = "auth")]
    Auth { user_id: String, token: String },
    #[serde(rename = "send")]
    Send {
        to: String,
        conversation_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        sender_seq: i64,
    },
    #[serde(rename = "ack")]
    Ack { message_id: String },
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum ServerMessage {
    #[serde(rename = "auth_ok")]
    AuthOk,
    #[serde(rename = "auth_fail")]
    AuthFail { reason: String },
    #[serde(rename = "message")]
    Message {
        message_id: String,
        from: String,
        conversation_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        sender_seq: i64,
        timestamp: i64,
    },
    #[serde(rename = "error")]
    Error { code: String, message: String },
    #[serde(rename = "delivered")]
    Delivered { message_id: String },
    #[serde(rename = "offline")]
    Offline { to: String },
}

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    let mut authenticated_user: Option<String> = None;

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender
                .send(Message::Text(msg.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    while let Some(Ok(msg)) = StreamExt::next(&mut ws_receiver).await {
        match msg {
            Message::Text(text) => {
                let text_str: &str = &text;
                match serde_json::from_str::<ClientMessage>(text_str) {
                    Ok(ClientMessage::Auth { user_id, token: _ }) => {
                        authenticated_user = Some(user_id.clone());
                        state.register(user_id, tx.clone());
                        let resp = serde_json::to_string(&ServerMessage::AuthOk).unwrap();
                        let _ = tx.send(resp);
                    }
                    Ok(ClientMessage::Send {
                        to,
                        conversation_id,
                        ciphertext,
                        signature,
                        sender_device_id,
                        sender_seq,
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

                        let message_id = uuid::Uuid::new_v4().to_string();
                        let timestamp = chrono_now();

                        let relay_msg = serde_json::to_string(&ServerMessage::Message {
                            message_id: message_id.clone(),
                            from: from.clone(),
                            conversation_id,
                            ciphertext,
                            signature,
                            sender_device_id,
                            sender_seq,
                            timestamp,
                        })
                        .unwrap();

                        if state.send_to(&to, relay_msg) {
                            let ack = serde_json::to_string(&ServerMessage::Delivered {
                                message_id,
                            })
                            .unwrap();
                            let _ = tx.send(ack);
                        } else {
                            let offline = serde_json::to_string(&ServerMessage::Offline {
                                to: to.clone(),
                            })
                            .unwrap();
                            let _ = tx.send(offline);
                        }
                    }
                    Ok(ClientMessage::Ack { message_id: _ }) => {}
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

    if let Some(uid) = &authenticated_user {
        state.unregister(uid);
        tracing::info!("User disconnected: {}", uid);
    }

    send_task.abort();
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
