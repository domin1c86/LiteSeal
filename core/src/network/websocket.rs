use futures_util::{SinkExt, StreamExt};
use liteseal_shared::protocol::{ClientMessage, EncryptedPayload, ServerMessage, SignedEnvelopeV2};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Duration};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::{error, info};

pub type MessageReceiver = mpsc::UnboundedReceiver<ServerMessage>;

pub struct WebSocketClient {
    write: Arc<
        Mutex<futures_util::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>,
    >,
    recv_task: Option<tokio::task::JoinHandle<()>>,
}

impl WebSocketClient {
    pub async fn connect(
        url: &str,
        user_id: String,
        token: String,
        device_id: String,
    ) -> Result<(Self, MessageReceiver), String> {
        let (ws_stream, _) = connect_async(url)
            .await
            .map_err(|e| format!("WebSocket connect failed: {}", e))?;

        info!("Connected to relay server: {}", url);

        let (write, mut read) = ws_stream.split();
        let write = Arc::new(Mutex::new(write));

        let auth_msg = ClientMessage::Auth {
            user_id: user_id.clone(),
            token,
            device_id: device_id.clone(),
        };
        let auth_json = serde_json::to_string(&auth_msg).map_err(|e| e.to_string())?;

        write
            .lock()
            .await
            .send(Message::Text(auth_json))
            .await
            .map_err(|e| format!("Failed to send auth: {}", e))?;

        let auth_response = timeout(Duration::from_secs(5), async {
            while let Some(msg) = read.next().await {
                match msg.map_err(|e| format!("Failed to read auth response: {}", e))? {
                    Message::Text(text) => {
                        return serde_json::from_str::<ServerMessage>(&text)
                            .map_err(|e| format!("Failed to parse auth response: {}", e));
                    }
                    Message::Close(_) => return Err("WebSocket closed during auth".to_string()),
                    _ => {}
                }
            }
            Err("WebSocket ended during auth".to_string())
        })
        .await
        .map_err(|_| "Timed out waiting for auth response".to_string())??;
        classify_auth_response(auth_response)?;

        let (tx, rx) = mpsc::unbounded_channel::<ServerMessage>();

        let recv_task = tokio::spawn(async move {
            while let Some(Ok(msg)) = read.next().await {
                match msg {
                    Message::Text(text) => match serde_json::from_str::<ServerMessage>(&text) {
                        Ok(server_msg) => {
                            if tx.send(server_msg).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse server message: {}", e);
                        }
                    },
                    Message::Close(_) => {
                        info!("WebSocket closed by server");
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok((
            Self {
                write,
                recv_task: Some(recv_task),
            },
            rx,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_message(
        &self,
        message_id: String,
        conversation_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        sender_seq: i64,
        prev_hash: Vec<u8>,
        payloads: Vec<EncryptedPayload>,
    ) -> Result<(), String> {
        if payloads.is_empty() {
            return Err("Message has no recipient payloads".to_string());
        }
        let msg = ClientMessage::Send {
            message_id,
            conversation_id,
            ciphertext,
            signature,
            sender_device_id,
            sender_seq,
            prev_hash,
            payloads,
        };
        let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;

        self.write
            .lock()
            .await
            .send(Message::Text(json))
            .await
            .map_err(|e| format!("Failed to send message: {}", e))
    }

    pub async fn send_v2(&self, envelope: SignedEnvelopeV2) -> Result<(), String> {
        let json = serde_json::to_string(&ClientMessage::SendV2 {
            envelopes: vec![envelope],
        })
        .map_err(|e| e.to_string())?;
        self.write
            .lock()
            .await
            .send(Message::Text(json))
            .await
            .map_err(|e| format!("Failed to send message: {e}"))
    }

    pub async fn send_ack(&self, message_id: String) -> Result<(), String> {
        let msg = ClientMessage::AckV2 {
            message_id,
            outcome: Default::default(),
        };
        let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;

        self.write
            .lock()
            .await
            .send(Message::Text(json))
            .await
            .map_err(|e| format!("Failed to send ack: {}", e))
    }

    pub async fn disconnect(&mut self) {
        let _ = self.write.lock().await.send(Message::Close(None)).await;
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
    }
}

fn classify_auth_response(msg: ServerMessage) -> Result<(), String> {
    match msg {
        ServerMessage::AuthOk => Ok(()),
        ServerMessage::AuthFail { reason } => Err(format!("Authentication failed: {}", reason)),
        _ => Err("Unexpected server response during authentication".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_response_accepts_only_auth_ok() {
        assert!(classify_auth_response(ServerMessage::AuthOk).is_ok());

        let err = classify_auth_response(ServerMessage::AuthFail {
            reason: "bad token".to_string(),
        })
        .unwrap_err();
        assert!(err.contains("bad token"));

        assert!(classify_auth_response(ServerMessage::Offline {
            message_id: "msg-1".to_string(),
            to: "user-2".to_string(),
        })
        .is_err());
    }
}
