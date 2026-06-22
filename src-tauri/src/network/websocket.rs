use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::{error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
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

pub type MessageReceiver = mpsc::UnboundedReceiver<ServerMessage>;

pub struct WebSocketClient {
    write: Arc<Mutex<futures_util::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
    recv_task: Option<tokio::task::JoinHandle<()>>,
}

impl WebSocketClient {
    pub async fn connect(
        url: &str,
        user_id: String,
        token: String,
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
        };
        let auth_json = serde_json::to_string(&auth_msg).map_err(|e| e.to_string())?;

        write
            .lock()
            .await
            .send(Message::Text(auth_json))
            .await
            .map_err(|e| format!("Failed to send auth: {}", e))?;

        let (tx, rx) = mpsc::unbounded_channel::<ServerMessage>();

        let recv_task = tokio::spawn(async move {
            while let Some(Ok(msg)) = read.next().await {
                match msg {
                    Message::Text(text) => {
                        match serde_json::from_str::<ServerMessage>(&text) {
                            Ok(server_msg) => {
                                if tx.send(server_msg).is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Failed to parse server message: {}", e);
                            }
                        }
                    }
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

    pub async fn send_message(
        &self,
        to: String,
        conversation_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        sender_seq: i64,
    ) -> Result<(), String> {
        let msg = ClientMessage::Send {
            to,
            conversation_id,
            ciphertext,
            signature,
            sender_device_id,
            sender_seq,
        };
        let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;

        self.write
            .lock()
            .await
            .send(Message::Text(json))
            .await
            .map_err(|e| format!("Failed to send message: {}", e))
    }

    pub async fn send_ack(&self, message_id: String) -> Result<(), String> {
        let msg = ClientMessage::Ack { message_id };
        let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;

        self.write
            .lock()
            .await
            .send(Message::Text(json))
            .await
            .map_err(|e| format!("Failed to send ack: {}", e))
    }

    pub async fn disconnect(&mut self) {
        let _ = self
            .write
            .lock()
            .await
            .send(Message::Close(None))
            .await;
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
    }
}
