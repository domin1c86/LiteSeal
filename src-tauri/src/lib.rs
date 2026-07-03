pub mod commands;
pub mod db;
pub mod network;

use std::sync::Mutex;
use tokio::sync::Mutex as AsyncMutex;

use db::repository::MessageRepository;
use liteseal_shared::protocol::ServerMessage;
use network::websocket::WebSocketClient;

pub struct AppState {
    pub db: Mutex<MessageRepository>,
    pub ws_client: AsyncMutex<Option<WebSocketClient>>,
    pub msg_receiver: AsyncMutex<Option<tokio::sync::mpsc::UnboundedReceiver<ServerMessage>>>,
}

impl AppState {
    pub fn new(db_path: &str) -> Result<Self, String> {
        let db = MessageRepository::new(db_path).map_err(|e| e.to_string())?;
        Ok(Self {
            db: Mutex::new(db),
            ws_client: AsyncMutex::new(None),
            msg_receiver: AsyncMutex::new(None),
        })
    }
}
