use dashmap::DashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::sync::mpsc;

use crate::db::Db;

pub type MessageSender = mpsc::Sender<String>;

#[derive(Clone)]
pub struct Connection {
    generation: u64,
    sender: MessageSender,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    Delivered,
    Offline,
}

#[derive(Clone)]
pub struct AppState {
    connections: Arc<DashMap<String, Connection>>,
    next_generation: Arc<AtomicU64>,
    pub db: Db,
    pub invite_codes: Arc<Vec<String>>,
}

impl AppState {
    pub fn new(db: Db) -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            next_generation: Arc::new(AtomicU64::new(1)),
            db,
            invite_codes: Arc::new(Vec::new()),
        }
    }

    pub fn accepts_invite(&self, code: &str) -> bool {
        let code = code.trim();
        !code.is_empty() && self.invite_codes.iter().any(|allowed| allowed == code)
    }

    pub fn register(&self, device_id: String, sender: MessageSender) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        self.connections
            .insert(device_id, Connection { generation, sender });
        generation
    }

    pub fn unregister(&self, device_id: &str, generation: u64) {
        self.connections.remove_if(device_id, |_, connection| {
            connection.generation == generation
        });
    }

    pub fn is_current(&self, device_id: &str, generation: u64) -> bool {
        self.connections
            .get(device_id)
            .is_some_and(|connection| connection.generation == generation)
    }

    pub fn send_to(&self, device_id: &str, message: String) -> SendOutcome {
        if let Some(connection) = self.connections.get(device_id) {
            let generation = connection.generation;
            let result = connection.sender.try_send(message);
            drop(connection);
            match result {
                Ok(()) => SendOutcome::Delivered,
                Err(mpsc::error::TrySendError::Full(_)) => SendOutcome::Offline,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.unregister(device_id, generation);
                    SendOutcome::Offline
                }
            }
        } else {
            SendOutcome::Offline
        }
    }

    pub async fn validate_auth(&self, token: &str, device_id: &str) -> Option<String> {
        let hash = crate::auth::service::hash_token(token);
        self.db
            .validate_access_token(&hash, device_id)
            .await
            .ok()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_to_removes_dead_connections() {
        let db = Db::connect_lazy("postgres://postgres:postgres@localhost/liteseal").unwrap();
        let state = AppState::new(db);
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        state.register("device-1".to_string(), tx);
        assert_eq!(
            state.send_to("device-1", "{}".to_string()),
            SendOutcome::Offline
        );
        assert!(!state.connections.contains_key("device-1"));
    }

    #[tokio::test]
    async fn stale_disconnect_cannot_remove_replacement_connection() {
        let db = Db::connect_lazy("postgres://postgres:postgres@localhost/liteseal").unwrap();
        let state = AppState::new(db);
        let (first_tx, _first_rx) = mpsc::channel(1);
        let first_generation = state.register("device-1".to_string(), first_tx);
        let (second_tx, mut second_rx) = mpsc::channel(1);
        let second_generation = state.register("device-1".to_string(), second_tx);

        state.unregister("device-1", first_generation);
        assert_eq!(
            state.send_to("device-1", "new".to_string()),
            SendOutcome::Delivered
        );
        assert_eq!(second_rx.recv().await.as_deref(), Some("new"));

        state.unregister("device-1", second_generation);
        assert_eq!(
            state.send_to("device-1", "gone".to_string()),
            SendOutcome::Offline
        );
    }

    #[tokio::test]
    async fn full_connection_channel_falls_back_to_offline_delivery() {
        let db = Db::connect_lazy("postgres://postgres:postgres@localhost/liteseal").unwrap();
        let state = AppState::new(db);
        let (tx, _rx) = mpsc::channel(1);
        state.register("device-1".to_string(), tx);

        assert_eq!(
            state.send_to("device-1", "first".to_string()),
            SendOutcome::Delivered
        );
        assert_eq!(
            state.send_to("device-1", "second".to_string()),
            SendOutcome::Offline
        );
    }
}
