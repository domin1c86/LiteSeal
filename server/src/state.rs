use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::db::Db;

pub type MessageSender = mpsc::UnboundedSender<String>;

#[derive(Clone)]
pub struct AppState {
    pub connections: Arc<DashMap<String, MessageSender>>,
    pub db: Db,
}

impl AppState {
    pub fn new(db: Db) -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            db,
        }
    }

    pub fn register(&self, user_id: String, sender: MessageSender) {
        self.connections.insert(user_id, sender);
    }

    pub fn unregister(&self, user_id: &str) {
        self.connections.remove(user_id);
    }

    pub fn send_to(&self, user_id: &str, message: String) -> bool {
        if let Some(sender) = self.connections.get(user_id) {
            let sent = sender.send(message).is_ok();
            drop(sender);
            if !sent {
                self.connections.remove(user_id);
            }
            sent
        } else {
            false
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
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);
        state.register("device-1".to_string(), tx);
        assert!(!state.send_to("device-1", "{}".to_string()));
        assert!(!state.connections.contains_key("device-1"));
    }
}
