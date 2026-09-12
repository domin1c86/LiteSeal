use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::db::Db;

pub type MessageSender = mpsc::UnboundedSender<String>;

#[derive(Clone)]
pub struct AppState {
    pub connections: Arc<DashMap<String, MessageSender>>,
    pub db: Db,
    pub invite_codes: Arc<Vec<String>>,
}

impl AppState {
    pub fn new(db: Db) -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            db,
            invite_codes: Arc::new(Vec::new()),
        }
    }

    pub fn accepts_invite(&self, code: &str) -> bool {
        let code = code.trim();
        !code.is_empty() && self.invite_codes.iter().any(|allowed| allowed == code)
    }

    pub fn register(&self, user_id: String, sender: MessageSender) {
        self.connections.insert(user_id, sender);
    }

    pub fn unregister_connection(&self, device_id: &str, sender: &MessageSender) {
        self.connections
            .remove_if(device_id, |_, current| current.same_channel(sender));
    }

    pub fn send_to(&self, user_id: &str, message: String) -> bool {
        if let Some(sender) = self.connections.get(user_id) {
            let connection = sender.clone();
            drop(sender);
            let sent = connection.send(message).is_ok();
            if !sent {
                self.unregister_connection(user_id, &connection);
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
