use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

pub type MessageSender = mpsc::UnboundedSender<String>;

pub struct RegisteredUser {
    pub username: String,
    pub token: String,
    pub public_key: Option<Vec<u8>>,
    pub ed25519_pk: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct AppState {
    pub connections: Arc<DashMap<String, MessageSender>>,
    pub users: Arc<DashMap<String, RegisteredUser>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            users: Arc::new(DashMap::new()),
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
            sender.send(message).is_ok()
        } else {
            false
        }
    }

    pub fn validate_auth(&self, user_id: &str, token: &str) -> bool {
        self.users
            .get(user_id)
            .is_some_and(|user| user.token == token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_auth_accepts_only_registered_token() {
        let state = AppState::new();
        state.users.insert(
            "user-1".to_string(),
            RegisteredUser {
                username: "alice".to_string(),
                token: "token-1".to_string(),
                public_key: None,
                ed25519_pk: None,
            },
        );

        assert!(state.validate_auth("user-1", "token-1"));
        assert!(!state.validate_auth("user-1", "wrong-token"));
        assert!(!state.validate_auth("missing-user", "token-1"));
    }
}
