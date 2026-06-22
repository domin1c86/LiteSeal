use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::mpsc;

pub type MessageSender = mpsc::UnboundedSender<String>;

#[derive(Clone)]
pub struct AppState {
    pub connections: Arc<DashMap<String, MessageSender>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
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
}
