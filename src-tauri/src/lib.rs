pub mod commands;

use liteseal_core::LitesealClient;

/// Thin Tauri wrapper around the shared client core; all business logic
/// lives in `liteseal-core`.
pub struct AppState {
    pub client: LitesealClient,
}

impl AppState {
    pub fn new(db_path: &str) -> Result<Self, String> {
        Ok(Self {
            client: LitesealClient::new(db_path)?,
        })
    }
}
