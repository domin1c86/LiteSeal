pub mod commands;
pub mod protocol;

pub struct AppState {
    pub client: liteseal_core::LitesealClient,
}
impl AppState {
    pub fn new(db_path: &str) -> Result<Self, String> {
        Ok(Self {
            client: liteseal_core::LitesealClient::new(db_path)?,
        })
    }
}
