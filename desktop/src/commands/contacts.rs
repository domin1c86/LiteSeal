use serde::{Deserialize, Serialize};

use crate::AppState;
use liteseal_core::api::{self, RemoteDevice};
use liteseal_core::db::models::ContactModel;
use liteseal_shared::types::PublicKeyInfo;

#[derive(Debug, Serialize, Deserialize)]
pub struct AddContactResult {
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveContactResult {
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetContactTrustResult {
    pub success: bool,
}

pub async fn add_contact(
    user_id: String,
    username: String,
    public_key: Vec<u8>,
    ed25519_pk: Option<Vec<u8>>,
    state: &AppState,
) -> Result<AddContactResult, String> {
    state
        .client
        .add_contact(user_id, username, public_key, ed25519_pk)?;
    Ok(AddContactResult { success: true })
}

pub async fn get_contacts(state: &AppState) -> Result<Vec<ContactModel>, String> {
    state.client.get_contacts()
}

pub async fn remove_contact(
    user_id: String,
    state: &AppState,
) -> Result<RemoveContactResult, String> {
    state.client.remove_contact(&user_id)?;
    Ok(RemoveContactResult { success: true })
}

pub async fn set_contact_trust(
    user_id: String,
    trust_state: String,
    state: &AppState,
) -> Result<SetContactTrustResult, String> {
    state.client.set_contact_trust(&user_id, &trust_state)?;
    Ok(SetContactTrustResult { success: true })
}

pub async fn get_user_devices(
    server_url: String,
    user_id: String,
) -> Result<Vec<RemoteDevice>, String> {
    api::get_user_devices(server_url, user_id).await
}

pub async fn search_users(server_url: String, query: String) -> Result<Vec<PublicKeyInfo>, String> {
    api::search_users(server_url, query).await
}
