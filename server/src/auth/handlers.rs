use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub public_key: Option<Vec<u8>>,
    pub ed25519_pk: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub token: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    if req.username.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let user_id = Uuid::new_v4().to_string();
    let token = Uuid::new_v4().to_string();

    state.users.insert(user_id.clone(), crate::state::RegisteredUser {
        username: req.username.clone(),
        public_key: req.public_key,
        ed25519_pk: req.ed25519_pk,
    });

    tracing::info!("User registered: {} ({})", req.username, user_id);

    Ok(Json(RegisterResponse { user_id, token }))
}
