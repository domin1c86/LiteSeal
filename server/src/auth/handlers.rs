use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub token: String,
}

pub async fn register(
    State(_state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    if req.username.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let user_id = Uuid::new_v4().to_string();
    let token = Uuid::new_v4().to_string();

    tracing::info!("User registered: {} ({})", req.username, user_id);

    Ok(Json(RegisterResponse { user_id, token }))
}
