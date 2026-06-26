use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
}

#[derive(Serialize)]
pub struct UserSearchResult {
    pub user_id: String,
    pub username: String,
    pub public_key: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct PublicKeyResponse {
    pub user_id: String,
    pub username: String,
    pub public_key: Option<Vec<u8>>,
}

pub async fn search_users(
    State(state): State<AppState>,
    Query(params): Query<SearchQuery>,
) -> Json<Vec<UserSearchResult>> {
    let query = params.q.to_lowercase();
    let mut results = Vec::new();

    for entry in state.users.iter() {
        if results.len() >= 50 {
            break;
        }
        let user_id = entry.key();
        let user = entry.value();
        if user.username.to_lowercase().contains(&query) || user_id.contains(&query) {
            results.push(UserSearchResult {
                user_id: user_id.clone(),
                username: user.username.clone(),
                public_key: user.public_key.clone(),
            });
        }
    }

    Json(results)
}

pub async fn get_public_key(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<PublicKeyResponse>, StatusCode> {
    match state.users.get(&user_id) {
        Some(user) => Ok(Json(PublicKeyResponse {
            user_id: user_id.clone(),
            username: user.username.clone(),
            public_key: user.public_key.clone(),
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}
