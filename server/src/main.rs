mod auth;
mod keys;
mod relay;
mod state;

use axum::{routing::get, routing::post, Router};
use state::AppState;
use tracing_subscriber;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = AppState::new();

    let app = Router::new()
        .route("/register", post(auth::handlers::register))
        .route("/users/search", get(keys::handlers::search_users))
        .route("/users/{user_id}/key", get(keys::handlers::get_public_key))
        .route("/ws", get(relay::handlers::ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("Server listening on 0.0.0.0:3000");

    axum::serve(listener, app).await.unwrap();
}
