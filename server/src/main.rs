mod auth;
mod config;
mod db;
mod keys;
mod relay;
mod state;

use axum::{
    http::{header, HeaderValue, Method},
    routing::{delete, get, post},
    Router,
};
use config::ServerConfig;
use db::Db;
use state::AppState;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = ServerConfig::from_env();
    let db = Db::connect(&config.database_url)
        .await
        .expect("failed to connect to Postgres");
    let state = AppState::new(db);
    let cors = HeaderValue::from_str(&config.cors_allow_origin)
        .map(|origin| {
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods([Method::GET, Method::POST, Method::DELETE])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        })
        .unwrap_or_else(|_| CorsLayer::permissive().allow_headers(Any));

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/auth/register", post(auth::handlers::register))
        .route("/auth/login", post(auth::handlers::login))
        .route("/auth/refresh", post(auth::handlers::refresh))
        .route("/auth/logout", post(auth::handlers::logout))
        .route("/auth/logout_all", post(auth::handlers::logout_all))
        .route(
            "/devices",
            get(auth::handlers::list_devices).post(auth::handlers::register_device),
        )
        .route(
            "/devices/{device_id}",
            delete(auth::handlers::revoke_device).put(auth::handlers::rotate_device_keys),
        )
        .route("/register", post(auth::handlers::register))
        .route("/users/search", get(keys::handlers::search_users))
        .route("/users/{user_id}/key", get(keys::handlers::get_public_key))
        .route(
            "/users/{user_id}/devices",
            get(keys::handlers::list_user_devices),
        )
        .route(
            "/contacts/{user_id}/trust",
            post(keys::handlers::trust_contact),
        )
        .route("/ws", get(relay::handlers::ws_handler))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .unwrap();
    tracing::info!("Server listening on {}", config.bind_addr);

    axum::serve(listener, app).await.unwrap();
}
