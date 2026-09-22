mod auth;
mod attachments;
mod contact_policy;
mod config;
mod db;
#[cfg(test)]
mod http_tests;
mod keys;
mod message_operations;
mod relay;
#[cfg(test)]
mod relay_tests;
mod state;

use axum::{
    extract::State,
    http::{header, HeaderValue, Method},
    routing::{delete, get, post},
    Router,
};
use config::ServerConfig;
use db::Db;
use state::AppState;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = ServerConfig::from_env().expect("invalid server configuration");
    let db = Db::connect(&config.database_url)
        .await
        .expect("failed to connect to Postgres");
    let mut state = AppState::new(db);
    state.invite_codes = std::sync::Arc::new(config.invite_codes);
    let allowed_origin = HeaderValue::from_str(&config.cors_allow_origin)
        .expect("LITESEAL_CORS_ALLOW_ORIGIN is not a valid origin");
    let app = build_router(state, allowed_origin);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .unwrap();
    tracing::info!("Server listening on {}", config.bind_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap();
}

fn build_router(state: AppState, allowed_origin: HeaderValue) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(allowed_origin)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PUT])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    Router::new()
        .route("/contact-policy", get(contact_policy::list).post(contact_policy::change))
        .route("/attachments", post(attachments::create))
        .route("/attachments/:id/:part", get(attachments::download).put(attachments::upload))
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(|State(state): State<AppState>| async move {
                match sqlx::query("SELECT 1").execute(state.db.pool()).await {
                    Ok(_) => (axum::http::StatusCode::OK, "ready"),
                    Err(_) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready"),
                }
            }),
        )
        .route("/auth/register", post(auth::handlers::register))
        .route(
            "/auth/invite/validate",
            post(auth::handlers::validate_invite),
        )
        .route("/auth/login", post(auth::handlers::login))
        .route("/auth/refresh", post(auth::handlers::refresh))
        .route("/auth/logout", post(auth::handlers::logout))
        .route("/auth/logout_all", post(auth::handlers::logout_all))
        .route("/auth/sessions", get(auth::handlers::list_sessions))
        .route(
            "/devices",
            get(auth::handlers::list_devices).post(auth::handlers::register_device),
        )
        .route(
            "/devices/:device_id",
            delete(auth::handlers::revoke_device).put(auth::handlers::rotate_device_keys),
        )
        .route("/users/search", get(keys::handlers::search_users))
        .route("/users/:user_id/key", get(keys::handlers::get_public_key))
        .route(
            "/users/:user_id/devices",
            get(keys::handlers::list_user_devices),
        )
        .route(
            "/contacts/:user_id/trust",
            post(keys::handlers::trust_contact),
        )
        .route(
            "/message-operations",
            get(message_operations::pending).post(message_operations::submit),
        )
        .route("/message-operations/ack", post(message_operations::ack))
        .route(
            "/message-operations/targets/:id",
            get(message_operations::targets),
        )
        .route("/ws", get(relay::handlers::ws_handler))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "Failed to install shutdown handler");
    }
    tracing::info!("Graceful shutdown requested");
}
