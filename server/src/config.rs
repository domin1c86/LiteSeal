#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub database_url: String,
    pub bind_addr: String,
    pub cors_allow_origin: String,
    pub bootstrap_invite_code: Option<String>,
}

impl ServerConfig {
    pub fn from_env() -> Self {
        Self {
            database_url: std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://postgres:postgres@localhost:5432/liteseal".to_string()
            }),
            bind_addr: std::env::var("LITESEAL_BIND")
                .unwrap_or_else(|_| "0.0.0.0:3000".to_string()),
            cors_allow_origin: std::env::var("LITESEAL_CORS_ALLOW_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:1420".to_string()),
            bootstrap_invite_code: std::env::var("LITESEAL_BOOTSTRAP_INVITE_CODE")
                .ok()
                .filter(|code| !code.trim().is_empty()),
        }
    }
}
