#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub database_url: String,
    pub bind_addr: String,
    pub cors_allow_origin: String,
    pub bootstrap_invite_code: Option<String>,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, String> {
        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| "DATABASE_URL must be configured".to_string())?;
        let cors_allow_origin = std::env::var("LITESEAL_CORS_ALLOW_ORIGIN")
            .map_err(|_| "LITESEAL_CORS_ALLOW_ORIGIN must be configured".to_string())?;
        if database_url.contains("postgres:postgres") {
            return Err("DATABASE_URL must not use the default Postgres credentials".to_string());
        }
        if cors_allow_origin == "*" {
            return Err("Wildcard CORS origins are forbidden".to_string());
        }
        Ok(Self {
            database_url,
            bind_addr: std::env::var("LITESEAL_BIND")
                .unwrap_or_else(|_| "0.0.0.0:3000".to_string()),
            cors_allow_origin,
            bootstrap_invite_code: std::env::var("LITESEAL_BOOTSTRAP_INVITE_CODE")
                .ok()
                .filter(|code| !code.trim().is_empty()),
        })
    }
}
