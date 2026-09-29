use sqlx::{postgres::PgPoolOptions, Row};

pub async fn run() {
    if let Err(reason) = check().await {
        // Do not print sqlx errors: they may contain credentials or server data.
        eprintln!("{reason}");
        std::process::exit(2);
    }
}

async fn check() -> Result<(), &'static str> {
    let url =
        std::env::var("LITESEAL_TEST_DATABASE_URL").map_err(|_| "test database not configured")?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await
        .map_err(|_| "test database connection failed")?;
    let row = sqlx::query("SELECT current_database() AS name, current_setting('server_version_num') AS version, shobj_description(oid, 'pg_database') AS marker FROM pg_database WHERE datname = current_database()")
        .fetch_one(&pool).await.map_err(|_| "test database inspection failed")?;
    let name: String = row.get("name");
    let marker: Option<String> = row.get("marker");
    if !name.starts_with("liteseal_test_")
        || marker.as_deref() != Some("liteseal-dedicated-test-v1")
    {
        return Err("dedicated test database name or marker missing");
    }
    let version: String = row.get("version");
    if std::env::args().any(|arg| arg == "--migrate") {
        let database = crate::db::Db::connect(&url)
            .await
            .map_err(|_| "test database migration failed")?;
        database.pool().close().await;
    }
    println!(
        "{}",
        serde_json::json!({ "server_version_num": version, "dedicated": true })
    );
    pool.close().await;
    Ok(())
}
