use super::*;

#[tokio::test]
async fn parameterized_routes_reach_authentication_instead_of_returning_404() {
    // No database is needed: every protected route must reject missing
    // credentials before attempting a query.
    let db = Db::connect_lazy("postgres://unused:unused@127.0.0.1:1/unused").unwrap();
    let app = build_router(
        AppState::new(db),
        HeaderValue::from_static("http://localhost:1420"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    for (method, path) in [
        (reqwest::Method::GET, "/users/test-user/key"),
        (reqwest::Method::GET, "/users/test-user/devices"),
        (reqwest::Method::DELETE, "/devices/test-device"),
        (reqwest::Method::PUT, "/devices/test-device"),
    ] {
        let response = client
            .request(method.clone(), format!("http://{address}{path}"))
            .json(&serde_json::json!({ "device_name": "test", "public_key": vec![1; 32], "ed25519_pk": vec![2; 32] }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }
    task.abort();
}
