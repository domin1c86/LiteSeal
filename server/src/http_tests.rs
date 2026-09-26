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
        (reqwest::Method::POST, "/auth/change_password"),
        (reqwest::Method::GET, "/users/test-user/profile"),
        (reqwest::Method::PUT, "/users/me/profile"),
        (
            reqwest::Method::GET,
            "/read-receipts?device_id=test-device&after=0",
        ),
        (reqwest::Method::POST, "/read-receipts"),
        (reqwest::Method::GET, "/groups?device_id=test-device"),
        (reqwest::Method::POST, "/groups"),
        (
            reqwest::Method::GET,
            "/groups/00000000-0000-0000-0000-000000000001/changes?device_id=test-device",
        ),
        (
            reqwest::Method::POST,
            "/groups/00000000-0000-0000-0000-000000000001/changes",
        ),
        (
            reqwest::Method::POST,
            "/groups/00000000-0000-0000-0000-000000000001/invites",
        ),
        (reqwest::Method::GET, "/group-invites?device_id=test-device"),
        (
            reqwest::Method::DELETE,
            "/group-invites/00000000-0000-0000-0000-000000000001?device_id=test-device",
        ),
    ] {
        let body = if path == "/auth/change_password" {
            serde_json::json!({"current_password":"old-password-123","new_password":"new-password-123"})
        } else if path == "/users/me/profile" {
            serde_json::json!({"display_name":"Test","avatar_png":null})
        } else if path == "/read-receipts" {
            serde_json::json!({"id":"event","target_id":"message","conversation_id":"dm:alice:bob","reader":"bob","device":"test-device","peer":"alice","signature":vec![0;64]})
        } else if path.ends_with("/invites") {
            serde_json::json!({"device_id":"test-device","invite":{"id":"invite","group_id":"group","epoch":1,"previous_hash":[],"member":{"user_id":"user","device_id":"device","public_key":vec![1;32],"signing_key":vec![2;32]},"issued_at":1,"expires_at":2,"signature":vec![0;64]}})
        } else if path == "/groups" || path.ends_with("/changes") {
            serde_json::json!({"device_id":"test-device","change":{"group_id":"group","epoch":2,"previous_hash":[],"actor":"user","created_at":1,"action":{"kind":"rename","name":"test"},"signature":vec![0;64]}})
        } else {
            serde_json::json!({ "device_name": "test", "public_key": vec![1; 32], "ed25519_pk": vec![2; 32] })
        };
        let response = client
            .request(method.clone(), format!("http://{address}{path}"))
            .json(&body)
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

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn changing_password_revokes_access_and_refresh_sessions() {
    let url = std::env::var("LITESEAL_TEST_DATABASE_URL")
        .expect("set LITESEAL_TEST_DATABASE_URL to a dedicated test database");
    let db = Db::connect(&url).await.expect("connect test Postgres");
    let username = format!("change-password-{}", uuid::Uuid::new_v4());
    let access = format!("access-{username}");
    let refresh = format!("refresh-{username}");
    db.register_user(
        &username,
        &auth::service::hash_password("old-password-123").unwrap(),
        "test device",
        &[1; 32],
        &[2; 32],
        &auth::service::hash_token(&access),
        &auth::service::hash_token(&refresh),
    )
    .await
    .unwrap();
    let app = build_router(
        AppState::new(db.clone()),
        HeaderValue::from_static("http://localhost:1420"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap()
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let endpoint = format!("http://{address}/auth/change_password");
    let wrong = client
        .post(&endpoint)
        .bearer_auth(&access)
        .json(&serde_json::json!({
            "current_password":"wrong-password", "new_password":"new-password-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), reqwest::StatusCode::FORBIDDEN);
    let changed = client
        .post(&endpoint)
        .bearer_auth(&access)
        .json(&serde_json::json!({
            "current_password":"old-password-123", "new_password":"new-password-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(changed.status(), reqwest::StatusCode::NO_CONTENT);
    let user = db.get_user_by_username(&username).await.unwrap().unwrap();
    assert!(auth::service::verify_password(
        "new-password-123",
        &user.password_hash
    ));
    assert!(!auth::service::verify_password(
        "old-password-123",
        &user.password_hash
    ));
    assert_eq!(
        db.user_for_access_token(&auth::service::hash_token(&access))
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        db.rotate_refresh_session(
            &auth::service::hash_token(&refresh),
            "unused-access",
            "unused-refresh"
        )
        .await
        .unwrap(),
        None
    );
    task.abort();
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn public_profile_updates_without_changing_account_identity() {
    let url = std::env::var("LITESEAL_TEST_DATABASE_URL")
        .expect("set LITESEAL_TEST_DATABASE_URL to a dedicated test database");
    let db = Db::connect(&url).await.expect("connect test Postgres");
    let username = format!("profile-{}", uuid::Uuid::new_v4());
    let access = format!("access-{username}");
    let (user, _) = db
        .register_user(
            &username,
            "password-hash",
            "test device",
            &[1; 32],
            &[2; 32],
            &auth::service::hash_token(&access),
            "unused-refresh",
        )
        .await
        .unwrap();
    let app = build_router(
        AppState::new(db),
        HeaderValue::from_static("http://localhost:1420"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap()
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let update = client
        .put(format!("http://{address}/users/me/profile"))
        .bearer_auth(&access)
        .json(&serde_json::json!({"display_name":"公开昵称","avatar_png":null}))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), reqwest::StatusCode::OK);
    let profile: serde_json::Value = client
        .get(format!("http://{address}/users/{}/profile", user.id))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(profile["username"], username);
    assert_eq!(profile["display_name"], "公开昵称");
    assert_eq!(profile["avatar_png"], serde_json::Value::Null);
    task.abort();
}
