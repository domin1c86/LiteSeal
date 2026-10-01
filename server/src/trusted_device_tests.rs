//! Synthetic accounts only; the dedicated marker is checked by the validation runner.
use super::*;
use axum::http::StatusCode;
use liteseal_shared::{crypto, trusted_device::*};
use sqlx::Row;
struct Fixture {
    db: Db,
    url: String,
    client: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Account {
    id: String,
    device: String,
    username: String,
    password: String,
    token: String,
    keys: crypto::KeyPair,
}
struct Join {
    keys: crypto::KeyPair,
    token: String,
    status: JoinStatus,
}
impl Fixture {
    async fn start(enabled: bool) -> Self {
        let database =
            std::env::var("LITESEAL_TEST_DATABASE_URL").expect("requires dedicated Postgres");
        let db = Db::connect(&database).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let mut state = AppState::new(db.clone());
        if enabled {
            state.device_authorization_origin = Some(url.clone());
        }
        let app = build_router(state, HeaderValue::from_static("http://localhost:1420"));
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .unwrap();
        Self {
            db,
            url,
            client,
            task,
        }
    }
    async fn account(&self) -> Account {
        let keys = crypto::generate_keypair().unwrap();
        let token = auth::service::generate_token();
        let username = format!("devices-{}", uuid::Uuid::new_v4());
        let password = auth::service::generate_token();
        let (user, device) = self
            .db
            .register_user(
                &username,
                &auth::service::hash_password(&password).unwrap(),
                "original",
                &keys.public_key,
                &keys.ed25519_pk,
                &auth::service::hash_token(&token),
                &auth::service::generate_token(),
            )
            .await
            .unwrap();
        Account {
            id: user.id,
            device: device.id,
            username,
            password,
            token,
            keys,
        }
    }
    async fn start_join(
        &self,
        root: &Account,
        keys: &crypto::KeyPair,
        id: &str,
        token: &str,
    ) -> reqwest::Response {
        self.client
            .post(format!("{}/devices/join_requests", self.url))
            .json(&JoinStartRequest {
                request_id: id.into(),
                request_token: token.into(),
                username: root.username.clone(),
                password: root.password.clone(),
                device_name: "second Windows".into(),
                encryption_key: keys.public_key,
                signing_key: keys.ed25519_pk,
            })
            .send()
            .await
            .unwrap()
    }
    async fn join(&self, root: &Account) -> Join {
        let keys = crypto::generate_keypair().unwrap();
        let token = hex::encode(crypto::random_challenge().unwrap());
        let response = self
            .start_join(root, &keys, &uuid::Uuid::new_v4().to_string(), &token)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let status = response.json::<JoinStatus>().await.unwrap();
        Join {
            keys,
            token,
            status,
        }
    }
    async fn ready(&self, join: &Join) -> JoinStatus {
        let intent = join.status.ticket.sign_intent(&join.keys).unwrap();
        let response = self
            .client
            .post(format!(
                "{}/devices/join_requests/{}/intent",
                self.url, intent.id
            ))
            .bearer_auth(&join.token)
            .json(&intent)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.json().await.unwrap()
    }
    async fn prove(&self, root: &Account, join: &Join, state: &DeviceState) -> DeviceEvent {
        let ready = self.ready(join).await;
        let intent = ready.intent.unwrap();
        let challenge = make_challenge(state, &intent, now(), &root.keys).unwrap();
        let response = self
            .client
            .post(format!(
                "{}/devices/join_requests/{}/challenge",
                self.url, intent.id
            ))
            .bearer_auth(&root.token)
            .json(&ChallengeSubmission {
                device_id: root.device.clone(),
                challenge: challenge.clone(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let proof = answer_challenge(state, &intent, &challenge, now(), &join.keys).unwrap();
        let response = self
            .client
            .post(format!(
                "{}/devices/join_requests/{}/proof",
                self.url, intent.id
            ))
            .bearer_auth(&join.token)
            .json(&proof)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        make_event(
            state,
            uuid::Uuid::new_v4().to_string(),
            DeviceAction::Grant {
                intent: Box::new(intent),
                challenge: Box::new(challenge),
                proof,
            },
            now(),
            &root.keys,
        )
        .unwrap()
    }
    async fn submit(&self, root: &Account, event: &DeviceEvent) -> reqwest::Response {
        let route = if matches!(event.action, DeviceAction::Grant { .. }) {
            "grants"
        } else {
            "revoke"
        };
        self.client
            .post(format!("{}/devices/{route}", self.url))
            .bearer_auth(&root.token)
            .json(&DeviceEventSubmission {
                device_id: root.device.clone(),
                event: event.clone(),
            })
            .send()
            .await
            .unwrap()
    }
    async fn manifest(
        &self,
        viewer: &Account,
        user: &str,
        after: u64,
        limit: usize,
    ) -> reqwest::Response {
        self.client
            .get(format!("{}/users/{user}/device_manifest", self.url))
            .bearer_auth(&viewer.token)
            .query(&[
                ("after_revision", after.to_string()),
                ("limit", limit.to_string()),
            ])
            .send()
            .await
            .unwrap()
    }
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn authorization_round_trip_manifest_pagination_and_revoke_are_isolated() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let peer = f.account().await;
    let join = f.join(&root).await;
    let state = DeviceState::pin(join.status.ticket.anchor.clone()).unwrap();
    let event = f.prove(&root, &join, &state).await;
    let response = f.submit(&root, &event).await;
    assert_eq!(response.status(), StatusCode::OK);
    let receipt: DeviceReceipt = response.json().await.unwrap();
    assert!(!receipt.messaging_enabled);
    assert_eq!(receipt.event_hash, event.hash());
    assert_eq!(receipt.accepted_revision, 1);
    let duplicate = f.submit(&root, &event).await;
    assert_eq!(duplicate.status(), StatusCode::OK);
    let mut changed = event.clone();
    changed.created_at -= 1;
    changed.signature = crypto::sign(&changed.signing_bytes(), &root.keys.ed25519_sk).unwrap();
    assert_eq!(
        f.submit(&root, &changed).await.status(),
        StatusCode::CONFLICT
    );
    let page: DeviceManifestPage = f
        .manifest(&peer, &root.id, 0, 1)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(page.anchor.root.encryption_key, root.keys.public_key);
    assert_eq!(page.anchor.root.signing_key, root.keys.ed25519_pk);
    assert_eq!(page.events, vec![event.clone()]);
    assert!(!page.more);
    let joined = state.apply(&page.events[0]).unwrap();
    assert_eq!(joined.secondary().unwrap(), &join.status.ticket.device);
    assert_eq!(f.db.list_user_devices(&root.id).await.unwrap().len(), 1);
    let normal = f.client.post(format!("{}/auth/login",f.url)).json(&serde_json::json!({"username":root.username,"password":root.password,
        "device_id":join.status.ticket.device.device_id,"device_public_key":join.keys.public_key,"ed25519_pk":join.keys.ed25519_pk})).send().await.unwrap();
    assert_eq!(normal.status(), StatusCode::FORBIDDEN);
    for path in [
        "/auth/sessions".to_string(),
        format!("/users/{}/key", root.id),
        "/devices".into(),
        format!("/groups?device_id={}", join.status.ticket.device.device_id),
        format!("/users/{}/device_manifest", root.id),
    ] {
        assert_eq!(
            f.client
                .get(format!("{}{path}", f.url))
                .bearer_auth(&join.token)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let revoke = make_event(
        &joined,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Revoke {
            device_id: join.status.ticket.device.device_id.clone(),
            grant_hash: event.hash(),
        },
        now(),
        &root.keys,
    )
    .unwrap();
    assert_eq!(f.submit(&root, &revoke).await.status(), StatusCode::OK);
    let replay: DeviceReceipt = f.submit(&root, &event).await.json().await.unwrap();
    assert_eq!(replay.current_revision, 2);
    let status = f
        .client
        .get(format!(
            "{}/devices/join_requests/{}",
            f.url, join.status.ticket.id
        ))
        .bearer_auth(&join.token)
        .send()
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::UNAUTHORIZED);
    let first: DeviceManifestPage = f
        .manifest(&peer, &root.id, 0, 1)
        .await
        .json()
        .await
        .unwrap();
    assert!(first.more);
    let last: DeviceManifestPage = f
        .manifest(&peer, &root.id, 1, 1)
        .await
        .json()
        .await
        .unwrap();
    assert!(!last.more);
    assert!(joined.apply(&last.events[0]).unwrap().secondary().is_none());
    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_authorizations WHERE user_id=$1 AND revoked=false",
    )
    .bind(&root.id)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(live, 0);
    assert_eq!(
        f.manifest(&peer, &root.id, 3, 1).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.manifest(&peer, &root.id, 0, 101).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn concurrent_join_start_and_original_ticket_retry_do_not_replace_identity() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let a = crypto::generate_keypair().unwrap();
    let b = crypto::generate_keypair().unwrap();
    let id_a = uuid::Uuid::new_v4().to_string();
    let id_b = uuid::Uuid::new_v4().to_string();
    let token_a = hex::encode(crypto::random_challenge().unwrap());
    let token_b = hex::encode(crypto::random_challenge().unwrap());
    let (one, two) = tokio::join!(
        f.start_join(&root, &a, &id_a, &token_a),
        f.start_join(&root, &b, &id_b, &token_b)
    );
    assert_ne!(
        one.status() == StatusCode::OK,
        two.status() == StatusCode::OK
    );
    let (response, keys, id, token) = if one.status() == StatusCode::OK {
        (one, &a, &id_a, &token_a)
    } else {
        (two, &b, &id_b, &token_b)
    };
    let original: JoinStatus = response.json().await.unwrap();
    let retried: JoinStatus = f
        .start_join(&root, keys, id, token)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(original, retried);
    assert_eq!(
        f.start_join(
            &root,
            keys,
            id,
            &hex::encode(crypto::random_challenge().unwrap())
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.start_join(&root, &crypto::generate_keypair().unwrap(), id, token)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_join_requests WHERE user_id=$1")
            .bind(&root.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(count, 1);
    assert_eq!(f.db.list_user_devices(&root.id).await.unwrap().len(), 1);
    let row = sqlx::query("SELECT token_hash,payload FROM device_join_requests WHERE id=$1")
        .bind(id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        row.get::<String, _>("token_hash"),
        auth::service::hash_token(token)
    );
    let payload = String::from_utf8(row.get::<Vec<u8>, _>("payload")).unwrap();
    assert!(!payload.contains(token));
    assert!(!payload.contains(&root.password));
    assert!(!payload.contains(&root.token));
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn cancellation_and_grant_serialize_and_late_proofs_cannot_admit() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let join = f.join(&root).await;
    let state = DeviceState::pin(join.status.ticket.anchor.clone()).unwrap();
    let event = f.prove(&root, &join, &state).await;
    let cancel = f
        .client
        .delete(format!(
            "{}/devices/join_requests/{}",
            f.url, join.status.ticket.id
        ))
        .bearer_auth(&join.token)
        .send();
    let (cancel, grant) = tokio::join!(cancel, f.submit(&root, &event));
    let cancel = cancel.unwrap();
    assert_ne!(
        cancel.status() == StatusCode::OK,
        grant.status() == StatusCode::OK
    );
    let page: DeviceManifestPage = f
        .manifest(&root, &root.id, 0, 100)
        .await
        .json()
        .await
        .unwrap();
    if cancel.status() == StatusCode::OK {
        assert!(page.events.is_empty());
        assert!(matches!(
            grant.status(),
            StatusCode::CONFLICT | StatusCode::GONE
        ));
        let retry = f
            .client
            .delete(format!(
                "{}/devices/join_requests/{}",
                f.url, join.status.ticket.id
            ))
            .bearer_auth(&join.token)
            .send()
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        assert_eq!(f.submit(&root, &event).await.status(), StatusCode::CONFLICT);
    } else {
        assert_eq!(page.events, vec![event]);
        assert_eq!(cancel.status(), StatusCode::CONFLICT);
    }
    // Deterministic cancellation also covers a late intent on the original request ID.
    let another_root = f.account().await;
    let pending = f.join(&another_root).await;
    let intent = pending.status.ticket.sign_intent(&pending.keys).unwrap();
    assert_eq!(
        f.client
            .delete(format!("{}/devices/join_requests/{}", f.url, intent.id))
            .bearer_auth(&pending.token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        f.client
            .post(format!(
                "{}/devices/join_requests/{}/intent",
                f.url, intent.id
            ))
            .bearer_auth(&pending.token)
            .json(&intent)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
    );
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn proof_transplants_wrong_actors_and_modified_ticket_are_rejected() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let stranger = f.account().await;
    let join = f.join(&root).await;
    let mut intent = join.status.ticket.sign_intent(&join.keys).unwrap();
    intent.server_challenge[0] ^= 1;
    intent.signature = crypto::sign(&intent.signing_bytes(), &join.keys.ed25519_sk).unwrap();
    assert_eq!(
        f.client
            .post(format!(
                "{}/devices/join_requests/{}/intent",
                f.url, intent.id
            ))
            .bearer_auth(&join.token)
            .json(&intent)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let ready = f.ready(&join).await;
    let intent = ready.intent.unwrap();
    let state = DeviceState::pin(join.status.ticket.anchor.clone()).unwrap();
    let challenge = make_challenge(&state, &intent, now(), &root.keys).unwrap();
    let mut bad = challenge.clone();
    bad.signature[0] ^= 1;
    let response = f
        .client
        .post(format!(
            "{}/devices/join_requests/{}/challenge",
            f.url, intent.id
        ))
        .bearer_auth(&root.token)
        .json(&ChallengeSubmission {
            device_id: root.device.clone(),
            challenge: bad,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let wrong = f
        .client
        .post(format!(
            "{}/devices/join_requests/{}/challenge",
            f.url, intent.id
        ))
        .bearer_auth(&stranger.token)
        .json(&ChallengeSubmission {
            device_id: stranger.device.clone(),
            challenge: challenge.clone(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::CONFLICT);
    assert_eq!(
        f.client
            .post(format!(
                "{}/devices/join_requests/{}/challenge",
                f.url, intent.id
            ))
            .bearer_auth(&root.token)
            .json(&ChallengeSubmission {
                device_id: root.device.clone(),
                challenge: challenge.clone()
            })
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let another_challenge = make_challenge(&state, &intent, now(), &root.keys).unwrap();
    let wrong_proof =
        answer_challenge(&state, &intent, &another_challenge, now(), &join.keys).unwrap();
    assert_eq!(
        f.client
            .post(format!(
                "{}/devices/join_requests/{}/proof",
                f.url, intent.id
            ))
            .bearer_auth(&join.token)
            .json(&wrong_proof)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let good = answer_challenge(&state, &intent, &challenge, now(), &join.keys).unwrap();
    assert_eq!(
        f.client
            .post(format!(
                "{}/devices/join_requests/{}/proof",
                f.url, intent.id
            ))
            .bearer_auth(&join.token)
            .json(&good)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let mut event = make_event(
        &state,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Grant {
            intent: Box::new(intent),
            challenge: Box::new(challenge),
            proof: good,
        },
        now(),
        &root.keys,
    )
    .unwrap();
    event.signature = crypto::sign(&event.signing_bytes(), &stranger.keys.ed25519_sk).unwrap();
    assert_eq!(
        f.submit(&root, &event).await.status(),
        StatusCode::FORBIDDEN
    );
    let page: DeviceManifestPage = f
        .manifest(&root, &root.id, 0, 100)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(page.current_revision, 0);
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn expiry_password_change_and_directory_corruption_fail_closed() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let mut join = f.join(&root).await;
    join.status.ticket.issued_at = now() - JOIN_LIFETIME_MS - 1000;
    join.status.ticket.expires_at = now() - 1000;
    sqlx::query("UPDATE device_join_requests SET expires_at=$2,payload=$3 WHERE id=$1")
        .bind(&join.status.ticket.id)
        .bind(join.status.ticket.expires_at)
        .bind(serde_json::to_vec(&join.status).unwrap())
        .execute(f.db.pool())
        .await
        .unwrap();
    let response = f
        .client
        .get(format!(
            "{}/devices/join_requests/{}",
            f.url, join.status.ticket.id
        ))
        .bearer_auth(&join.token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.json::<JoinStatus>().await.unwrap().phase,
        JoinPhase::Expired
    );
    let intent = join.status.ticket.sign_intent(&join.keys).unwrap();
    assert_eq!(
        f.client
            .post(format!(
                "{}/devices/join_requests/{}/intent",
                f.url, intent.id
            ))
            .bearer_auth(&join.token)
            .json(&intent)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
    );
    let next = f.join(&root).await;
    let ready = f.ready(&next).await;
    let changed = f.client.post(format!("{}/auth/change_password",f.url)).bearer_auth(&root.token)
        .json(&serde_json::json!({"current_password":root.password,"new_password":"fresh-isolated-password"})).send().await.unwrap();
    assert_eq!(changed.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        f.client
            .get(format!(
                "{}/devices/join_requests/{}",
                f.url, ready.ticket.id
            ))
            .bearer_auth(&next.token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.manifest(&root, &root.id, 0, 100).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let other = f.account().await;
    let fresh = f.join(&other).await;
    let initial = DeviceState::pin(fresh.status.ticket.anchor.clone()).unwrap();
    let event = f.prove(&other, &fresh, &initial).await;
    assert_eq!(f.submit(&other, &event).await.status(), StatusCode::OK);
    sqlx::query("DELETE FROM device_authorization_events WHERE user_id=$1")
        .bind(&other.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        f.manifest(&other, &other.id, 0, 100).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        f.submit(&other, &event).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let retained: i64 =
        sqlx::query_scalar("SELECT revision FROM device_authorization_roots WHERE user_id=$1")
            .bind(&other.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(retained, 1);
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn authorization_opt_in_defaults_closed_and_preserves_beta_device_rules() {
    let f = Fixture::start(false).await;
    let root = f.account().await;
    let response = f
        .start_join(
            &root,
            &crypto::generate_keypair().unwrap(),
            &uuid::Uuid::new_v4().to_string(),
            &hex::encode(crypto::random_challenge().unwrap()),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        f.manifest(&root, &root.id, 0, 1).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.client
            .post(format!("{}/devices", f.url))
            .bearer_auth(&root.token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.db.list_user_devices(&root.id).await.unwrap().len(), 1);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_join_requests WHERE user_id=$1")
            .bind(&root.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn rust_control_client_verifies_repeated_join_after_revocation_and_restart() {
    use liteseal_core::trusted_devices::{api::DeviceControlApi, Checkpoint, DeviceTrustStore};
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let api = DeviceControlApi::new(&f.url).unwrap();
    let mut pinned = DeviceState::pin(Anchor {
        origin: f.url.clone(),
        account: root.id.clone(),
        root: DeviceIdentity::from_keys(root.device.clone(), &root.keys),
    })
    .unwrap();
    let path = std::env::temp_dir().join(format!(
        "liteseal-control-client-{}.db",
        uuid::Uuid::new_v4()
    ));
    let mut store = DeviceTrustStore::open(&path).unwrap();
    store.pin(pinned.anchor()).unwrap();
    for turn in 0..2 {
        let keys = crypto::generate_keypair().unwrap();
        let token = hex::encode(crypto::random_challenge().unwrap());
        let input = JoinStartRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            request_token: token.clone(),
            username: root.username.clone(),
            password: root.password.clone(),
            device_name: format!("synthetic Windows {turn}"),
            encryption_key: keys.public_key,
            signing_key: keys.ed25519_pk,
        };
        let ticket = api.begin(&input).await.unwrap();
        assert_eq!(api.begin(&input).await.unwrap(), ticket);
        // This root is compared with the separately known original identity, not accepted from the ticket.
        assert_eq!(ticket.ticket.anchor, *pinned.anchor());
        let own_page = api
            .join_manifest(&token, &ticket.ticket.id, 0)
            .await
            .unwrap();
        let mut second_state = DeviceState::pin(pinned.anchor().clone()).unwrap();
        for event in &own_page.events {
            second_state = second_state.apply(event).unwrap();
        }
        assert_eq!(second_state, pinned);
        let intent = ticket.ticket.sign_intent(&keys).unwrap();
        api.intent(&token, &intent).await.unwrap();
        assert_eq!(api.list(&root.token, &root.device).await.unwrap().len(), 1);
        let challenge = make_challenge(&pinned, &intent, now(), &root.keys).unwrap();
        api.challenge(&root.token, &intent.id, &root.device, &challenge)
            .await
            .unwrap();
        let status = api.status(&token, &intent.id, None).await.unwrap();
        let proof = answer_challenge(
            &second_state,
            &intent,
            status.challenge.as_ref().unwrap(),
            now(),
            &keys,
        )
        .unwrap();
        api.proof(&token, &intent.id, &proof).await.unwrap();
        let event = make_event(
            &pinned,
            uuid::Uuid::new_v4().to_string(),
            DeviceAction::Grant {
                intent: Box::new(intent),
                challenge: Box::new(challenge),
                proof,
            },
            now(),
            &root.keys,
        )
        .unwrap();
        let accepted = api.submit(&root.token, &root.device, &event).await.unwrap();
        assert!(!accepted.messaging_enabled);
        let page = api
            .manifest(&root.token, &root.id, pinned.revision())
            .await
            .unwrap();
        pinned = store
            .import_page(pinned.anchor(), &Checkpoint::from_state(&pinned), &page)
            .unwrap();
        assert_eq!(pinned.secondary().unwrap().encryption_key, keys.public_key);
        let revoke = make_event(
            &pinned,
            uuid::Uuid::new_v4().to_string(),
            DeviceAction::Revoke {
                device_id: ticket.ticket.device.device_id,
                grant_hash: event.hash(),
            },
            now(),
            &root.keys,
        )
        .unwrap();
        api.submit(&root.token, &root.device, &revoke)
            .await
            .unwrap();
        let page = api
            .manifest(&root.token, &root.id, pinned.revision())
            .await
            .unwrap();
        pinned = store
            .import_page(pinned.anchor(), &Checkpoint::from_state(&pinned), &page)
            .unwrap();
        assert!(pinned.secondary().is_none());
        assert_eq!(
            api.submit(&root.token, &root.device, &event)
                .await
                .unwrap()
                .current_revision,
            pinned.revision()
        );
        assert_eq!(
            api.join_manifest(&token, &input.request_id, 0)
                .await
                .unwrap_err()
                .status,
            Some(401)
        );
    }
    drop(store);
    assert_eq!(
        DeviceTrustStore::open(&path)
            .unwrap()
            .load(pinned.anchor(), Some(&Checkpoint::from_state(&pinned)))
            .unwrap(),
        pinned
    );
    let _ = std::fs::remove_file(path);
    let cancelled = f.join(&root).await;
    assert_eq!(
        api.cancel(&cancelled.token, &cancelled.status.ticket.id, None)
            .await
            .unwrap()
            .phase,
        JoinPhase::Cancelled
    );
    assert_eq!(
        api.join_manifest(&cancelled.token, &cancelled.status.ticket.id, 0)
            .await
            .unwrap_err()
            .status,
        Some(410)
    );
    // A token for this request cannot select another account or request.
    let peer = f.account().await;
    let peer_join = f.join(&peer).await;
    assert_eq!(
        api.join_manifest(&cancelled.token, &peer_join.status.ticket.id, 0)
            .await
            .unwrap_err()
            .status,
        Some(401)
    );
}
