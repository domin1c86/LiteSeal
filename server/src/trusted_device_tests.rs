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
    proxy_task: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(task) = &self.proxy_task {
            task.abort();
        }
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
            proxy_task: None,
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
async fn cancellation_after_authorization_confirms_verified_acceptance_on_both_clients() {
    use liteseal_core::{
        backup::WorkDirectory,
        trusted_devices::{api::DeviceControlApi, coordinator::*, tasks::*},
    };
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let keys = crypto::generate_keypair().unwrap();
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let owner = TaskOwner::for_join(
        &f.url,
        &root.username,
        &uuid::Uuid::new_v4().to_string(),
        &keys,
    )
    .unwrap();
    let joining = DeviceCoordinator::open(&work.0.join("joining.db"), owner, &keys).unwrap();
    let task = joining.prepare_join("second", &keys).unwrap();
    joining
        .step(&task.id, Some(&root.password), &keys)
        .await
        .unwrap();
    let anchor = Anchor {
        origin: f.url.clone(),
        account: root.id.clone(),
        root: DeviceIdentity::from_keys(root.device.clone(), &root.keys),
    };
    joining
        .confirm_root(&task.id, &anchor_fingerprint(&anchor), &keys)
        .unwrap();
    joining.step(&task.id, None, &keys).await.unwrap();
    let owner = TaskOwner::for_root(&anchor, &root.keys).unwrap();
    let authority = DeviceCoordinator::open(&work.0.join("root.db"), owner, &root.keys).unwrap();
    authority.renew_session(root.token.clone()).unwrap();
    let inspected = authority.inspect_join(&task.id, &root.keys).await.unwrap();
    let challenge = authority
        .prepare_challenge(&task.id, &inspected.combined_fingerprint, &root.keys)
        .await
        .unwrap()
        .unwrap();
    *lose.lock().unwrap() = Some(format!("/devices/join_requests/{}/challenge", task.id));
    assert_eq!(
        authority
            .step(&challenge.id, None, &root.keys)
            .await
            .unwrap()
            .condition,
        Condition::Retry
    );
    joining.step(&task.id, None, &keys).await.unwrap();
    joining.step(&task.id, None, &keys).await.unwrap();
    let api = DeviceControlApi::new(&f.url).unwrap();
    let ready = api
        .status(&root.token, &task.id, Some(&root.device))
        .await
        .unwrap();
    let state = DeviceState::pin(anchor).unwrap();
    let event = make_event(
        &state,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Grant {
            intent: Box::new(ready.intent.unwrap()),
            challenge: Box::new(ready.challenge.unwrap()),
            proof: ready.proof.unwrap(),
        },
        now(),
        &root.keys,
    )
    .unwrap();
    api.submit(&root.token, &root.device, &event).await.unwrap();
    joining.request_cancel(&task.id, &keys).unwrap();
    authority.request_cancel(&challenge.id, &root.keys).unwrap();
    for (client, id, identity) in [
        (&joining, &task.id, &keys),
        (&authority, &challenge.id, &root.keys),
    ] {
        let progress = client.step(id, None, identity).await.unwrap();
        assert_eq!(progress.condition, Condition::Terminal);
        assert_eq!(progress.task.phase, TaskPhase::Complete);
        assert_eq!(
            client.tasks(identity).unwrap()[0].phase,
            TaskPhase::Complete
        );
    }
    assert_eq!(
        api.manifest(&root.token, &root.id, 0).await.unwrap().events,
        vec![event]
    );
    assert_eq!(f.db.list_user_devices(&root.id).await.unwrap().len(), 1);
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn both_desktop_join_profiles_recover_lost_responses_without_activating_or_replacing_identity(
) {
    use liteseal_core::backup::WorkDirectory;
    use liteseal_desktop::{
        protocol::{dispatch, Command},
        AppState as DesktopState,
    };
    async fn call(
        state: &DesktopState,
        name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        dispatch(
            serde_json::from_value::<Command>(serde_json::json!({"name":name,"args":args}))
                .unwrap(),
            state,
        )
        .await
    }
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let original_dir = work.0.join("original");
    let protection = liteseal_core::trusted_devices::witness::platform::Protection::isolated_test();
    let joining_dir = work.0.join("joining");
    std::fs::create_dir(&original_dir).unwrap();
    std::fs::create_dir(&joining_dir).unwrap();
    let original_path = original_dir.join("normal.bin");
    let original_db = original_dir.join("normal.db");
    let original = DesktopState::with_device_protection(
        original_db.to_str().unwrap(),
        Some(original_path.clone()),
        protection.clone(),
    )
    .unwrap();
    original
        .save_identity(liteseal_core::keystore::KeystoreData {
            user_id: root.id.clone(),
            device_id: root.device.clone(),
            server_url: f.url.clone(),
            token: root.token.clone(),
            refresh_token: "synthetic-unused".into(),
            public_key: root.keys.public_key.to_vec(),
            secret_key: root.keys.secret_key.to_vec(),
            ed25519_pk: root.keys.ed25519_pk.to_vec(),
            ed25519_sk: root.keys.ed25519_sk.to_vec(),
        })
        .unwrap();
    let original_bytes = std::fs::read(&original_path).unwrap();
    let joining_path = joining_dir.join("normal.bin");
    let joining_db = joining_dir.join("normal.db");
    let joining = DesktopState::with_device_protection(
        joining_db.to_str().unwrap(),
        Some(joining_path.clone()),
        protection.clone(),
    )
    .unwrap();
    let created=call(&joining,"create_device_join_profile",serde_json::json!({"origin":f.url,"username":root.username,"deviceName":"new Windows 中文 🦭"})).await.unwrap();
    let id = created["profile"]["id"].as_str().unwrap();
    let request = created["join"]["task"]["id"].as_str().unwrap();
    *lose.lock().unwrap() = Some("/devices/join_requests".into());
    assert_eq!(
        call(
            &joining,
            "device_join_step",
            serde_json::json!({"profileId":id,"password":root.password})
        )
        .await
        .unwrap()["condition"],
        "retry"
    );
    drop(joining);
    let joining = DesktopState::with_device_protection(
        joining_db.to_str().unwrap(),
        Some(joining_path.clone()),
        protection.clone(),
    )
    .unwrap();
    assert_eq!(
        call(
            &joining,
            "get_device_join_profile",
            serde_json::json!({"profileId":id})
        )
        .await
        .unwrap()["join"]["task"]["id"],
        request
    );
    assert_eq!(
        call(
            &joining,
            "device_join_step",
            serde_json::json!({"profileId":id})
        )
        .await
        .unwrap()["condition"],
        "needs_confirmation"
    );
    assert!(call(
        &joining,
        "confirm_device_join_root",
        serde_json::json!({"profileId":id,"confirmedFingerprint":"wrong"})
    )
    .await
    .is_err());
    let original_view = call(&original, "get_device_control", serde_json::json!({}))
        .await
        .unwrap();
    call(&joining,"confirm_device_join_root",serde_json::json!({"profileId":id,"confirmedFingerprint":original_view["root_fingerprint"]})).await.unwrap();
    *lose.lock().unwrap() = Some(format!("/devices/join_requests/{request}/intent"));
    assert_eq!(
        call(
            &joining,
            "device_join_step",
            serde_json::json!({"profileId":id})
        )
        .await
        .unwrap()["condition"],
        "retry"
    );
    call(
        &joining,
        "device_join_step",
        serde_json::json!({"profileId":id}),
    )
    .await
    .unwrap();
    let inspected = call(
        &original,
        "inspect_device_request",
        serde_json::json!({"requestId":request}),
    )
    .await
    .unwrap();
    assert_eq!(
        inspected["encryption_fingerprint"],
        created["profile"]["encryption_fingerprint"]
    );
    assert_eq!(
        inspected["signing_fingerprint"],
        created["profile"]["signing_fingerprint"]
    );
    let confirmed = serde_json::json!({"requestId":request,"confirmedFingerprint":inspected["combined_fingerprint"]});
    let challenge = call(&original, "prepare_device_challenge", confirmed.clone())
        .await
        .unwrap();
    *lose.lock().unwrap() = Some(format!("/devices/join_requests/{request}/challenge"));
    assert_eq!(
        call(
            &original,
            "device_task_step",
            serde_json::json!({"id":challenge["id"]})
        )
        .await
        .unwrap()["condition"],
        "retry"
    );
    call(
        &original,
        "device_task_step",
        serde_json::json!({"id":challenge["id"]}),
    )
    .await
    .unwrap();
    call(
        &joining,
        "device_join_step",
        serde_json::json!({"profileId":id}),
    )
    .await
    .unwrap();
    *lose.lock().unwrap() = Some(format!("/devices/join_requests/{request}/proof"));
    assert_eq!(
        call(
            &joining,
            "device_join_step",
            serde_json::json!({"profileId":id})
        )
        .await
        .unwrap()["condition"],
        "retry"
    );
    call(
        &joining,
        "device_join_step",
        serde_json::json!({"profileId":id}),
    )
    .await
    .unwrap();
    let grant = call(&original, "prepare_device_grant", confirmed)
        .await
        .unwrap();
    *lose.lock().unwrap() = Some("/devices/grants".into());
    assert_eq!(
        call(
            &original,
            "device_task_step",
            serde_json::json!({"id":grant["id"]})
        )
        .await
        .unwrap()["condition"],
        "retry"
    );
    drop(original);
    drop(joining);
    let original = DesktopState::with_device_protection(
        original_db.to_str().unwrap(),
        Some(original_path.clone()),
        protection.clone(),
    )
    .unwrap();
    let joining = DesktopState::with_device_protection(
        joining_db.to_str().unwrap(),
        Some(joining_path.clone()),
        protection.clone(),
    )
    .unwrap();
    call(
        &original,
        "device_task_step",
        serde_json::json!({"id":grant["id"]}),
    )
    .await
    .unwrap();
    call(
        &joining,
        "device_join_step",
        serde_json::json!({"profileId":id}),
    )
    .await
    .unwrap();
    let accepted = call(
        &joining,
        "get_device_join_profile",
        serde_json::json!({"profileId":id}),
    )
    .await
    .unwrap();
    assert_eq!(accepted["join"]["task"]["phase"], "complete");
    assert_eq!(accepted["messaging_enabled"], false);
    assert_eq!(
        accepted["profile"]["encryption_fingerprint"],
        created["profile"]["encryption_fingerprint"]
    );
    for field in [
        "secret_key",
        "ed25519_sk",
        "request_token",
        "password",
        "refresh_token",
    ] {
        assert!(!accepted.to_string().contains(field));
    }
    assert!(joining.identity().is_err());
    assert!(joining.existing_pending_keys().unwrap().is_none());
    assert!(!joining_path.exists());
    assert_eq!(std::fs::read(&original_path).unwrap(), original_bytes);
    assert_eq!(f.db.list_user_devices(&root.id).await.unwrap().len(), 1);
    assert!(call(
        &joining,
        "forget_device_join_profile",
        serde_json::json!({"profileId":id})
    )
    .await
    .is_err());
    let keys = liteseal_core::trusted_devices::profiles::JoinProfileStore::new(
        joining_dir.join("join-profiles"),
    )
    .load(id)
    .unwrap()
    .keys()
    .unwrap();
    let login=f.client.post(format!("{}/auth/login",f.url)).json(&serde_json::json!({"username":root.username,"password":root.password,"device_id":accepted["join"]["device_id"],"device_public_key":keys.public_key,"ed25519_pk":keys.ed25519_pk})).send().await.unwrap();
    assert_eq!(login.status(), StatusCode::FORBIDDEN);
    let another = f.account().await;
    let cancel=call(&joining,"create_device_join_profile",serde_json::json!({"origin":f.url,"username":another.username,"deviceName":"cancelled Windows"})).await.unwrap();
    let cancel_id = cancel["profile"]["id"].as_str().unwrap();
    let cancel_request = cancel["join"]["task"]["id"].as_str().unwrap();
    call(
        &joining,
        "device_join_step",
        serde_json::json!({"profileId":cancel_id,"password":another.password}),
    )
    .await
    .unwrap();
    call(
        &joining,
        "cancel_device_join",
        serde_json::json!({"profileId":cancel_id}),
    )
    .await
    .unwrap();
    *lose.lock().unwrap() = Some(format!("/devices/join_requests/{cancel_request}"));
    assert_eq!(
        call(
            &joining,
            "device_join_step",
            serde_json::json!({"profileId":cancel_id})
        )
        .await
        .unwrap()["condition"],
        "retry"
    );
    call(
        &joining,
        "device_join_step",
        serde_json::json!({"profileId":cancel_id}),
    )
    .await
    .unwrap();
    let cancelled = call(
        &joining,
        "get_device_join_profile",
        serde_json::json!({"profileId":cancel_id}),
    )
    .await
    .unwrap();
    assert_eq!(cancelled["join"]["task"]["phase"], "cancelled");
    assert_eq!(cancelled["join"]["local_abandonment"], false);
    call(
        &joining,
        "forget_device_join_profile",
        serde_json::json!({"profileId":cancel_id}),
    )
    .await
    .unwrap();
    let disabled = Fixture::start(false).await;
    let absent=call(&joining,"create_device_join_profile",serde_json::json!({"origin":disabled.url,"username":"no-account-needed","deviceName":"unsupported"})).await.unwrap();
    let absent_id = absent["profile"]["id"].as_str().unwrap();
    assert_eq!(
        call(
            &joining,
            "device_join_step",
            serde_json::json!({"profileId":absent_id})
        )
        .await
        .unwrap()["condition"],
        "unsupported"
    );
    let abandoned = call(
        &joining,
        "abandon_device_join",
        serde_json::json!({"profileId":absent_id}),
    )
    .await
    .unwrap();
    assert_eq!(abandoned["join"]["local_abandonment"], true);
    call(
        &joining,
        "forget_device_join_profile",
        serde_json::json!({"profileId":absent_id}),
    )
    .await
    .unwrap();
    assert_eq!(
        call(&joining, "list_device_join_profiles", serde_json::json!({}))
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
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

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn signed_event_cancellation_serializes_late_grant_revoke_and_quota() {
    use liteseal_core::trusted_devices::api::DeviceControlApi;
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let api = DeviceControlApi::new(&f.url).unwrap();
    let join = f.join(&root).await;
    let initial = DeviceState::pin(join.status.ticket.anchor.clone()).unwrap();
    let event = f.prove(&root, &join, &initial).await;
    let (cancel, send) = tokio::join!(
        api.cancel_event(&root.token, &root.device, &event),
        api.submit(&root.token, &root.device, &event)
    );
    let cancel = cancel.unwrap();
    if cancel.cancelled {
        assert_eq!(send.unwrap_err().status, Some(410));
        assert_eq!(
            api.submit(&root.token, &root.device, &event)
                .await
                .unwrap_err()
                .status,
            Some(410)
        );
        assert!(
            api.cancel_event(&root.token, &root.device, &event)
                .await
                .unwrap()
                .cancelled
        );
        let mut changed = event.clone();
        changed.created_at -= 1;
        changed.signature = crypto::sign(&changed.signing_bytes(), &root.keys.ed25519_sk).unwrap();
        assert_eq!(
            api.cancel_event(&root.token, &root.device, &changed)
                .await
                .unwrap_err()
                .status,
            Some(409)
        );
        assert_eq!(
            api.submit(&root.token, &root.device, &changed)
                .await
                .unwrap_err()
                .status,
            Some(409)
        );
        // An explicit new authorization uses a different ID; it cannot reuse the cancelled one.
        let DeviceAction::Grant {
            intent,
            challenge,
            proof,
        } = event.action.clone()
        else {
            panic!()
        };
        let replacement = make_event(
            &initial,
            uuid::Uuid::new_v4().to_string(),
            DeviceAction::Grant {
                intent,
                challenge,
                proof,
            },
            now(),
            &root.keys,
        )
        .unwrap();
        api.submit(&root.token, &root.device, &replacement)
            .await
            .unwrap();
    } else {
        send.unwrap();
        assert_eq!(cancel.receipt.unwrap().event_hash, event.hash());
    }
    let page = api.manifest(&root.token, &root.id, 0).await.unwrap();
    let accepted = &page.events[0];
    let joined = initial.apply(accepted).unwrap();
    let revoke = make_event(
        &joined,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Revoke {
            device_id: join.status.ticket.device.device_id,
            grant_hash: accepted.hash(),
        },
        now(),
        &root.keys,
    )
    .unwrap();
    assert!(
        api.cancel_event(&root.token, &root.device, &revoke)
            .await
            .unwrap()
            .cancelled
    );
    assert_eq!(
        api.submit(&root.token, &root.device, &revoke)
            .await
            .unwrap_err()
            .status,
        Some(410)
    );
    let peer = f.account().await;
    assert_eq!(
        api.cancel_event(&peer.token, &root.device, &revoke)
            .await
            .unwrap_err()
            .status,
        Some(403)
    );
    let mut forged = revoke.clone();
    forged.signature[0] ^= 1;
    assert_eq!(
        api.cancel_event(&root.token, &root.device, &forged)
            .await
            .unwrap_err()
            .status,
        Some(403)
    );
    // Quota fixtures contain only cancellation routing digests, no message ciphertext.
    let current:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM device_authorization_events WHERE user_id=$1)+(SELECT COUNT(*) FROM device_event_cancellations WHERE user_id=$1)")
        .bind(&root.id).fetch_one(f.db.pool()).await.unwrap();
    sqlx::query("INSERT INTO device_event_cancellations(user_id,event_id,digest) SELECT $1,'quota-'||n,decode(repeat('01',32),'hex') FROM generate_series(1,$2::integer) n")
        .bind(&root.id).bind((MAX_DEVICE_EVENTS as i64-current) as i32).execute(f.db.pool()).await.unwrap();
    assert!(
        api.cancel_event(&root.token, &root.device, &revoke)
            .await
            .unwrap()
            .cancelled
    );
    assert!(
        !api.cancel_event(&root.token, &root.device, accepted)
            .await
            .unwrap()
            .cancelled
    );
    let extra = make_event(
        &joined,
        uuid::Uuid::new_v4().to_string(),
        revoke.action.clone(),
        now(),
        &root.keys,
    )
    .unwrap();
    assert_eq!(
        api.cancel_event(&root.token, &root.device, &extra)
            .await
            .unwrap_err()
            .status,
        Some(409)
    );
    assert_eq!(
        api.submit(&root.token, &root.device, &extra)
            .await
            .unwrap_err()
            .status,
        Some(409)
    );
}

#[derive(Clone)]
struct LossProxy {
    upstream: String,
    client: reqwest::Client,
    lose: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}
async fn proxy_control_request(
    axum::extract::State(proxy): axum::extract::State<LossProxy>,
    request: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = request.uri().to_string();
    let method = request.method().clone();
    let authorization = request.headers().get("authorization").cloned();
    let body = axum::body::to_bytes(request.into_body(), MAX_DEVICE_EVENT_BYTES)
        .await
        .unwrap();
    let mut outgoing = proxy
        .client
        .request(method.clone(), format!("{}{path}", proxy.upstream))
        .header("content-type", "application/json")
        .body(body);
    if let Some(header) = authorization {
        outgoing = outgoing.header("authorization", header);
    }
    let response = outgoing.send().await.unwrap();
    let status = response.status();
    let bytes = response.bytes().await.unwrap();
    let lose = {
        let mut expected = proxy.lose.lock().unwrap();
        if status.is_success()
            && matches!(method, reqwest::Method::POST | reqwest::Method::DELETE)
            && expected.as_deref() == Some(&path)
        {
            expected.take();
            true
        } else {
            false
        }
    };
    if lose {
        (StatusCode::SERVICE_UNAVAILABLE, "").into_response()
    } else {
        (status, [("content-type", "application/json")], bytes).into_response()
    }
}
impl Fixture {
    async fn start_with_loss() -> (Self, std::sync::Arc<std::sync::Mutex<Option<String>>>) {
        let database = std::env::var("LITESEAL_TEST_DATABASE_URL").unwrap();
        let db = Db::connect(&database).await.unwrap();
        let front = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", front.local_addr().unwrap());
        let upstream = format!("http://{}", back.local_addr().unwrap());
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .unwrap();
        let mut state = AppState::new(db.clone());
        state.device_authorization_origin = Some(url.clone());
        let app = build_router(state, HeaderValue::from_static("http://localhost:1420"));
        let task = tokio::spawn(async move {
            axum::serve(
                back,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let lose = std::sync::Arc::new(std::sync::Mutex::new(None));
        let proxy = axum::Router::new()
            .fallback(proxy_control_request)
            .with_state(LossProxy {
                upstream,
                client: client.clone(),
                lose: lose.clone(),
            });
        let proxy_task = tokio::spawn(async move {
            axum::serve(front, proxy.into_make_service()).await.unwrap();
        });
        (
            Self {
                db,
                url,
                client,
                task,
                proxy_task: Some(proxy_task),
            },
            lose,
        )
    }
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn encrypted_control_jobs_reopen_after_lost_acceptance_and_ignore_locked_callbacks() {
    use liteseal_core::trusted_devices::{api::DeviceControlApi, tasks::*, Checkpoint};
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let keys = crypto::generate_keypair().unwrap();
    let path =
        std::env::temp_dir().join(format!("liteseal-control-jobs-{}.db", uuid::Uuid::new_v4()));
    let root_path =
        std::env::temp_dir().join(format!("liteseal-root-jobs-{}.db", uuid::Uuid::new_v4()));
    let local_device = uuid::Uuid::new_v4().to_string();
    let owner = TaskOwner::for_join(&f.url, &root.username, &local_device, &keys).unwrap();
    let api = DeviceControlApi::new(&f.url).unwrap();
    let mut joining = DeviceTaskStore::open(&path, owner.clone(), &keys).unwrap();
    let draft = joining.prepare_join("new Windows", &keys).unwrap();
    let id = draft.view().id;
    let credential = draft.join_credential().unwrap().to_string();
    *lose.lock().unwrap() = Some("/devices/join_requests".into());
    assert_eq!(
        api.begin(&draft.start_request(&root.password).unwrap())
            .await
            .unwrap_err()
            .status,
        Some(503)
    );
    drop(joining);
    let mut joining = DeviceTaskStore::open(&path, owner.clone(), &keys).unwrap();
    let draft = joining.get(&id, &keys).unwrap();
    assert_eq!(draft.join_credential().unwrap(), credential);
    let ticket = api.status(&credential, &id, None).await.unwrap();
    let draft = joining.accept_ticket(&draft, &ticket, &keys).unwrap();
    let anchor = Anchor {
        origin: f.url.clone(),
        account: root.id.clone(),
        root: DeviceIdentity::from_keys(root.device.clone(), &root.keys),
    };
    let job = joining
        .confirm_root(&draft, &anchor, &anchor_fingerprint(&anchor), &keys)
        .unwrap();
    let intent = job.intent().unwrap().clone();
    *lose.lock().unwrap() = Some(format!("/devices/join_requests/{id}/intent"));
    assert_eq!(
        api.intent(&credential, &intent).await.unwrap_err().status,
        Some(503)
    );
    drop(joining);
    let mut joining = DeviceTaskStore::open(&path, owner, &keys).unwrap();
    let job = joining.get(&id, &keys).unwrap();
    assert_eq!(job.intent().unwrap(), &intent);
    let remote = api.status(&credential, &id, None).await.unwrap();
    assert_eq!(remote.intent.as_ref(), Some(&intent));
    let root_owner = TaskOwner::for_root(&anchor, &root.keys).unwrap();
    let mut authority = DeviceTaskStore::open(&root_path, root_owner.clone(), &root.keys).unwrap();
    let initial = authority.trust().pin(&anchor).unwrap();
    let challenge = authority
        .prepare_challenge(&initial, &intent, now(), &root.keys)
        .unwrap();
    let challenge_id = challenge.view().id;
    let signed_challenge = challenge.challenge().unwrap().clone();
    *lose.lock().unwrap() = Some(format!("/devices/join_requests/{id}/challenge"));
    assert_eq!(
        api.challenge(&root.token, &id, &root.device, &signed_challenge)
            .await
            .unwrap_err()
            .status,
        Some(503)
    );
    drop(authority);
    let mut authority = DeviceTaskStore::open(&root_path, root_owner.clone(), &root.keys).unwrap();
    let challenge = authority.get(&challenge_id, &root.keys).unwrap();
    assert_eq!(challenge.challenge().unwrap(), &signed_challenge);
    let remote = api
        .status(&root.token, &id, Some(&root.device))
        .await
        .unwrap();
    authority
        .confirm_challenge(&challenge, &remote, &root.keys)
        .unwrap();
    let proof_job = joining
        .seal_proof(&job, &initial, &signed_challenge, now(), &keys)
        .unwrap();
    let proof = proof_job.proof().unwrap().clone();
    *lose.lock().unwrap() = Some(format!("/devices/join_requests/{id}/proof"));
    assert_eq!(
        api.proof(&credential, &id, &proof)
            .await
            .unwrap_err()
            .status,
        Some(503)
    );
    let remote = api
        .status(&root.token, &id, Some(&root.device))
        .await
        .unwrap();
    assert_eq!(remote.proof.as_ref(), Some(&proof));
    let grant = authority
        .prepare_grant(&initial, &remote, now(), &root.keys)
        .unwrap();
    let grant_id = grant.view().id;
    let event = grant.event().unwrap().clone();
    *lose.lock().unwrap() = Some("/devices/grants".into());
    assert_eq!(
        api.submit(&root.token, &root.device, &event)
            .await
            .unwrap_err()
            .status,
        Some(503)
    );
    drop(authority);
    let mut authority = DeviceTaskStore::open(&root_path, root_owner, &root.keys).unwrap();
    let grant = authority.get(&grant_id, &root.keys).unwrap();
    assert_eq!(grant.event().unwrap(), &event);
    let gate = TaskGate::new().unwrap();
    let lease = gate.lease().unwrap();
    let page = api.manifest(&root.token, &root.id, 0).await.unwrap();
    gate.invalidate().unwrap();
    assert!(gate
        .with_current(&lease, || authority.trust().import_page(
            &anchor,
            &Checkpoint::from_state(&initial),
            &page
        ))
        .is_err());
    assert_eq!(
        authority.get(&grant_id, &root.keys).unwrap().view().phase,
        TaskPhase::Prepared
    );
    gate.unlock().unwrap();
    let lease = gate.lease().unwrap();
    let joined = gate
        .with_current(&lease, || {
            authority
                .trust()
                .import_page(&anchor, &Checkpoint::from_state(&initial), &page)
        })
        .unwrap();
    authority
        .confirm_event_accepted(&grant, &root.keys)
        .unwrap(); // Only the verified page confirms success.
    let join_job = joining.get(&id, &keys).unwrap();
    let own_page = api.join_manifest(&credential, &id, 0).await.unwrap();
    joining
        .trust()
        .import_page(&anchor, &Checkpoint::from_state(&initial), &own_page)
        .unwrap();
    let complete = joining
        .confirm_join_authorized(&join_job, &event.id, &keys)
        .unwrap();
    assert_eq!(complete.view().phase, TaskPhase::Complete);
    assert!(complete.join_credential().is_err());
    let revoke = authority
        .prepare_revoke(&joined, now(), &root.keys)
        .unwrap();
    let event = revoke.event().unwrap().clone();
    let cancellation = authority.request_cancel(&revoke, &root.keys).unwrap();
    let result = api
        .cancel_event(&root.token, &root.device, &event)
        .await
        .unwrap();
    authority
        .confirm_event_cancel(&cancellation, &result, &root.keys)
        .unwrap();
    assert_eq!(
        api.submit(&root.token, &root.device, &event)
            .await
            .unwrap_err()
            .status,
        Some(410)
    );
    drop(authority);
    drop(joining);
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(root_path);
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn coordinator_drives_join_retry_verified_acceptance_and_cancel_without_resigning() {
    use liteseal_core::trusted_devices::{api::DeviceControlApi, coordinator::*, tasks::*};
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let keys = crypto::generate_keypair().unwrap();
    let path = std::env::temp_dir().join(format!(
        "liteseal-coordinator-join-{}.db",
        uuid::Uuid::new_v4()
    ));
    let root_path = std::env::temp_dir().join(format!(
        "liteseal-coordinator-root-{}.db",
        uuid::Uuid::new_v4()
    ));
    let owner = TaskOwner::for_join(
        &f.url,
        &root.username,
        &uuid::Uuid::new_v4().to_string(),
        &keys,
    )
    .unwrap();
    let joining = DeviceCoordinator::open(&path, owner.clone(), &keys).unwrap();
    let job = joining.prepare_join("new Windows", &keys).unwrap();
    assert_eq!(
        joining.step(&job.id, None, &keys).await.unwrap().condition,
        Condition::NeedsPassword
    );
    *lose.lock().unwrap() = Some("/devices/join_requests".into());
    assert_eq!(
        joining
            .step(&job.id, Some(&root.password), &keys)
            .await
            .unwrap()
            .condition,
        Condition::Retry
    );
    drop(joining);
    let joining = DeviceCoordinator::open(&path, owner, &keys).unwrap();
    assert_eq!(
        joining.step(&job.id, None, &keys).await.unwrap().condition,
        Condition::NeedsConfirmation
    );
    let anchor = Anchor {
        origin: f.url.clone(),
        account: root.id.clone(),
        root: DeviceIdentity::from_keys(root.device.clone(), &root.keys),
    };
    assert!(joining
        .confirm_root(&job.id, "bad-fingerprint", &keys)
        .is_err());
    joining
        .confirm_root(&job.id, &anchor_fingerprint(&anchor), &keys)
        .unwrap();
    *lose.lock().unwrap() = Some(format!("/devices/join_requests/{}/intent", job.id));
    assert_eq!(
        joining.step(&job.id, None, &keys).await.unwrap().condition,
        Condition::Retry
    );
    assert_eq!(
        joining.step(&job.id, None, &keys).await.unwrap().condition,
        Condition::Waiting
    );
    let root_owner = TaskOwner::for_root(&anchor, &root.keys).unwrap();
    let authority = DeviceCoordinator::open(&root_path, root_owner.clone(), &root.keys).unwrap();
    authority.renew_session(root.token.clone()).unwrap();
    let inspection = authority.inspect_join(&job.id, &root.keys).await.unwrap();
    assert!(authority
        .prepare_challenge(&job.id, "bad-fingerprint", &root.keys)
        .await
        .is_err());
    let challenge = authority
        .prepare_challenge(&job.id, &inspection.combined_fingerprint, &root.keys)
        .await
        .unwrap()
        .unwrap();
    *lose.lock().unwrap() = Some(format!("/devices/join_requests/{}/challenge", job.id));
    assert_eq!(
        authority
            .step(&challenge.id, None, &root.keys)
            .await
            .unwrap()
            .condition,
        Condition::Retry
    );
    drop(authority);
    let authority = DeviceCoordinator::open(&root_path, root_owner, &root.keys).unwrap();
    authority.renew_session(root.token.clone()).unwrap();
    assert_eq!(
        authority
            .step(&challenge.id, None, &root.keys)
            .await
            .unwrap()
            .condition,
        Condition::Terminal
    );
    assert_eq!(
        joining.step(&job.id, None, &keys).await.unwrap().condition,
        Condition::Advanced
    ); // Seal proof before sending it.
    *lose.lock().unwrap() = Some(format!("/devices/join_requests/{}/proof", job.id));
    assert_eq!(
        joining.step(&job.id, None, &keys).await.unwrap().condition,
        Condition::Retry
    );
    assert_eq!(
        joining.step(&job.id, None, &keys).await.unwrap().condition,
        Condition::Waiting
    );
    let grant = authority
        .prepare_grant(&job.id, &inspection.combined_fingerprint, &root.keys)
        .await
        .unwrap()
        .unwrap();
    *lose.lock().unwrap() = Some("/devices/grants".into());
    assert_eq!(
        authority
            .step(&grant.id, None, &root.keys)
            .await
            .unwrap()
            .condition,
        Condition::Retry
    );
    assert_eq!(
        authority
            .step(&grant.id, None, &root.keys)
            .await
            .unwrap()
            .task
            .phase,
        TaskPhase::Complete
    );
    assert_eq!(
        joining.step(&job.id, None, &keys).await.unwrap().task.phase,
        TaskPhase::Complete
    );
    let revoke = authority.prepare_revoke(&root.keys).await.unwrap().unwrap();
    authority.request_cancel(&revoke.id, &root.keys).unwrap();
    *lose.lock().unwrap() = Some("/devices/events/cancel".into());
    assert_eq!(
        authority
            .step(&revoke.id, None, &root.keys)
            .await
            .unwrap()
            .condition,
        Condition::Retry
    );
    assert_eq!(
        authority
            .step(&revoke.id, None, &root.keys)
            .await
            .unwrap()
            .task
            .phase,
        TaskPhase::Cancelled
    );
    let pending = authority.prepare_revoke(&root.keys).await.unwrap().unwrap();
    let api = DeviceControlApi::new(&f.url).unwrap();
    // A later accepted operation makes this original queued version conflict; the coordinator does not re-sign it.
    let page = api.manifest(&root.token, &root.id, 0).await.unwrap();
    let mut state = DeviceState::pin(anchor.clone()).unwrap();
    for event in &page.events {
        state = state.apply(event).unwrap();
    }
    let other = make_event(
        &state,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Revoke {
            device_id: state.secondary().unwrap().device_id.clone(),
            grant_hash: state.grant_hash().unwrap().to_vec(),
        },
        now(),
        &root.keys,
    )
    .unwrap();
    api.submit(&root.token, &root.device, &other).await.unwrap();
    assert_eq!(
        authority
            .step(&pending.id, None, &root.keys)
            .await
            .unwrap()
            .condition,
        Condition::Conflict
    );
    assert_eq!(
        authority
            .tasks(&root.keys)
            .unwrap()
            .iter()
            .find(|v| v.id == pending.id)
            .unwrap()
            .phase,
        TaskPhase::Conflict
    );
    assert_eq!(f.db.list_user_devices(&root.id).await.unwrap().len(), 1);
    drop(authority);
    drop(joining);
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(root_path);
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn desktop_original_device_commands_confirm_grant_retry_revoke_and_disabled_server() {
    use liteseal_core::{
        backup::WorkDirectory, keystore::KeystoreData, trusted_devices::api::DeviceControlApi,
    };
    use liteseal_desktop::{
        protocol::{dispatch, Command},
        AppState as DesktopState,
    };
    async fn call(
        state: &DesktopState,
        name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let command: Command =
            serde_json::from_value(serde_json::json!({"name":name,"args":args})).unwrap();
        dispatch(command, state).await
    }
    fn saved(root: &Account, url: &str) -> KeystoreData {
        KeystoreData {
            user_id: root.id.clone(),
            device_id: root.device.clone(),
            server_url: url.into(),
            token: root.token.clone(),
            refresh_token: "synthetic-unused".into(),
            public_key: root.keys.public_key.to_vec(),
            secret_key: root.keys.secret_key.to_vec(),
            ed25519_pk: root.keys.ed25519_pk.to_vec(),
            ed25519_sk: root.keys.ed25519_sk.to_vec(),
        }
    }
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let join = f.join(&root).await;
    f.ready(&join).await;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let db = work.0.join("original.db");
    let protection = liteseal_core::trusted_devices::witness::platform::Protection::isolated_test();
    let keyfile = work.0.join("original.bin");
    let state = DesktopState::with_device_protection(
        db.to_str().unwrap(),
        Some(keyfile.clone()),
        protection.clone(),
    )
    .unwrap();
    state.save_identity(saved(&root, &f.url)).unwrap();
    let snapshot = call(&state, "get_device_control", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(snapshot["supported"], true);
    assert_eq!(snapshot["messaging_enabled"], false);
    assert_eq!(snapshot["requests"][0]["request_id"], join.status.ticket.id);
    let serialized = snapshot.to_string();
    for field in ["token", "secret_key", "ed25519_sk", "request_token"] {
        assert!(!serialized.contains(field));
    }
    let inspection = call(
        &state,
        "inspect_device_request",
        serde_json::json!({"requestId":join.status.ticket.id}),
    )
    .await
    .unwrap();
    let fingerprint = inspection["combined_fingerprint"].as_str().unwrap();
    assert!(call(
        &state,
        "prepare_device_challenge",
        serde_json::json!({"requestId":join.status.ticket.id,"confirmedFingerprint":"wrong"})
    )
    .await
    .is_err());
    let challenge = call(
        &state,
        "prepare_device_challenge",
        serde_json::json!({"requestId":join.status.ticket.id,"confirmedFingerprint":fingerprint}),
    )
    .await
    .unwrap();
    assert_eq!(
        call(
            &state,
            "device_task_step",
            serde_json::json!({"id":challenge["id"]})
        )
        .await
        .unwrap()["task"]["phase"],
        "complete"
    );
    let api = DeviceControlApi::new(&f.url).unwrap();
    let remote = api
        .status(&join.token, &join.status.ticket.id, None)
        .await
        .unwrap();
    let initial = DeviceState::pin(join.status.ticket.anchor.clone()).unwrap();
    let proof = answer_challenge(
        &initial,
        remote.intent.as_ref().unwrap(),
        remote.challenge.as_ref().unwrap(),
        now(),
        &join.keys,
    )
    .unwrap();
    api.proof(&join.token, &join.status.ticket.id, &proof)
        .await
        .unwrap();
    let grant = call(
        &state,
        "prepare_device_grant",
        serde_json::json!({"requestId":join.status.ticket.id,"confirmedFingerprint":fingerprint}),
    )
    .await
    .unwrap();
    *lose.lock().unwrap() = Some("/devices/grants".into());
    assert_eq!(
        call(
            &state,
            "device_task_step",
            serde_json::json!({"id":grant["id"]})
        )
        .await
        .unwrap()["condition"],
        "retry"
    );
    drop(state);
    let state =
        DesktopState::with_device_protection(db.to_str().unwrap(), Some(keyfile), protection)
            .unwrap();
    assert_eq!(
        call(
            &state,
            "device_task_step",
            serde_json::json!({"id":grant["id"]})
        )
        .await
        .unwrap()["task"]["phase"],
        "complete"
    );
    let snapshot = call(&state, "get_device_control", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(
        snapshot["authorized"]["device_id"],
        join.status.ticket.device.device_id
    );
    assert_eq!(snapshot["authorized"]["combined_fingerprint"], fingerprint);
    assert!(call(
        &state,
        "prepare_device_revoke",
        serde_json::json!({"confirmedFingerprint":"wrong-target"})
    )
    .await
    .is_err());
    let args = serde_json::json!({"confirmedFingerprint":fingerprint});
    let revoke = call(&state, "prepare_device_revoke", args.clone())
        .await
        .unwrap();
    call(
        &state,
        "cancel_device_task",
        serde_json::json!({"id":revoke["id"]}),
    )
    .await
    .unwrap();
    assert_eq!(
        call(
            &state,
            "device_task_step",
            serde_json::json!({"id":revoke["id"]})
        )
        .await
        .unwrap()["task"]["phase"],
        "cancelled"
    );
    call(
        &state,
        "discard_device_task",
        serde_json::json!({"id":revoke["id"]}),
    )
    .await
    .unwrap();
    let revoke = call(&state, "prepare_device_revoke", args).await.unwrap();
    call(
        &state,
        "device_task_step",
        serde_json::json!({"id":revoke["id"]}),
    )
    .await
    .unwrap();
    assert!(call(&state, "get_device_control", serde_json::json!({}))
        .await
        .unwrap()["authorized"]
        .is_null());
    assert_eq!(f.db.list_user_devices(&root.id).await.unwrap().len(), 1);
    let disabled = Fixture::start(false).await;
    let another = disabled.account().await;
    state.save_identity(saved(&another, &disabled.url)).unwrap();
    let snapshot = call(&state, "get_device_control", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(snapshot["supported"], false);
    assert_eq!(snapshot["tasks"], serde_json::json!([]));
    assert!(snapshot["authorized"].is_null());
}
