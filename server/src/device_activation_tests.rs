use super::direct_message_tests::enable_mode;
use super::*;
use liteseal_shared::device_activation::{
    ActivationCancel, ActivationCancelResult, Challenge as SessionChallenge, Enable, EnableCancel,
    EnableCancelResult, Envelope, Proof, Start,
};
async fn state(f: &Fixture, root: &Account) -> DeviceState {
    let page = f
        .manifest(root, &root.id, 0, 100)
        .await
        .json::<DeviceManifestPage>()
        .await
        .unwrap();
    let mut state = DeviceState::pin(page.anchor).unwrap();
    for event in page.events {
        state = state.apply(&event).unwrap();
    }
    state
}
async fn attempt(f: &Fixture, root: &Account, device: &str) -> (Start, DeviceState, Enable) {
    let mode = enable_mode(f, root).await;
    let state = state(f, root).await;
    let authority = liteseal_shared::direct_message::Directory::from_state(&state)
        .members
        .into_iter()
        .find(|m| m.device.device_id == device)
        .unwrap()
        .authorization_hash;
    (
        Start {
            id: uuid::Uuid::new_v4().to_string(),
            request_token: hex::encode(crypto::random_challenge().unwrap()),
            username: root.username.clone(),
            password: root.password.clone(),
            device: device.into(),
            authorization: authority,
        },
        state,
        mode,
    )
}
async fn begin(f: &Fixture, input: &Start) -> reqwest::Response {
    f.client
        .post(format!("{}/auth/v3/begin", f.url))
        .json(input)
        .send()
        .await
        .unwrap()
}
async fn prove(f: &Fixture, input: &Start, proof: &Proof) -> reqwest::Response {
    f.client
        .post(format!("{}/auth/v3/{}/proof", f.url, input.id))
        .bearer_auth(&input.request_token)
        .json(proof)
        .send()
        .await
        .unwrap()
}
async fn authorized(f: &Fixture, root: &Account) -> (Join, DeviceState) {
    let old = state(f, root).await;
    let join = f.join(root).await;
    let event = f.prove(root, &join, &old).await;
    assert_eq!(f.submit(root, &event).await.status(), StatusCode::OK);
    (join, old.apply(&event).unwrap())
}
async fn cancel(f: &Fixture, input: &Start, packet: &ActivationCancel) -> reqwest::Response {
    f.client
        .post(format!("{}/auth/v3/cancel", f.url))
        .bearer_auth(&input.request_token)
        .json(packet)
        .send()
        .await
        .unwrap()
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn enable_cancel_lost_response_fences_late_submit_and_accepted_is_irreversible() {
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let current = state(&f, &root).await;
    let mode = Enable::make(&current, &uuid::Uuid::new_v4().to_string(), &root.keys).unwrap();
    let packet = EnableCancel::make(mode.clone(), current.anchor(), &root.keys).unwrap();
    let api = liteseal_core::trusted_devices::activation::ActivationApi::new(&f.url).unwrap();
    *lose.lock().unwrap() = Some("/devices/messaging/cancel".into());
    assert_eq!(
        api.cancel_enable(&root.token, &packet, current.anchor())
            .await
            .unwrap_err()
            .status,
        Some(503)
    );
    assert_eq!(
        api.cancel_enable(&root.token, &packet, current.anchor())
            .await
            .unwrap(),
        EnableCancelResult::Cancelled {
            event: mode.digest().unwrap()
        }
    );
    assert_eq!(
        api.enable(&root.token, &mode, current.anchor())
            .await
            .unwrap_err()
            .status,
        Some(410)
    );
    assert!(api
        .status(&root.token, current.anchor())
        .await
        .unwrap()
        .is_none());
    let original_cancel = packet;
    let mode = Enable::make(&current, &uuid::Uuid::new_v4().to_string(), &root.keys).unwrap();
    assert_eq!(
        api.enable(&root.token, &mode, current.anchor())
            .await
            .unwrap(),
        mode
    );
    let packet = EnableCancel::make(mode.clone(), current.anchor(), &root.keys).unwrap();
    assert_eq!(
        api.cancel_enable(&root.token, &packet, current.anchor())
            .await
            .unwrap(),
        EnableCancelResult::Accepted {
            event: mode.clone()
        }
    );
    assert_eq!(
        api.status(&root.token, current.anchor()).await.unwrap(),
        Some(mode)
    );
    assert!(
        matches!(api.cancel_enable(&root.token, &original_cancel, current.anchor()).await.unwrap(),
        EnableCancelResult::Cancelled { event } if event == original_cancel.event.digest().unwrap())
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn activation_cancel_before_begin_survives_lost_response_and_fences_late_password_request() {
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let (join, _) = authorized(&f, &root).await;
    let (input, state, mode) = attempt(&f, &root, &join.status.ticket.device.device_id).await;
    let packet = ActivationCancel::make(
        &state,
        &mode,
        &input.id,
        &input.request_token,
        &input.device,
        &join.keys,
    )
    .unwrap();
    let api = liteseal_core::trusted_devices::activation::ActivationApi::new(&f.url).unwrap();
    *lose.lock().unwrap() = Some("/auth/v3/cancel".into());
    assert_eq!(
        api.cancel(&input.request_token, &packet, &state, &mode, &join.keys)
            .await
            .unwrap_err()
            .status,
        Some(503)
    );
    assert_eq!(
        api.cancel(&input.request_token, &packet, &state, &mode, &join.keys)
            .await
            .unwrap(),
        ActivationCancelResult::Cancelled {
            cancellation: packet.digest().unwrap()
        }
    );
    assert_eq!(begin(&f, &input).await.status(), StatusCode::GONE);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_session_attempts WHERE id=$1")
        .bind(&input.id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn activation_cancel_and_proof_race_preserves_one_terminal_result_and_original_ciphertext() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let (join, _) = authorized(&f, &root).await;
    // Two short races use independent IDs; no long load test is implied.
    for _ in 0..2 {
        let (input, state, mode) = attempt(&f, &root, &join.status.ticket.device.device_id).await;
        let challenge: SessionChallenge = begin(&f, &input).await.json().await.unwrap();
        let proof = challenge.answer(&state, &mode, now(), &join.keys).unwrap();
        let packet = ActivationCancel::make(
            &state,
            &mode,
            &input.id,
            &input.request_token,
            &input.device,
            &join.keys,
        )
        .unwrap();
        let (sent, cancelled) =
            tokio::join!(prove(&f, &input, &proof), cancel(&f, &input, &packet));
        assert_eq!(cancelled.status(), StatusCode::OK);
        let result: ActivationCancelResult = cancelled.json().await.unwrap();
        match result {
            ActivationCancelResult::Cancelled { cancellation } => {
                assert_eq!(cancellation, packet.digest().unwrap());
                assert_eq!(sent.status(), StatusCode::GONE);
                assert_eq!(prove(&f, &input, &proof).await.status(), StatusCode::GONE);
                assert_eq!(begin(&f, &input).await.status(), StatusCode::GONE);
                assert_eq!(
                    f.client
                        .get(format!("{}/auth/v3/{}", f.url, input.id))
                        .bearer_auth(&input.request_token)
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    StatusCode::GONE
                );
            }
            ActivationCancelResult::Accepted {
                challenge: accepted,
                envelope,
            } => {
                assert_eq!(*accepted, challenge);
                assert_eq!(sent.status(), StatusCode::OK);
                assert_eq!(sent.json::<Envelope>().await.unwrap(), envelope);
                let api =
                    liteseal_core::trusted_devices::activation::ActivationApi::new(&f.url).unwrap();
                assert_eq!(
                    api.prove_envelope(&input.request_token, &challenge, &proof, &join.keys)
                        .await
                        .unwrap(),
                    envelope
                );
                assert!(
                    matches!(api.cancel(&input.request_token, &packet, &state, &mode, &join.keys).await.unwrap(),
                    ActivationCancelResult::Accepted { envelope: original, .. } if original == envelope)
                );
            }
        }
        let issued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE id=(SELECT session_id FROM device_session_attempts WHERE id=$1)")
            .bind(&input.id).fetch_one(f.db.pool()).await.unwrap();
        assert_eq!(issued, i64::from(sent_status_accepted(&f, &input).await));
    }
}
async fn sent_status_accepted(f: &Fixture, input: &Start) -> bool {
    sqlx::query_scalar("SELECT proof_hash IS NOT NULL FROM device_session_attempts WHERE id=$1")
        .bind(&input.id)
        .fetch_one(f.db.pool())
        .await
        .unwrap()
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn accepted_activation_cancel_after_lost_proof_returns_original_envelope_even_after_expiry() {
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let (join, _) = authorized(&f, &root).await;
    let (input, state, mode) = attempt(&f, &root, &join.status.ticket.device.device_id).await;
    let challenge: SessionChallenge = begin(&f, &input).await.json().await.unwrap();
    let proof = challenge.answer(&state, &mode, now(), &join.keys).unwrap();
    *lose.lock().unwrap() = Some(format!("/auth/v3/{}/proof", input.id));
    assert_eq!(
        prove(&f, &input, &proof).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let original: Envelope = prove(&f, &input, &proof).await.json().await.unwrap();
    sqlx::query("UPDATE device_session_attempts SET expires_at=$2 WHERE id=$1")
        .bind(&input.id)
        .bind(now() - 1)
        .execute(f.db.pool())
        .await
        .unwrap();
    let packet = ActivationCancel::make(
        &state,
        &mode,
        &input.id,
        &input.request_token,
        &input.device,
        &join.keys,
    )
    .unwrap();
    let api = liteseal_core::trusted_devices::activation::ActivationApi::new(&f.url).unwrap();
    let accepted = api
        .cancel(&input.request_token, &packet, &state, &mode, &join.keys)
        .await
        .unwrap();
    assert_eq!(
        accepted,
        ActivationCancelResult::Accepted {
            challenge: Box::new(challenge.clone()),
            envelope: original.clone()
        }
    );
    assert_eq!(
        api.prove_envelope(&input.request_token, &challenge, &proof, &join.keys)
            .await
            .unwrap(),
        original
    );
    let session = original.open(&challenge, &join.keys).unwrap();
    assert!(f
        .db
        .validate_access_token(
            &auth::service::hash_token(&session.access_token),
            &session.device
        )
        .await
        .unwrap()
        .is_some());
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_session_cancellations WHERE id=$1")
            .bind(&input.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn cancellation_quota_is_bounded_and_retry_remains_available_at_limit() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let (input, state, mode) = attempt(&f, &root, &root.device).await;
    let packet = ActivationCancel::make(
        &state,
        &mode,
        &input.id,
        &input.request_token,
        &root.device,
        &root.keys,
    )
    .unwrap();
    assert_eq!(cancel(&f, &input, &packet).await.status(), StatusCode::OK);
    // Synthetic SQL rows exercise the hard storage limit without 4095 HTTP requests.
    sqlx::query("INSERT INTO device_session_cancellations(id,user_id,device_id,token_hash,digest) SELECT $1 || ':' || n::TEXT,$1,$2,'synthetic',decode(repeat('11',32),'hex') FROM generate_series(1,4095) n")
        .bind(&root.id).bind(&root.device).execute(f.db.pool()).await.unwrap();
    assert_eq!(cancel(&f, &input, &packet).await.status(), StatusCode::OK);
    let mut next: Start = serde_json::from_slice(&serde_json::to_vec(&input).unwrap()).unwrap();
    next.id = uuid::Uuid::new_v4().to_string();
    let packet = ActivationCancel::make(
        &state,
        &mode,
        &next.id,
        &next.request_token,
        &root.device,
        &root.keys,
    )
    .unwrap();
    assert_eq!(
        cancel(&f, &next, &packet).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let other = f.account().await;
    let current = self::state(&f, &other).await;
    sqlx::query("INSERT INTO device_mode_cancellations(id,user_id,digest) SELECT $1 || ':' || n::TEXT,$1,decode(repeat('11',32),'hex') FROM generate_series(1,4096) n")
        .bind(&other.id).execute(f.db.pool()).await.unwrap();
    let event = Enable::make(&current, &uuid::Uuid::new_v4().to_string(), &other.keys).unwrap();
    let packet = EnableCancel::make(event, current.anchor(), &other.keys).unwrap();
    let api = liteseal_core::trusted_devices::activation::ActivationApi::new(&f.url).unwrap();
    assert_eq!(
        api.cancel_enable(&other.token, &packet, current.anchor())
            .await
            .unwrap_err()
            .status,
        Some(429)
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn cancellation_rejects_wrong_signature_token_account_mode_and_duplicate_scope() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let (join, _) = authorized(&f, &root).await;
    let (input, state, mode) = attempt(&f, &root, &join.status.ticket.device.device_id).await;
    let challenge: SessionChallenge = begin(&f, &input).await.json().await.unwrap();
    let proof = challenge.answer(&state, &mode, now(), &join.keys).unwrap();
    let packet = ActivationCancel::make(
        &state,
        &mode,
        &input.id,
        &input.request_token,
        &input.device,
        &join.keys,
    )
    .unwrap();
    for field in ["signature", "token_hash", "mode", "account"] {
        let mut altered = packet.clone();
        match field {
            "signature" => altered.signature[0] ^= 1,
            "token_hash" => altered.token_hash[0] ^= 1,
            "mode" => altered.mode[0] ^= 1,
            _ => altered.account = uuid::Uuid::new_v4().to_string(),
        }
        assert!(!cancel(&f, &input, &altered).await.status().is_success());
    }
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_session_cancellations WHERE id=$1")
            .bind(&input.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(count, 0);
    assert_eq!(cancel(&f, &input, &packet).await.status(), StatusCode::OK);
    assert_eq!(prove(&f, &input, &proof).await.status(), StatusCode::GONE);
    assert!(!sent_status_accepted(&f, &input).await);
    let different = ActivationCancel::make(
        &state,
        &mode,
        &input.id,
        &input.request_token,
        &root.device,
        &root.keys,
    )
    .unwrap();
    assert_eq!(
        cancel(&f, &input, &different).await.status(),
        StatusCode::CONFLICT
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn explicit_root_mode_waits_for_old_queue_and_blocks_late_legacy_admission() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    let current = state(&f, &a).await;
    let event = Enable::make(&current, &uuid::Uuid::new_v4().to_string(), &a.keys).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO offline_messages(id,protocol_version,message_id,conversation_id,from_user_id,sender_device_id,sender_seq,prev_hash,recipient_user_id,recipient_device_id,ciphertext,signature,timestamp,created_at) VALUES($1,2,$1,'old queue',$2,$3,1,''::BYTEA,$4,$5,'x'::BYTEA,'x'::BYTEA,1,now())").bind(&id).bind(&b.id).bind(&b.device).bind(&a.id).bind(&a.device).execute(f.db.pool()).await.unwrap();
    let submit = || {
        f.client
            .post(format!("{}/devices/messaging/enable", f.url))
            .bearer_auth(&a.token)
            .json(&event)
            .send()
    };
    assert_eq!(submit().await.unwrap().status(), StatusCode::CONFLICT);
    sqlx::query("DELETE FROM offline_messages WHERE id=$1")
        .bind(id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(submit().await.unwrap().status(), StatusCode::OK);
    assert_eq!(submit().await.unwrap().status(), StatusCode::OK);
    let mut changed = event.clone();
    changed.id = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        f.client
            .post(format!("{}/devices/messaging/enable", f.url))
            .bearer_auth(&a.token)
            .json(&changed)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let msg = crate::db::OfflineMessageRecord {
        protocol_version: 2,
        message_id: uuid::Uuid::new_v4().to_string(),
        conversation_id: "late".into(),
        from_user_id: b.id,
        sender_device_id: b.device,
        sender_seq: 1,
        prev_hash: vec![],
        recipient_user_id: a.id.clone(),
        recipient_device_id: a.device.clone(),
        message_type: "text".into(),
        ciphertext: vec![1; 40],
        signature: vec![1; 64],
        timestamp: now(),
    };
    assert_eq!(
        f.db.store_offline_message(&msg).await.unwrap(),
        crate::db::StoreOfflineOutcome::UpgradeRequired
    );
    assert!(!f.db.is_beta_device(&a.id, &a.device).await.unwrap());
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn real_activation_lost_responses_return_same_encrypted_session_and_refresh_once() {
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let (join, _) = authorized(&f, &root).await;
    let (input, state, mode) = attempt(&f, &root, &join.status.ticket.device.device_id).await;
    *lose.lock().unwrap() = Some("/auth/v3/begin".into());
    assert_eq!(
        begin(&f, &input).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let challenge: SessionChallenge = begin(&f, &input).await.json().await.unwrap();
    assert_eq!(
        begin(&f, &input)
            .await
            .json::<SessionChallenge>()
            .await
            .unwrap(),
        challenge
    );
    let proof = challenge.answer(&state, &mode, now(), &join.keys).unwrap();
    *lose.lock().unwrap() = Some(format!("/auth/v3/{}/proof", input.id));
    assert_eq!(
        prove(&f, &input, &proof).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let envelope: Envelope = prove(&f, &input, &proof).await.json().await.unwrap();
    assert_eq!(
        prove(&f, &input, &proof)
            .await
            .json::<Envelope>()
            .await
            .unwrap(),
        envelope
    );
    let session = envelope.open(&challenge, &join.keys).unwrap();
    assert!(envelope.open(&challenge, &root.keys).is_err());
    assert!(!String::from_utf8(serde_json::to_vec(&envelope).unwrap())
        .unwrap()
        .contains(&session.access_token));
    assert_eq!(
        f.db.validate_access_token(
            &auth::service::hash_token(&session.access_token),
            &session.device
        )
        .await
        .unwrap()
        .as_deref(),
        Some(root.id.as_str())
    );
    let devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE user_id=$1")
        .bind(&root.id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(devices, 2);
    let sessions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id=$1 AND device_id=$2")
            .bind(&root.id)
            .bind(&session.device)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(sessions, 1);
    let refresh = || {
        f.client
            .post(format!("{}/auth/refresh", f.url))
            .json(&serde_json::json!({"refresh_token":session.refresh_token}))
            .send()
    };
    let (one, two) = tokio::join!(refresh(), refresh());
    let one = one.unwrap();
    let two = two.unwrap();
    assert!([one.status(), two.status()].contains(&StatusCode::OK));
    assert!([one.status(), two.status()].contains(&StatusCode::UNAUTHORIZED));
    let rotated: serde_json::Value = if one.status() == StatusCode::OK {
        one.json().await.unwrap()
    } else {
        two.json().await.unwrap()
    };
    assert!(f
        .db
        .validate_access_token(
            &auth::service::hash_token(rotated["access_token"].as_str().unwrap()),
            &session.device
        )
        .await
        .unwrap()
        .is_some());
    assert_eq!(prove(&f, &input, &proof).await.status(), StatusCode::GONE);
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn active_secondary_cannot_use_old_login_groups_or_replace_account_identity() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let (join, _) = authorized(&f, &root).await;
    let session = super::direct_message_tests::verified_activation(
        &f,
        &root,
        &join.status.ticket.device.device_id,
        &join.keys,
    )
    .await;
    let old_login = |device: &str, keys: &crypto::KeyPair| {
        f.client.post(format!("{}/auth/login",f.url)).json(&serde_json::json!({"username":root.username,"password":root.password,"device_id":device,"device_public_key":keys.public_key,"ed25519_pk":keys.ed25519_pk})).send()
    };
    assert_eq!(
        old_login(&session.device, &join.keys)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        old_login(&root.device, &root.keys).await.unwrap().status(),
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(
        f.client
            .get(format!("{}/groups", f.url))
            .bearer_auth(&session.access_token)
            .query(&[("device_id", &session.device)])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.client
            .get(format!("{}/groups", f.url))
            .bearer_auth(&root.token)
            .query(&[("device_id", &root.device)])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        f.client
            .delete(format!("{}/devices/{}", f.url, root.device))
            .bearer_auth(&session.access_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let key: serde_json::Value = f
        .client
        .get(format!("{}/users/{}/key", f.url, root.id))
        .bearer_auth(&session.access_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(key["public_key"], serde_json::json!(root.keys.public_key));
    assert!(f
        .db
        .is_beta_device(&root.id, &session.device)
        .await
        .is_ok_and(|active| !active));
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn wrong_token_proof_phase_expiry_and_password_state_never_issue_a_session() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let (join, current) = authorized(&f, &root).await;
    let (input, state, mode) = attempt(&f, &root, &join.status.ticket.device.device_id).await;
    let challenge: SessionChallenge = begin(&f, &input).await.json().await.unwrap();
    let proof = challenge.answer(&state, &mode, now(), &join.keys).unwrap();
    assert_eq!(
        f.client
            .get(format!("{}/auth/v3/{}", f.url, input.id))
            .bearer_auth("synthetic-wrong-credential")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut altered = serde_json::to_value(&proof).unwrap();
    altered["signature"][0] =
        serde_json::json!((altered["signature"][0].as_u64().unwrap() + 1) % 256);
    let altered: Proof = serde_json::from_value(altered).unwrap();
    assert_eq!(
        prove(&f, &input, &altered).await.status(),
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE device_session_attempts SET expires_at=$2 WHERE id=$1")
        .bind(&input.id)
        .bind(now() - 1)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        f.client
            .get(format!("{}/auth/v3/{}", f.url, input.id))
            .bearer_auth(&input.request_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
    );
    // The live challenge's own authenticated expiry also controls proof acceptance.
    let event = make_event(
        &current,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Revoke {
            device_id: join.status.ticket.device.device_id.clone(),
            grant_hash: current.grant_hash().unwrap().to_vec(),
        },
        now(),
        &root.keys,
    )
    .unwrap();
    assert_eq!(f.submit(&root, &event).await.status(), StatusCode::OK);
    assert_eq!(
        prove(&f, &input, &proof).await.status(),
        StatusCode::FORBIDDEN
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE device_id=$1")
        .bind(&join.status.ticket.device.device_id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn password_change_and_authorization_revoke_invalidate_activated_access_and_refresh() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let (join, current) = authorized(&f, &root).await;
    let session = super::direct_message_tests::verified_activation(
        &f,
        &root,
        &join.status.ticket.device.device_id,
        &join.keys,
    )
    .await;
    let event = make_event(
        &current,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Revoke {
            device_id: join.status.ticket.device.device_id.clone(),
            grant_hash: current.grant_hash().unwrap().to_vec(),
        },
        now(),
        &root.keys,
    )
    .unwrap();
    assert_eq!(f.submit(&root, &event).await.status(), StatusCode::OK);
    assert!(f
        .db
        .validate_access_token(
            &auth::service::hash_token(&session.access_token),
            &session.device
        )
        .await
        .unwrap()
        .is_none());
    assert!(f
        .db
        .rotate_refresh_session(
            &auth::service::hash_token(&session.refresh_token),
            &auth::service::generate_token(),
            &auth::service::generate_token()
        )
        .await
        .unwrap()
        .is_none());
    let (input, state, mode) = attempt(&f, &root, &root.device).await;
    let challenge: SessionChallenge = begin(&f, &input).await.json().await.unwrap();
    let proof = challenge.answer(&state, &mode, now(), &root.keys).unwrap();
    sqlx::query("UPDATE users SET password_hash=$2 WHERE id=$1")
        .bind(&root.id)
        .bind(auth::service::hash_password("synthetic-new-password").unwrap())
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        prove(&f, &input, &proof).await.status(),
        StatusCode::UNAUTHORIZED
    );
}
