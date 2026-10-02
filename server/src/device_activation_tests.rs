use super::direct_message_tests::enable_mode;
use super::*;
use liteseal_core::{
    backup::WorkDirectory,
    trusted_devices::{
        activation::jobs::{
            Condition as ActivationCondition, Coordinator as ActivationCoordinator,
            Owner as ActivationOwner, Stage as ActivationStage, Store as ActivationStore,
        },
        witness::platform::Protection,
        Checkpoint, DeviceTrustStore,
    },
};
use liteseal_shared::device_activation::{
    ActivationCancel, ActivationCancelResult, Challenge as SessionChallenge, ClosedReason, Enable,
    EnableCancel, EnableCancelResult, Envelope, Inspection, InspectionResult, Proof, Start,
};
fn activation_actor(
    path: &std::path::Path,
    directory: &DeviceState,
    device: &str,
    keys: &crypto::KeyPair,
    protection: &Protection,
) -> ActivationCoordinator {
    ActivationCoordinator::open_with_protection(
        path,
        ActivationOwner::new(directory.anchor().clone(), device, keys).unwrap(),
        keys,
        protection.clone(),
    )
    .unwrap()
}
fn seed_activation(
    path: &std::path::Path,
    directory: &DeviceState,
    events: &[DeviceEvent],
    protection: &Protection,
) {
    let mut trust = DeviceTrustStore::open(path).unwrap();
    trust.protect(protection.witness(path).unwrap()).unwrap();
    let initial = trust.pin(directory.anchor()).unwrap();
    if !events.is_empty() {
        trust
            .import_verified(
                directory.anchor(),
                &Checkpoint::from_state(&initial),
                events,
            )
            .unwrap();
    }
}
async fn activation_events(f: &Fixture, root: &Account) -> Vec<DeviceEvent> {
    f.manifest(root, &root.id, 0, 100)
        .await
        .json::<DeviceManifestPage>()
        .await
        .unwrap()
        .events
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn durable_enable_and_activation_jobs_recover_all_lost_successes_without_new_identity() {
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let (join, directory) = authorized(&f, &root).await;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = work.0.join("root-activation.db");
    let protection = Protection::isolated_test();
    let events = activation_events(&f, &root).await;
    seed_activation(&path, &directory, &events, &protection);
    let actor = activation_actor(&path, &directory, &root.device, &root.keys, &protection);
    actor.renew_session(root.token.clone()).unwrap();
    let enable = actor.prepare_enable(&root.keys).unwrap();
    *lose.lock().unwrap() = Some("/devices/messaging/enable".into());
    let progress = actor.step(&enable.id, None, &root.keys).await.unwrap();
    assert_eq!(progress.condition, ActivationCondition::Retry);
    assert_eq!(progress.http_status, Some(503));
    drop(actor);
    let mut stored = ActivationStore::open(
        &path,
        ActivationOwner::new(directory.anchor().clone(), &root.device, &root.keys).unwrap(),
        &root.keys,
        protection.witness(&path).unwrap(),
    )
    .unwrap();
    let original_mode = stored
        .task(&enable.id, &root.keys)
        .unwrap()
        .enable()
        .clone();
    drop(stored);
    let actor = activation_actor(&path, &directory, &root.device, &root.keys, &protection);
    // Root login and the unresolved enable have separate pending lanes. No old
    // access/refresh bearer is needed to prove this new root session.
    let login = actor
        .prepare_login(&root.username, original_mode, &root.keys)
        .unwrap();
    assert_eq!(
        actor
            .step(&login.id, Some(&root.password), &root.keys)
            .await
            .unwrap()
            .condition,
        ActivationCondition::Complete
    );
    let session = actor.session(&login.id, &root.keys).unwrap();
    actor.renew_session(session.access_token.clone()).unwrap();
    assert_eq!(
        actor
            .step(&enable.id, None, &root.keys)
            .await
            .unwrap()
            .condition,
        ActivationCondition::Complete
    );
    let mode = liteseal_core::trusted_devices::activation::ActivationApi::new(&f.url)
        .unwrap()
        .status(&root.token, directory.anchor())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mode.id, enable.id);
    drop(actor);
    let path = work.0.join("secondary-activation.db");
    seed_activation(&path, &directory, &events, &protection);
    let device = &join.status.ticket.device.device_id;
    let actor = activation_actor(&path, &directory, device, &join.keys, &protection);
    let task = actor
        .prepare_login(&root.username, mode.clone(), &join.keys)
        .unwrap();
    assert_eq!(
        actor
            .step(&task.id, None, &join.keys)
            .await
            .unwrap()
            .condition,
        ActivationCondition::NeedsPassword
    );
    *lose.lock().unwrap() = Some("/auth/v3/begin".into());
    assert_eq!(
        actor
            .step(&task.id, Some(&root.password), &join.keys)
            .await
            .unwrap()
            .http_status,
        Some(503)
    );
    drop(actor);
    let actor = activation_actor(&path, &directory, device, &join.keys, &protection);
    *lose.lock().unwrap() = Some(format!("/auth/v3/{}/proof", task.id));
    assert_eq!(
        actor
            .step(&task.id, None, &join.keys)
            .await
            .unwrap()
            .http_status,
        Some(503)
    );
    drop(actor);
    let mut stored = ActivationStore::open(
        &path,
        ActivationOwner::new(directory.anchor().clone(), device, &join.keys).unwrap(),
        &join.keys,
        protection.witness(&path).unwrap(),
    )
    .unwrap();
    let original = stored.task(&task.id, &join.keys).unwrap();
    let proof = serde_json::to_vec(&original.proof().unwrap().unwrap()).unwrap();
    let challenge = original.challenge().unwrap().clone();
    drop(stored);
    let actor = activation_actor(&path, &directory, device, &join.keys, &protection);
    assert_eq!(
        actor
            .step(&task.id, None, &join.keys)
            .await
            .unwrap()
            .condition,
        ActivationCondition::Complete
    );
    let session = actor.session(&task.id, &join.keys).unwrap();
    assert!(f
        .db
        .validate_access_token(&auth::service::hash_token(&session.access_token), device)
        .await
        .unwrap()
        .is_some());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE device_id=$1")
        .bind(device)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
    drop(actor);
    let mut stored = ActivationStore::open(
        &path,
        ActivationOwner::new(directory.anchor().clone(), device, &join.keys).unwrap(),
        &join.keys,
        protection.witness(&path).unwrap(),
    )
    .unwrap();
    let original = stored.task(&task.id, &join.keys).unwrap();
    assert_eq!(original.challenge().unwrap(), &challenge);
    assert_eq!(
        serde_json::to_vec(&original.proof().unwrap().unwrap()).unwrap(),
        proof
    );
    assert_eq!(original.view().stage, ActivationStage::Complete);
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn durable_activation_cancellation_reopens_after_lost_begin_and_cancel_response() {
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let (join, directory) = authorized(&f, &root).await;
    let mode = enable_mode(&f, &root).await;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = work.0.join("secondary-cancel.db");
    let protection = Protection::isolated_test();
    let events = activation_events(&f, &root).await;
    seed_activation(&path, &directory, &events, &protection);
    let device = &join.status.ticket.device.device_id;
    let actor = activation_actor(&path, &directory, device, &join.keys, &protection);
    let task = actor
        .prepare_login(&root.username, mode, &join.keys)
        .unwrap();
    *lose.lock().unwrap() = Some("/auth/v3/begin".into());
    assert_eq!(
        actor
            .step(&task.id, Some(&root.password), &join.keys)
            .await
            .unwrap()
            .http_status,
        Some(503)
    );
    assert!(
        actor
            .request_cancel(&task.id, &join.keys)
            .unwrap()
            .cancel_requested
    );
    *lose.lock().unwrap() = Some("/auth/v3/cancel".into());
    assert_eq!(
        actor
            .step(&task.id, None, &join.keys)
            .await
            .unwrap()
            .http_status,
        Some(503)
    );
    drop(actor);
    let actor = activation_actor(&path, &directory, device, &join.keys, &protection);
    assert!(actor.views(&join.keys).unwrap()[0].cancel_requested);
    assert_eq!(
        actor
            .step(&task.id, None, &join.keys)
            .await
            .unwrap()
            .condition,
        ActivationCondition::Cancelled
    );
    assert!(actor.session(&task.id, &join.keys).is_err());
    let mut stored = ActivationStore::open(
        &path,
        ActivationOwner::new(directory.anchor().clone(), device, &join.keys).unwrap(),
        &join.keys,
        protection.witness(&path).unwrap(),
    )
    .unwrap();
    let original = stored
        .task(&task.id, &join.keys)
        .unwrap()
        .start(&root.password)
        .unwrap();
    assert_eq!(begin(&f, &original).await.status(), StatusCode::GONE);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE device_id=$1")
        .bind(device)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn durable_cancel_after_unknown_proof_acceptance_recovers_the_original_session() {
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let (join, directory) = authorized(&f, &root).await;
    let mode = enable_mode(&f, &root).await;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = work.0.join("accepted-cancel.db");
    let protection = Protection::isolated_test();
    let events = activation_events(&f, &root).await;
    seed_activation(&path, &directory, &events, &protection);
    let device = &join.status.ticket.device.device_id;
    let actor = activation_actor(&path, &directory, device, &join.keys, &protection);
    let task = actor
        .prepare_login(&root.username, mode, &join.keys)
        .unwrap();
    *lose.lock().unwrap() = Some(format!("/auth/v3/{}/proof", task.id));
    assert_eq!(
        actor
            .step(&task.id, Some(&root.password), &join.keys)
            .await
            .unwrap()
            .http_status,
        Some(503)
    );
    assert!(
        actor
            .request_cancel(&task.id, &join.keys)
            .unwrap()
            .cancel_requested
    );
    *lose.lock().unwrap() = Some("/auth/v3/cancel".into());
    assert_eq!(
        actor
            .step(&task.id, None, &join.keys)
            .await
            .unwrap()
            .http_status,
        Some(503)
    );
    drop(actor);
    let actor = activation_actor(&path, &directory, device, &join.keys, &protection);
    let result = actor.step(&task.id, None, &join.keys).await.unwrap();
    assert_eq!(result.condition, ActivationCondition::Complete);
    assert!(result.task.cancel_requested);
    let session = actor.session(&task.id, &join.keys).unwrap();
    assert!(f
        .db
        .validate_access_token(&auth::service::hash_token(&session.access_token), device)
        .await
        .unwrap()
        .is_some());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE device_id=$1")
        .bind(device)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        actor
            .step(&task.id, None, &join.keys)
            .await
            .unwrap()
            .condition,
        ActivationCondition::Complete
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn signed_inspection_unknown_pending_and_wrong_scope_do_not_cancel_or_issue_sessions() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let (input, directory, mode) = attempt(&f, &root, &root.device).await;
    let query = Inspection::make(
        &directory,
        &mode,
        &input.id,
        &input.request_token,
        &root.device,
        &root.keys,
    )
    .unwrap();
    let lookup = |query: &Inspection| {
        f.client
            .post(format!("{}/auth/v3/inspect", f.url))
            .bearer_auth(&input.request_token)
            .json(query)
            .send()
    };
    assert!(matches!(
        lookup(&query)
            .await
            .unwrap()
            .json::<InspectionResult>()
            .await
            .unwrap(),
        InspectionResult::Unknown { .. }
    ));
    let challenge: SessionChallenge = begin(&f, &input).await.json().await.unwrap();
    assert!(
        matches!(lookup(&query).await.unwrap().json::<InspectionResult>().await.unwrap(), InspectionResult::Pending { challenge: actual, .. } if *actual == challenge)
    );
    let mut altered = query.clone();
    altered.signature[0] ^= 1;
    assert_eq!(
        lookup(&altered).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        cancel(&f, &input, &query.intent).await.status(),
        StatusCode::FORBIDDEN
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_session_closures WHERE id=$1")
        .bind(&input.id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    let proof = challenge
        .answer(&directory, &mode, now(), &root.keys)
        .unwrap();
    assert_eq!(prove(&f, &input, &proof).await.status(), StatusCode::OK);
    assert!(matches!(
        lookup(&query)
            .await
            .unwrap()
            .json::<InspectionResult>()
            .await
            .unwrap(),
        InspectionResult::Accepted { .. }
    ));
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn expired_unknown_activation_closes_after_lost_response_and_explicit_new_request_succeeds() {
    let (f, lose) = Fixture::start_with_loss().await;
    let root = f.account().await;
    let (join, directory) = authorized(&f, &root).await;
    let mode = enable_mode(&f, &root).await;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = work.0.join("expired-job.db");
    let protection = Protection::isolated_test();
    seed_activation(
        &path,
        &directory,
        &activation_events(&f, &root).await,
        &protection,
    );
    let device = &join.status.ticket.device.device_id;
    let actor = activation_actor(&path, &directory, device, &join.keys, &protection);
    let task = actor
        .prepare_login(&root.username, mode.clone(), &join.keys)
        .unwrap();
    *lose.lock().unwrap() = Some("/auth/v3/begin".into());
    assert_eq!(
        actor
            .step(&task.id, Some(&root.password), &join.keys)
            .await
            .unwrap()
            .http_status,
        Some(503)
    );
    sqlx::query("UPDATE device_session_attempts SET expires_at=$2 WHERE id=$1")
        .bind(&task.id)
        .bind(now() - 1)
        .execute(f.db.pool())
        .await
        .unwrap();
    *lose.lock().unwrap() = Some("/auth/v3/inspect".into());
    assert_eq!(
        actor
            .inspect(&task.id, &join.keys)
            .await
            .unwrap()
            .http_status,
        Some(503)
    );
    drop(actor);
    let actor = activation_actor(&path, &directory, device, &join.keys, &protection);
    let result = actor.inspect(&task.id, &join.keys).await.unwrap();
    assert_eq!(result.condition, ActivationCondition::Ended);
    let closed = result.task.closed.unwrap();
    assert_eq!(closed.reason, ClosedReason::Expired);
    assert!(!closed.accepted);
    let mut store = ActivationStore::open(
        &path,
        ActivationOwner::new(directory.anchor().clone(), device, &join.keys).unwrap(),
        &join.keys,
        protection.witness(&path).unwrap(),
    )
    .unwrap();
    let original = store
        .task(&task.id, &join.keys)
        .unwrap()
        .start(&root.password)
        .unwrap();
    assert_eq!(begin(&f, &original).await.status(), StatusCode::GONE);
    drop(store);
    let next = actor
        .prepare_login(&root.username, mode, &join.keys)
        .unwrap();
    assert_ne!(next.id, task.id);
    assert_eq!(
        actor
            .step(&next.id, Some(&root.password), &join.keys)
            .await
            .unwrap()
            .condition,
        ActivationCondition::Complete
    );
    assert!(actor.forget_ended(&next.id, &join.keys).is_err());
    actor.forget_ended(&task.id, &join.keys).unwrap();
    assert!(actor
        .views(&join.keys)
        .unwrap()
        .iter()
        .all(|v| v.id != task.id));
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn ended_original_session_does_not_revoke_its_refreshed_successor_or_issue_another_session() {
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let (join, directory) = authorized(&f, &root).await;
    let mode = enable_mode(&f, &root).await;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = work.0.join("session-end.db");
    let protection = Protection::isolated_test();
    seed_activation(
        &path,
        &directory,
        &activation_events(&f, &root).await,
        &protection,
    );
    let device = &join.status.ticket.device.device_id;
    let actor = activation_actor(&path, &directory, device, &join.keys, &protection);
    let task = actor
        .prepare_login(&root.username, mode, &join.keys)
        .unwrap();
    assert_eq!(
        actor
            .step(&task.id, Some(&root.password), &join.keys)
            .await
            .unwrap()
            .condition,
        ActivationCondition::Complete
    );
    let session = actor.session(&task.id, &join.keys).unwrap();
    let access = auth::service::generate_token();
    let refresh = auth::service::generate_token();
    assert!(f
        .db
        .rotate_refresh_session(
            &auth::service::hash_token(&session.refresh_token),
            &auth::service::hash_token(&access),
            &auth::service::hash_token(&refresh)
        )
        .await
        .unwrap()
        .is_some());
    let result = actor.inspect(&task.id, &join.keys).await.unwrap();
    assert_eq!(result.condition, ActivationCondition::Ended);
    assert_eq!(
        result.task.closed.unwrap().reason,
        ClosedReason::SessionEnded
    );
    assert!(actor.session(&task.id, &join.keys).is_err());
    assert!(f
        .db
        .validate_access_token(&auth::service::hash_token(&access), device)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        actor.inspect(&task.id, &join.keys).await.unwrap().condition,
        ActivationCondition::Ended
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE device_id=$1")
        .bind(device)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 2);
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn password_and_directory_change_close_unaccepted_originals_without_resigning_or_recalling_sessions(
) {
    for password_change in [false, true] {
        let (f, lose) = Fixture::start_with_loss().await;
        let root = f.account().await;
        let mode = enable_mode(&f, &root).await;
        let directory = state(&f, &root).await;
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let path = work.0.join("changed-job.db");
        let protection = Protection::isolated_test();
        seed_activation(&path, &directory, &[], &protection);
        let actor = activation_actor(&path, &directory, &root.device, &root.keys, &protection);
        let task = actor
            .prepare_login(&root.username, mode, &root.keys)
            .unwrap();
        *lose.lock().unwrap() = Some("/auth/v3/begin".into());
        assert_eq!(
            actor
                .step(&task.id, Some(&root.password), &root.keys)
                .await
                .unwrap()
                .http_status,
            Some(503)
        );
        if password_change {
            sqlx::query("UPDATE users SET password_hash=$2 WHERE id=$1")
                .bind(&root.id)
                .bind(auth::service::hash_password("synthetic-changed-password").unwrap())
                .execute(f.db.pool())
                .await
                .unwrap();
        } else {
            let (_, current) = authorized(&f, &root).await;
            seed_activation(
                &path,
                &current,
                &activation_events(&f, &root).await,
                &protection,
            );
        }
        let result = actor.inspect(&task.id, &root.keys).await.unwrap();
        assert_eq!(result.condition, ActivationCondition::Ended);
        assert_eq!(
            result.task.closed.unwrap().reason,
            if password_change {
                ClosedReason::CredentialsChanged
            } else {
                ClosedReason::DirectoryChanged
            }
        );
        assert!(actor.session(&task.id, &root.keys).is_err());
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM device_session_closures WHERE id=$1")
                .bind(&task.id)
                .fetch_one(f.db.pool())
                .await
                .unwrap();
        assert_eq!(count, 1);
    }
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn joined_windows_profile_uses_server_device_and_dpapi_session_without_replacing_original_identity(
) {
    use liteseal_core::trusted_devices::{
        coordinator::DeviceCoordinator,
        profiles::{active, JoinProfileStore},
        tasks::{anchor_fingerprint, TaskOwner, TaskPhase},
    };
    let f = Fixture::start(true).await;
    let root = f.account().await;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let profile_root = work.0.join("joining");
    let protection = Protection::isolated_test();
    let profiles = JoinProfileStore::with_protection(profile_root.clone(), protection.clone());
    let profile = profiles
        .create(&f.url, &root.username, "normal joined Windows")
        .unwrap();
    let id = profile.view().id;
    let keys = profile.keys().unwrap();
    let path = profiles.database(&id).unwrap();
    let original = std::fs::read(profile_root.join(&id).join("identity.bin")).unwrap();
    let joining = DeviceCoordinator::open_protected(
        &path,
        profile.owner().unwrap(),
        &keys,
        protection.witness(&path).unwrap(),
    )
    .unwrap();
    joining
        .step(profile.task_id(), Some(&root.password), &keys)
        .await
        .unwrap();
    let anchor = Anchor {
        origin: f.url.clone(),
        account: root.id.clone(),
        root: DeviceIdentity::from_keys(root.device.clone(), &root.keys),
    };
    joining
        .confirm_root(profile.task_id(), &anchor_fingerprint(&anchor), &keys)
        .unwrap();
    joining.step(profile.task_id(), None, &keys).await.unwrap();
    let authority_path = work.0.join("authority.db");
    drop(DeviceTrustStore::open(&authority_path).unwrap());
    let authority = DeviceCoordinator::open_protected(
        &authority_path,
        TaskOwner::for_root(&anchor, &root.keys).unwrap(),
        &root.keys,
        protection.witness(&authority_path).unwrap(),
    )
    .unwrap();
    authority.renew_session(root.token.clone()).unwrap();
    let inspect = authority
        .inspect_join(profile.task_id(), &root.keys)
        .await
        .unwrap();
    let challenge = authority
        .prepare_challenge(profile.task_id(), &inspect.combined_fingerprint, &root.keys)
        .await
        .unwrap()
        .unwrap();
    authority
        .step(&challenge.id, None, &root.keys)
        .await
        .unwrap();
    joining.step(profile.task_id(), None, &keys).await.unwrap();
    let inspect = authority
        .inspect_join(profile.task_id(), &root.keys)
        .await
        .unwrap();
    let grant = authority
        .prepare_grant(profile.task_id(), &inspect.combined_fingerprint, &root.keys)
        .await
        .unwrap()
        .unwrap();
    authority.step(&grant.id, None, &root.keys).await.unwrap();
    assert_eq!(
        joining
            .step(profile.task_id(), None, &keys)
            .await
            .unwrap()
            .task
            .phase,
        TaskPhase::Complete
    );
    let mode = enable_mode(&f, &root).await;
    let store =
        active::Store::open_with_protection(profile_root.clone(), &id, protection.clone()).unwrap();
    let actor = ActivationCoordinator::open_with_protection(
        &path,
        store.job_owner().unwrap(),
        &keys,
        protection.clone(),
    )
    .unwrap();
    let task = actor.prepare_login(&root.username, mode, &keys).unwrap();
    assert_eq!(
        actor
            .step(&task.id, Some(&root.password), &keys)
            .await
            .unwrap()
            .condition,
        ActivationCondition::Complete
    );
    let session = actor.session(&task.id, &keys).unwrap();
    assert_ne!(session.device, profile.view().local_device_id);
    let account =
        active::Coordinator::open_with_protection(profile_root.clone(), &id, protection.clone())
            .unwrap();
    let view = account.activate(&task.id).await.unwrap();
    assert_eq!(view.account, root.id);
    assert_eq!(view.device, session.device);
    assert!(view.has_saved_session);
    let public = serde_json::to_string(&view).unwrap();
    assert!(
        !public.contains(&session.access_token)
            && !public.contains(&session.refresh_token)
            && !public.contains("secret_key")
    );
    let identity = account.checked_identity().await.unwrap();
    assert_eq!(identity.user_id, root.id);
    assert_eq!(identity.device_id, session.device);
    assert_eq!(identity.public_key, keys.public_key);
    assert_eq!(identity.secret_key, keys.secret_key);
    assert_eq!(
        std::fs::read(profile_root.join(&id).join("identity.bin")).unwrap(),
        original
    );
    assert!(profiles.remove(&id).is_err());
    drop(account);
    drop(store);
    let account =
        active::Coordinator::open_with_protection(profile_root.clone(), &id, protection.clone())
            .unwrap();
    assert!(account.checked_identity().await.is_ok());
    let saved = std::fs::read(&path).unwrap();
    assert!(!saved
        .windows(session.access_token.len())
        .any(|p| p == session.access_token.as_bytes()));
    account.clear_session().unwrap();
    assert!(!account.view().unwrap().unwrap().has_saved_session);
    assert!(account.checked_identity().await.is_err());
    let mut store = active::Store::open_with_protection(profile_root, &id, protection).unwrap();
    let history_identity = store.load().unwrap().unwrap().identity();
    assert_eq!(history_identity.user_id, root.id);
    assert!(history_identity.token.is_empty());
    assert_eq!(history_identity.secret_key, keys.secret_key);
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn v3_session_metadata_is_current_device_scoped_and_rejects_beta_or_consumed_tokens() {
    use liteseal_shared::device_activation::SessionInfo;
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
    let response = f
        .client
        .get(format!("{}/auth/v3/session/{}", f.url, session.device))
        .bearer_auth(&session.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let info: SessionInfo = response.json().await.unwrap();
    assert_eq!(info.id, session.id);
    assert_eq!(info.account, root.id);
    assert_eq!(info.device.encryption_key, join.keys.public_key);
    assert_eq!(
        f.client
            .get(format!("{}/auth/v3/session/{}", f.url, root.device))
            .bearer_auth(&session.access_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.client
            .get(format!("{}/auth/v3/session/{}", f.url, root.device))
            .bearer_auth(&root.token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UPGRADE_REQUIRED
    );
    f.db.revoke_session(&auth::service::hash_token(&session.access_token))
        .await
        .unwrap();
    assert_eq!(
        f.client
            .get(format!("{}/auth/v3/session/{}", f.url, session.device))
            .bearer_auth(&session.access_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
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
