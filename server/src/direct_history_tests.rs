use super::*;
use liteseal_core::trusted_devices::messages::api::{DirectApi, HistoryAction};
use liteseal_shared::history_transfer::{self as h, Envelope, Evidence, Offer, Record, RelayState};
async fn transfer(f: &Fixture, a: &Account, b: &Account) -> (Join, DeviceState, Envelope) {
    accepted(f, a, b).await;
    let old = directory(f, a);
    let peer = directory(f, b);
    let original = batch(
        &old,
        &peer,
        &a.device,
        &a.keys,
        None,
        b"explicit old history Chinese: \xe4\xb8\xad\xe6\x96\x87",
    );
    let published = send(f, &a.token, &original)
        .await
        .json::<Outcome>()
        .await
        .unwrap();
    let Outcome::Accepted { receipt, .. } = published else {
        panic!("synthetic original was not accepted")
    };
    let (join, own) = grant(f, a, &old).await;
    let directory = liteseal_shared::direct_message::Directory::from_state(&own);
    let record = Record {
        original,
        sender: Evidence {
            anchor: old.anchor().clone(),
            events: vec![],
        },
        peer: Evidence {
            anchor: peer.anchor().clone(),
            events: vec![],
        },
        accepted_at: receipt.accepted_at,
        operations: vec![],
        text: Some("explicit old history Chinese: 中文".into()),
        media: None,
    };
    let created_at = now();
    let header = h::Header {
        version: 1,
        id: uuid::Uuid::new_v4().to_string(),
        origin: f.url.clone(),
        account: a.id.clone(),
        source: old.anchor().root.clone(),
        target: directory
            .members
            .iter()
            .find(|m| m.device.device_id != a.device)
            .unwrap()
            .clone(),
        directory,
        peer: b.id.clone(),
        created_at,
        expires_at: created_at + h::LIFETIME,
        selection: vec![record.reference().unwrap()],
    };
    let envelope = Envelope::make(header, &own, &a.keys, vec![record]).unwrap();
    (join, own, envelope)
}
async fn upload(api: &DirectApi, token: &str, envelope: &Envelope) -> Offer {
    let offer = envelope.offer();
    let status = api.register_history(token, &offer).await.unwrap();
    assert_eq!(status.state, RelayState::Staging);
    for part in 0..offer.size.div_ceil(h::CHUNK) {
        assert_eq!(
            api.upload_history_chunk(
                token,
                &offer,
                part,
                envelope.ciphertext_chunk(part).unwrap().to_vec()
            )
            .await
            .unwrap()
            .next,
            part + 1
        );
    }
    assert_eq!(
        api.history_action(token, &offer, HistoryAction::Publish)
            .await
            .unwrap()
            .state,
        RelayState::Ready
    );
    offer
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn relay_original_chunks_permit_signed_receipt_and_cancel_are_separate_from_delivery() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    let (join, own, envelope) = transfer(&f, &a, &b).await;
    let target = synthetic_activation(&f, &a, &join).await;
    let api = DirectApi::new(&f.url).unwrap();
    let offer = upload(&api, &a.token, &envelope).await;
    assert!(api.register_history(&b.token, &offer).await.is_err());
    assert_eq!(
        api.register_history(&a.token, &offer).await.unwrap().state,
        RelayState::Ready
    );
    let offers = api
        .pending_history(&target, &a.id, &offer.header.target.device.device_id)
        .await
        .unwrap();
    assert_eq!(offers, vec![offer.clone()]);
    let mut bytes = Vec::new();
    for part in 0..offer.size.div_ceil(h::CHUNK) {
        bytes.extend(
            api.download_history_chunk(&target, &offer, part)
                .await
                .unwrap(),
        );
    }
    let received = Envelope::from_offer(offer.clone(), bytes).unwrap();
    assert_eq!(
        received.open(&own, &join.keys, now()).unwrap()[0]
            .text
            .as_deref(),
        Some("explicit old history Chinese: 中文")
    );
    assert_eq!(
        api.history_action(&target, &offer, HistoryAction::Permit)
            .await
            .unwrap()
            .state,
        RelayState::Permitted
    );
    assert_eq!(
        api.history_action(&a.token, &offer, HistoryAction::Cancel)
            .await
            .unwrap()
            .state,
        RelayState::Permitted
    );
    assert!(h::Received::make(&offer, now(), &a.keys).is_err());
    let mut receipt = h::Received::make(&offer, now(), &join.keys).unwrap();
    receipt.signature[0] ^= 1;
    assert!(api
        .history_received(&target, &offer, &receipt)
        .await
        .is_err());
    let receipt = h::Received::make(&offer, now(), &join.keys).unwrap();
    assert_eq!(
        api.history_received(&target, &offer, &receipt)
            .await
            .unwrap()
            .state,
        RelayState::Received
    );
    assert_eq!(
        api.history_status(&a.token, &offer).await.unwrap().state,
        RelayState::Received
    );
    assert!(api
        .pending_history(&target, &a.id, &offer.header.target.device.device_id)
        .await
        .unwrap()
        .is_empty());
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM direct_v3_deliveries WHERE device=$1")
            .bind(&offer.header.target.device.device_id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(count, 0);
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM direct_v3_history_chunks WHERE transfer=$1")
            .bind(&offer.header.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    let records = envelope.open(&own, &join.keys, now()).unwrap();
    let mut header = envelope.header.clone();
    header.id = uuid::Uuid::new_v4().to_string();
    let cancel = Envelope::make(header, &own, &a.keys, records).unwrap();
    let cancelled = upload(&api, &a.token, &cancel).await;
    assert_eq!(
        api.history_action(&a.token, &cancelled, HistoryAction::Cancel)
            .await
            .unwrap()
            .state,
        RelayState::Cancelled
    );
    assert!(api
        .history_action(&target, &cancelled, HistoryAction::Permit)
        .await
        .is_err());
    assert_eq!(
        api.register_history(&a.token, &cancelled)
            .await
            .unwrap()
            .state,
        RelayState::Cancelled
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn revoked_current_directory_blocks_pending_download_and_permit_but_keeps_original_result() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    let (join, own, envelope) = transfer(&f, &a, &b).await;
    let token = synthetic_activation(&f, &a, &join).await;
    let api = DirectApi::new(&f.url).unwrap();
    let offer = upload(&api, &a.token, &envelope).await;
    let event = make_event(
        &own,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Revoke {
            device_id: offer.header.target.device.device_id.clone(),
            grant_hash: own.grant_hash().unwrap().to_vec(),
        },
        now(),
        &a.keys,
    )
    .unwrap();
    assert_eq!(f.submit(&a, &event).await.status(), StatusCode::OK);
    assert!(api
        .pending_history(&token, &a.id, &offer.header.target.device.device_id)
        .await
        .is_err());
    assert!(api.download_history_chunk(&token, &offer, 0).await.is_err());
    assert!(api
        .history_action(&token, &offer, HistoryAction::Permit)
        .await
        .is_err());
    assert_eq!(
        api.history_status(&a.token, &offer).await.unwrap().state,
        RelayState::Ineligible
    );
    assert_eq!(
        api.history_action(&a.token, &offer, HistoryAction::Cancel)
            .await
            .unwrap()
            .state,
        RelayState::Cancelled
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn core_coordinators_forward_receive_and_reconcile_original_history_without_old_ack() {
    use liteseal_core::{
        backup::WorkDirectory,
        trusted_devices::{
            messages::{
                coordinator::{Condition, MessageCoordinator},
                history_transfer::PrepareHistory,
                Owner,
            },
            tasks::anchor_fingerprint,
            witness::platform::Protection,
        },
    };
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let source = MessageCoordinator::open_with_protection(
        &work.0.join("history-source.db"),
        Owner::new(&f.url, &a.id, &a.device, &a.keys).unwrap(),
        &a.keys,
        protection.clone(),
    )
    .unwrap();
    for anchor in [directory(&f, &a).anchor(), directory(&f, &b).anchor()] {
        source
            .confirm_root(anchor, &anchor_fingerprint(anchor), &a.keys)
            .unwrap();
    }
    source.renew_session(a.token.clone()).unwrap();
    let id = source
        .prepare_text(&b.id, "old selected body", &a.keys)
        .await
        .unwrap()
        .task
        .unwrap()
        .id;
    assert_eq!(
        source.step(&id, &a.keys).await.unwrap().condition,
        Condition::Accepted
    );
    let (join, _) = grant(&f, &a, &directory(&f, &a)).await;
    let device = &join.status.ticket.device.device_id;
    let token = synthetic_activation(&f, &a, &join).await;
    let target = MessageCoordinator::open_with_protection(
        &work.0.join("history-target.db"),
        Owner::new(&f.url, &a.id, device, &join.keys).unwrap(),
        &join.keys,
        protection,
    )
    .unwrap();
    for anchor in [directory(&f, &a).anchor(), directory(&f, &b).anchor()] {
        target
            .confirm_root(anchor, &anchor_fingerprint(anchor), &join.keys)
            .unwrap();
    }
    target.renew_session(token).unwrap();
    let transfer = uuid::Uuid::new_v4().to_string();
    let selected = vec![id];
    let view = source
        .prepare_history_transfer(
            PrepareHistory {
                id: &transfer,
                peer: &b.id,
                target: device,
                selection: &selected,
                created_at: now(),
                include_media: false,
            },
            &a.keys,
        )
        .await
        .unwrap();
    let mut ready = false;
    assert!(source.drive_history_send(&a.keys).await.unwrap().is_none());
    source
        .history_relay_step(&transfer, view.revision, &a.keys)
        .await
        .unwrap();
    let job = source.history_relay_jobs(&a.keys).unwrap().remove(0);
    source
        .pause_history_relay(&job.id, job.revision, true, &a.keys)
        .unwrap();
    assert!(source.drive_history_send(&a.keys).await.unwrap().is_none());
    let job = source.history_relay_jobs(&a.keys).unwrap().remove(0);
    source
        .pause_history_relay(&job.id, job.revision, false, &a.keys)
        .unwrap();
    for _ in 0..132 {
        let progress = source.drive_history_send(&a.keys).await.unwrap().unwrap();
        if progress.state == RelayState::Ready {
            ready = true;
            break;
        }
    }
    assert!(ready);
    let first = target.receive_history_relay(&join.keys).await.unwrap();
    assert!(!first.imported && first.downloaded > 0);
    let receive = target.history_receives(&join.keys).unwrap().remove(0);
    target
        .pause_history_receive(&receive.id, receive.revision, true, true, &join.keys)
        .unwrap();
    assert!(target
        .drive_history_receive(&join.keys)
        .await
        .unwrap()
        .is_none());
    assert!(target
        .receive_history_relay(&join.keys)
        .await
        .unwrap()
        .id
        .is_none());
    let receive = target.history_receives(&join.keys).unwrap().remove(0);
    assert_eq!(receive.downloaded, 0);
    assert!(receive.abandoned);
    target
        .pause_history_receive(&receive.id, receive.revision, false, false, &join.keys)
        .unwrap();
    let mut imported = false;
    for _ in 0..132 {
        if target
            .drive_history_receive(&join.keys)
            .await
            .unwrap()
            .unwrap()
            .imported
        {
            imported = true;
            break;
        }
    }
    assert!(imported);
    let history = target.transferred_history(Some(&b.id), &join.keys).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].text.as_deref(), Some("old selected body"));
    assert!(target.history(None, 50, &join.keys).unwrap().is_empty());
    assert!(target.tasks(&join.keys).unwrap().is_empty());
    assert!(target.claim_notifications(&join.keys).unwrap().is_empty());
    assert_eq!(
        source
            .history_relay_step(&transfer, view.revision, &a.keys)
            .await
            .unwrap()
            .state,
        RelayState::Received
    );
    assert!(target
        .receive_history_relay(&join.keys)
        .await
        .unwrap()
        .id
        .is_none());
    assert!(target.history_receives(&join.keys).unwrap().is_empty());
    let cancelled = uuid::Uuid::new_v4().to_string();
    let cancel_view = source
        .prepare_history_transfer(
            PrepareHistory {
                id: &cancelled,
                peer: &b.id,
                target: device,
                selection: &selected,
                created_at: now(),
                include_media: false,
            },
            &a.keys,
        )
        .await
        .unwrap();
    // Cancel an unknown original: register only its immutable signed offer,
    // save a tombstone, and never upload or publish its ciphertext.
    assert_eq!(
        source
            .cancel_history_relay(&cancelled, cancel_view.revision, &a.keys)
            .await
            .unwrap()
            .state,
        RelayState::Cancelled
    );
    source
        .cancel_history_transfer(&cancelled, cancel_view.revision, &a.keys)
        .unwrap();
    assert_eq!(
        source
            .cancel_history_relay(&cancelled, cancel_view.revision, &a.keys)
            .await
            .unwrap()
            .state,
        RelayState::Cancelled
    );
}
