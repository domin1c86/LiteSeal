//! Real HTTP/PostgreSQL; synthetic operational secondary sessions are test-only.
use super::*;
use liteseal_shared::{
    direct_message::{Ack, Batch, Header, Kind, MessageSpec},
    direct_transport::{Page, Result as Outcome},
    protocol::AckOutcome,
};
fn directory(f: &Fixture, account: &Account) -> DeviceState {
    DeviceState::pin(Anchor {
        origin: f.url.clone(),
        account: account.id.clone(),
        root: DeviceIdentity::from_keys(account.device.clone(), &account.keys),
    })
    .unwrap()
}
async fn grant(f: &Fixture, root: &Account, old: &DeviceState) -> (Join, DeviceState) {
    let join = f.join(root).await;
    let event = f.prove(root, &join, old).await;
    assert_eq!(f.submit(root, &event).await.status(), StatusCode::OK);
    let next = old.apply(&event).unwrap();
    (join, next)
}
async fn synthetic_activation(f: &Fixture, root: &Account, join: &Join) -> String {
    let device = &join.status.ticket.device.device_id;
    let token = auth::service::generate_token();
    let mut tx = f.db.pool().begin().await.unwrap();
    sqlx::query("INSERT INTO devices(id,user_id,name,public_key,ed25519_pk,created_at,last_seen) VALUES($1,$2,'synthetic activated',$3,$4,now(),now())")
        .bind(device).bind(&root.id).bind(join.keys.public_key.as_slice()).bind(join.keys.ed25519_pk.as_slice()).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO sessions(id,user_id,device_id,access_token_hash,refresh_token_hash,expires_at,refresh_expires_at,created_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour',now()+interval '1 day',now())")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&root.id).bind(device).bind(auth::service::hash_token(&token)).bind(auth::service::generate_token()).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    token
}
async fn accepted(f: &Fixture, sender: &Account, peer: &Account) {
    sqlx::query("INSERT INTO contact_policy(user_id,peer_id,status) VALUES($1,$2,'accepted') ON CONFLICT(user_id,peer_id) DO UPDATE SET status='accepted'")
        .bind(&peer.id).bind(&sender.id).execute(f.db.pool()).await.unwrap();
}
fn batch(
    sender: &DeviceState,
    peer: &DeviceState,
    device: &str,
    keys: &crypto::KeyPair,
    previous: Option<&Batch>,
    body: &[u8],
) -> Batch {
    let header = Header::new(
        sender,
        peer,
        device,
        MessageSpec {
            id: uuid::Uuid::new_v4().to_string(),
            sequence: previous.map_or(1, |b| b.header.sequence + 1),
            previous: previous.map_or(vec![], |b| b.digest().unwrap().to_vec()),
            sent_at: now(),
            kind: Kind::Text,
        },
    )
    .unwrap();
    Batch::make(header, sender, peer, keys, body).unwrap()
}
async fn send(f: &Fixture, token: &str, batch: &Batch) -> reqwest::Response {
    f.client
        .post(format!("{}/direct/v3/batches", f.url))
        .bearer_auth(token)
        .json(batch)
        .send()
        .await
        .unwrap()
}
async fn cancel(f: &Fixture, token: &str, batch: &Batch) -> reqwest::Response {
    f.client
        .post(format!("{}/direct/v3/cancel", f.url))
        .bearer_auth(token)
        .json(batch)
        .send()
        .await
        .unwrap()
}
async fn lookup(f: &Fixture, token: &str, batch: &Batch) -> reqwest::Response {
    f.client
        .get(format!("{}/direct/v3/batches/{}", f.url, batch.header.id))
        .bearer_auth(token)
        .query(&[
            ("device_id", batch.header.sender_device.as_str()),
            ("digest", &hex::encode(batch.digest().unwrap())),
        ])
        .send()
        .await
        .unwrap()
}
async fn pending(f: &Fixture, token: &str, device: &str, limit: usize) -> reqwest::Response {
    f.client
        .get(format!("{}/direct/v3/pending", f.url))
        .bearer_auth(token)
        .query(&[("device_id", device), ("limit", &limit.to_string())])
        .send()
        .await
        .unwrap()
}
async fn ack(f: &Fixture, token: &str, ack: &Ack) -> reqwest::Response {
    f.client
        .post(format!("{}/direct/v3/ack", f.url))
        .bearer_auth(token)
        .json(ack)
        .send()
        .await
        .unwrap()
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn four_keys_atomic_batch_independent_ack_and_lost_response_replay() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    let (aj, as_) = grant(&f, &a, &directory(&f, &a)).await;
    let (bj, bs) = grant(&f, &b, &directory(&f, &b)).await;
    let at = synthetic_activation(&f, &a, &aj).await;
    let bt = synthetic_activation(&f, &b, &bj).await;
    accepted(&f, &a, &b).await;
    let original = batch(&as_, &bs, &a.device, &a.keys, None, "中文🙂".as_bytes());
    // Drop the accepted HTTP response, then resolve the exact original digest.
    assert_eq!(send(&f, &a.token, &original).await.status(), StatusCode::OK);
    let result = lookup(&f, &a.token, &original)
        .await
        .json::<Outcome>()
        .await
        .unwrap();
    let Outcome::Accepted { receipt, .. } = result.clone() else {
        panic!("not accepted")
    };
    assert_eq!(
        send(&f, &a.token, &original)
            .await
            .json::<Outcome>()
            .await
            .unwrap(),
        result
    );
    for (account, device, token, keys) in [
        (&a.id, &aj.status.ticket.device.device_id, &at, &aj.keys),
        (&b.id, &b.device, &b.token, &b.keys),
        (&b.id, &bj.status.ticket.device.device_id, &bt, &bj.keys),
    ] {
        let page = pending(&f, token, device, 100)
            .await
            .json::<Page>()
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].receipt, receipt);
        assert_eq!(
            page.items[0].batch.to_wire().unwrap(),
            original.to_wire().unwrap()
        );
        assert_eq!(
            original.open(&as_, &bs, account, device, keys).unwrap(),
            "中文🙂".as_bytes()
        );
        let signed = Ack::make(
            &original,
            &as_,
            &bs,
            account,
            device,
            keys,
            AckOutcome::Processed,
        )
        .unwrap();
        assert_eq!(
            ack(&f, token, &signed).await.status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            ack(&f, token, &signed).await.status(),
            StatusCode::NO_CONTENT
        );
        assert!(pending(&f, token, device, 100)
            .await
            .json::<Page>()
            .await
            .unwrap()
            .items
            .is_empty());
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM direct_v3_deliveries WHERE batch=$1")
        .bind(&original.header.id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 3);
    let wire: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wire FROM direct_v3_batches WHERE id=$1")
            .bind(&original.header.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert!(wire.is_none());
    let Outcome::Accepted {
        acknowledgements, ..
    } = lookup(&f, &a.token, &original)
        .await
        .json::<Outcome>()
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(acknowledgements.len(), 3);
    for signed in &acknowledgements {
        signed.verify(&original, &as_, &bs).unwrap();
    }
    assert!(matches!(
        send(&f, &a.token, &original)
            .await
            .json::<Outcome>()
            .await
            .unwrap(),
        Outcome::Accepted { .. }
    ));
    let secondary_batch = batch(
        &as_,
        &bs,
        &aj.status.ticket.device.device_id,
        &aj.keys,
        None,
        b"second sender",
    );
    assert_eq!(
        send(&f, &at, &secondary_batch).await.status(),
        StatusCode::OK
    );
    let root_copy = pending(&f, &a.token, &a.device, 100)
        .await
        .json::<Page>()
        .await
        .unwrap();
    assert_eq!(root_copy.items.len(), 1);
    assert_eq!(
        root_copy.items[0]
            .batch
            .open(&as_, &bs, &a.id, &a.device, &a.keys)
            .unwrap(),
        b"second sender"
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn unknown_is_not_cancelled_and_submit_cancel_race_has_one_terminal_result() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let s = directory(&f, &a);
    let p = directory(&f, &b);
    let first = batch(&s, &p, &a.device, &a.keys, None, b"race");
    assert!(matches!(
        lookup(&f, &a.token, &first)
            .await
            .json::<Outcome>()
            .await
            .unwrap(),
        Outcome::Unknown { .. }
    ));
    let (publish, cancellation) =
        tokio::join!(send(&f, &a.token, &first), cancel(&f, &a.token, &first));
    assert_eq!(publish.status(), StatusCode::OK);
    assert_eq!(cancellation.status(), StatusCode::OK);
    let publish = publish.json::<Outcome>().await.unwrap();
    let cancellation = cancellation.json::<Outcome>().await.unwrap();
    assert_eq!(publish, cancellation);
    assert_eq!(
        lookup(&f, &a.token, &first)
            .await
            .json::<Outcome>()
            .await
            .unwrap(),
        publish
    );
    let second = batch(
        &s,
        &p,
        &a.device,
        &a.keys,
        if matches!(publish, Outcome::Accepted { .. }) {
            Some(&first)
        } else {
            None
        },
        b"cancel first",
    );
    let cancellation = cancel(&f, &a.token, &second)
        .await
        .json::<Outcome>()
        .await
        .unwrap();
    assert!(matches!(cancellation, Outcome::Cancelled { .. }));
    assert_eq!(
        send(&f, &a.token, &second)
            .await
            .json::<Outcome>()
            .await
            .unwrap(),
        cancellation
    );
    let queues: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM direct_v3_deliveries WHERE batch=$1")
            .bind(&second.header.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(queues, 0);
    let mut changed = second.clone();
    changed.signature[0] ^= 1;
    assert_eq!(
        send(&f, &a.token, &changed).await.status(),
        StatusCode::CONFLICT
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn malformed_audience_chain_identity_and_ack_cannot_partially_commit() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    let (bj, bs) = grant(&f, &b, &directory(&f, &b)).await;
    let bt = synthetic_activation(&f, &b, &bj).await;
    let oversized = f
        .client
        .post(format!("{}/direct/v3/ack", f.url))
        .bearer_auth(&b.token)
        .header("content-type", "application/json")
        .body(" ".repeat(liteseal_shared::direct_message::MAX_ACK_WIRE + 1))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    accepted(&f, &a, &b).await;
    let as_ = directory(&f, &a);
    let original = batch(&as_, &bs, &a.device, &a.keys, None, b"valid");
    let mut bad = original.clone();
    bad.payloads.pop();
    assert_eq!(
        send(&f, &a.token, &bad).await.status(),
        StatusCode::BAD_REQUEST
    );
    bad = original.clone();
    bad.signature[0] ^= 1;
    assert_eq!(
        send(&f, &a.token, &bad).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&f, &b.token, &original).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let bad_chain = batch(&as_, &bs, &a.device, &a.keys, Some(&original), b"skip");
    assert_eq!(
        send(&f, &a.token, &bad_chain).await.status(),
        StatusCode::CONFLICT
    );
    let mut media_header = original.header.clone();
    media_header.id = uuid::Uuid::new_v4().to_string();
    media_header.kind = Kind::Attachment;
    let media = Batch::make(
        media_header,
        &as_,
        &bs,
        &a.keys,
        b"opaque media description",
    )
    .unwrap();
    assert_eq!(
        send(&f, &a.token, &media).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert!(pending(&f, &b.token, &b.device, 100)
        .await
        .json::<Page>()
        .await
        .unwrap()
        .items
        .is_empty());
    assert_eq!(send(&f, &a.token, &original).await.status(), StatusCode::OK);
    let signed = Ack::make(
        &original,
        &as_,
        &bs,
        &b.id,
        &b.device,
        &b.keys,
        AckOutcome::Rejected,
    )
    .unwrap();
    assert_eq!(
        ack(&f, &bt, &signed).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let mut forged = signed.clone();
    forged.signature[0] ^= 1;
    assert_eq!(
        ack(&f, &b.token, &forged).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        ack(&f, &b.token, &signed).await.status(),
        StatusCode::NO_CONTENT
    );
    let changed = Ack::make(
        &original,
        &as_,
        &bs,
        &b.id,
        &b.device,
        &b.keys,
        AckOutcome::Processed,
    )
    .unwrap();
    assert_eq!(
        ack(&f, &b.token, &changed).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        pending(&f, &bt, &bj.status.ticket.device.device_id, 100)
            .await
            .json::<Page>()
            .await
            .unwrap()
            .items
            .len(),
        1
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn directory_conflict_revoke_rejoin_and_old_result_do_not_reencrypt() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let as_ = directory(&f, &a);
    let old = directory(&f, &b);
    let stale = batch(&as_, &old, &a.device, &a.keys, None, b"before grant");
    let (bj, bs) = grant(&f, &b, &old).await;
    let bt = synthetic_activation(&f, &b, &bj).await;
    assert_eq!(
        send(&f, &a.token, &stale).await.status(),
        StatusCode::CONFLICT
    );
    assert!(matches!(
        cancel(&f, &a.token, &stale)
            .await
            .json::<Outcome>()
            .await
            .unwrap(),
        Outcome::Cancelled { .. }
    ));
    let delivered = batch(&as_, &bs, &a.device, &a.keys, None, b"new stage");
    assert_eq!(
        send(&f, &a.token, &delivered).await.status(),
        StatusCode::OK
    );
    let event = make_event(
        &bs,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Revoke {
            device_id: bj.status.ticket.device.device_id.clone(),
            grant_hash: bs.grant_hash().unwrap().to_vec(),
        },
        now(),
        &b.keys,
    )
    .unwrap();
    assert_eq!(f.submit(&b, &event).await.status(), StatusCode::OK);
    let revoked = bs.apply(&event).unwrap();
    assert_eq!(
        pending(&f, &bt, &bj.status.ticket.device.device_id, 100)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let state: String =
        sqlx::query_scalar("SELECT state FROM direct_v3_deliveries WHERE batch=$1 AND device=$2")
            .bind(&delivered.header.id)
            .bind(&bj.status.ticket.device.device_id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(state, "ineligible");
    assert!(matches!(
        send(&f, &a.token, &delivered)
            .await
            .json::<Outcome>()
            .await
            .unwrap(),
        Outcome::Accepted { .. }
    ));
    let (fresh, bs2) = grant(&f, &b, &revoked).await;
    let fresh_token = synthetic_activation(&f, &b, &fresh).await;
    assert!(
        pending(&f, &fresh_token, &fresh.status.ticket.device.device_id, 100)
            .await
            .json::<Page>()
            .await
            .unwrap()
            .items
            .is_empty()
    );
    let next = batch(&as_, &bs2, &a.device, &a.keys, None, b"fresh only");
    assert_eq!(send(&f, &a.token, &next).await.status(), StatusCode::OK);
    assert_eq!(
        pending(&f, &fresh_token, &fresh.status.ticket.device.device_id, 100)
            .await
            .json::<Page>()
            .await
            .unwrap()
            .items
            .len(),
        1
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn page_is_bounded_ordered_and_blocked_queue_stays_private() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let as_ = directory(&f, &a);
    let bs = directory(&f, &b);
    let mut previous = None;
    for i in 0..65 {
        let b_ = batch(
            &as_,
            &bs,
            &a.device,
            &a.keys,
            previous.as_ref(),
            format!("中文🙂 {i}").as_bytes(),
        );
        assert_eq!(send(&f, &a.token, &b_).await.status(), StatusCode::OK);
        previous = Some(b_);
    }
    let page = pending(&f, &b.token, &b.device, 25)
        .await
        .json::<Page>()
        .await
        .unwrap();
    assert_eq!(page.items.len(), 25);
    assert!(page.has_more);
    assert!(page.items.windows(2).all(|w| w[0].order < w[1].order));
    assert_eq!(
        pending(&f, &b.token, &b.device, 101).await.status(),
        StatusCode::BAD_REQUEST
    );
    for item in &page.items {
        let signed = Ack::make(
            &item.batch,
            &as_,
            &bs,
            &b.id,
            &b.device,
            &b.keys,
            AckOutcome::Processed,
        )
        .unwrap();
        assert_eq!(
            ack(&f, &b.token, &signed).await.status(),
            StatusCode::NO_CONTENT
        );
    }
    let page = pending(&f, &b.token, &b.device, 100)
        .await
        .json::<Page>()
        .await
        .unwrap();
    assert_eq!(page.items.len(), 40);
    assert_eq!(page.items[0].batch.header.sequence, 26);
    sqlx::query("UPDATE contact_policy SET status='blocked' WHERE user_id=$1 AND peer_id=$2")
        .bind(&b.id)
        .bind(&a.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert!(pending(&f, &b.token, &b.device, 100)
        .await
        .json::<Page>()
        .await
        .unwrap()
        .items
        .is_empty());
    let next = batch(&as_, &bs, &a.device, &a.keys, previous.as_ref(), b"blocked");
    assert_eq!(
        send(&f, &a.token, &next).await.status(),
        StatusCode::FORBIDDEN
    );
    accepted(&f, &a, &b).await;
    assert_eq!(
        pending(&f, &b.token, &b.device, 100)
            .await
            .json::<Page>()
            .await
            .unwrap()
            .items
            .len(),
        40
    );
    sqlx::query("INSERT INTO contact_policy(user_id,peer_id,status) VALUES($1,$2,'blocked')")
        .bind(&a.id)
        .bind(&b.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert!(pending(&f, &b.token, &b.device, 100)
        .await
        .json::<Page>()
        .await
        .unwrap()
        .items
        .is_empty());
    assert_eq!(
        send(&f, &a.token, &next).await.status(),
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn disabled_missing_session_and_join_credential_never_activate_chat() {
    let f = Fixture::start(false).await;
    let a = f.account().await;
    let b = f.account().await;
    let original = batch(
        &directory(&f, &a),
        &directory(&f, &b),
        &a.device,
        &a.keys,
        None,
        b"disabled",
    );
    assert_eq!(
        send(&f, &a.token, &original).await.status(),
        StatusCode::NOT_FOUND
    );
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    let (join, s) = grant(&f, &a, &directory(&f, &a)).await;
    let original = batch(
        &s,
        &directory(&f, &b),
        &join.status.ticket.device.device_id,
        &join.keys,
        None,
        b"no activation",
    );
    assert_eq!(
        send(&f, &join.token, &original).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        pending(&f, &join.token, &join.status.ticket.device.device_id, 100)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        pending(&f, &a.token, &a.device, 100).await.status(),
        StatusCode::OK
    );
    f.db.revoke_session(&auth::service::hash_token(&a.token))
        .await
        .unwrap();
    assert_eq!(
        pending(&f, &a.token, &a.device, 100).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn parallel_v3_and_legacy_queue_quota_cannot_accept_partial_audience() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    let c = f.account().await;
    accepted(&f, &a, &b).await;
    accepted(&f, &c, &b).await;
    let (_, as_) = grant(&f, &a, &directory(&f, &a)).await;
    let bs = directory(&f, &b);
    let cs = directory(&f, &c);
    // Existing synthetic legacy load, not 999 validated message deliveries.
    sqlx::query("INSERT INTO offline_messages(id,protocol_version,message_id,conversation_id,from_user_id,sender_device_id,sender_seq,prev_hash,recipient_user_id,recipient_device_id,ciphertext,signature,timestamp,created_at) SELECT $1||'-'||i::TEXT,2,$1||'-'||i::TEXT,'quota',$2,$3,i,''::BYTEA,$4,$5,'x'::BYTEA,'x'::BYTEA,1,now() FROM generate_series(1,999) i")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&a.id).bind(&a.device).bind(&b.id).bind(&b.device).execute(f.db.pool()).await.unwrap();
    let one = batch(&as_, &bs, &a.device, &a.keys, None, b"one slot");
    let two = batch(&cs, &bs, &c.device, &c.keys, None, b"other sender");
    let (r1, r2) = tokio::join!(send(&f, &a.token, &one), send(&f, &c.token, &two));
    let statuses = [r1.status(), r2.status()];
    assert!(statuses.contains(&StatusCode::OK));
    assert!(statuses.contains(&StatusCode::TOO_MANY_REQUESTS));
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM direct_v3_deliveries WHERE device=$1 AND state='stored'",
    )
    .bind(&b.device)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(count, 1);
    let (winner, loser, token, sender) = if r1.status() == StatusCode::OK {
        (&one, &two, &c.token, &as_)
    } else {
        (&two, &one, &a.token, &cs)
    };
    let partial: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM direct_v3_deliveries WHERE batch=$1")
            .bind(&loser.header.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(partial, 0);
    let winner_ack = Ack::make(
        winner,
        sender,
        &bs,
        &b.id,
        &b.device,
        &b.keys,
        AckOutcome::Processed,
    )
    .unwrap();
    let legacy = crate::db::OfflineMessageRecord {
        protocol_version: 2,
        message_id: uuid::Uuid::new_v4().to_string(),
        conversation_id: liteseal_shared::direct_message::conversation(&a.id, &b.id).unwrap(),
        from_user_id: a.id.clone(),
        sender_device_id: a.device.clone(),
        sender_seq: 1001,
        prev_hash: vec![1; 32],
        recipient_user_id: b.id.clone(),
        recipient_device_id: b.device.clone(),
        message_type: "text".into(),
        ciphertext: vec![1; 40],
        signature: vec![1; 64],
        timestamp: now(),
    };
    assert_eq!(
        f.db.store_offline_message(&legacy).await.unwrap(),
        crate::db::StoreOfflineOutcome::QuotaExceeded
    );
    assert_eq!(
        ack(&f, &b.token, &winner_ack).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(send(&f, token, loser).await.status(), StatusCode::OK);
    // Quota failure never advanced the loser's sequence or accepted receipt.
    assert_eq!(loser.header.sequence, 1);
}

#[tokio::test]
#[cfg(windows)]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn real_http_receipt_reopens_native_protected_store_before_independent_ack() {
    use liteseal_core::{
        backup::WorkDirectory,
        trusted_devices::{
            messages::{Acceptance, Owner, Prepare, Store},
            witness::platform::Protection,
        },
    };
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let as_ = directory(&f, &a);
    let bs = directory(&f, &b);
    let protection = Protection::isolated_test();
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let sender_path = work.0.join("sender.db");
    let receiver_path = work.0.join("receiver.db");
    let aowner = Owner::new(&f.url, &a.id, &a.device, &a.keys).unwrap();
    let bowner = Owner::new(&f.url, &b.id, &b.device, &b.keys).unwrap();
    let open = |path: &std::path::Path, owner: Owner| {
        drop(liteseal_core::trusted_devices::DeviceTrustStore::open(path).unwrap());
        let mut store = Store::open(path, owner, protection.witness(path).unwrap()).unwrap();
        store.trust().pin(as_.anchor()).unwrap();
        store.trust().pin(bs.anchor()).unwrap();
        store
    };
    let mut sender = open(&sender_path, aowner.clone());
    let id = uuid::Uuid::new_v4().to_string();
    let task = sender
        .prepare(
            Prepare {
                id: &id,
                peer: &b.id,
                sent_at: now(),
                kind: Kind::Text,
                body: "原批次🙂".as_bytes(),
            },
            &a.keys,
        )
        .unwrap();
    let original = sender.original(&id, &a.keys).unwrap();
    sender.begin_publish(&id, task.revision, &a.keys).unwrap();
    assert_eq!(send(&f, &a.token, &original).await.status(), StatusCode::OK);
    drop(sender);
    let mut sender = open(&sender_path, aowner);
    assert_eq!(
        sender.original(&id, &a.keys).unwrap().to_wire().unwrap(),
        original.to_wire().unwrap()
    );
    let Outcome::Accepted { receipt, .. } = lookup(&f, &a.token, &original)
        .await
        .json::<Outcome>()
        .await
        .unwrap()
    else {
        panic!("original result missing")
    };
    let accepted = Acceptance::from_authenticated_response(
        &original,
        &receipt.id,
        receipt.digest,
        receipt.accepted_at,
    )
    .unwrap();
    sender.confirm_accepted(&accepted, &a.keys).unwrap();
    assert_eq!(sender.body(&id, &a.keys).unwrap(), "原批次🙂".as_bytes());
    let page = pending(&f, &b.token, &b.device, 100)
        .await
        .json::<Page>()
        .await
        .unwrap();
    let delivery = &page.items[0];
    let accepted = Acceptance::from_authenticated_response(
        &delivery.batch,
        &delivery.receipt.id,
        delivery.receipt.digest,
        delivery.receipt.accepted_at,
    )
    .unwrap();
    let mut receiver = open(&receiver_path, bowner.clone());
    receiver
        .receive(&delivery.batch, &accepted, &b.keys)
        .unwrap();
    let signed = receiver.pending_acks(&b.keys).unwrap().pop().unwrap();
    let ack_wire = signed.to_wire().unwrap();
    drop(receiver);
    let mut receiver = open(&receiver_path, bowner);
    assert_eq!(
        receiver.pending_acks(&b.keys).unwrap()[0]
            .to_wire()
            .unwrap(),
        ack_wire
    );
    assert_eq!(
        ack(&f, &b.token, &signed).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        ack(&f, &b.token, &signed).await.status(),
        StatusCode::NO_CONTENT
    );
    receiver.confirm_ack(&signed, &b.keys).unwrap();
    receiver.hide(&id, &b.keys).unwrap();
    receiver
        .receive(&delivery.batch, &accepted, &b.keys)
        .unwrap();
    assert!(receiver.history(None, 100, &b.keys).unwrap().is_empty());
    assert_eq!(
        receiver.pending_acks(&b.keys).unwrap()[0]
            .to_wire()
            .unwrap(),
        ack_wire
    );
    assert!(pending(&f, &b.token, &b.device, 100)
        .await
        .json::<Page>()
        .await
        .unwrap()
        .items
        .is_empty());
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn maximum_text_page_respects_wire_budget_and_byte_quota() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let as_ = directory(&f, &a);
    let bs = directory(&f, &b);
    let body = "汉".repeat(5461);
    let mut previous = None;
    for _ in 0..12 {
        let next = batch(
            &as_,
            &bs,
            &a.device,
            &a.keys,
            previous.as_ref(),
            body.as_bytes(),
        );
        assert_eq!(send(&f, &a.token, &next).await.status(), StatusCode::OK);
        previous = Some(next);
    }
    let wire = pending(&f, &b.token, &b.device, 100)
        .await
        .bytes()
        .await
        .unwrap();
    assert!(wire.len() <= liteseal_shared::direct_transport::MAX_PAGE_BYTES);
    let page: Page = serde_json::from_slice(&wire).unwrap();
    assert!(page.has_more);
    assert!(!page.items.is_empty());
    assert!(page.items.len() < 12);
    // Synthetic existing byte load exceeds the remaining cap, independent of count.
    sqlx::query("INSERT INTO offline_messages(id,protocol_version,message_id,conversation_id,from_user_id,sender_device_id,sender_seq,prev_hash,recipient_user_id,recipient_device_id,ciphertext,signature,timestamp,created_at) VALUES($1,2,$1,'byte quota',$2,$3,1,''::BYTEA,$4,$5,decode(repeat('00',10485760),'hex'),'x'::BYTEA,1,now())")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&a.id).bind(&a.device).bind(&b.id).bind(&b.device).execute(f.db.pool()).await.unwrap();
    let next = batch(
        &as_,
        &bs,
        &a.device,
        &a.keys,
        previous.as_ref(),
        b"over bytes",
    );
    assert_eq!(
        send(&f, &a.token, &next).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert!(matches!(
        lookup(&f, &a.token, &next)
            .await
            .json::<Outcome>()
            .await
            .unwrap(),
        Outcome::Unknown { .. }
    ));
}
