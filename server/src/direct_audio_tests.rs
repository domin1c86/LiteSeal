//! Synthetic isolated HTTP/PG and native call tests. No actual audio devices.
use super::*;
use liteseal_shared::voice_call as v;
fn admission(f: &Fixture, a: &Account, b: &Account) -> v::Admission {
    v::Admission::make(
        v::Header::new(
            &directory(f, a),
            &a.device,
            &directory(f, b),
            &b.device,
            v::SignalSpec {
                id: hex::encode(crypto::random_challenge().unwrap()),
                sequence: 1,
                sent_at: now(),
                kind: v::Kind::Offer,
            },
        )
        .unwrap(),
        &a.keys,
    )
    .unwrap()
}
fn audio_sdp() -> String {
    format!("v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=ice-ufrag:isolated\r\na=ice-pwd:isolated-generated-test-only\r\na=fingerprint:sha-256 {}\r\na=rtcp-mux\r\na=rtpmap:111 opus/48000/2\r\n",vec!["AA";32].join(":"))
}
async fn pending(f: &Fixture, account: &Account, active: Option<&str>) -> v::Pending {
    let mut request = f
        .client
        .get(format!("{}/audio/v1/pending", f.url))
        .bearer_auth(&account.token)
        .query(&[("device", &account.device)]);
    if let Some(id) = active {
        request = request.query(&[("active", id)]);
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}
async fn reserve(f: &Fixture, a: &Account, admission: &v::Admission) -> reqwest::Response {
    f.client
        .post(format!("{}/audio/v1/admit", f.url))
        .bearer_auth(&a.token)
        .json(admission)
        .send()
        .await
        .unwrap()
}
async fn publish(
    f: &Fixture,
    a: &Account,
    ticket: &str,
    envelope: v::Envelope,
) -> reqwest::Response {
    f.client
        .post(format!("{}/audio/v1/signal", f.url))
        .bearer_auth(&a.token)
        .json(&v::Submission {
            ticket: ticket.into(),
            envelope,
        })
        .send()
        .await
        .unwrap()
}
async fn close(f: &Fixture, a: &Account, stop: &v::Stop) -> reqwest::Response {
    f.client
        .post(format!("{}/audio/v1/stop", f.url))
        .bearer_auth(&a.token)
        .json(stop)
        .send()
        .await
        .unwrap()
}
fn wire(
    f: &Fixture,
    a: &Account,
    b: &Account,
    id: &str,
    sequence: u64,
    kind: v::Kind,
) -> v::Envelope {
    v::Envelope::seal(
        v::Header::new(
            &directory(f, a),
            &a.device,
            &directory(f, b),
            &b.device,
            v::SignalSpec {
                id: id.into(),
                sequence,
                sent_at: now(),
                kind,
            },
        )
        .unwrap(),
        &directory(f, a),
        &directory(f, b),
        &a.keys,
        matches!(kind, v::Kind::Offer | v::Kind::Answer | v::Kind::Restart).then(audio_sdp),
    )
    .unwrap()
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn original_admission_retry_stop_before_reserve_and_wrong_proofs_fail_closed() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    accepted(&f, &b, &a).await;
    pending(&f, &b, None).await;
    let original = admission(&f, &a, &b);
    let stop = v::Stop::make(original.clone(), original.header.source.clone(), &a.keys).unwrap();
    let mut forged = stop.clone();
    forged.signature[0] ^= 1;
    assert_eq!(close(&f, &a, &forged).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(close(&f, &a, &stop).await.status(), StatusCode::OK);
    assert_eq!(close(&f, &a, &stop).await.status(), StatusCode::OK);
    assert_eq!(
        reserve(&f, &a, &original).await.status(),
        StatusCode::CONFLICT
    );
    let next = admission(&f, &a, &b);
    let first = reserve(&f, &a, &next).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first: v::Reservation = first.json().await.unwrap();
    let retry: v::Reservation = reserve(&f, &a, &next).await.json().await.unwrap();
    assert_eq!(first.id, retry.id);
    assert_eq!(first.ticket, retry.ticket);
    let mut replaced = next.header.clone();
    replaced.sent_at += 1;
    replaced.expires_at += 1;
    let replaced = v::Admission::make(replaced, &a.keys).unwrap();
    assert_ne!(reserve(&f, &a, &replaced).await.status(), StatusCode::OK);
    let wrong = wire(&f, &a, &b, &next.header.id, 1, v::Kind::Offer);
    assert_eq!(
        publish(&f, &a, &"0".repeat(64), wrong).await.status(),
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn encrypted_audio_receipt_retries_and_invalid_sequence_do_not_mutate_negotiation() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    accepted(&f, &b, &a).await;
    pending(&f, &b, None).await;
    let original = admission(&f, &a, &b);
    let id = &original.header.id;
    let reservation: v::Reservation = reserve(&f, &a, &original).await.json().await.unwrap();
    let offer = wire(&f, &a, &b, id, 1, v::Kind::Offer);
    let mut forged = offer.clone();
    forged.signature[0] ^= 1;
    assert_eq!(
        publish(&f, &a, &reservation.ticket, forged).await.status(),
        StatusCode::FORBIDDEN
    );
    for _ in 0..2 {
        assert_eq!(
            publish(&f, &a, &reservation.ticket, offer.clone())
                .await
                .status(),
            StatusCode::OK
        );
    }
    let delivery = pending(&f, &b, Some(id)).await.delivery.unwrap();
    assert_eq!(
        delivery
            .envelope
            .open(&directory(&f, &a), &directory(&f, &b), &b.keys, now())
            .unwrap()
            .sdp
            .as_deref(),
        Some(audio_sdp().as_str())
    );
    assert!(pending(&f, &b, Some(id)).await.delivery.is_some());
    let ack = v::Acknowledge {
        device: b.device.clone(),
        ticket: reservation.ticket.clone(),
        receipt: v::Receipt {
            id: id.clone(),
            sequence: 1,
            digest: offer.digest().unwrap(),
        },
    };
    for _ in 0..2 {
        let response = f
            .client
            .post(format!("{}/audio/v1/ack", f.url))
            .bearer_auth(&b.token)
            .json(&ack)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert!(pending(&f, &b, Some(id)).await.delivery.is_none());
    let gap = wire(&f, &b, &a, id, 2, v::Kind::Answer);
    assert_eq!(
        publish(&f, &b, &reservation.ticket, gap).await.status(),
        StatusCode::FORBIDDEN
    );
    let answer = wire(&f, &b, &a, id, 1, v::Kind::Answer);
    assert_eq!(
        publish(&f, &b, &reservation.ticket, answer).await.status(),
        StatusCode::OK
    );
    assert!(pending(&f, &a, Some(id)).await.delivery.is_some());
    let stop = v::Stop::make(original.clone(), original.header.target.clone(), &b.keys).unwrap();
    assert_eq!(close(&f, &b, &stop).await.status(), StatusCode::OK);
    assert_eq!(
        pending(&f, &a, Some(id)).await.closed.as_deref(),
        Some(id.as_str())
    );
    let persisted: i64 = sqlx::query_scalar("SELECT count(*) FROM direct_v3_batches WHERE id=$1")
        .bind(id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(persisted, 0);
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn mutual_contact_presence_busy_and_policy_revocation_fence_calls() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    assert_eq!(
        reserve(&f, &a, &admission(&f, &a, &b)).await.status(),
        StatusCode::CONFLICT
    );
    pending(&f, &b, None).await;
    assert_eq!(
        reserve(&f, &a, &admission(&f, &a, &b)).await.status(),
        StatusCode::FORBIDDEN
    );
    accepted(&f, &b, &a).await;
    let original = admission(&f, &a, &b);
    assert_eq!(reserve(&f, &a, &original).await.status(), StatusCode::OK);
    assert_eq!(
        reserve(&f, &a, &admission(&f, &a, &b)).await.status(),
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE contact_policy SET status='blocked' WHERE user_id=$1 AND peer_id=$2")
        .bind(&b.id)
        .bind(&a.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        pending(&f, &a, Some(&original.header.id))
            .await
            .closed
            .as_deref(),
        Some(original.header.id.as_str())
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn native_call_handles_are_one_use_and_session_retirement_drops_original_call() {
    use liteseal_core::{
        backup::WorkDirectory,
        trusted_devices::{
            messages::{coordinator::MessageCoordinator, Owner},
            tasks::anchor_fingerprint,
            witness::platform::Protection,
        },
    };
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    accepted(&f, &b, &a).await;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let make = |account: &Account, name: &str| {
        let actor = MessageCoordinator::open_with_protection(
            &work.0.join(name),
            Owner::new(&f.url, &account.id, &account.device, &account.keys).unwrap(),
            &account.keys,
            protection.clone(),
        )
        .unwrap();
        for directory in [directory(&f, &a), directory(&f, &b)] {
            actor
                .confirm_root(
                    directory.anchor(),
                    &anchor_fingerprint(directory.anchor()),
                    &account.keys,
                )
                .unwrap();
        }
        actor.renew_session(account.token.clone()).unwrap();
        actor
    };
    let caller = make(&a, "audio-caller.db");
    let callee = make(&b, "audio-callee.db");
    callee.poll_audio(&b.keys).await.unwrap();
    let call = caller.begin_audio(&b.id, &b.device, &a.keys).await.unwrap();
    let handle = caller
        .prepare_audio_signal(&call.id, v::Kind::Offer, Some(audio_sdp()), &a.keys)
        .unwrap();
    assert!(caller.open_audio_signal(&handle, &a.keys).is_err());
    caller.publish_audio_signal(&handle, &a.keys).await.unwrap();
    assert!(caller.publish_audio_signal(&handle, &a.keys).await.is_err());
    let pending = callee.poll_audio(&b.keys).await.unwrap();
    let incoming = pending.handle.unwrap();
    assert!(callee.open_audio_signal(&incoming, &a.keys).is_err());
    let signal = callee.open_audio_signal(&incoming, &b.keys).unwrap();
    assert_eq!(signal.kind, v::Kind::Offer);
    assert!(callee.open_audio_signal(&incoming, &b.keys).is_err());
    let answer = callee
        .prepare_audio_signal(&call.id, v::Kind::Answer, Some(audio_sdp()), &b.keys)
        .unwrap();
    callee.publish_audio_signal(&answer, &b.keys).await.unwrap();
    let incoming = caller.poll_audio(&a.keys).await.unwrap().handle.unwrap();
    caller.renew_session(a.token.clone()).unwrap();
    assert!(caller.open_audio_signal(&incoming, &a.keys).is_err());
    assert!(caller
        .prepare_audio_signal(&call.id, v::Kind::Restart, Some(audio_sdp()), &a.keys)
        .is_err());
    assert!(caller.tasks(&a.keys).unwrap().is_empty());
    // Cancellation is best effort, bounded to 5s; cleanup is witnessed through
    // the callee's current original call instead of inspecting worker tokens.
    callee.retire_audio(&call.id, &b.keys).unwrap();
}
