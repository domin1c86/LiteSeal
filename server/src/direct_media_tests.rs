//! Marked dedicated PostgreSQL only; all files and identities are synthetic.
use super::*;
use liteseal_core::trusted_devices::messages::api::{DirectApi, MediaObject, RemoteState};
use liteseal_shared::direct_media::{self as m, Descriptor, Submission};

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn core_http_client_upload_publish_four_device_download_and_expiry() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    let (aj, sender) = grant(&f, &a, &directory(&f, &a)).await;
    let (bj, peer) = grant(&f, &b, &directory(&f, &b)).await;
    let at = synthetic_activation(&f, &a, &aj).await;
    let bt = synthetic_activation(&f, &b, &bj).await;
    accepted(&f, &a, &b).await;
    let bytes = "中文与 emoji 🦭".as_bytes().repeat(70_000);
    let (value, cipher) = media(&sender, &peer, &a.device, &a.keys, &bytes);
    let api = DirectApi::new(&f.url).unwrap();
    let object = MediaObject {
        device: &a.device,
        id: &value.batch.header.id,
        reference: &value.object,
    };
    for _ in 0..2 {
        api.create_media(&a.token, object.device, object.id, &b.id, object.reference)
            .await
            .unwrap();
    }
    api.upload_media_chunk(&a.token, &object, 0, cipher[..m::CHUNK].to_vec())
        .await
        .unwrap();
    assert_eq!(
        api.publish_media(&a.token, &value)
            .await
            .err()
            .unwrap()
            .status,
        Some(409)
    );
    assert_eq!(
        api.lookup(&a.token, &value.batch).await.unwrap().state(),
        RemoteState::Unknown
    );
    for (part, bytes) in cipher.chunks(m::CHUNK).enumerate() {
        api.upload_media_chunk(&a.token, &object, part as i32, bytes.to_vec())
            .await
            .unwrap();
    }
    for _ in 0..2 {
        assert_eq!(
            api.publish_media(&a.token, &value).await.unwrap().state(),
            RemoteState::Accepted
        );
    }
    assert_eq!(
        api.pending(&b.token, &b.id, &b.device, 1)
            .await
            .unwrap()
            .len(),
        1
    );
    for (token, device) in [
        (&a.token, &a.device),
        (&at, &aj.status.ticket.device.device_id),
        (&b.token, &b.device),
        (&bt, &bj.status.ticket.device.device_id),
    ] {
        let target = MediaObject { device, ..object };
        let mut downloaded = vec![];
        for part in 0..cipher.len().div_ceil(m::CHUNK) {
            downloaded.extend(
                api.download_media_chunk(token, &target, part as i32)
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(downloaded, cipher);
        let body = value
            .batch
            .open(&sender, &peer, &b.id, &b.device, &b.keys)
            .unwrap();
        let descriptor = Descriptor::from_body(&value.batch.header, &body).unwrap();
        assert_eq!(
            descriptor.decrypt(Kind::Attachment, &downloaded).unwrap(),
            bytes
        );
    }
    sqlx::query(
        "UPDATE direct_v3_media_objects SET expires_at=now()-interval '1 second' WHERE id=$1",
    )
    .bind(object.id)
    .execute(f.db.pool())
    .await
    .unwrap();
    let target = MediaObject {
        device: &b.device,
        ..object
    };
    assert_eq!(
        api.download_media_chunk(&b.token, &target, 0)
            .await
            .err()
            .unwrap()
            .status,
        Some(404)
    );
    assert_eq!(
        api.lookup(&a.token, &value.batch).await.unwrap().state(),
        RemoteState::Accepted
    );
    assert_eq!(
        api.publish_media(&a.token, &value).await.unwrap().state(),
        RemoteState::Accepted
    );
}
fn media(
    a: &DeviceState,
    b: &DeviceState,
    device: &str,
    keys: &crypto::KeyPair,
    bytes: &[u8],
) -> (Submission, Vec<u8>) {
    let id = uuid::Uuid::new_v4().to_string();
    let (descriptor, cipher) = Descriptor::encrypt(
        id.clone(),
        "synthetic.bin".into(),
        bytes,
        Kind::Attachment,
        None,
    )
    .unwrap();
    let header = Header::new(
        a,
        b,
        device,
        MessageSpec {
            id,
            sequence: 1,
            previous: vec![],
            sent_at: now(),
            kind: Kind::Attachment,
        },
    )
    .unwrap();
    (
        Submission::make(header, a, b, keys, &descriptor).unwrap(),
        cipher,
    )
}
async fn stage(f: &Fixture, token: &str, value: &Submission) -> reqwest::Response {
    f.client.post(format!("{}/direct/v3/media/objects",f.url)).bearer_auth(token).json(&serde_json::json!({"device_id":value.batch.header.sender_device,"id":value.batch.header.id,"peer":value.batch.header.peer,"size":value.object.size,"hash":value.object.hash})).send().await.unwrap()
}
async fn put(
    f: &Fixture,
    token: &str,
    value: &Submission,
    part: usize,
    bytes: Vec<u8>,
) -> reqwest::Response {
    f.client
        .put(format!(
            "{}/direct/v3/media/objects/{}/{}",
            f.url, value.batch.header.id, part
        ))
        .bearer_auth(token)
        .query(&[("device_id", value.batch.header.sender_device.as_str())])
        .body(bytes)
        .send()
        .await
        .unwrap()
}
async fn get(f: &Fixture, token: &str, id: &str, device: &str, part: usize) -> reqwest::Response {
    f.client
        .get(format!("{}/direct/v3/media/objects/{id}/{part}", f.url))
        .bearer_auth(token)
        .query(&[("device_id", device)])
        .send()
        .await
        .unwrap()
}
async fn publish(f: &Fixture, token: &str, value: &Submission) -> reqwest::Response {
    f.client
        .post(format!("{}/direct/v3/media/batches", f.url))
        .bearer_auth(token)
        .json(value)
        .send()
        .await
        .unwrap()
}
async fn upload_all(f: &Fixture, token: &str, value: &Submission, cipher: &[u8]) {
    assert_eq!(stage(f, token, value).await.status(), StatusCode::OK);
    for (part, bytes) in cipher.chunks(m::CHUNK).enumerate() {
        assert_eq!(
            put(f, token, value, part, bytes.to_vec()).await.status(),
            StatusCode::NO_CONTENT
        );
    }
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn complete_upload_atomic_audience_exact_retry_and_expired_result() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    let (aj, as_) = grant(&f, &a, &directory(&f, &a)).await;
    let (bj, bs) = grant(&f, &b, &directory(&f, &b)).await;
    let at = synthetic_activation(&f, &a, &aj).await;
    let bt = synthetic_activation(&f, &b, &bj).await;
    accepted(&f, &a, &b).await;
    let bytes = vec![7; m::CHUNK + 8];
    let (value, cipher) = media(&as_, &bs, &a.device, &a.keys, &bytes);
    assert_eq!(stage(&f, &a.token, &value).await.status(), StatusCode::OK);
    assert_eq!(stage(&f, &a.token, &value).await.status(), StatusCode::OK);
    assert_eq!(
        put(&f, &a.token, &value, 0, cipher[..m::CHUNK].to_vec())
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put(&f, &a.token, &value, 0, cipher[..m::CHUNK].to_vec())
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put(&f, &a.token, &value, 0, vec![2; m::CHUNK])
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        publish(&f, &a.token, &value).await.status(),
        StatusCode::CONFLICT
    );
    assert!(pending(&f, &b.token, &b.device, 100)
        .await
        .json::<Page>()
        .await
        .unwrap()
        .items
        .is_empty());
    assert_eq!(
        get(&f, &b.token, &value.batch.header.id, &b.device, 0)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(&f, &a.token, &value, 1, cipher[m::CHUNK..].to_vec())
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let result = publish(&f, &a.token, &value).await;
    assert_eq!(result.status(), StatusCode::OK);
    let result = result.json::<Outcome>().await.unwrap();
    assert_eq!(
        publish(&f, &a.token, &value)
            .await
            .json::<Outcome>()
            .await
            .unwrap(),
        result
    );
    for (token, device) in [
        (&a.token, &a.device),
        (&at, &aj.status.ticket.device.device_id),
        (&b.token, &b.device),
        (&bt, &bj.status.ticket.device.device_id),
    ] {
        let mut downloaded = Vec::new();
        for part in 0..2 {
            let reply = get(&f, token, &value.batch.header.id, device, part).await;
            assert_eq!(reply.status(), StatusCode::OK);
            downloaded.extend_from_slice(&reply.bytes().await.unwrap());
        }
        assert_eq!(downloaded, cipher);
    }
    let body = value
        .batch
        .open(&as_, &bs, &b.id, &b.device, &b.keys)
        .unwrap();
    let descriptor = Descriptor::from_body(&value.batch.header, &body).unwrap();
    assert_eq!(
        descriptor.decrypt(Kind::Attachment, &cipher).unwrap(),
        bytes
    );
    let mut changed = value.clone();
    changed.object.hash[0] ^= 1;
    assert_eq!(
        publish(&f, &a.token, &changed).await.status(),
        StatusCode::FORBIDDEN
    );
    sqlx::query(
        "UPDATE direct_v3_media_objects SET expires_at=now()-interval '1 second' WHERE id=$1",
    )
    .bind(&value.batch.header.id)
    .execute(f.db.pool())
    .await
    .unwrap();
    crate::direct_messages::media::cleanup(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        get(&f, &b.token, &value.batch.header.id, &b.device, 0)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        publish(&f, &a.token, &value)
            .await
            .json::<Outcome>()
            .await
            .unwrap(),
        result
    );
    assert_eq!(
        stage(&f, &a.token, &value).await.status(),
        StatusCode::CONFLICT
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn revoked_and_new_grants_cannot_download_original_media_and_policy_is_current() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    let as_ = directory(&f, &a);
    let (bj, bs) = grant(&f, &b, &directory(&f, &b)).await;
    let bt = synthetic_activation(&f, &b, &bj).await;
    accepted(&f, &a, &b).await;
    let (value, cipher) = media(&as_, &bs, &a.device, &a.keys, b"original audience");
    upload_all(&f, &a.token, &value, &cipher).await;
    assert_eq!(publish(&f, &a.token, &value).await.status(), StatusCode::OK);
    assert_eq!(
        get(
            &f,
            &bt,
            &value.batch.header.id,
            &bj.status.ticket.device.device_id,
            0
        )
        .await
        .status(),
        StatusCode::OK
    );
    let revoke = make_event(
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
    assert_eq!(f.submit(&b, &revoke).await.status(), StatusCode::OK);
    let revoked = bs.apply(&revoke).unwrap();
    assert!(matches!(
        get(
            &f,
            &bt,
            &value.batch.header.id,
            &bj.status.ticket.device.device_id,
            0
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));
    let (fresh, _) = grant(&f, &b, &revoked).await;
    let fresh_token = synthetic_activation(&f, &b, &fresh).await;
    assert_eq!(
        get(
            &f,
            &fresh_token,
            &value.batch.header.id,
            &fresh.status.ticket.device.device_id,
            0
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&f, &b.token, &value.batch.header.id, &b.device, 0)
            .await
            .status(),
        StatusCode::OK
    );
    sqlx::query("UPDATE contact_policy SET status='blocked' WHERE user_id=$1 AND peer_id=$2")
        .bind(&b.id)
        .bind(&a.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        get(&f, &b.token, &value.batch.header.id, &b.device, 0)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(publish(&f, &a.token, &value).await.status(), StatusCode::OK); // Original accepted result remains queryable.
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn legacy_and_v3_share_quota_and_bad_chunks_or_original_cancel_cannot_publish() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let as_ = directory(&f, &a);
    let bs = directory(&f, &b);
    let (value, cipher) = media(&as_, &bs, &a.device, &a.keys, b"file");
    let ids = (0..2000)
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect::<Vec<_>>();
    sqlx::query("INSERT INTO attachment_objects(id,owner,message_id,recipient,size,expires_at) SELECT id,$2,id,$3,40,now()+interval '30 days' FROM unnest($1::text[]) AS source(id)").bind(ids).bind(&a.id).bind(&b.id).execute(f.db.pool()).await.unwrap();
    assert_eq!(
        stage(&f, &a.token, &value).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    sqlx::query("DELETE FROM attachment_objects WHERE owner=$1")
        .bind(&a.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(stage(&f, &a.token, &value).await.status(), StatusCode::OK);
    assert_eq!(
        put(&f, &a.token, &value, 1, vec![0]).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put(&f, &a.token, &value, 0, vec![0; cipher.len()])
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        publish(&f, &a.token, &value).await.status(),
        StatusCode::CONFLICT
    ); // Correct length, wrong full digest.
    assert!(pending(&f, &b.token, &b.device, 100)
        .await
        .json::<Page>()
        .await
        .unwrap()
        .items
        .is_empty());
    assert_eq!(
        cancel(&f, &a.token, &value.batch).await.status(),
        StatusCode::OK
    );
    let Outcome::Cancelled { .. } = publish(&f, &a.token, &value)
        .await
        .json::<Outcome>()
        .await
        .unwrap()
    else {
        panic!("cancelled original unexpectedly published");
    };
    assert_eq!(
        get(&f, &b.token, &value.batch.header.id, &b.device, 0)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    sqlx::query(
        "UPDATE direct_v3_media_objects SET created_at=now()-interval '25 hours' WHERE id=$1",
    )
    .bind(&value.batch.header.id)
    .execute(f.db.pool())
    .await
    .unwrap();
    crate::direct_messages::media::cleanup(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        stage(&f, &a.token, &value).await.status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn concurrent_legacy_and_v3_quota_admission_never_overfills_or_deadlocks() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let as_ = directory(&f, &a);
    let bs = directory(&f, &b);
    let ids = (0..1999)
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect::<Vec<_>>();
    sqlx::query("INSERT INTO attachment_objects(id,owner,message_id,recipient,size,expires_at) SELECT id,$2,id,$3,40,now()+interval '30 days' FROM unnest($1::text[]) AS source(id)").bind(ids).bind(&a.id).bind(&b.id).execute(f.db.pool()).await.unwrap();
    let (one, _) = media(&as_, &bs, &a.device, &a.keys, b"one");
    let (two, _) = media(&as_, &bs, &a.device, &a.keys, b"two");
    let legacy = async {
        f.client.post(format!("{}/attachments",f.url)).bearer_auth(&a.token).json(&serde_json::json!({"device_id":a.device,"id":uuid::Uuid::new_v4().to_string(),"message_id":uuid::Uuid::new_v4().to_string(),"recipient":b.id,"size":43})).send().await.unwrap()
    };
    let (one, two, legacy) =
        tokio::join!(stage(&f, &a.token, &one), stage(&f, &a.token, &two), legacy);
    let results = [one.status(), two.status(), legacy.status()];
    assert_eq!(results.iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|s| **s == StatusCode::PAYLOAD_TOO_LARGE)
            .count(),
        2
    );
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT id FROM attachment_objects WHERE owner=$1 UNION ALL SELECT id FROM direct_v3_media_objects WHERE owner=$1 UNION ALL SELECT id FROM group_attachment_objects WHERE owner=$1) a").bind(&a.id).fetch_one(f.db.pool()).await.unwrap();
    assert_eq!(count, 2000);
    sqlx::query("DELETE FROM attachment_objects WHERE owner=$1")
        .bind(&a.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM direct_v3_media_objects WHERE owner=$1")
        .bind(&a.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    let ids = (0..26)
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect::<Vec<_>>();
    sqlx::query("INSERT INTO attachment_objects(id,owner,message_id,recipient,size,expires_at) SELECT id,$2,id,$3,CASE WHEN n<=25 THEN 20971560 ELSE 12581872 END,now()+interval '30 days' FROM unnest($1::text[]) WITH ORDINALITY AS source(id,n)").bind(ids).bind(&a.id).bind(&b.id).execute(f.db.pool()).await.unwrap();
    let (over_bytes, _) = media(&as_, &bs, &a.device, &a.keys, b"file");
    assert_eq!(
        stage(&f, &a.token, &over_bytes).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
