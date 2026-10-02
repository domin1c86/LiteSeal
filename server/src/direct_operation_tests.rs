//! Isolated HTTP/PostgreSQL identities, including body release and old phases.
use super::*;
use liteseal_shared::direct_operation::{self as op, Action, Operation, Page};
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn core_imports_real_operation_page_before_root_reopens_and_projects_retraction() {
    use liteseal_core::{
        backup::WorkDirectory,
        trusted_devices::{
            messages::{api::DirectApi, Acceptance, Owner, Store},
            witness::platform::Protection,
        },
    };
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let s = directory(&f, &a);
    let p = directory(&f, &b);
    let original = batch(
        &s,
        &p,
        &a.device,
        &a.keys,
        None,
        "原正文 中文 🦭".as_bytes(),
    );
    assert_eq!(send(&f, &a.token, &original).await.status(), StatusCode::OK);
    let edit = make(
        &original,
        (&s, &p),
        (&s, &p),
        &a.keys,
        0,
        Action::Edit,
        Some("网络补收 编辑 🦭"),
    );
    assert_eq!(submit(&f, &a.token, &edit).await.status(), StatusCode::OK);
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let path = work.0.join("operation-recipient.db");
    drop(liteseal_core::trusted_devices::DeviceTrustStore::open(&path).unwrap());
    let owner = Owner::new(&f.url, &b.id, &b.device, &b.keys).unwrap();
    let mut store = Store::open(&path, owner.clone(), protection.witness(&path).unwrap()).unwrap();
    store.trust().pin(s.anchor()).unwrap();
    store.trust().pin(p.anchor()).unwrap();
    let api = DirectApi::new(&f.url).unwrap();
    let page = api
        .operations(&b.token, &b.id, &b.device, 0, 100)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert!(!page.has_more());
    let cursor = page.through();
    let other_path = work.0.join("operation-wrong-recipient.db");
    drop(liteseal_core::trusted_devices::DeviceTrustStore::open(&other_path).unwrap());
    let other_owner = Owner::new(&f.url, &a.id, &a.device, &a.keys).unwrap();
    let mut other = Store::open(
        &other_path,
        other_owner,
        protection.witness(&other_path).unwrap(),
    )
    .unwrap();
    other.trust().pin(s.anchor()).unwrap();
    other.trust().pin(p.anchor()).unwrap();
    assert!(other
        .import_authenticated_operations(0, &page, &a.keys)
        .is_err());
    assert_eq!(other.operation_cursor(&a.keys).unwrap(), 0);
    assert!(store
        .import_authenticated_operations(1, &page, &b.keys)
        .is_err());
    store
        .import_authenticated_operations(0, &page, &b.keys)
        .unwrap();
    assert!(store.history(None, 100, &b.keys).unwrap().is_empty());
    drop(store);
    let mut store = Store::open(&path, owner, protection.witness(&path).unwrap()).unwrap();
    assert_eq!(store.operation_cursor(&b.keys).unwrap(), cursor);
    let liteseal_shared::direct_transport::Result::Accepted { receipt, .. } =
        lookup(&f, &a.token, &original).await.json().await.unwrap()
    else {
        panic!("original receipt missing")
    };
    let acceptance = Acceptance::from_authenticated_response(
        &original,
        &receipt.id,
        receipt.digest,
        receipt.accepted_at,
    )
    .unwrap();
    store.receive(&original, &acceptance, &b.keys).unwrap();
    assert_eq!(
        store.body(&original.header.id, &b.keys).unwrap(),
        "网络补收 编辑 🦭".as_bytes()
    );
    let retract = make(
        &original,
        (&s, &p),
        (&s, &p),
        &a.keys,
        1,
        Action::Retract,
        None,
    );
    assert_eq!(
        submit(&f, &a.token, &retract).await.status(),
        StatusCode::OK
    );
    let next = api
        .operations(&b.token, &b.id, &b.device, cursor, 100)
        .await
        .unwrap();
    assert_eq!(next.len(), 1);
    store
        .import_authenticated_operations(cursor, &next, &b.keys)
        .unwrap();
    assert!(store.body(&original.header.id, &b.keys).is_err());
    let history = store.history(None, 100, &b.keys).unwrap();
    assert_eq!(history.len(), 1);
    assert!(history[0].retracted);
    assert_eq!(history[0].operation_revision, 2);
    let empty = api
        .operations(&b.token, &b.id, &b.device, next.through(), 100)
        .await
        .unwrap();
    assert!(empty.is_empty());
    store
        .import_authenticated_operations(next.through(), &empty, &b.keys)
        .unwrap();
    assert_eq!(store.conversations(&b.keys).unwrap()[0].unread, 1);
    assert!(api
        .operations(&b.token, &a.id, &b.device, 0, 100)
        .await
        .is_err());
    assert!(api
        .operations(&b.token, &b.id, &b.device, -1, 100)
        .await
        .is_err());
}
async fn submit(f: &Fixture, token: &str, operation: &Operation) -> reqwest::Response {
    f.client
        .post(format!("{}/direct/v3/operations", f.url))
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body(operation.to_wire().unwrap())
        .send()
        .await
        .unwrap()
}
fn make(
    original: &Batch,
    old: (&DeviceState, &DeviceState),
    current: (&DeviceState, &DeviceState),
    keys: &crypto::KeyPair,
    base: u64,
    action: Action,
    text: Option<&str>,
) -> Operation {
    Operation::make(
        original.clone(),
        old,
        current,
        keys,
        op::Header {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            original: original.digest().unwrap(),
            action,
            base,
            revision: base + 1,
            created_at: now(),
        },
        text,
    )
    .unwrap()
}
async fn read(
    f: &Fixture,
    token: &str,
    device: &str,
    after: i64,
    limit: usize,
) -> reqwest::Response {
    f.client
        .get(format!("{}/direct/v3/operations", f.url))
        .bearer_auth(token)
        .query(&[
            ("device_id", device),
            ("after", &after.to_string()),
            ("limit", &limit.to_string()),
        ])
        .send()
        .await
        .unwrap()
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn operation_original_proof_after_body_release_idempotence_conflict_and_retraction() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let s = directory(&f, &a);
    let p = directory(&f, &b);
    let original = batch(
        &s,
        &p,
        &a.device,
        &a.keys,
        None,
        "原正文 中文 🦭".as_bytes(),
    );
    assert_eq!(send(&f, &a.token, &original).await.status(), StatusCode::OK);
    // Simulate normal all-ACK body reclamation. Immutable receipt/deliveries remain.
    sqlx::query("UPDATE direct_v3_batches SET wire=NULL WHERE id=$1")
        .bind(&original.header.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    let edit = make(
        &original,
        (&s, &p),
        (&s, &p),
        &a.keys,
        0,
        Action::Edit,
        Some("新正文 中文 🦭"),
    );
    let (one, two) = tokio::join!(submit(&f, &a.token, &edit), submit(&f, &a.token, &edit));
    assert_eq!(one.status(), StatusCode::OK);
    assert_eq!(two.status(), StatusCode::OK);
    let one: serde_json::Value = one.json().await.unwrap();
    let two: serde_json::Value = two.json().await.unwrap();
    assert_eq!(one, two);
    assert_eq!(one["revision"], 1);
    let page = read(&f, &b.token, &b.device, 0, 1).await;
    assert_eq!(page.status(), StatusCode::OK);
    let page: Page = page.json().await.unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(
        page.events[0]
            .operation
            .open(
                &s,
                &p,
                &b.id,
                &b.device,
                p.anchor().hash().try_into().unwrap(),
                &b.keys
            )
            .unwrap()
            .as_deref(),
        Some("新正文 中文 🦭")
    );
    let stale = make(
        &original,
        (&s, &p),
        (&s, &p),
        &a.keys,
        0,
        Action::Edit,
        Some("并发旧版本"),
    );
    assert_eq!(
        submit(&f, &a.token, &stale).await.status(),
        StatusCode::CONFLICT
    );
    let retract = make(
        &original,
        (&s, &p),
        (&s, &p),
        &a.keys,
        1,
        Action::Retract,
        None,
    );
    assert_eq!(
        submit(&f, &a.token, &retract).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        submit(&f, &a.token, &retract).await.status(),
        StatusCode::OK
    );
    let after = make(
        &original,
        (&s, &p),
        (&s, &p),
        &a.keys,
        2,
        Action::Edit,
        Some("撤回后不恢复"),
    );
    assert_eq!(
        submit(&f, &a.token, &after).await.status(),
        StatusCode::CONFLICT
    );
    let page: Page = read(&f, &b.token, &b.device, page.through, 1)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].operation.header.action, Action::Retract);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM direct_v3_operations WHERE target=$1")
            .bind(&original.header.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(count, 2);
    let unchanged: Vec<u8> = sqlx::query_scalar("SELECT digest FROM direct_v3_batches WHERE id=$1")
        .bind(&original.header.id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(unchanged, original.digest().unwrap());
    assert_eq!(
        read(&f, &b.token, &b.device, -1, 1).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        read(&f, &b.token, &b.device, 0, 101).await.status(),
        StatusCode::BAD_REQUEST
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn operation_requires_original_author_and_never_grants_new_device_old_details() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let s = directory(&f, &a);
    let p = directory(&f, &b);
    let original = batch(&s, &p, &a.device, &a.keys, None, b"original");
    assert_eq!(send(&f, &a.token, &original).await.status(), StatusCode::OK);
    let (joined, new_peer) = grant(&f, &b, &p).await;
    let token = synthetic_activation(&f, &b, &joined).await;
    let edit = make(
        &original,
        (&s, &p),
        (&s, &new_peer),
        &a.keys,
        0,
        Action::Edit,
        Some("only original audience"),
    );
    assert_eq!(edit.payloads.len(), 2);
    assert_eq!(submit(&f, &a.token, &edit).await.status(), StatusCode::OK);
    let newcomer: Page = read(&f, &token, &joined.status.ticket.device.device_id, 0, 100)
        .await
        .json()
        .await
        .unwrap();
    assert!(newcomer.events.is_empty());
    let root: Page = read(&f, &b.token, &b.device, 0, 100)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(root.events.len(), 1);
    assert_ne!(submit(&f, &b.token, &edit).await.status(), StatusCode::OK);
    let (other, _) = grant(&f, &a, &s).await;
    let other_token = synthetic_activation(&f, &a, &other).await;
    assert_ne!(
        submit(&f, &other_token, &edit).await.status(),
        StatusCode::OK
    );
    let lookup = f
        .client
        .get(format!("{}/direct/v3/operations/{}", f.url, edit.header.id))
        .bearer_auth(&a.token)
        .query(&[("device_id", &a.device)])
        .send()
        .await
        .unwrap();
    assert_eq!(lookup.status(), StatusCode::OK);
    let result: serde_json::Value = lookup.json().await.unwrap();
    assert_eq!(result["id"], edit.header.id);
    let private = f
        .client
        .get(format!("{}/direct/v3/operations/{}", f.url, edit.header.id))
        .bearer_auth(&b.token)
        .query(&[("device_id", &b.device)])
        .send()
        .await
        .unwrap();
    assert_eq!(private.status(), StatusCode::OK);
    assert_eq!(
        private.json::<serde_json::Value>().await.unwrap(),
        serde_json::Value::Null
    );
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn operation_rejects_signature_forgery_unaccepted_original_and_log_byte_quota() {
    let f = Fixture::start(true).await;
    let a = f.account().await;
    let b = f.account().await;
    accepted(&f, &a, &b).await;
    let s = directory(&f, &a);
    let p = directory(&f, &b);
    let original = batch(&s, &p, &a.device, &a.keys, None, b"root proof");
    let valid = make(
        &original,
        (&s, &p),
        (&s, &p),
        &a.keys,
        0,
        Action::Edit,
        Some("private edit"),
    );
    assert_eq!(
        submit(&f, &a.token, &valid).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(send(&f, &a.token, &original).await.status(), StatusCode::OK);
    let mut forged = valid.clone();
    forged.signature[0] ^= 1;
    assert_eq!(
        submit(&f, &a.token, &forged).await.status(),
        StatusCode::FORBIDDEN
    );
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM direct_v3_operation_subjects WHERE target=$1")
            .bind(&original.header.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(count, 0);
    // Synthetic quota load has no audience rows; it cannot become a delivery.
    sqlx::query("INSERT INTO direct_v3_operations(id,target,owner,source,revision,digest,wire,accepted_at) SELECT $1 || ':' || n::text,$1,$2,$3,n,decode(repeat('11',32),'hex'),decode(repeat('00',524288),'hex'),1 FROM generate_series(1,64) n").bind(&original.header.id).bind(&a.id).bind(&a.device).execute(f.db.pool()).await.unwrap();
    assert_eq!(
        submit(&f, &a.token, &valid).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM direct_v3_operations WHERE id=$1)")
            .bind(&valid.header.id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert!(!exists);
    let page: Page = read(&f, &b.token, &b.device, 0, 100)
        .await
        .json()
        .await
        .unwrap();
    assert!(page.events.is_empty());
}
