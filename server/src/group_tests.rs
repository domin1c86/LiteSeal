//! Only synthetic identities in a dedicated test database; no local credentials.
use super::*;
use liteseal_shared::{crypto, group::*};
use sqlx::Row;

struct Account {
    identity: GroupIdentity,
    keys: crypto::KeyPair,
    token: String,
}
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
impl Fixture {
    async fn start() -> Self {
        let url =
            std::env::var("LITESEAL_TEST_DATABASE_URL").expect("requires dedicated test Postgres");
        let db = Db::connect(&url).await.unwrap();
        let app = build_router(
            AppState::new(db.clone()),
            HeaderValue::from_static("http://localhost:1420"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
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
        let token = uuid::Uuid::new_v4().to_string();
        let (user, device) = self
            .db
            .register_user(
                &format!("group-{}", uuid::Uuid::new_v4()),
                "test-only-hash",
                "group test",
                &keys.public_key,
                &keys.ed25519_pk,
                &auth::service::hash_token(&token),
                &uuid::Uuid::new_v4().to_string(),
            )
            .await
            .unwrap();
        Account {
            identity: GroupIdentity {
                user_id: user.id,
                device_id: device.id,
                public_key: keys.public_key.to_vec(),
                signing_key: keys.ed25519_pk.to_vec(),
            },
            keys,
            token,
        }
    }
    async fn change(
        &self,
        account: &Account,
        event: &GroupChange,
        create: bool,
    ) -> reqwest::Response {
        let path = if create {
            "/groups".into()
        } else {
            format!("/groups/{}/changes", event.group_id)
        };
        self.client
            .post(format!("{}{path}", self.url))
            .bearer_auth(&account.token)
            .json(&GroupChangeRequest {
                device_id: account.identity.device_id.clone(),
                change: event.clone(),
            })
            .send()
            .await
            .unwrap()
    }
    async fn invite(&self, owner: &Account, invite: &GroupInvite) -> reqwest::Response {
        self.client
            .post(format!("{}/groups/{}/invites", self.url, invite.group_id))
            .bearer_auth(&owner.token)
            .json(&GroupInviteRequest {
                device_id: owner.identity.device_id.clone(),
                invite: invite.clone(),
            })
            .send()
            .await
            .unwrap()
    }
    async fn history(&self, account: &Account, id: &str, after: u64) -> reqwest::Response {
        self.client
            .get(format!("{}/groups/{id}/changes", self.url))
            .bearer_auth(&account.token)
            .query(&[
                ("device_id", account.identity.device_id.clone()),
                ("after_epoch", after.to_string()),
            ])
            .send()
            .await
            .unwrap()
    }
    async fn pending(&self, account: &Account) -> GroupInvitePage {
        self.client
            .get(format!("{}/group-invites", self.url))
            .bearer_auth(&account.token)
            .query(&[("device_id", &account.identity.device_id)])
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }
    async fn cancel(&self, account: &Account, id: &str) -> reqwest::Response {
        self.client
            .delete(format!("{}/group-invites/{id}", self.url))
            .bearer_auth(&account.token)
            .query(&[("device_id", &account.identity.device_id)])
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
fn event(state: Option<&GroupState>, actor: &Account, action: GroupAction) -> GroupChange {
    let mut change = GroupChange {
        group_id: state
            .map(|state| state.group_id().to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        epoch: state.map(|state| state.epoch() + 1).unwrap_or(1),
        previous_hash: state
            .map(|state| state.revision_hash().to_vec())
            .unwrap_or_default(),
        actor: actor.identity.user_id.clone(),
        created_at: now(),
        action,
        signature: Vec::new(),
    };
    change.signature = crypto::sign(&change.signing_bytes(), &actor.keys.ed25519_sk).unwrap();
    change
}
fn invitation(state: &GroupState, owner: &Account, target: &Account) -> GroupInvite {
    let mut invite = GroupInvite {
        id: uuid::Uuid::new_v4().to_string(),
        group_id: state.group_id().into(),
        epoch: state.epoch(),
        previous_hash: state.revision_hash().to_vec(),
        member: target.identity.clone(),
        issued_at: now(),
        expires_at: now() + 60_000,
        signature: Vec::new(),
    };
    invite.signature = crypto::sign(&invite.signing_bytes(), &owner.keys.ed25519_sk).unwrap();
    invite
}
fn joining(state: &GroupState, target: &Account, invite: GroupInvite) -> GroupChange {
    let mut acceptance = GroupAcceptance {
        invite_id: invite.id.clone(),
        invite_hash: invite.digest(),
        signature: Vec::new(),
    };
    acceptance.signature =
        crypto::sign(&acceptance.signing_bytes(), &target.keys.ed25519_sk).unwrap();
    event(
        Some(state),
        target,
        GroupAction::Join { invite, acceptance },
    )
}

impl Fixture {
    async fn add(&self, state: &GroupState, owner: &Account, target: &Account) -> GroupState {
        let invite = invitation(state, owner, target);
        assert_eq!(
            self.invite(owner, &invite).await.status(),
            reqwest::StatusCode::OK
        );
        let change = joining(state, target, invite);
        assert_eq!(
            self.change(target, &change, false).await.status(),
            reqwest::StatusCode::OK
        );
        apply_change(Some(state), &change).unwrap()
    }
    async fn send_group(&self, sender: &Account, batch: &[GroupEnvelope]) -> reqwest::Response {
        self.client
            .post(format!(
                "{}/groups/{}/messages",
                self.url, batch[0].group_id
            ))
            .bearer_auth(&sender.token)
            .json(&GroupSendRequest {
                device_id: sender.identity.device_id.clone(),
                envelopes: batch.to_vec(),
            })
            .send()
            .await
            .unwrap()
    }
    async fn receive_group(&self, account: &Account, group: &str) -> reqwest::Response {
        self.client
            .get(format!("{}/groups/{group}/messages", self.url))
            .bearer_auth(&account.token)
            .query(&[("device_id", &account.identity.device_id)])
            .send()
            .await
            .unwrap()
    }
    async fn ack_group(
        &self,
        account: &Account,
        group: &str,
        joined: u64,
        ids: &[String],
    ) -> reqwest::Response {
        self.client
            .post(format!("{}/groups/{group}/messages/ack", self.url))
            .bearer_auth(&account.token)
            .json(&GroupAckRequest {
                device_id: account.identity.device_id.clone(),
                recipient_join_epoch: joined,
                message_ids: ids.to_vec(),
            })
            .send()
            .await
            .unwrap()
    }
    async fn group_receipt(
        &self,
        account: &Account,
        envelope: &GroupEnvelope,
    ) -> reqwest::Response {
        self.client
            .get(format!(
                "{}/groups/{}/messages/{}/receipt",
                self.url, envelope.group_id, envelope.message_id
            ))
            .bearer_auth(&account.token)
            .query(&[("device_id", &account.identity.device_id)])
            .send()
            .await
            .unwrap()
    }
}
fn batch(
    state: &GroupState,
    sender: &Account,
    recipients: &[(&Account, Option<&GroupEnvelope>)],
) -> Vec<GroupEnvelope> {
    let id = uuid::Uuid::new_v4().to_string();
    let sent_at = now();
    recipients
        .iter()
        .map(|(recipient, previous)| {
            let mut envelope = GroupEnvelope {
                version: 1,
                message_id: id.clone(),
                group_id: state.group_id().into(),
                epoch: state.epoch(),
                membership_hash: state.revision_hash().to_vec(),
                sender_user_id: sender.identity.user_id.clone(),
                sender_device_id: sender.identity.device_id.clone(),
                sender_join_epoch: state.member(&sender.identity.user_id).unwrap().joined_epoch,
                recipient_user_id: recipient.identity.user_id.clone(),
                recipient_device_id: recipient.identity.device_id.clone(),
                recipient_join_epoch: state
                    .member(&recipient.identity.user_id)
                    .unwrap()
                    .joined_epoch,
                sender_seq: previous.map(|p| p.sender_seq + 1).unwrap_or(1),
                prev_hash: previous.map(|p| p.chain_hash()).unwrap_or_default(),
                sent_at,
                ciphertext: crypto::encrypt(
                    b"test group text",
                    &recipient.keys.public_key,
                    &sender.keys.secret_key,
                )
                .unwrap(),
                signature: vec![],
            };
            envelope.signature =
                crypto::sign(&envelope.signing_bytes(), &sender.keys.ed25519_sk).unwrap();
            envelope
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn extension_roots_are_atomic_idempotent_cancelled_and_phase_scoped() {
    use liteseal_shared::{collaboration::Member, group_extension as e};
    let f = Fixture::start().await;
    let a = f.account().await;
    let b = f.account().await;
    let create = event(
        None,
        &a,
        GroupAction::Create {
            name: "extensions".into(),
            owner: a.identity.clone(),
        },
    );
    assert!(f.change(&a, &create, true).await.status().is_success());
    let g = f
        .add(&pin_creation(&create, &a.identity).unwrap(), &a, &b)
        .await;
    let endpoint = format!("{}/groups/{}/extensions", f.url, g.group_id());
    let content = e::Content::Activity(e::Activity {
        title: "private activity".into(),
        start_at: now(),
        timezone: "UTC".into(),
        location: "".into(),
        description: "".into(),
    });
    let build = || {
        let mut roots = batch(&g, &a, &[(&b, None)]);
        roots[0].ciphertext = crypto::encrypt(
            e::PLACEHOLDER.as_bytes(),
            &b.keys.public_key,
            &a.keys.secret_key,
        )
        .unwrap();
        roots[0].signature = crypto::sign(&roots[0].signing_bytes(), &a.keys.ed25519_sk).unwrap();
        e::make(
            &g,
            &Member::from(g.member(&a.identity.user_id).unwrap()),
            roots[0].message_id.clone(),
            uuid::Uuid::new_v4().to_string(),
            None,
            e::Action::Activity,
            Some(&content),
            roots.clone(),
            &a.keys,
            roots[0].sent_at,
        )
        .unwrap()
    };
    let send = |actor: &Account, sub: &e::Submission| {
        f.client
            .post(&endpoint)
            .bearer_auth(&actor.token)
            .json(&serde_json::json!({"device_id":actor.identity.device_id,"submission":sub}))
            .send()
    };
    let task = build();
    let mut invalid = task.clone();
    invalid.boxes[0].ciphertext[0] ^= 1;
    assert_eq!(
        send(&a, &invalid).await.unwrap().status(),
        reqwest::StatusCode::CONFLICT
    );
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM group_message_batches WHERE group_id=$1")
        .bind(g.group_id())
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(n, 0);
    let receipt = send(&a, &task)
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<e::Receipt>()
        .await
        .unwrap();
    let again = send(&a, &task)
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<e::Receipt>()
        .await
        .unwrap();
    assert_eq!(receipt.seq, again.seq);
    assert_eq!(receipt.hash, again.hash);
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM group_message_batches WHERE group_id=$1")
        .bind(g.group_id())
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(n, 1);
    let page = f
        .client
        .get(&endpoint)
        .bearer_auth(&b.token)
        .query(&[("device_id", &b.identity.device_id)])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<e::Page>()
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert!(page.items[0].ciphertext.is_some());
    let old = e::transition(None, &g, &task.event).unwrap();
    let close = e::make(
        &g,
        &Member::from(g.member(&a.identity.user_id).unwrap()),
        task.event.object.clone(),
        uuid::Uuid::new_v4().to_string(),
        Some(&old),
        e::Action::Close,
        None,
        vec![],
        &a.keys,
        now(),
    )
    .unwrap();
    let answer = e::make(
        &g,
        &Member::from(g.member(&b.identity.user_id).unwrap()),
        task.event.object.clone(),
        uuid::Uuid::new_v4().to_string(),
        Some(&old),
        e::Action::Respond {
            answer: e::Answer::Maybe,
        },
        None,
        vec![],
        &b.keys,
        now(),
    )
    .unwrap();
    let (x, y) = tokio::join!(send(&a, &close), send(&b, &answer));
    let (x, y) = (x.unwrap().status(), y.unwrap().status());
    assert!(x.is_success() != y.is_success());
    let abandoned = build();
    let cancelled = f
        .client
        .post(format!("{}/{}/cancel", endpoint, abandoned.event.id))
        .bearer_auth(&a.token)
        .json(&serde_json::json!({"device_id":a.identity.device_id,"root":abandoned.event.object}))
        .send()
        .await
        .unwrap();
    assert!(cancelled.status().is_success());
    assert_eq!(
        send(&a, &abandoned).await.unwrap().status(),
        reqwest::StatusCode::CONFLICT
    );
    let remove = event(
        Some(&g),
        &a,
        GroupAction::Remove {
            user_id: b.identity.user_id.clone(),
        },
    );
    assert!(f.change(&a, &remove, false).await.status().is_success());
    let left = apply_change(Some(&g), &remove).unwrap();
    let _joined = f.add(&left, &a, &b).await;
    let page = f
        .client
        .get(&endpoint)
        .bearer_auth(&b.token)
        .query(&[("device_id", &b.identity.device_id)])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<e::Page>()
        .await
        .unwrap();
    assert!(page.items.iter().all(|x| x.ciphertext.is_none()));
    assert_eq!(
        send(&b, &answer).await.unwrap().status(),
        if y.is_success() {
            reqwest::StatusCode::OK
        } else {
            reqwest::StatusCode::CONFLICT
        }
    );
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn extension_attachment_chunks_publication_rejoin_and_shared_quota() {
    use liteseal_shared::{collaboration as c, group_extension as e};
    let f = Fixture::start().await;
    let a = f.account().await;
    let b = f.account().await;
    let create = event(
        None,
        &a,
        GroupAction::Create {
            name: "group media".into(),
            owner: a.identity.clone(),
        },
    );
    assert!(f.change(&a, &create, true).await.status().is_success());
    let g = f
        .add(&pin_creation(&create, &a.identity).unwrap(), &a, &b)
        .await;
    let blob = uuid::Uuid::new_v4().to_string();
    let plain = vec![17; 1024 * 1024 + 9];
    let (cipher, key) = crypto::encrypt_attachment(&plain).unwrap();
    let media = format!("{}/groups/{}/attachments", f.url, g.group_id());
    let result = f
        .client
        .post(&media)
        .bearer_auth(&a.token)
        .json(&serde_json::json!({"device_id":a.identity.device_id,"id":blob,"size":cipher.len()}))
        .send()
        .await
        .unwrap();
    assert!(result.status().is_success());
    let mut roots = batch(&g, &a, &[(&b, None)]);
    roots[0].ciphertext = crypto::encrypt(
        e::PLACEHOLDER.as_bytes(),
        &b.keys.public_key,
        &a.keys.secret_key,
    )
    .unwrap();
    roots[0].signature = crypto::sign(&roots[0].signing_bytes(), &a.keys.ed25519_sk).unwrap();
    let content = e::Content::Attachment(e::Attachment {
        version: 1,
        blob: blob.clone(),
        name: "中文.png".into(),
        size: plain.len() as u64,
        mime: "application/octet-stream".into(),
        duration_ms: None,
        key,
        hash: c::digest(&cipher),
    });
    let sub = e::make(
        &g,
        &c::Member::from(g.member(&a.identity.user_id).unwrap()),
        roots[0].message_id.clone(),
        uuid::Uuid::new_v4().to_string(),
        None,
        e::Action::Attachment {
            blob: blob.clone(),
            size: plain.len() as u64,
            hash: c::digest(&cipher),
        },
        Some(&content),
        roots.clone(),
        &a.keys,
        roots[0].sent_at,
    )
    .unwrap();
    let send = || {
        f.client
            .post(format!("{}/groups/{}/extensions", f.url, g.group_id()))
            .bearer_auth(&a.token)
            .json(&serde_json::json!({"device_id":a.identity.device_id,"submission":sub}))
            .send()
    };
    assert_eq!(
        send().await.unwrap().status(),
        reqwest::StatusCode::CONFLICT
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM group_message_batches WHERE group_id=$1"
        )
        .bind(g.group_id())
        .fetch_one(f.db.pool())
        .await
        .unwrap(),
        0
    );
    for (part, bytes) in cipher.chunks(1024 * 1024).enumerate() {
        assert!(f
            .client
            .put(format!("{media}/{blob}/{part}"))
            .bearer_auth(&a.token)
            .query(&[("device_id", &a.identity.device_id)])
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
    }
    assert_eq!(
        f.client
            .put(format!("{media}/{blob}/0"))
            .bearer_auth(&a.token)
            .query(&[("device_id", &a.identity.device_id)])
            .body(vec![0; 1024 * 1024])
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::CONFLICT
    );
    assert!(send().await.unwrap().status().is_success());
    assert!(send().await.unwrap().status().is_success());
    let download = || {
        f.client
            .get(format!("{media}/{blob}/0"))
            .bearer_auth(&b.token)
            .query(&[("device_id", &b.identity.device_id)])
            .send()
    };
    assert_eq!(
        download()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        &cipher[..1024 * 1024]
    );
    let remove = event(
        Some(&g),
        &a,
        GroupAction::Remove {
            user_id: b.identity.user_id.clone(),
        },
    );
    assert!(f.change(&a, &remove, false).await.status().is_success());
    assert_eq!(
        download().await.unwrap().status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let left = apply_change(Some(&g), &remove).unwrap();
    let _next = f.add(&left, &a, &b).await;
    assert_eq!(
        download().await.unwrap().status(),
        reqwest::StatusCode::NOT_FOUND
    );
    // Synthetic retained direct quota; no allocating hundreds of MiB of ciphertext.
    sqlx::query("INSERT INTO attachment_objects(id,owner,message_id,recipient,size,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 day')").bind(uuid::Uuid::new_v4().to_string()).bind(&a.identity.user_id).bind(uuid::Uuid::new_v4().to_string()).bind(&b.identity.user_id).bind(512_i64*1024*1024-cipher.len() as i64).execute(f.db.pool()).await.unwrap();
    assert_eq!(f.client.post(&media).bearer_auth(&a.token).json(&serde_json::json!({"device_id":a.identity.device_id,"id":uuid::Uuid::new_v4().to_string(),"size":40})).send().await.unwrap().status(),reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(f.client.post(format!("{}/attachments",f.url)).bearer_auth(&a.token).json(&serde_json::json!({"device_id":a.identity.device_id,"id":uuid::Uuid::new_v4().to_string(),"message_id":uuid::Uuid::new_v4().to_string(),"recipient":b.identity.user_id,"size":40})).send().await.unwrap().status(),reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    sqlx::query(
        "UPDATE group_attachment_objects SET expires_at=now()-interval '1 second' WHERE id=$1",
    )
    .bind(&blob)
    .execute(f.db.pool())
    .await
    .unwrap();
    crate::attachments::cleanup(f.db.pool()).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM group_attachment_chunks WHERE object_id=$1"
        )
        .bind(&blob)
        .fetch_one(f.db.pool())
        .await
        .unwrap(),
        0
    );
    // A retired publication cannot recycle its blob ID into a later membership phase.
    assert_eq!(
        f.client
            .post(&media)
            .bearer_auth(&a.token)
            .json(
                &serde_json::json!({"device_id":a.identity.device_id,"id":blob,"size":cipher.len()})
            )
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::CONFLICT
    );
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn extension_pagination_retention_and_cancellation_idempotency() {
    use liteseal_shared::{collaboration as c, group_extension as e};
    let f = Fixture::start().await;
    let a = f.account().await;
    let b = f.account().await;
    let create = event(
        None,
        &a,
        GroupAction::Create {
            name: "extension bounds".into(),
            owner: a.identity.clone(),
        },
    );
    assert!(f.change(&a, &create, true).await.status().is_success());
    let g = f
        .add(&pin_creation(&create, &a.identity).unwrap(), &a, &b)
        .await;
    let endpoint = format!("{}/groups/{}/extensions", f.url, g.group_id());
    let mut roots = batch(&g, &a, &[(&b, None)]);
    roots[0].ciphertext = crypto::encrypt(
        e::PLACEHOLDER.as_bytes(),
        &b.keys.public_key,
        &a.keys.secret_key,
    )
    .unwrap();
    roots[0].signature = crypto::sign(&roots[0].signing_bytes(), &a.keys.ed25519_sk).unwrap();
    let content = e::Content::Activity(e::Activity {
        title: "bounds".into(),
        start_at: now(),
        timezone: "UTC".into(),
        location: "".into(),
        description: "".into(),
    });
    let original = e::make(
        &g,
        &c::Member::from(g.member(&a.identity.user_id).unwrap()),
        roots[0].message_id.clone(),
        uuid::Uuid::new_v4().to_string(),
        None,
        e::Action::Activity,
        Some(&content),
        roots.clone(),
        &a.keys,
        roots[0].sent_at,
    )
    .unwrap();
    assert!(f
        .client
        .post(&endpoint)
        .bearer_auth(&a.token)
        .json(&serde_json::json!({"device_id":a.identity.device_id,"submission":original}))
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    // Seed valid signed responses to exercise pages without defeating HTTP rate limits.
    let mut object = e::transition(None, &g, &original.event).unwrap();
    for _ in 0..104 {
        let sub = e::make(
            &g,
            &c::Member::from(g.member(&b.identity.user_id).unwrap()),
            object.id.clone(),
            uuid::Uuid::new_v4().to_string(),
            Some(&object),
            e::Action::Respond {
                answer: e::Answer::Maybe,
            },
            None,
            vec![],
            &b.keys,
            now(),
        )
        .unwrap();
        object = e::transition(Some(&object), &g, &sub.event).unwrap();
        sqlx::query("INSERT INTO group_extension_events(group_id,id,object_id,revision,header,submission_hash) VALUES($1,$2,$3,$4,$5,$6)").bind(g.group_id()).bind(&sub.event.id).bind(&sub.event.object).bind(sub.event.revision as i64).bind(serde_json::to_string(&sub.event).unwrap()).bind(c::digest(&serde_json::to_vec(&sub).unwrap())).execute(f.db.pool()).await.unwrap();
    }
    let response = f
        .client
        .get(&endpoint)
        .bearer_auth(&b.token)
        .query(&[("device_id", &b.identity.device_id)])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let bytes = response.bytes().await.unwrap();
    assert!(bytes.len() <= 512 * 1024);
    let page: e::Page = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(page.items.len(), 100);
    assert!(page.more);
    let next = f
        .client
        .get(&endpoint)
        .bearer_auth(&b.token)
        .query(&[
            ("device_id", b.identity.device_id.clone()),
            ("after", page.cursor.to_string()),
        ])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<e::Page>()
        .await
        .unwrap();
    assert_eq!(next.items.len(), 5);
    assert!(!next.more);
    assert!(next.items[0].seq > page.cursor);
    let cancel_id = uuid::Uuid::new_v4().to_string();
    let root_id = uuid::Uuid::new_v4().to_string();
    let cancel = || {
        f.client
            .post(format!("{endpoint}/{cancel_id}/cancel"))
            .bearer_auth(&a.token)
            .json(&serde_json::json!({"device_id":a.identity.device_id,"root":root_id}))
            .send()
    };
    assert!(cancel().await.unwrap().status().is_success());
    sqlx::query("INSERT INTO group_extension_cancellations(group_id,id,device_id) SELECT $1,md5(i::text)::uuid::text,$2 FROM generate_series(1,9894) i").bind(g.group_id()).bind(&a.identity.device_id).execute(f.db.pool()).await.unwrap();
    assert!(cancel().await.unwrap().status().is_success());
    let changed=f.client.post(format!("{endpoint}/{cancel_id}/cancel")).bearer_auth(&a.token).json(&serde_json::json!({"device_id":a.identity.device_id,"root":uuid::Uuid::new_v4().to_string()})).send().await.unwrap();
    assert_eq!(changed.status(), reqwest::StatusCode::CONFLICT);
    let extra = f
        .client
        .post(format!("{endpoint}/{}/cancel", uuid::Uuid::new_v4()))
        .bearer_auth(&a.token)
        .json(&serde_json::json!({"device_id":a.identity.device_id,"root":null}))
        .send()
        .await
        .unwrap();
    assert_eq!(extra.status(), reqwest::StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM group_message_payloads WHERE group_id=$1"
        )
        .bind(g.group_id())
        .fetch_one(f.db.pool())
        .await
        .unwrap(),
        1
    );
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn extension_and_direct_attachment_creation_share_concurrent_byte_and_count_caps() {
    let f = Fixture::start().await;
    let a = f.account().await;
    let b = f.account().await;
    let create = event(
        None,
        &a,
        GroupAction::Create {
            name: "shared quota race".into(),
            owner: a.identity.clone(),
        },
    );
    assert!(f.change(&a, &create, true).await.status().is_success());
    let g = f
        .add(&pin_creation(&create, &a.identity).unwrap(), &a, &b)
        .await;
    let group_request = || {
        f.client.post(format!("{}/groups/{}/attachments",f.url,g.group_id())).bearer_auth(&a.token).json(&serde_json::json!({"device_id":a.identity.device_id,"id":uuid::Uuid::new_v4().to_string(),"size":40})).send()
    };
    let direct_request = || {
        f.client.post(format!("{}/attachments",f.url)).bearer_auth(&a.token).json(&serde_json::json!({"device_id":a.identity.device_id,"id":uuid::Uuid::new_v4().to_string(),"message_id":uuid::Uuid::new_v4().to_string(),"recipient":b.identity.user_id,"size":40})).send()
    };
    sqlx::query("INSERT INTO attachment_objects(id,owner,message_id,recipient,size,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 day')").bind(uuid::Uuid::new_v4().to_string()).bind(&a.identity.user_id).bind(uuid::Uuid::new_v4().to_string()).bind(&b.identity.user_id).bind(512_i64*1024*1024-40).execute(f.db.pool()).await.unwrap();
    let (x, y) = tokio::join!(group_request(), direct_request());
    let (x, y) = (x.unwrap().status(), y.unwrap().status());
    assert!(x.is_success() != y.is_success());
    assert!(
        x == reqwest::StatusCode::PAYLOAD_TOO_LARGE || y == reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );
    sqlx::query("DELETE FROM attachment_objects WHERE owner=$1")
        .bind(&a.identity.user_id)
        .execute(f.db.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM group_attachment_objects WHERE owner=$1")
        .bind(&a.identity.user_id)
        .execute(f.db.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO attachment_objects(id,owner,message_id,recipient,size,expires_at) SELECT md5($1||i::text)::uuid::text,$1,md5('m'||$1||i::text)::uuid::text,$2,40,now()+interval '1 day' FROM generate_series(1,1999) i").bind(&a.identity.user_id).bind(&b.identity.user_id).execute(f.db.pool()).await.unwrap();
    let (x, y) = tokio::join!(group_request(), direct_request());
    let (x, y) = (x.unwrap().status(), y.unwrap().status());
    assert!(x.is_success() != y.is_success());
    assert!(
        x == reqwest::StatusCode::PAYLOAD_TOO_LARGE || y == reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );
    let count:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM attachment_objects WHERE owner=$1)+(SELECT COUNT(*) FROM group_attachment_objects WHERE owner=$1)").bind(&a.identity.user_id).fetch_one(f.db.pool()).await.unwrap();
    assert_eq!(count, 2000);
}
async fn page(f: &Fixture, account: &Account, group: &str) -> GroupMessagePage {
    f.receive_group(account, group)
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn atomic_group_cancellation_prevents_late_admission_without_recalling_accepted_messages() {
    let f = Fixture::start().await;
    let alice = f.account().await;
    let bob = f.account().await;
    let create = event(
        None,
        &alice,
        GroupAction::Create {
            name: "cancel test".into(),
            owner: alice.identity.clone(),
        },
    );
    assert_eq!(
        f.change(&alice, &create, true).await.status(),
        reqwest::StatusCode::OK
    );
    let group = f
        .add(
            &pin_creation(&create, &alice.identity).unwrap(),
            &alice,
            &bob,
        )
        .await;
    let cancelled = batch(&group, &alice, &[(&bob, None)]);
    let cancel = |message: String| {
        f.client
            .post(format!(
                "{}/groups/{}/messages/{message}/cancel",
                f.url,
                group.group_id()
            ))
            .bearer_auth(&alice.token)
            .json(&GroupCancelRequest {
                device_id: alice.identity.device_id.clone(),
            })
    };
    let response: GroupCancelResult = cancel(cancelled[0].message_id.clone())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(response.cancelled);
    assert!(response.receipt.is_none());
    assert!(
        cancel(cancelled[0].message_id.clone())
            .send()
            .await
            .unwrap()
            .json::<GroupCancelResult>()
            .await
            .unwrap()
            .cancelled
    );
    assert_eq!(
        f.send_group(&alice, &cancelled).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    let first = batch(&group, &alice, &[(&bob, None)]);
    assert_eq!(
        f.send_group(&alice, &first).await.status(),
        reqwest::StatusCode::OK
    );
    let accepted: GroupCancelResult = cancel(first[0].message_id.clone())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!accepted.cancelled);
    assert_eq!(accepted.receipt.unwrap().message_id, first[0].message_id);
    assert_eq!(page(&f, &bob, group.group_id()).await.envelopes.len(), 1);
    let next = batch(&group, &alice, &[(&bob, Some(&first[0]))]);
    let (sent, cancelled) = tokio::join!(
        f.send_group(&alice, &next),
        cancel(next[0].message_id.clone()).send()
    );
    let cancelled: GroupCancelResult = cancelled
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        sent.status(),
        if cancelled.cancelled {
            reqwest::StatusCode::CONFLICT
        } else {
            reqwest::StatusCode::OK
        }
    );
    assert_eq!(
        page(&f, &bob, group.group_id()).await.envelopes.len(),
        if cancelled.cancelled { 1 } else { 2 }
    );
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn group_fanout_ack_and_rejoin_keep_recipient_boundaries() {
    let f = Fixture::start().await;
    let alice = f.account().await;
    let bob = f.account().await;
    let carol = f.account().await;
    let outsider = f.account().await;
    let creation = event(
        None,
        &alice,
        GroupAction::Create {
            name: "delivery".into(),
            owner: alice.identity.clone(),
        },
    );
    assert_eq!(
        f.change(&alice, &creation, true).await.status(),
        reqwest::StatusCode::OK
    );
    let initial = pin_creation(&creation, &alice.identity).unwrap();
    let two = f.add(&initial, &alice, &bob).await;
    let first = batch(&two, &alice, &[(&bob, None)]);
    assert_eq!(
        f.send_group(&alice, &first).await.status(),
        reqwest::StatusCode::OK
    );
    let three = f.add(&two, &alice, &carol).await;
    assert!(page(&f, &carol, three.group_id())
        .await
        .envelopes
        .is_empty());
    assert_eq!(page(&f, &bob, three.group_id()).await.envelopes, first);
    let second = batch(&three, &alice, &[(&bob, Some(&first[0])), (&carol, None)]);
    assert_eq!(
        f.send_group(&alice, &second[..1]).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    let mut invalid = second.clone();
    invalid[1].signature[0] ^= 1;
    assert_eq!(
        f.send_group(&alice, &invalid).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    assert_eq!(page(&f, &bob, three.group_id()).await.envelopes.len(), 1);
    assert!(page(&f, &carol, three.group_id())
        .await
        .envelopes
        .is_empty());
    assert_eq!(
        f.send_group(&outsider, &second).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    assert_eq!(
        f.receive_group(&outsider, three.group_id()).await.status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let old_version = batch(&two, &alice, &[(&bob, Some(&first[0]))]);
    assert_eq!(
        f.send_group(&alice, &old_version).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    assert_eq!(
        f.send_group(&alice, &second).await.status(),
        reqwest::StatusCode::OK
    );
    let mut reversed = second.clone();
    reversed.reverse();
    assert_eq!(
        f.send_group(&alice, &reversed).await.status(),
        reqwest::StatusCode::OK
    );
    let ids = vec![first[0].message_id.clone(), second[0].message_id.clone()];
    assert_eq!(
        f.ack_group(&alice, three.group_id(), 1, &ids)
            .await
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let delivered = page(&f, &bob, three.group_id()).await;
    assert_eq!(delivered.envelopes.len(), 2);
    assert_eq!(
        crypto::decrypt(
            &delivered.envelopes[1].ciphertext,
            &alice.keys.public_key,
            &bob.keys.secret_key
        )
        .unwrap(),
        b"test group text"
    );
    assert_eq!(
        f.ack_group(&bob, three.group_id(), two.epoch(), &ids)
            .await
            .status(),
        reqwest::StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.ack_group(&bob, three.group_id(), two.epoch(), &ids)
            .await
            .status(),
        reqwest::StatusCode::NO_CONTENT
    );
    assert!(page(&f, &bob, three.group_id()).await.envelopes.is_empty());
    assert_eq!(page(&f, &carol, three.group_id()).await.envelopes.len(), 1);
    let third = batch(
        &three,
        &alice,
        &[(&bob, Some(&second[0])), (&carol, Some(&second[1]))],
    );
    assert_eq!(
        f.send_group(&alice, &third).await.status(),
        reqwest::StatusCode::OK
    );
    let remove = event(
        Some(&three),
        &alice,
        GroupAction::Remove {
            user_id: bob.identity.user_id.clone(),
        },
    );
    assert_eq!(
        f.change(&alice, &remove, false).await.status(),
        reqwest::StatusCode::OK
    );
    let removed = apply_change(Some(&three), &remove).unwrap();
    assert_eq!(
        f.receive_group(&bob, three.group_id()).await.status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let retry: GroupMessageReceipt = f
        .send_group(&alice, &third)
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        retry
            .recipients
            .iter()
            .find(|r| r.recipient_user_id == bob.identity.user_id)
            .unwrap()
            .status,
        "removed"
    );
    assert_eq!(
        f.group_receipt(&outsider, &third[0]).await.status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let rejoined = f.add(&removed, &alice, &bob).await;
    assert!(page(&f, &bob, rejoined.group_id())
        .await
        .envelopes
        .is_empty());
    let imported = batch(
        &rejoined,
        &alice,
        &[(&bob, Some(&third[0])), (&carol, Some(&third[1]))],
    );
    assert_eq!(
        f.send_group(&alice, &imported).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    let fresh = batch(
        &rejoined,
        &alice,
        &[(&bob, None), (&carol, Some(&third[1]))],
    );
    assert_eq!(
        f.send_group(&alice, &fresh).await.status(),
        reqwest::StatusCode::OK
    );
    let new_page = page(&f, &bob, rejoined.group_id()).await;
    assert_eq!(new_page.envelopes.len(), 1);
    assert_eq!(new_page.envelopes[0].sender_seq, 1);
    assert_eq!(
        f.ack_group(&bob, rejoined.group_id(), two.epoch(), &ids)
            .await
            .status(),
        reqwest::StatusCode::CONFLICT
    );
    let close = event(Some(&rejoined), &alice, GroupAction::Close);
    assert_eq!(
        f.change(&alice, &close, false).await.status(),
        reqwest::StatusCode::OK
    );
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM group_message_payloads WHERE group_id=$1")
            .bind(rejoined.group_id())
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(count, 0);
    let receipts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM group_message_receipts WHERE group_id=$1")
            .bind(rejoined.group_id())
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(receipts, 7);
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn group_queue_quota_concurrent_chains_and_blocking_are_atomic() {
    let f = Fixture::start().await;
    let alice = f.account().await;
    let bob = f.account().await;
    let carol = f.account().await;
    let creation = event(
        None,
        &alice,
        GroupAction::Create {
            name: "atomic delivery".into(),
            owner: alice.identity.clone(),
        },
    );
    assert_eq!(
        f.change(&alice, &creation, true).await.status(),
        reqwest::StatusCode::OK
    );
    let initial = pin_creation(&creation, &alice.identity).unwrap();
    let two = f.add(&initial, &alice, &bob).await;
    let three = f.add(&two, &alice, &carol).await;
    let first = batch(&three, &alice, &[(&bob, None), (&carol, None)]);
    assert_eq!(
        f.send_group(&alice, &first).await.status(),
        reqwest::StatusCode::OK
    );
    // Synthetic storage pressure in this fixture's rows only, restored below.
    sqlx::query(
        "UPDATE group_message_payloads SET body=$3 WHERE group_id=$1 AND recipient_device_id=$2",
    )
    .bind(three.group_id())
    .bind(&bob.identity.device_id)
    .bind("x".repeat(10 * 1024 * 1024))
    .execute(f.db.pool())
    .await
    .unwrap();
    let left = batch(
        &three,
        &alice,
        &[(&bob, Some(&first[0])), (&carol, Some(&first[1]))],
    );
    assert_eq!(
        f.send_group(&alice, &left).await.status(),
        reqwest::StatusCode::INSUFFICIENT_STORAGE
    );
    assert_eq!(page(&f, &carol, three.group_id()).await.envelopes.len(), 1);
    sqlx::query(
        "UPDATE group_message_payloads SET body=$3 WHERE group_id=$1 AND recipient_device_id=$2",
    )
    .bind(three.group_id())
    .bind(&bob.identity.device_id)
    .bind(serde_json::to_string(&first[0]).unwrap())
    .execute(f.db.pool())
    .await
    .unwrap();
    let right = batch(
        &three,
        &alice,
        &[(&bob, Some(&first[0])), (&carol, Some(&first[1]))],
    );
    let (a, b) = tokio::join!(f.send_group(&alice, &left), f.send_group(&alice, &right));
    let mut codes = [a.status().as_u16(), b.status().as_u16()];
    codes.sort();
    assert_eq!(codes, [200, 409]);
    let winner = if a.status().is_success() { left } else { right };
    let mut altered = winner.clone();
    altered[0].ciphertext[0] ^= 1;
    assert_eq!(
        f.send_group(&alice, &altered).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    let next = batch(
        &three,
        &alice,
        &[(&bob, Some(&winner[0])), (&carol, Some(&winner[1]))],
    );
    let policy = |status: &str| serde_json::json!({"device_id":bob.identity.device_id,"peer_id":alice.identity.user_id,"status":status});
    let url = format!("{}/contact-policy", f.url);
    assert_eq!(
        f.client
            .post(&url)
            .bearer_auth(&bob.token)
            .json(&policy("blocked"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.send_group(&alice, &next).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    assert!(page(&f, &bob, three.group_id()).await.envelopes.is_empty());
    assert_eq!(
        f.client
            .post(&url)
            .bearer_auth(&bob.token)
            .json(&policy("accepted"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NO_CONTENT
    );
    assert_eq!(page(&f, &bob, three.group_id()).await.envelopes.len(), 2);
    sqlx::query("UPDATE devices SET revoked=true WHERE id=$1")
        .bind(&carol.identity.device_id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        f.send_group(&alice, &next).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    assert_eq!(
        f.receive_group(&carol, three.group_id()).await.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM group_message_batches WHERE group_id=$1")
            .bind(three.group_id())
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn group_invitation_consent_and_removed_member_history_are_scoped() {
    let f = Fixture::start().await;
    let alice = f.account().await;
    let bob = f.account().await;
    let carol = f.account().await;
    let create = event(
        None,
        &alice,
        GroupAction::Create {
            name: "test group".into(),
            owner: alice.identity.clone(),
        },
    );
    assert_eq!(
        f.change(&alice, &create, true).await.status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        f.change(&alice, &create, true).await.status(),
        reqwest::StatusCode::OK
    );
    let state = pin_creation(&create, &alice.identity).unwrap();
    assert_eq!(
        f.history(&bob, state.group_id(), 0).await.status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let invite = invitation(&state, &alice, &bob);
    assert_eq!(
        f.invite(&alice, &invite).await.status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(f.pending(&bob).await.invites.len(), 1);
    assert!(f.pending(&carol).await.invites.is_empty());
    let page: GroupEventPage = f
        .history(&bob, state.group_id(), 0)
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page.through_epoch, 1);
    assert_eq!(page.changes.len(), 1);
    let join = joining(&state, &bob, invite);
    assert_eq!(
        f.change(&carol, &join, false).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    let mut forged = join.clone();
    forged.signature[0] ^= 1;
    assert_eq!(
        f.change(&bob, &forged, false).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    assert_eq!(
        f.change(&bob, &join, false).await.status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        f.change(&bob, &join, false).await.status(),
        reqwest::StatusCode::OK
    );
    let state = apply_change(Some(&state), &join).unwrap();
    let remove = event(
        Some(&state),
        &alice,
        GroupAction::Remove {
            user_id: bob.identity.user_id.clone(),
        },
    );
    assert_eq!(
        f.change(&alice, &remove, false).await.status(),
        reqwest::StatusCode::OK
    );
    let state = apply_change(Some(&state), &remove).unwrap();
    let rename = event(
        Some(&state),
        &alice,
        GroupAction::Rename {
            name: "future name".into(),
        },
    );
    assert_eq!(
        f.change(&alice, &rename, false).await.status(),
        reqwest::StatusCode::OK
    );
    let page: GroupEventPage = f
        .history(&bob, state.group_id(), 2)
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page.through_epoch, 3);
    assert_eq!(page.changes.len(), 1);
    assert!(!page.has_more);
    assert!(matches!(page.changes[0].action, GroupAction::Remove { .. }));
    assert_eq!(
        f.history(&carol, state.group_id(), 0).await.status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let row = sqlx::query("SELECT g.head_epoch,m.removed_epoch FROM private_groups g JOIN group_memberships m ON m.group_id=g.id WHERE g.id=$1 AND m.user_id=$2")
        .bind(state.group_id()).bind(&bob.identity.user_id).fetch_one(f.db.pool()).await.unwrap();
    assert_eq!(row.get::<i64, _>("head_epoch"), 4);
    assert_eq!(row.get::<i64, _>("removed_epoch"), 3);
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn concurrent_group_revision_and_cancelled_invitation_cannot_diverge() {
    let f = Fixture::start().await;
    let alice = f.account().await;
    let bob = f.account().await;
    let create = event(
        None,
        &alice,
        GroupAction::Create {
            name: "test group".into(),
            owner: alice.identity.clone(),
        },
    );
    assert_eq!(
        f.change(&alice, &create, true).await.status(),
        reqwest::StatusCode::OK
    );
    let state = pin_creation(&create, &alice.identity).unwrap();
    let invite = invitation(&state, &alice, &bob);
    assert_eq!(
        f.invite(&alice, &invite).await.status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        f.cancel(&alice, &invite.id).await.status(),
        reqwest::StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.cancel(&alice, &invite.id).await.status(),
        reqwest::StatusCode::NO_CONTENT
    );
    assert!(f.pending(&bob).await.invites.is_empty());
    assert_eq!(
        f.history(&bob, state.group_id(), 0).await.status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.change(&bob, &joining(&state, &bob, invite), false)
            .await
            .status(),
        reqwest::StatusCode::CONFLICT
    );
    let left = event(
        Some(&state),
        &alice,
        GroupAction::Rename {
            name: "left".into(),
        },
    );
    let right = event(
        Some(&state),
        &alice,
        GroupAction::Rename {
            name: "right".into(),
        },
    );
    let (a, b) = tokio::join!(
        f.change(&alice, &left, false),
        f.change(&alice, &right, false)
    );
    let mut codes = [a.status().as_u16(), b.status().as_u16()];
    codes.sort();
    assert_eq!(codes, [200, 409]);
    let page: GroupEventPage = f
        .history(&alice, state.group_id(), 0)
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page.through_epoch, 2);
    assert_eq!(page.changes.len(), 2);
    let head = apply_change(Some(&state), &page.changes[1]).unwrap();
    let pending = invitation(&head, &alice, &bob);
    assert_eq!(
        f.invite(&alice, &pending).await.status(),
        reqwest::StatusCode::OK
    );
    let close = event(Some(&head), &alice, GroupAction::Close);
    assert_eq!(
        f.change(&alice, &close, false).await.status(),
        reqwest::StatusCode::OK
    );
    assert!(f.pending(&bob).await.invites.is_empty());
    assert_eq!(
        f.history(&bob, state.group_id(), 0).await.status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM group_memberships WHERE group_id=$1 AND removed_epoch IS NULL",
    )
    .bind(head.group_id())
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(active, 0);
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn sent_invites_are_owner_scoped_paged_and_serialized_with_acceptance() {
    let f = Fixture::start().await;
    let alice = f.account().await;
    let bob = f.account().await;
    let other = f.account().await;
    let create = event(
        None,
        &alice,
        GroupAction::Create {
            name: "sent invites".into(),
            owner: alice.identity.clone(),
        },
    );
    assert!(f.change(&alice, &create, true).await.status().is_success());
    let state = pin_creation(&create, &alice.identity).unwrap();
    let list = |actor: &Account, after: String| {
        f.client
            .get(format!("{}/groups/{}/invites", f.url, state.group_id()))
            .bearer_auth(&actor.token)
            .query(&[
                ("device_id", actor.identity.device_id.clone()),
                ("after_id", after),
            ])
    };
    // Populate retained signed history directly to exercise pagination without hitting action rate limits.
    for n in 0..101 {
        let mut invite = invitation(&state, &alice, &bob);
        if n == 0 {
            invite.expires_at = now() - 1;
        }
        invite.signature = crypto::sign(&invite.signing_bytes(), &alice.keys.ed25519_sk).unwrap();
        sqlx::query("INSERT INTO group_invites(id,group_id,target_user_id,target_device_id,base_epoch,expires_at,body,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&invite.id).bind(state.group_id()).bind(&bob.identity.user_id).bind(&bob.identity.device_id).bind(1_i64).bind(invite.expires_at).bind(serde_json::to_string(&invite).unwrap()).bind(if n==1 {"revoked"}else{"pending"}).execute(f.db.pool()).await.unwrap();
    }
    let first: GroupSentInvitePage = list(&alice, uuid::Uuid::nil().to_string())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first.invites.len(), 100);
    let second: GroupSentInvitePage = list(&alice, first.next_cursor.clone().unwrap())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(second.invites.len(), 1);
    assert!(second.next_cursor.is_none());
    let all: Vec<_> = first.invites.iter().chain(&second.invites).collect();
    assert!(all.iter().any(|i| i.status == "expired"));
    assert!(all.iter().any(|i| i.status == "revoked"));
    assert_eq!(
        list(&other, uuid::Uuid::nil().to_string())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    // Clear only this test group's synthetic history; exercise a real invitation race.
    sqlx::query("DELETE FROM group_invites WHERE group_id=$1")
        .bind(state.group_id())
        .execute(f.db.pool())
        .await
        .unwrap();
    let invite = invitation(&state, &alice, &bob);
    assert!(f.invite(&alice, &invite).await.status().is_success());
    let joined = joining(&state, &bob, invite.clone());
    let cancel = f
        .client
        .delete(format!("{}/group-invites/{}", f.url, invite.id))
        .bearer_auth(&alice.token)
        .query(&[("device_id", &alice.identity.device_id)]);
    let (accepted, revoked) = tokio::join!(f.change(&bob, &joined, false), cancel.send());
    let revoked = revoked.unwrap();
    assert_ne!(
        accepted.status().is_success(),
        revoked.status().is_success()
    );
    let final_page: GroupSentInvitePage = list(&alice, uuid::Uuid::nil().to_string())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        final_page.invites[0].status,
        if accepted.status().is_success() {
            "accepted"
        } else {
            "revoked"
        }
    );
    assert_eq!(
        list(&bob, uuid::Uuid::nil().to_string())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    sqlx::query("UPDATE sessions SET revoked=true WHERE access_token_hash=$1")
        .bind(auth::service::hash_token(&alice.token))
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        list(&alice, uuid::Uuid::nil().to_string())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
}

fn collab_event(
    group: &GroupState,
    actor: &Account,
    action: liteseal_shared::collaboration::Action,
    prior: Option<&liteseal_shared::collaboration::Object>,
) -> liteseal_shared::collaboration::Submission {
    use liteseal_shared::collaboration as c;
    let id = uuid::Uuid::new_v4().to_string();
    let mut e = c::Event {
        version: 1,
        id: id.clone(),
        group: group.group_id().into(),
        epoch: group.epoch(),
        membership_hash: group.revision_hash().to_vec(),
        actor: c::Member::from(group.member(&actor.identity.user_id).unwrap()),
        object: prior.map_or(id, |p| p.id.clone()),
        revision: prior.map_or(1, |p| p.revision + 1),
        previous: prior.map_or(vec![], |p| p.head.clone()),
        at: now(),
        action,
        audience: c::members(group),
        slots: vec![],
        signature: vec![],
    };
    let mut boxes = vec![];
    if matches!(
        e.action,
        c::Action::Poll { .. } | c::Action::Mention | c::Action::Pin { .. }
    ) {
        for m in &e.audience {
            let pk: [u8; 32] = group
                .member(&m.user)
                .unwrap()
                .identity
                .public_key
                .as_slice()
                .try_into()
                .unwrap();
            let cipher =
                crypto::encrypt(b"synthetic private content", &pk, &actor.keys.secret_key).unwrap();
            e.slots.push(c::Slot {
                member: m.clone(),
                hash: c::digest(&cipher),
            });
            boxes.push(c::Boxed {
                member: m.clone(),
                ciphertext: cipher,
            });
        }
    }
    e.signature = crypto::sign(&e.signing_bytes(), &actor.keys.ed25519_sk).unwrap();
    c::Submission {
        event: e,
        boxes,
        pin_target: None,
    }
}
#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn collaboration_votes_close_and_fanout_are_atomic_and_scoped() {
    use liteseal_shared::collaboration as c;
    let f = Fixture::start().await;
    let a = f.account().await;
    let b = f.account().await;
    let outsider = f.account().await;
    let create = event(
        None,
        &a,
        GroupAction::Create {
            name: "collaboration".into(),
            owner: a.identity.clone(),
        },
    );
    assert!(f.change(&a, &create, true).await.status().is_success());
    let one = pin_creation(&create, &a.identity).unwrap();
    let g = f.add(&one, &a, &b).await;
    let endpoint = format!("{}/groups/{}/collaboration", f.url, g.group_id());
    let root = collab_event(
        &g,
        &a,
        c::Action::Poll {
            options: vec!["option-a".into(), "option-b".into()],
        },
        None,
    );
    let send = |actor: &Account, req: &c::Submission| {
        f.client
            .post(&endpoint)
            .bearer_auth(&actor.token)
            .json(req)
            .send()
    };
    let accepted = send(&a, &root).await.unwrap();
    assert_eq!(accepted.status(), reqwest::StatusCode::OK);
    let seq = accepted.json::<i64>().await.unwrap();
    assert_eq!(
        send(&a, &root).await.unwrap().json::<i64>().await.unwrap(),
        seq
    );
    assert_eq!(
        send(&outsider, &root).await.unwrap().status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let p = c::transition(None, &g, &root.event).unwrap();
    let vote = collab_event(
        &g,
        &b,
        c::Action::Vote {
            option: "option-a".into(),
        },
        Some(&p),
    );
    let close = collab_event(&g, &a, c::Action::Close, Some(&p));
    let (x, y) = tokio::join!(send(&b, &vote), send(&a, &close));
    let (x, y) = (x.unwrap().status(), y.unwrap().status());
    assert!(x.is_success() != y.is_success());
    assert!(x == reqwest::StatusCode::CONFLICT || y == reqwest::StatusCode::CONFLICT);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM group_collab_events WHERE group_id=$1")
            .bind(g.group_id())
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(count, 2);
    let page = f
        .client
        .get(&endpoint)
        .bearer_auth(&b.token)
        .query(&[("device_id", &b.identity.device_id)])
        .send()
        .await
        .unwrap()
        .json::<c::Page>()
        .await
        .unwrap();
    assert_eq!(page.items.len(), 2);
    assert!(page.items[0].ciphertext.is_some());
    let denied = f
        .client
        .get(&endpoint)
        .bearer_auth(&outsider.token)
        .query(&[("device_id", &outsider.identity.device_id)])
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::NOT_FOUND);
    let mut changed = root.clone();
    changed.boxes[0].ciphertext[0] ^= 1;
    assert_eq!(
        send(&a, &changed).await.unwrap().status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let remove = event(
        Some(&g),
        &a,
        GroupAction::Remove {
            user_id: b.identity.user_id.clone(),
        },
    );
    assert!(f.change(&a, &remove, false).await.status().is_success());
    assert_eq!(
        f.client
            .get(&endpoint)
            .bearer_auth(&b.token)
            .query(&[("device_id", &b.identity.device_id)])
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
}

#[tokio::test]
#[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
async fn collaboration_and_text_ids_cannot_alias_and_blocking_stops_download() {
    use liteseal_shared::collaboration as c;
    let f = Fixture::start().await;
    let a = f.account().await;
    let b = f.account().await;
    let root = event(
        None,
        &a,
        GroupAction::Create {
            name: "collab boundaries".into(),
            owner: a.identity.clone(),
        },
    );
    assert!(f.change(&a, &root, true).await.status().is_success());
    let initial = pin_creation(&root, &a.identity).unwrap();
    let g = f.add(&initial, &a, &b).await;
    let endpoint = format!("{}/groups/{}/collaboration", f.url, g.group_id());
    let poll = collab_event(
        &g,
        &a,
        c::Action::Poll {
            options: vec!["a".into(), "b".into()],
        },
        None,
    );
    assert!(f
        .client
        .post(&endpoint)
        .bearer_auth(&a.token)
        .json(&poll)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let mut text = batch(&g, &a, &[(&b, None)]);
    text[0].message_id = poll.event.id.clone();
    text[0].signature = crypto::sign(&text[0].signing_bytes(), &a.keys.ed25519_sk).unwrap();
    assert_eq!(
        f.send_group(&a, &text).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    let text = batch(&g, &a, &[(&b, None)]);
    assert!(f.send_group(&a, &text).await.status().is_success());
    let mut alias = collab_event(&g, &a, c::Action::Mention, None);
    alias.event.id = text[0].message_id.clone();
    alias.event.object = alias.event.id.clone();
    alias.event.signature = crypto::sign(&alias.event.signing_bytes(), &a.keys.ed25519_sk).unwrap();
    assert_eq!(
        f.client
            .post(&endpoint)
            .bearer_auth(&a.token)
            .json(&alias)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::CONFLICT
    );
    for policy in ["blocked", "accepted"] {
        assert_eq!(f.client.post(format!("{}/contact-policy",f.url)).bearer_auth(&b.token).json(&serde_json::json!({"device_id":b.identity.device_id,"peer_id":a.identity.user_id,"status":policy})).send().await.unwrap().status(),reqwest::StatusCode::NO_CONTENT);
        let response = f
            .client
            .get(&endpoint)
            .bearer_auth(&b.token)
            .query(&[("device_id", &b.identity.device_id)])
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if policy == "blocked" {
                reqwest::StatusCode::CONFLICT
            } else {
                reqwest::StatusCode::OK
            }
        );
    }
}
