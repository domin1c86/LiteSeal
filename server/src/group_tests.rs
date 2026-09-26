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
