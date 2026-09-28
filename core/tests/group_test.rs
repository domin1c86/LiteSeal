#[path = "../../shared/examples/group_trial/support.rs"]
mod support;
use liteseal_core::groups::{api::GroupApi, GroupClient, GroupStore};
use liteseal_shared::{crypto, group::*};
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use support::{change, envelope, join, Participant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct TempDb(String);
impl TempDb {
    fn new() -> Self {
        Self(
            std::env::temp_dir()
                .join(format!("liteseal-group-{}.db", uuid::Uuid::new_v4()))
                .to_str()
                .unwrap()
                .into(),
        )
    }
}
impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn fixture() -> (
    Participant,
    Participant,
    Participant,
    GroupState,
    Vec<GroupChange>,
) {
    let alice = Participant::new("alice");
    let bob = Participant::new("bob");
    let carol = Participant::new("carol");
    let mut create = change(
        None,
        &alice,
        GroupAction::Create {
            name: "test group".into(),
            owner: alice.identity(),
        },
        1000,
    );
    create.group_id = uuid::Uuid::new_v4().to_string();
    create.signature = crypto::sign(&create.signing_bytes(), &alice.keys.ed25519_sk).unwrap();
    let first = pin_creation(&create, &alice.identity()).unwrap();
    let bob_join = join(&first, &alice, &bob, 1001);
    let second = apply_change(Some(&first), &bob_join).unwrap();
    let carol_join = join(&second, &alice, &carol, 1002);
    let third = apply_change(Some(&second), &carol_join).unwrap();
    (alice, bob, carol, third, vec![create, bob_join, carol_join])
}
fn seed(
    path: &str,
    origin: &str,
    identity: GroupIdentity,
    owner: &GroupIdentity,
    events: &[GroupChange],
) -> GroupStore {
    let mut store = GroupStore::open(path, origin, identity).unwrap();
    store.pin(&events[0], owner).unwrap();
    store.apply(&events[0].group_id, &events[1..]).unwrap();
    store
}
fn receipt(batch: &[GroupEnvelope]) -> GroupMessageReceipt {
    GroupMessageReceipt {
        group_id: batch[0].group_id.clone(),
        message_id: batch[0].message_id.clone(),
        recipients: batch
            .iter()
            .map(|e| GroupDeliveryStatus {
                recipient_user_id: e.recipient_user_id.clone(),
                recipient_device_id: e.recipient_device_id.clone(),
                recipient_join_epoch: e.recipient_join_epoch,
                status: "pending".into(),
            })
            .collect(),
    }
}

#[test]
fn encrypted_outbox_survives_restart_and_advances_only_on_bound_receipt() {
    let path = TempDb::new();
    let (alice, _, _, state, events) = fixture();
    let mut store = seed(
        &path.0,
        "http://localhost:3000",
        alice.identity(),
        &alice.identity(),
        &events,
    );
    let text = "private payload unique 机密 12345";
    store
        .seal_text(state.group_id(), text, &alice.keys)
        .unwrap();
    let original = store.queued(state.group_id()).unwrap().unwrap();
    assert!(store
        .seal_text(state.group_id(), "next", &alice.keys)
        .is_err());
    let db = Connection::open(&path.0).unwrap();
    let body: Vec<u8> = db
        .query_row("SELECT body FROM local_group_messages", [], |r| r.get(0))
        .unwrap();
    assert!(!body.windows(text.len()).any(|w| w == text.as_bytes()));
    let batch: String = db
        .query_row("SELECT batch FROM local_group_outbox", [], |r| r.get(0))
        .unwrap();
    assert!(!batch.contains(text));
    drop(store);
    let mut reopened =
        GroupStore::open(&path.0, "http://localhost:3000", alice.identity()).unwrap();
    assert_eq!(
        reopened.queued(state.group_id()).unwrap().unwrap(),
        original
    );
    let mut wrong = receipt(&original);
    wrong.recipients[0].recipient_join_epoch += 1;
    assert!(reopened.accepted(state.group_id(), &wrong).is_err());
    assert!(reopened.queued(state.group_id()).unwrap().is_some());
    reopened
        .accepted(state.group_id(), &receipt(&original))
        .unwrap();
    reopened
        .seal_text(state.group_id(), "second", &alice.keys)
        .unwrap();
    for next in reopened.queued(state.group_id()).unwrap().unwrap() {
        let prev = original
            .iter()
            .find(|e| e.recipient_device_id == next.recipient_device_id)
            .unwrap();
        validate_chain(&next, Some(prev)).unwrap();
    }
    assert_eq!(
        reopened
            .messages(state.group_id(), &alice.keys)
            .unwrap()
            .iter()
            .find(|m| m.id == original[0].message_id)
            .unwrap()
            .text,
        text
    );
    assert_eq!(
        GroupStore::open(&path.0, "HTTP://LOCALHOST:3000/", alice.identity())
            .unwrap()
            .group_ids()
            .unwrap(),
        vec![state.group_id().to_string()]
    );
    assert!(
        GroupStore::open(&path.0, "http://localhost:3001", alice.identity())
            .unwrap()
            .group_ids()
            .unwrap()
            .is_empty()
    );
    let mut other = alice.identity();
    other.device_id = "other-device".into();
    assert!(GroupStore::open(&path.0, "http://localhost:3000", other)
        .unwrap()
        .group_ids()
        .unwrap()
        .is_empty());
    let bad = crypto::generate_keypair().unwrap();
    let mixed = crypto::KeyPair {
        public_key: alice.keys.public_key,
        secret_key: bad.secret_key,
        ed25519_pk: alice.keys.ed25519_pk,
        ed25519_sk: alice.keys.ed25519_sk,
    };
    assert!(reopened.messages(state.group_id(), &mixed).is_err());
}
#[test]
fn invalid_or_out_of_order_messages_never_allocate_ack_or_receive_head() {
    let (alice, bob, _, state, events) = fixture();
    let mut store = seed(
        ":memory:",
        "http://localhost",
        bob.identity(),
        &alice.identity(),
        &events,
    );
    let first = envelope(
        &state,
        &alice,
        &bob,
        &uuid::Uuid::new_v4().to_string(),
        "first",
        None,
    );
    let next = envelope(
        &state,
        &alice,
        &bob,
        &uuid::Uuid::new_v4().to_string(),
        "next",
        Some(&first),
    );
    assert!(store.receive(&next, &bob.keys).is_err());
    let mut invalid = first.clone();
    invalid.signature[0] ^= 1;
    assert!(store.receive(&invalid, &bob.keys).is_err());
    let mut wrong_box = first.clone();
    wrong_box.ciphertext[0] ^= 1;
    wrong_box.signature = crypto::sign(&wrong_box.signing_bytes(), &alice.keys.ed25519_sk).unwrap();
    assert!(store.receive(&wrong_box, &bob.keys).is_err());
    assert!(store
        .acknowledgements(state.group_id(), 2)
        .unwrap()
        .is_empty());
    assert!(store
        .messages(state.group_id(), &bob.keys)
        .unwrap()
        .is_empty());
    assert!(store.receive(&first, &bob.keys).unwrap());
    assert!(!store.receive(&first, &bob.keys).unwrap());
    assert!(store.receive(&next, &bob.keys).unwrap());
    assert_eq!(
        store.acknowledgements(state.group_id(), 2).unwrap().len(),
        2
    );
}
#[test]
fn disk_failure_rolls_back_plaintext_chain_and_ack_together() {
    let path = TempDb::new();
    let (alice, bob, _, state, events) = fixture();
    let mut store = seed(
        &path.0,
        "http://localhost",
        bob.identity(),
        &alice.identity(),
        &events,
    );
    let db = Connection::open(&path.0).unwrap();
    db.execute_batch("CREATE TRIGGER fail_ack BEFORE INSERT ON local_group_ack BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
    let first = envelope(
        &state,
        &alice,
        &bob,
        &uuid::Uuid::new_v4().to_string(),
        "first",
        None,
    );
    assert!(store.receive(&first, &bob.keys).is_err());
    let count:i64=db.query_row("SELECT (SELECT COUNT(*) FROM local_group_messages)+(SELECT COUNT(*) FROM local_group_heads)+(SELECT COUNT(*) FROM local_group_ack)",[],|r|r.get(0)).unwrap();
    assert_eq!(count, 0);
    db.execute_batch("DROP TRIGGER fail_ack;").unwrap();
    assert!(store.receive(&first, &bob.keys).unwrap());
}
#[test]
fn membership_forks_and_untrusted_creation_do_not_change_the_saved_prefix() {
    let (alice, bob, carol, state, events) = fixture();
    let mut store = GroupStore::open(":memory:", "http://localhost", bob.identity()).unwrap();
    assert!(store.pin(&events[0], &carol.identity()).is_err());
    assert!(store.group_ids().unwrap().is_empty());
    store.pin(&events[0], &alice.identity()).unwrap();
    let mut fork = events[2].clone();
    fork.signature[0] ^= 1;
    assert!(store
        .apply(state.group_id(), &[events[1].clone(), fork])
        .is_err());
    assert_eq!(store.state(state.group_id()).unwrap().epoch(), 1);
    store.apply(state.group_id(), &events[1..]).unwrap();
    assert_eq!(store.apply(state.group_id(), &events).unwrap(), state);
    let mut fork = events[1].clone();
    fork.created_at += 1;
    assert!(store.apply(state.group_id(), &[fork]).is_err());
    assert_eq!(store.state(state.group_id()).unwrap(), state);
}
#[test]
fn removed_and_rejoined_members_keep_history_but_never_import_an_old_chain() {
    let (alice, bob, _, state, events) = fixture();
    let mut store = seed(
        ":memory:",
        "http://localhost",
        bob.identity(),
        &alice.identity(),
        &events,
    );
    let old = envelope(
        &state,
        &alice,
        &bob,
        &uuid::Uuid::new_v4().to_string(),
        "old",
        None,
    );
    store.receive(&old, &bob.keys).unwrap();
    let remove = change(
        Some(&state),
        &alice,
        GroupAction::Remove {
            user_id: bob.user.clone(),
        },
        1003,
    );
    let removed = store.apply(state.group_id(), &[remove]).unwrap();
    assert!(store.receive(&old, &bob.keys).is_err());
    assert!(store
        .acknowledgements(state.group_id(), 2)
        .unwrap()
        .is_empty());
    assert_eq!(
        store.messages(state.group_id(), &bob.keys).unwrap()[0].text,
        "old"
    );
    let again = join(&removed, &alice, &bob, 1004);
    let rejoined = store.apply(state.group_id(), &[again]).unwrap();
    let imported = envelope(
        &rejoined,
        &alice,
        &bob,
        &uuid::Uuid::new_v4().to_string(),
        "bad",
        Some(&old),
    );
    assert!(store.receive(&imported, &bob.keys).is_err());
    let fresh = envelope(
        &rejoined,
        &alice,
        &bob,
        &uuid::Uuid::new_v4().to_string(),
        "fresh",
        None,
    );
    assert!(store.receive(&fresh, &bob.keys).unwrap());
    assert_eq!(
        store.acknowledgements(state.group_id(), 5).unwrap(),
        vec![fresh.message_id]
    );
}

#[derive(Default)]
struct MockState {
    events: Vec<GroupChange>,
    pending: Vec<GroupEnvelope>,
    batches: Vec<Vec<GroupEnvelope>>,
    ack_attempts: usize,
    fail_ack: bool,
    fail_send_once: bool,
    cancelled: Vec<String>,
    calls: Vec<String>,
}

#[test]
fn group_drafts_are_scope_bound_and_seen_markers_do_not_ack_or_create_read_receipts() {
    let path = TempDb::new();
    let (alice, bob, _, state, events) = fixture();
    let mut receiver = seed(
        &path.0,
        "http://localhost",
        bob.identity(),
        &alice.identity(),
        &events,
    );
    receiver
        .save_draft(state.group_id(), "encrypted group draft", &bob.keys)
        .unwrap();
    let db = Connection::open(&path.0).unwrap();
    let body: Vec<u8> = db
        .query_row("SELECT body FROM local_group_drafts", [], |r| r.get(0))
        .unwrap();
    assert!(!body.windows(21).any(|w| w == b"encrypted group draft"));
    drop(receiver);
    let mut receiver = GroupStore::open(&path.0, "http://localhost", bob.identity()).unwrap();
    assert_eq!(
        receiver.draft(state.group_id(), &bob.keys).unwrap(),
        "encrypted group draft"
    );
    receiver
        .seal_text(state.group_id(), "submitted text", &bob.keys)
        .unwrap();
    assert_eq!(receiver.draft(state.group_id(), &bob.keys).unwrap(), "");
    let message = envelope(
        &state,
        &alice,
        &bob,
        &uuid::Uuid::new_v4().to_string(),
        "inbound",
        None,
    );
    receiver.receive(&message, &bob.keys).unwrap();
    assert_eq!(receiver.unread(state.group_id()).unwrap(), 1);
    receiver
        .mark_seen("different-group", std::slice::from_ref(&message.message_id))
        .unwrap();
    assert_eq!(receiver.unread(state.group_id()).unwrap(), 1);
    receiver
        .mark_seen(state.group_id(), std::slice::from_ref(&message.message_id))
        .unwrap();
    assert_eq!(receiver.unread(state.group_id()).unwrap(), 0);
    assert_eq!(
        receiver
            .acknowledgements(state.group_id(), 2)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn history_pagination_keeps_older_rows_and_local_ciphertext_is_bound_to_its_group() {
    let path = TempDb::new();
    let (alice, bob, _, state, events) = fixture();
    let mut store = seed(
        &path.0,
        "http://localhost",
        alice.identity(),
        &alice.identity(),
        &events,
    );
    for n in 0..105 {
        store
            .seal_text(state.group_id(), &format!("entry {n}"), &alice.keys)
            .unwrap();
        let queued = store.queued(state.group_id()).unwrap().unwrap();
        store.accepted(state.group_id(), &receipt(&queued)).unwrap();
    }
    let recent = store.history(state.group_id(), None, &alice.keys).unwrap();
    assert_eq!(recent.messages.len(), 100);
    assert_eq!(recent.messages[0].text, "entry 5");
    let older = store
        .history(state.group_id(), recent.next_before, &alice.keys)
        .unwrap();
    assert_eq!(older.messages.len(), 5);
    assert!(older.next_before.is_none());
    assert_eq!(older.messages[0].text, "entry 0");
    assert!(older
        .messages
        .iter()
        .all(|old| recent.messages.iter().all(|new| new.id != old.id)));
    let mut create = change(
        None,
        &alice,
        GroupAction::Create {
            name: "other group".into(),
            owner: alice.identity(),
        },
        1000,
    );
    create.group_id = uuid::Uuid::new_v4().to_string();
    create.signature = crypto::sign(&create.signing_bytes(), &alice.keys.ed25519_sk).unwrap();
    store.pin(&create, &alice.identity()).unwrap();
    let other = pin_creation(&create, &alice.identity()).unwrap();
    store
        .apply(other.group_id(), &[join(&other, &alice, &bob, 1001)])
        .unwrap();
    store
        .seal_text(other.group_id(), "other text", &alice.keys)
        .unwrap();
    let db = Connection::open(&path.0).unwrap();
    db.execute("UPDATE local_group_messages SET body=(SELECT body FROM local_group_messages WHERE group_id=?1 LIMIT 1) WHERE group_id=?2",rusqlite::params![state.group_id(),other.group_id()]).unwrap();
    assert!(store.messages(other.group_id(), &alice.keys).is_err());
    assert_eq!(
        store
            .history(state.group_id(), recent.next_before, &alice.keys)
            .unwrap()
            .messages
            .len(),
        5
    );
    db.execute(
        "UPDATE local_group_outbox SET batch='[]' WHERE group_id=?1 AND status='queued'",
        [other.group_id()],
    )
    .unwrap();
    assert!(store.queued(other.group_id()).is_err());
}
struct MockServer {
    origin: String,
    state: Arc<Mutex<MockState>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl MockServer {
    async fn new(events: Vec<GroupChange>) -> Self {
        let state = Arc::new(Mutex::new(MockState {
            events,
            ..Default::default()
        }));
        let work = state.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 8192];
                let (start, length, path) = loop {
                    let count = socket.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break (0, 0, String::new());
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end]);
                        assert!(header
                            .to_lowercase()
                            .contains("authorization: bearer test-token"));
                        let length = header
                            .lines()
                            .find_map(|line| {
                                line.to_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(|value| value.parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        let path = header
                            .lines()
                            .next()
                            .unwrap()
                            .split_whitespace()
                            .nth(1)
                            .unwrap()
                            .to_string();
                        break (end + 4, length, path);
                    }
                };
                if path.is_empty() {
                    continue;
                }
                while bytes.len() < start + length {
                    let count = socket.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                }
                let body: serde_json::Value = if length == 0 {
                    serde_json::Value::Null
                } else {
                    serde_json::from_slice(&bytes[start..start + length]).unwrap()
                };
                let (status, response) = {
                    let mut state = work.lock().unwrap();
                    state.calls.push(path.clone());
                    mock_response(&mut state, &path, body)
                };
                let response = serde_json::to_vec(&response).unwrap();
                let header=format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len());
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(&response).await.unwrap();
            }
        });
        Self {
            origin,
            state,
            task,
        }
    }
}
fn mock_response(
    state: &mut MockState,
    path: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let route = path.split('?').next().unwrap();
    let group = &state.events[0].group_id;
    if route.ends_with("/changes") {
        let url = url::Url::parse(&format!("http://test{path}")).unwrap();
        let after = url
            .query_pairs()
            .find(|(key, _)| key == "after_epoch")
            .unwrap()
            .1
            .parse::<u64>()
            .unwrap();
        return (
            200,
            serde_json::to_value(GroupEventPage {
                changes: state
                    .events
                    .iter()
                    .filter(|e| e.epoch > after)
                    .cloned()
                    .collect(),
                through_epoch: state.events.last().unwrap().epoch,
                has_more: false,
            })
            .unwrap(),
        );
    }
    if route.ends_with("/ack") {
        state.ack_attempts += 1;
        if state.fail_ack {
            return (503, serde_json::Value::Null);
        }
        let ack: GroupAckRequest = serde_json::from_value(body).unwrap();
        state
            .pending
            .retain(|e| !ack.message_ids.contains(&e.message_id));
        return (204, serde_json::Value::Null);
    }
    if route.ends_with("/cancel") {
        let message = route.split('/').nth(4).unwrap().to_string();
        let existing = state
            .batches
            .iter()
            .find(|batch| batch[0].message_id == message);
        let response = if let Some(batch) = existing {
            GroupCancelResult {
                group_id: group.clone(),
                message_id: message,
                cancelled: false,
                receipt: Some(receipt(batch)),
            }
        } else {
            state.cancelled.push(message.clone());
            GroupCancelResult {
                group_id: group.clone(),
                message_id: message,
                cancelled: true,
                receipt: None,
            }
        };
        return (200, serde_json::to_value(response).unwrap());
    }
    if route.ends_with("/messages") && body.is_null() {
        return (
            200,
            serde_json::to_value(GroupMessagePage {
                envelopes: state.pending.clone(),
                has_more: false,
            })
            .unwrap(),
        );
    }
    if route.ends_with("/messages") {
        let request: GroupSendRequest = serde_json::from_value(body).unwrap();
        if state.cancelled.contains(&request.envelopes[0].message_id) {
            return (409, serde_json::Value::Null);
        }
        if let Some(previous) = state
            .batches
            .iter()
            .find(|batch| batch[0].message_id == request.envelopes[0].message_id)
        {
            assert_eq!(*previous, request.envelopes);
        } else {
            state.batches.push(request.envelopes.clone());
        }
        if state.fail_send_once {
            state.fail_send_once = false;
            return (503, serde_json::Value::Null);
        }
        return (
            200,
            serde_json::to_value(receipt(&request.envelopes)).unwrap(),
        );
    }
    panic!("unexpected synthetic route")
}

#[tokio::test]
async fn poll_never_acks_invalid_data_and_retries_durable_ack_after_restart() {
    let path = TempDb::new();
    let (alice, bob, _, state, events) = fixture();
    let mock = MockServer::new(events.clone()).await;
    drop(seed(
        &path.0,
        &mock.origin,
        bob.identity(),
        &alice.identity(),
        &events,
    ));
    let first = envelope(
        &state,
        &alice,
        &bob,
        &uuid::Uuid::new_v4().to_string(),
        "durable",
        None,
    );
    let mut invalid = first.clone();
    invalid.signature[0] ^= 1;
    mock.state.lock().unwrap().pending = vec![first.clone(), invalid];
    let client =
        GroupClient::new(&path.0, &mock.origin, "test-token".into(), bob.identity()).unwrap();
    assert!(client.poll(state.group_id(), &bob.keys).await.is_err());
    assert_eq!(mock.state.lock().unwrap().ack_attempts, 0);
    assert_eq!(
        client.messages(state.group_id(), &bob.keys).unwrap().len(),
        1
    );
    drop(client);
    {
        let mut m = mock.state.lock().unwrap();
        m.pending = vec![first];
        m.fail_ack = true;
    }
    let client =
        GroupClient::new(&path.0, &mock.origin, "test-token".into(), bob.identity()).unwrap();
    assert!(client.poll(state.group_id(), &bob.keys).await.is_err());
    drop(client);
    mock.state.lock().unwrap().fail_ack = false;
    let client =
        GroupClient::new(&path.0, &mock.origin, "test-token".into(), bob.identity()).unwrap();
    assert_eq!(client.poll(state.group_id(), &bob.keys).await.unwrap(), 0);
    assert!(mock.state.lock().unwrap().pending.is_empty());
    assert_eq!(
        client.messages(state.group_id(), &bob.keys).unwrap().len(),
        1
    );
    let store = GroupStore::open(&path.0, &mock.origin, bob.identity()).unwrap();
    assert!(store
        .acknowledgements(state.group_id(), 2)
        .unwrap()
        .is_empty());
}
#[tokio::test]
async fn ambiguous_send_retries_original_batch_and_cancel_does_not_submit_text() {
    let path = TempDb::new();
    let (alice, bob, _, state, events) = fixture();
    let mock = MockServer::new(events.clone()).await;
    drop(seed(
        &path.0,
        &mock.origin,
        bob.identity(),
        &alice.identity(),
        &events,
    ));
    let client =
        GroupClient::new(&path.0, &mock.origin, "test-token".into(), bob.identity()).unwrap();
    client
        .queue_text(state.group_id(), "ambiguous", &bob.keys)
        .await
        .unwrap();
    mock.state.lock().unwrap().fail_send_once = true;
    assert!(client.send_queued(state.group_id()).await.is_err());
    drop(client);
    let client =
        GroupClient::new(&path.0, &mock.origin, "test-token".into(), bob.identity()).unwrap();
    client.send_queued(state.group_id()).await.unwrap();
    assert_eq!(mock.state.lock().unwrap().batches.len(), 1);
    let cancelled = client
        .queue_text(state.group_id(), "cancel before send", &bob.keys)
        .await
        .unwrap();
    client.cancel_unsent(state.group_id()).await.unwrap();
    assert_eq!(mock.state.lock().unwrap().batches.len(), 1);
    assert!(mock.state.lock().unwrap().cancelled.contains(&cancelled));
    client
        .queue_text(state.group_id(), "after cancellation", &bob.keys)
        .await
        .unwrap();
    client.send_queued(state.group_id()).await.unwrap();
    assert!(mock.state.lock().unwrap().batches[1]
        .iter()
        .all(|e| e.sender_seq == 2));
    let messages = client.messages(state.group_id(), &bob.keys).unwrap();
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|m| m.status == "accepted"));
    let ambiguous = client
        .queue_text(state.group_id(), "accepted before lost response", &bob.keys)
        .await
        .unwrap();
    mock.state.lock().unwrap().fail_send_once = true;
    assert!(client.send_queued(state.group_id()).await.is_err());
    assert!(client.cancel_unsent(state.group_id()).await.is_err());
    assert!(client
        .send_queued(state.group_id())
        .await
        .unwrap()
        .is_none());
    assert!(!mock.state.lock().unwrap().cancelled.contains(&ambiguous));
    assert_eq!(
        client.messages(state.group_id(), &bob.keys).unwrap().len(),
        3
    );
}
#[tokio::test]
async fn api_rejects_path_injection_and_credentials_in_server_urls_before_requests() {
    let (_, _, _, _, events) = fixture();
    let mock = MockServer::new(events).await;
    assert!(GroupApi::new(
        "http://user:password@localhost",
        "test-token".into(),
        "device".into()
    )
    .is_err());
    let api = GroupApi::new(&mock.origin, "test-token".into(), "device".into()).unwrap();
    assert!(api.changes("../auth/logout", 0).await.is_err());
    assert!(api.cancel_message("../auth", "logout").await.is_err());
    assert!(mock.state.lock().unwrap().calls.is_empty());
}

#[test]
fn group_notifications_are_fresh_private_scoped_and_muting_survives_restart() {
    let path = TempDb::new();
    let (alice, bob, _, state, events) = fixture();
    let id = state.group_id();
    let mut receiver = seed(
        &path.0,
        "http://localhost:3000",
        bob.identity(),
        &alice.identity(),
        &events,
    );
    let sender_path = TempDb::new();
    let mut sender = seed(
        &sender_path.0,
        "http://localhost:3000",
        alice.identity(),
        &alice.identity(),
        &events,
    );
    sender
        .seal_text(id, "secret notification body", &alice.keys)
        .unwrap();
    let batch = sender.queued(id).unwrap().unwrap();
    let message = batch
        .iter()
        .find(|e| e.recipient_user_id == bob.identity().user_id)
        .unwrap();
    assert!(receiver.receive(message, &bob.keys).unwrap());
    assert!(!receiver.receive(message, &bob.keys).unwrap());
    let notices = receiver.take_notifications().unwrap();
    assert_eq!(notices.len(), 1);
    let serialized = serde_json::to_string(&notices).unwrap();
    assert!(!serialized.contains("secret notification body"));
    assert_eq!(notices[0].message_id, message.message_id);
    assert!(receiver.take_notifications().unwrap().is_empty());
    receiver.set_muted(id, true).unwrap();
    assert_eq!(receiver.unread(id).unwrap(), 1);
    assert!(!receiver
        .acknowledgements(id, message.recipient_join_epoch)
        .unwrap()
        .is_empty());
    drop(receiver);
    let receiver = GroupStore::open(&path.0, "http://localhost:3000", bob.identity()).unwrap();
    assert!(receiver.muted(id).unwrap());
    let other = seed(
        &path.0,
        "http://localhost:3001",
        bob.identity(),
        &alice.identity(),
        &events,
    );
    assert!(!other.muted(id).unwrap());
}
