use super::{store::Store, Peer};
use liteseal_shared::{
    crypto,
    protocol::{AckOutcome, SignedEnvelopeV2},
};

fn peer(id: &str, keys: &crypto::KeyPair) -> Peer {
    Peer {
        user_id: id.into(),
        username: id.into(),
        device_id: format!("{id}-device"),
        public_key: keys.public_key.to_vec(),
        ed25519_pk: keys.ed25519_pk.to_vec(),
        fingerprint: crate::contacts::fingerprint(&keys.ed25519_pk),
        accepted: false,
        verified: false,
        blocked: false,
        key_changed: false,
    }
}
fn envelope(
    id: &str,
    seq: i64,
    previous: Vec<u8>,
    alice: &crypto::KeyPair,
    bob: &crypto::KeyPair,
) -> SignedEnvelopeV2 {
    let mut e = SignedEnvelopeV2 {
        protocol_version: 2,
        message_id: id.into(),
        conversation_id: "dm:alice:bob".into(),
        sender_user_id: "alice".into(),
        sender_device_id: "alice-device".into(),
        recipient_user_id: "bob".into(),
        recipient_device_id: "bob-device".into(),
        sender_seq: seq,
        prev_hash: previous,
        sent_at: seq,
        message_type: "text".into(),
        ciphertext: crypto::encrypt(
            b"synthetic beta fixture",
            &bob.public_key,
            &alice.secret_key,
        )
        .unwrap(),
        signature: vec![],
    };
    e.signature = crypto::sign(&e.signing_bytes().unwrap(), &alice.ed25519_sk).unwrap();
    e
}

#[test]
fn queue_is_encrypted_and_sealing_rolls_back_without_consuming_sequence() {
    let store = Store::open(":memory:").unwrap();
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();
    let bob_peer = peer("bob", &bob);
    store.discover(&bob_peer).unwrap();
    assert!(store
        .queue("alice", "bob", "synthetic beta fixture")
        .is_err());
    store.accept("bob", &bob_peer.fingerprint, true).unwrap();
    let id = store
        .queue("alice", "bob", "synthetic beta fixture")
        .unwrap();
    let outgoing = store.ready().unwrap().remove(0);
    assert!(!outgoing
        .body
        .windows(b"synthetic beta fixture".len())
        .any(|w| w == b"synthetic beta fixture"));
    assert!(store
        .seal(&id, "dm:alice:bob", "alice-device", |_, _| Err(
            "injected failure".into()
        ))
        .is_err());
    let original = store
        .seal(&id, "dm:alice:bob", "alice-device", |seq, hash| {
            Ok(envelope(&id, seq, hash, &alice, &bob))
        })
        .unwrap();
    assert_eq!(original.sender_seq, 1);
    let replay = store
        .seal(&id, "dm:alice:bob", "alice-device", |_, _| {
            panic!("must reuse original")
        })
        .unwrap();
    assert_eq!(original, replay);
    store.status(&id, "delivered", "").unwrap();
    store.status(&id, "stored", "").unwrap();
    assert_eq!(
        store
            .history("alice", "alice-device", "bob", 50, 0)
            .unwrap()[0]
            .local_state,
        "delivered"
    );
}

#[test]
fn requests_and_gaps_wait_without_ack_then_process_idempotently() {
    let store = Store::open(":memory:").unwrap();
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();
    let first = envelope("one", 1, vec![], &alice, &bob);
    let second = envelope("two", 2, first.chain_hash(), &alice, &bob);
    store.receive("bob", "bob-device", &second).unwrap();
    assert_eq!(store.requests().unwrap().len(), 1);
    assert!(store.acks().unwrap().is_empty());
    let identity = peer("alice", &alice);
    store.discover(&identity).unwrap();
    assert!(!store.process(&bob.secret_key, &second).unwrap());
    store.accept("alice", &identity.fingerprint, true).unwrap();
    assert!(!store.process(&bob.secret_key, &second).unwrap());
    store.receive("bob", "bob-device", &first).unwrap();
    for item in store.pending().unwrap() {
        assert!(store.process(&bob.secret_key, &item).unwrap());
    }
    assert_eq!(
        store
            .history("bob", "bob-device", "alice", 50, 0)
            .unwrap()
            .len(),
        2
    );
    store.ack_sent("one").unwrap();
    store.receive("bob", "bob-device", &first).unwrap();
    assert!(store
        .acks()
        .unwrap()
        .contains(&("one".into(), AckOutcome::Processed)));
    let mut conflict = first;
    conflict.ciphertext.push(9);
    assert!(store.receive("bob", "bob-device", &conflict).is_err());
    assert_eq!(
        store
            .history("bob", "bob-device", "alice", 50, 0)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn rejecting_preserves_chain_evidence_for_unblocking() {
    let store = Store::open(":memory:").unwrap();
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();
    let identity = peer("alice", &alice);
    store.discover(&identity).unwrap();
    let first = envelope("one", 1, vec![], &alice, &bob);
    store.receive("bob", "bob-device", &first).unwrap();
    store.block("alice", true).unwrap();
    assert!(store.process(&bob.secret_key, &first).unwrap());
    assert_eq!(
        store.acks().unwrap(),
        vec![("one".into(), AckOutcome::Rejected)]
    );
    store.block("alice", false).unwrap();
    store.accept("alice", &identity.fingerprint, true).unwrap();
    let next = envelope("two", 2, first.chain_hash(), &alice, &bob);
    store.receive("bob", "bob-device", &next).unwrap();
    assert!(store.process(&bob.secret_key, &next).unwrap());
    assert_eq!(
        store
            .history("bob", "bob-device", "alice", 50, 0)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn durable_request_and_ack_survive_reopening() {
    let path = std::env::temp_dir().join(format!("liteseal-beta-{}.sqlite", uuid::Uuid::new_v4()));
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();
    let item = envelope("one", 1, vec![], &alice, &bob);
    {
        let store = Store::open(path.to_str().unwrap()).unwrap();
        store.receive("bob", "bob-device", &item).unwrap();
    }
    {
        let store = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(store.requests().unwrap().len(), 1);
        let identity = peer("alice", &alice);
        store.discover(&identity).unwrap();
        store.accept("alice", &identity.fingerprint, true).unwrap();
        store.process(&bob.secret_key, &item).unwrap();
    }
    {
        let store = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(store.acks().unwrap().len(), 1);
    }
    std::fs::remove_file(path).unwrap();
}
