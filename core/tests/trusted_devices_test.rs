use liteseal_core::trusted_devices::{Checkpoint, DeviceTrustStore};
use liteseal_shared::{
    crypto::{self, KeyPair},
    trusted_device::*,
};
use rusqlite::{params, Connection};
use std::path::PathBuf;
struct Fixture {
    path: PathBuf,
    anchor: Anchor,
    root: KeyPair,
    second: KeyPair,
}
impl Fixture {
    fn new() -> Self {
        let root = crypto::generate_keypair().unwrap();
        let second = crypto::generate_keypair().unwrap();
        let anchor = Anchor {
            origin: "https://test.example".into(),
            account: "isolated".into(),
            root: DeviceIdentity::from_keys("root".into(), &root),
        };
        Self {
            path: std::env::temp_dir()
                .join(format!("liteseal-device-trust-{}.db", uuid::Uuid::new_v4())),
            anchor,
            root,
            second,
        }
    }
    fn grant(&self, state: &DeviceState, name: &str, keys: &KeyPair) -> DeviceEvent {
        let intent = make_intent(
            &self.anchor,
            format!("join-{name}"),
            name.into(),
            crypto::random_challenge().unwrap(),
            1000,
            keys,
        )
        .unwrap();
        let challenge = make_challenge(state, &intent, 1001, &self.root).unwrap();
        let proof = answer_challenge(state, &intent, &challenge, 1002, keys).unwrap();
        make_event(
            state,
            format!("grant-{name}"),
            DeviceAction::Grant {
                intent: Box::new(intent),
                challenge: Box::new(challenge),
                proof,
            },
            1003,
            &self.root,
        )
        .unwrap()
    }
    fn open(&self) -> DeviceTrustStore {
        DeviceTrustStore::open(&self.path).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
#[test]
fn restart_replays_and_revoked_old_retry_never_resurrects() {
    let f = Fixture::new();
    let mut store = f.open();
    let initial = store.pin(&f.anchor).unwrap();
    let grant = f.grant(&initial, "second", &f.second);
    let joined = store
        .append_live(
            &f.anchor,
            &Checkpoint::from_state(&initial),
            std::slice::from_ref(&grant),
            1004,
        )
        .unwrap();
    drop(store);
    let mut store = f.open();
    assert_eq!(
        store
            .load(&f.anchor, Some(&Checkpoint::from_state(&joined)))
            .unwrap(),
        joined
    );
    let revoke = make_event(
        &joined,
        "revoke".into(),
        DeviceAction::Revoke {
            device_id: "second".into(),
            grant_hash: grant.hash(),
        },
        2000,
        &f.root,
    )
    .unwrap();
    let revoked = store
        .append_live(&f.anchor, &Checkpoint::from_state(&joined), &[revoke], 2000)
        .unwrap();
    let again = store
        .append_live(
            &f.anchor,
            &Checkpoint::from_state(&revoked),
            &[grant],
            999_999,
        )
        .unwrap();
    assert_eq!(again, revoked);
    assert!(again.secondary().is_none());
    drop(store);
    assert_eq!(f.open().load(&f.anchor, None).unwrap(), revoked);
}
#[test]
fn batch_failure_is_atomic_and_expired_live_import_differs() {
    let f = Fixture::new();
    let mut store = f.open();
    let initial = store.pin(&f.anchor).unwrap();
    let grant = f.grant(&initial, "second", &f.second);
    let joined = initial.apply(&grant).unwrap();
    let mut bad = make_event(
        &joined,
        "revoke".into(),
        DeviceAction::Revoke {
            device_id: "second".into(),
            grant_hash: grant.hash(),
        },
        2000,
        &f.root,
    )
    .unwrap();
    bad.signature[0] ^= 1;
    let checkpoint = Checkpoint::from_state(&initial);
    assert!(store
        .import_verified(&f.anchor, &checkpoint, &[grant.clone(), bad])
        .is_err());
    assert_eq!(store.load(&f.anchor, None).unwrap(), initial);
    assert!(store
        .append_live(
            &f.anchor,
            &checkpoint,
            std::slice::from_ref(&grant),
            601_000
        )
        .is_err());
    assert_eq!(store.load(&f.anchor, None).unwrap(), initial);
    assert_eq!(
        store
            .import_verified(&f.anchor, &checkpoint, &[grant])
            .unwrap(),
        joined
    );
}
#[test]
fn two_connections_serialize_competing_versions_without_overwriting() {
    let f = Fixture::new();
    let mut first = f.open();
    let initial = first.pin(&f.anchor).unwrap();
    let a = f.grant(&initial, "second", &f.second);
    let b = f.grant(&initial, "third", &crypto::generate_keypair().unwrap());
    let path = f.path.clone();
    let anchor = f.anchor.clone();
    let checkpoint = Checkpoint::from_state(&initial);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other_barrier = barrier.clone();
    let other_checkpoint = checkpoint.clone();
    let thread = std::thread::spawn(move || {
        let mut second = DeviceTrustStore::open(&path).unwrap();
        other_barrier.wait();
        second.append_live(&anchor, &other_checkpoint, &[b], 1004)
    });
    barrier.wait();
    let result = first.append_live(&f.anchor, &checkpoint, &[a], 1004);
    let other = thread.join().unwrap();
    assert_ne!(result.is_ok(), other.is_ok());
    let current = first.load(&f.anchor, None).unwrap();
    assert_eq!(current.revision(), 1);
    assert!(current.secondary().is_some());
}
#[test]
fn wrong_pin_account_origin_and_known_high_water_rollback_are_rejected() {
    let f = Fixture::new();
    let mut store = f.open();
    let initial = store.pin(&f.anchor).unwrap();
    let grant = f.grant(&initial, "second", &f.second);
    let joined = store
        .import_verified(&f.anchor, &Checkpoint::from_state(&initial), &[grant])
        .unwrap();
    let mut wrong = f.anchor.clone();
    wrong.root = DeviceIdentity::from_keys("fake-root".into(), &f.second);
    assert!(store.pin(&wrong).is_err());
    assert!(store.load(&wrong, None).is_err());
    let mut other = f.anchor.clone();
    other.account = "different".into();
    assert!(store.load(&other, None).is_err());
    let mut other = f.anchor.clone();
    other.origin = "https://other.example".into();
    assert!(store.load(&other, None).is_err());
    let conn = Connection::open(&f.path).unwrap();
    conn.execute("DELETE FROM trusted_device_events", [])
        .unwrap();
    assert!(store.load(&f.anchor, None).is_err()); // Metadata detects missing tail.
    conn.execute(
        "UPDATE trusted_device_anchors SET revision=0,head=?1",
        params![initial.head()],
    )
    .unwrap();
    assert!(store
        .load(&f.anchor, Some(&Checkpoint::from_state(&joined)))
        .is_err());
    assert_eq!(store.load(&f.anchor, None).unwrap(), initial); // No false claim of whole-DB rollback protection.
}
#[test]
fn corrupted_payload_and_checkpoint_reject_without_repairing_evidence() {
    let f = Fixture::new();
    let mut store = f.open();
    let initial = store.pin(&f.anchor).unwrap();
    let grant = f.grant(&initial, "second", &f.second);
    store
        .import_verified(
            &f.anchor,
            &Checkpoint::from_state(&initial),
            std::slice::from_ref(&grant),
        )
        .unwrap();
    let conn = Connection::open(&f.path).unwrap();
    let mut broken = grant.clone();
    broken.signature[0] ^= 1;
    let payload = serde_json::to_vec(&broken).unwrap();
    conn.execute(
        "UPDATE trusted_device_events SET payload=?1",
        params![payload],
    )
    .unwrap();
    assert!(store.load(&f.anchor, None).is_err());
    let retained: Vec<u8> = conn
        .query_row("SELECT payload FROM trusted_device_events", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(retained, payload);
    conn.execute(
        "UPDATE trusted_device_events SET payload=?1",
        params![serde_json::to_vec(&grant).unwrap()],
    )
    .unwrap();
    conn.execute(
        "UPDATE trusted_device_anchors SET head=?1",
        params![vec![0u8; 32]],
    )
    .unwrap();
    assert!(store.load(&f.anchor, None).is_err());
}
#[test]
fn public_log_contains_no_private_keys_and_batch_bound_is_enforced() {
    let f = Fixture::new();
    let mut store = f.open();
    let initial = store.pin(&f.anchor).unwrap();
    let grant = f.grant(&initial, "second", &f.second);
    assert!(store
        .import_verified(
            &f.anchor,
            &Checkpoint::from_state(&initial),
            &vec![grant.clone(); 101]
        )
        .is_err());
    assert!(store
        .import_verified(&f.anchor, &Checkpoint::from_state(&initial), &[])
        .is_err());
    store
        .import_verified(&f.anchor, &Checkpoint::from_state(&initial), &[grant])
        .unwrap();
    let conn = Connection::open(&f.path).unwrap();
    let payload: Vec<u8> = conn
        .query_row("SELECT payload FROM trusted_device_events", [], |r| {
            r.get(0)
        })
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    let json = String::from_utf8(payload).unwrap();
    for secret in [
        &f.root.secret_key[..],
        &f.second.secret_key[..],
        &f.root.ed25519_sk[..],
        &f.second.ed25519_sk[..],
    ] {
        let encoded = serde_json::to_string(secret).unwrap();
        assert!(!json.contains(&encoded));
    }
    assert!(value["action"]["intent"]["device"]["encryption_key"].is_array());
    assert!(!json.contains("access_token"));
    assert!(!json.contains("secret_key"));
}

#[test]
fn manifest_pages_verify_terminal_head_before_any_persistence() {
    let f = Fixture::new();
    let mut store = f.open();
    let initial = store.pin(&f.anchor).unwrap();
    let grant = f.grant(&initial, "second", &f.second);
    let joined = initial.apply(&grant).unwrap();
    let revoke = make_event(
        &joined,
        "revoke-page".into(),
        DeviceAction::Revoke {
            device_id: "second".into(),
            grant_hash: grant.hash(),
        },
        2000,
        &f.root,
    )
    .unwrap();
    let revoked = joined.apply(&revoke).unwrap();
    let first = DeviceManifestPage {
        anchor: f.anchor.clone(),
        events: vec![grant],
        through_revision: 1,
        current_revision: 2,
        current_hash: revoked.head().to_vec(),
        more: true,
    };
    assert_eq!(
        store
            .import_page(&f.anchor, &Checkpoint::from_state(&initial), &first)
            .unwrap(),
        joined
    );
    let mut last = DeviceManifestPage {
        anchor: f.anchor.clone(),
        events: vec![revoke],
        through_revision: 2,
        current_revision: 2,
        current_hash: vec![0; 32],
        more: false,
    };
    assert!(store
        .import_page(&f.anchor, &Checkpoint::from_state(&joined), &last)
        .is_err());
    assert_eq!(store.load(&f.anchor, None).unwrap(), joined);
    last.current_hash = revoked.head().to_vec();
    assert_eq!(
        store
            .import_page(&f.anchor, &Checkpoint::from_state(&joined), &last)
            .unwrap(),
        revoked
    );
    assert!(store
        .import_page(&f.anchor, &Checkpoint::from_state(&revoked), &last)
        .is_err());
    drop(store);
    assert_eq!(f.open().load(&f.anchor, None).unwrap(), revoked);
}

#[test]
fn malformed_manifest_scope_gap_more_flag_and_bad_second_event_are_atomic() {
    let f = Fixture::new();
    let mut store = f.open();
    let initial = store.pin(&f.anchor).unwrap();
    let checkpoint = Checkpoint::from_state(&initial);
    let grant = f.grant(&initial, "second", &f.second);
    let joined = initial.apply(&grant).unwrap();
    let valid = DeviceManifestPage {
        anchor: f.anchor.clone(),
        events: vec![grant.clone()],
        through_revision: 1,
        current_revision: 1,
        current_hash: joined.head().to_vec(),
        more: false,
    };
    let mut wrong = valid.clone();
    wrong.anchor.account = "other".into();
    assert!(store.import_page(&f.anchor, &checkpoint, &wrong).is_err());
    let mut wrong = valid.clone();
    wrong.through_revision = 2;
    assert!(store.import_page(&f.anchor, &checkpoint, &wrong).is_err());
    let mut wrong = valid.clone();
    wrong.events[0].revision = 2;
    assert!(store.import_page(&f.anchor, &checkpoint, &wrong).is_err());
    let mut wrong = valid;
    wrong.events.clear();
    wrong.through_revision = 0;
    wrong.more = true;
    assert!(store.import_page(&f.anchor, &checkpoint, &wrong).is_err());
    let mut revoke = make_event(
        &joined,
        "revoke-bad-page".into(),
        DeviceAction::Revoke {
            device_id: "second".into(),
            grant_hash: grant.hash(),
        },
        2000,
        &f.root,
    )
    .unwrap();
    let end = joined.apply(&revoke).unwrap();
    revoke.signature[0] ^= 1;
    let batch = DeviceManifestPage {
        anchor: f.anchor.clone(),
        events: vec![grant, revoke],
        through_revision: 2,
        current_revision: 2,
        current_hash: end.head().to_vec(),
        more: false,
    };
    assert!(store.import_page(&f.anchor, &checkpoint, &batch).is_err());
    assert_eq!(store.load(&f.anchor, None).unwrap(), initial);
}
