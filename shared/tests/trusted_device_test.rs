use liteseal_shared::{
    crypto::{self, KeyPair},
    trusted_device::*,
};

struct Fixture {
    root: KeyPair,
    second: KeyPair,
    state: DeviceState,
}
impl Fixture {
    fn new() -> Self {
        let root = crypto::generate_keypair().unwrap();
        let second = crypto::generate_keypair().unwrap();
        let state = DeviceState::pin(Anchor {
            origin: "https://relay.example".into(),
            account: "alice".into(),
            root: DeviceIdentity::from_keys("root-device".into(), &root),
        })
        .unwrap();
        Self {
            root,
            second,
            state,
        }
    }
    fn grant(&self) -> DeviceEvent {
        grant(
            &self.state,
            &self.root,
            &self.second,
            "join-1",
            "second-device",
            "grant-1",
            1000,
        )
    }
}
fn grant(
    state: &DeviceState,
    root: &KeyPair,
    second: &KeyPair,
    intent_id: &str,
    device_id: &str,
    event_id: &str,
    at: i64,
) -> DeviceEvent {
    let intent = make_intent(
        state.anchor(),
        intent_id.into(),
        device_id.into(),
        crypto::random_challenge().unwrap(),
        at,
        second,
    )
    .unwrap();
    let challenge = make_challenge(state, &intent, at, root).unwrap();
    let proof = answer_challenge(state, &intent, &challenge, at, second).unwrap();
    make_event(
        state,
        event_id.into(),
        DeviceAction::Grant {
            intent: Box::new(intent),
            challenge: Box::new(challenge),
            proof,
        },
        at,
        root,
    )
    .unwrap()
}
fn resign(event: &mut DeviceEvent, keys: &KeyPair) {
    event.signature = crypto::sign(&event.signing_bytes(), &keys.ed25519_sk).unwrap();
}
#[test]
fn independent_keys_grant_revoke_and_exact_retry() {
    let f = Fixture::new();
    let event = f.grant();
    let joined = f.state.apply_live(&event, 1001).unwrap();
    assert_ne!(f.root.public_key, f.second.public_key);
    assert_ne!(f.root.ed25519_pk, f.second.ed25519_pk);
    assert_eq!(
        joined.secondary().unwrap().encryption_key,
        f.second.public_key
    );
    assert_eq!(joined.apply_live(&event, 2_000_000).unwrap(), joined);
    let revoke = make_event(
        &joined,
        "revoke-1".into(),
        DeviceAction::Revoke {
            device_id: "second-device".into(),
            grant_hash: event.hash(),
        },
        2000,
        &f.root,
    )
    .unwrap();
    let revoked = joined.apply(&revoke).unwrap();
    assert!(revoked.secondary().is_none());
    assert_eq!(revoked.apply(&event).unwrap(), revoked); // Never resurrect on old retry.
    assert_eq!(revoked.apply(&revoke).unwrap(), revoked);
}
#[test]
fn all_event_fields_are_signed_and_wrong_root_rejected() {
    let f = Fixture::new();
    let event = f.grant();
    let mut changed = vec![];
    let mut e = event.clone();
    e.id = "other".into();
    changed.push(e);
    let mut e = event.clone();
    e.version = 2;
    changed.push(e);
    let mut e = event.clone();
    e.anchor_hash[0] ^= 1;
    changed.push(e);
    let mut e = event.clone();
    e.revision += 1;
    changed.push(e);
    let mut e = event.clone();
    e.previous[0] ^= 1;
    changed.push(e);
    let mut e = event.clone();
    e.created_at += 1;
    changed.push(e);
    let mut e = event.clone();
    e.signature.pop();
    changed.push(e);
    let mut e = event.clone();
    resign(&mut e, &f.second);
    changed.push(e);
    for e in changed {
        assert!(f.state.apply(&e).is_err());
    }
    let mut other = f.state.anchor().clone();
    other.origin = "https://other.example".into();
    assert!(DeviceState::pin(other).unwrap().apply(&event).is_err());
    let mut other = f.state.anchor().clone();
    other.account = "bob".into();
    assert!(DeviceState::pin(other).unwrap().apply(&event).is_err());
}
#[test]
fn decryption_and_signing_possession_are_both_required() {
    let f = Fixture::new();
    let mut event = f.grant();
    let DeviceAction::Grant {
        intent,
        challenge,
        proof,
    } = &mut event.action
    else {
        panic!()
    };
    let stranger = crypto::generate_keypair().unwrap();
    assert!(answer_challenge(&f.state, intent, challenge, 1001, &stranger).is_err());
    // A signature over the advertised commitment cannot replace decrypting the random nonce.
    proof.nonce = challenge.nonce_commitment.clone();
    proof.signature = crypto::sign(&proof.signing_bytes(), &f.second.ed25519_sk).unwrap();
    resign(&mut event, &f.root);
    assert_eq!(f.state.apply(&event), Err(DeviceError::Proof));
    let mut event = f.grant();
    if let DeviceAction::Grant { proof, .. } = &mut event.action {
        proof.signature = crypto::sign(&proof.signing_bytes(), &stranger.ed25519_sk).unwrap();
    }
    resign(&mut event, &f.root);
    assert_eq!(f.state.apply(&event), Err(DeviceError::Proof));
}
#[test]
fn challenge_ciphertext_and_proof_cannot_be_transplanted() {
    let f = Fixture::new();
    let event = f.grant();
    let DeviceAction::Grant {
        intent,
        challenge,
        proof,
    } = &event.action
    else {
        panic!()
    };
    let mut tampered = challenge.clone();
    tampered.ciphertext[24] ^= 1;
    assert!(answer_challenge(&f.state, intent, &tampered, 1001, &f.second).is_err());
    tampered.signature = crypto::sign(&tampered.signing_bytes(), &f.root.ed25519_sk).unwrap();
    assert!(answer_challenge(&f.state, intent, &tampered, 1001, &f.second).is_err());
    let other = make_challenge(&f.state, intent, 1001, &f.root).unwrap();
    assert!(proof.verify(&other, &intent.device).is_err());
    let mut second_intent = intent.clone();
    second_intent.id = "different".into();
    second_intent.signature =
        crypto::sign(&second_intent.signing_bytes(), &f.second.ed25519_sk).unwrap();
    assert!(answer_challenge(&f.state, &second_intent, challenge, 1001, &f.second).is_err());
}
#[test]
fn live_expiration_differs_from_historical_replay() {
    let f = Fixture::new();
    let event = f.grant();
    assert_eq!(f.state.apply_live(&event, 999), Err(DeviceError::Expired));
    assert!(f.state.apply_live(&event, 600_999).is_ok());
    assert_eq!(
        f.state.apply_live(&event, 601_000),
        Err(DeviceError::Expired)
    );
    assert!(f.state.apply(&event).is_ok());
    let DeviceAction::Grant {
        intent, challenge, ..
    } = &event.action
    else {
        panic!()
    };
    assert!(answer_challenge(&f.state, intent, challenge, 999, &f.second).is_err());
    assert!(answer_challenge(&f.state, intent, challenge, 601_000, &f.second).is_err());
}
#[test]
fn concurrent_grants_root_revocation_and_secondary_signer_fail() {
    let f = Fixture::new();
    let event = f.grant();
    let joined = f.state.apply(&event).unwrap();
    let other = grant(
        &f.state,
        &f.root,
        &crypto::generate_keypair().unwrap(),
        "join-2",
        "third-device",
        "grant-2",
        1001,
    );
    assert_eq!(joined.apply(&other), Err(DeviceError::Chain));
    let action = DeviceAction::Revoke {
        device_id: "root-device".into(),
        grant_hash: event.hash(),
    };
    assert!(make_event(&joined, "illegal".into(), action, 2000, &f.root).is_err());
    let action = DeviceAction::Revoke {
        device_id: "second-device".into(),
        grant_hash: event.hash(),
    };
    assert!(make_event(&joined, "illegal".into(), action.clone(), 2000, &f.second).is_err());
    let mut wrong = make_event(&joined, "revoke".into(), action, 2000, &f.root).unwrap();
    if let DeviceAction::Revoke { grant_hash, .. } = &mut wrong.action {
        grant_hash[0] ^= 1;
    }
    resign(&mut wrong, &f.root);
    assert!(joined.apply(&wrong).is_err());
}
#[test]
fn retired_keys_ids_and_consumed_intents_never_regain_eligibility() {
    let f = Fixture::new();
    let event = f.grant();
    let joined = f.state.apply(&event).unwrap();
    let revoke = make_event(
        &joined,
        "revoke".into(),
        DeviceAction::Revoke {
            device_id: "second-device".into(),
            grant_hash: event.hash(),
        },
        2000,
        &f.root,
    )
    .unwrap();
    let revoked = joined.apply(&revoke).unwrap();
    let fresh = crypto::generate_keypair().unwrap();
    for (request, device, keys) in [
        ("new", "second-device", &fresh),
        ("new", "new-device", &f.second),
        ("join-1", "new-device", &fresh),
    ] {
        let intent = make_intent(
            revoked.anchor(),
            request.into(),
            device.into(),
            crypto::random_challenge().unwrap(),
            2001,
            keys,
        )
        .unwrap();
        assert_eq!(
            make_challenge(&revoked, &intent, 2001, &f.root),
            Err(DeviceError::Conflict)
        );
    }
    let next = grant(
        &revoked,
        &f.root,
        &fresh,
        "join-new",
        "fresh-device",
        "grant-new",
        2001,
    );
    assert!(revoked.apply(&next).is_ok());
}
#[test]
fn exact_id_retry_is_idempotent_but_changed_content_conflicts() {
    let f = Fixture::new();
    let event = f.grant();
    let joined = f.state.apply(&event).unwrap();
    let mut changed = event.clone();
    changed.created_at += 1;
    resign(&mut changed, &f.root);
    assert_eq!(joined.apply(&changed), Err(DeviceError::Conflict));
    let mut changed = event.clone();
    changed.signature[0] ^= 1;
    assert_eq!(joined.apply(&changed), Err(DeviceError::Conflict));
}
#[test]
fn strict_origin_shape_unknown_fields_and_maximum_times() {
    assert_eq!(
        canonical_origin("HTTPS://Relay.Example:443/").unwrap(),
        "https://relay.example"
    );
    for origin in [
        "https://relay.example/path",
        "https://u:p@relay.example",
        "https://relay.example?x=1",
        "https://relay.example/#fragment",
        "file:///tmp/db",
    ] {
        assert!(canonical_origin(origin).is_err());
    }
    let f = Fixture::new();
    let mut anchor = f.state.anchor().clone();
    anchor.origin += "/";
    assert!(DeviceState::pin(anchor).is_err());
    assert!(make_intent(
        f.state.anchor(),
        "join".into(),
        "new".into(),
        [1; 32],
        i64::MAX,
        &f.second
    )
    .is_err());
    let event = f.grant();
    let mut json = serde_json::to_value(event).unwrap();
    json["private_key"] = serde_json::json!([1, 2, 3]);
    assert!(serde_json::from_value::<DeviceEvent>(json).is_err());
}
