use liteseal_shared::device_activation::Challenge;
use liteseal_shared::{crypto, device_activation::*, trusted_device::*};
const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
const ROOT: &str = "22222222-2222-4222-8222-222222222222";
const SECOND: &str = "33333333-3333-4333-8333-333333333333";
const MODE: &str = "44444444-4444-4444-8444-444444444444";
const REQUEST: &str = "55555555-5555-4555-8555-555555555555";
struct Fixture {
    root: crypto::KeyPair,
    second: crypto::KeyPair,
    initial: DeviceState,
    joined: DeviceState,
    mode: Enable,
}
impl Fixture {
    fn new() -> Self {
        let root = crypto::generate_keypair().unwrap();
        let second = crypto::generate_keypair().unwrap();
        let initial = DeviceState::pin(Anchor {
            origin: "https://activation.invalid".into(),
            account: ACCOUNT.into(),
            root: DeviceIdentity::from_keys(ROOT.into(), &root),
        })
        .unwrap();
        let intent = make_intent(
            initial.anchor(),
            "grant-request".into(),
            SECOND.into(),
            crypto::random_challenge().unwrap(),
            1000,
            &second,
        )
        .unwrap();
        let challenge = make_challenge(&initial, &intent, 1001, &root).unwrap();
        let proof = answer_challenge(&initial, &intent, &challenge, 1002, &second).unwrap();
        let event = make_event(
            &initial,
            "grant-event".into(),
            DeviceAction::Grant {
                intent: Box::new(intent),
                challenge: Box::new(challenge),
                proof,
            },
            1003,
            &root,
        )
        .unwrap();
        let joined = initial.apply(&event).unwrap();
        let mode = Enable::make(&joined, MODE, &root).unwrap();
        Self {
            root,
            second,
            initial,
            joined,
            mode,
        }
    }
}
#[test]
fn session_metadata_requires_live_original_device_authority_and_bounded_expiry() {
    let f = Fixture::new();
    let device = f.joined.secondary().unwrap().clone();
    let directory = liteseal_shared::direct_message::Directory::from_state(&f.joined);
    let info = SessionInfo {
        version: 1,
        id: REQUEST.into(),
        account: ACCOUNT.into(),
        device: device.clone(),
        authorization: directory
            .members
            .iter()
            .find(|m| m.device == device)
            .unwrap()
            .authorization_hash,
        mode: f.mode.digest().unwrap(),
        expires_at: 3000,
        refresh_expires_at: 4000,
        refresh_hash: [1; 32],
    };
    info.verify(&f.joined, &f.mode, &device, 2000).unwrap();
    assert!(info.verify(&f.initial, &f.mode, &device, 2000).is_err());
    assert!(info.verify(&f.joined, &f.mode, &device, 3000).is_err());
    for case in 0..9 {
        let mut wrong = info.clone();
        match case {
            0 => wrong.version = 2,
            1 => wrong.id = "not-a-session".into(),
            2 => wrong.account = ROOT.into(),
            3 => wrong.device = f.joined.anchor().root.clone(),
            4 => wrong.authorization[0] ^= 1,
            5 => wrong.mode[0] ^= 1,
            6 => wrong.refresh_expires_at = wrong.expires_at,
            7 => wrong.refresh_hash = [0; 32],
            _ => wrong.refresh_expires_at = 8_640_000_000_000_001,
        }
        assert!(wrong.verify(&f.joined, &f.mode, &device, 2000).is_err());
    }
}
#[test]
fn original_signature_enables_exact_directory_and_secondary_cannot_enable() {
    let f = Fixture::new();
    f.mode.verify_current(&f.joined).unwrap();
    assert!(f.mode.verify_current(&f.initial).is_err());
    assert!(Enable::make(&f.joined, MODE, &f.second).is_err());
    for field in ["origin", "account", "root", "revision", "head"] {
        let mut value = serde_json::to_value(&f.mode).unwrap();
        match field {
            "revision" => value[field] = serde_json::json!(2),
            "head" => value[field][0] = serde_json::json!(0),
            "origin" => value[field] = serde_json::json!("https://other.invalid"),
            _ => value[field] = serde_json::json!(REQUEST),
        };
        let modified: Enable = serde_json::from_value(value).unwrap();
        assert!(modified.verify_current(&f.joined).is_err());
    }
}
#[test]
fn both_private_keys_are_required_and_proof_retry_is_exact() {
    let f = Fixture::new();
    for (device, keys) in [(ROOT, &f.root), (SECOND, &f.second)] {
        let challenge = Challenge::make(&f.joined, &f.mode, REQUEST, device, 2000).unwrap();
        let proof = challenge.answer(&f.joined, &f.mode, 2001, keys).unwrap();
        proof.verify(&challenge).unwrap();
        let wire = serde_json::to_vec(&proof).unwrap();
        let replay: Proof = serde_json::from_slice(&wire).unwrap();
        assert_eq!(replay.digest().unwrap(), proof.digest().unwrap());
        let other = crypto::generate_keypair().unwrap();
        let wrong_curve = crypto::KeyPair {
            public_key: keys.public_key,
            secret_key: other.secret_key,
            ed25519_pk: keys.ed25519_pk,
            ed25519_sk: keys.ed25519_sk,
        };
        assert!(challenge
            .answer(&f.joined, &f.mode, 2001, &wrong_curve)
            .is_err());
        let wrong_sign = crypto::KeyPair {
            public_key: keys.public_key,
            secret_key: keys.secret_key,
            ed25519_pk: keys.ed25519_pk,
            ed25519_sk: other.ed25519_sk,
        };
        assert!(challenge
            .answer(&f.joined, &f.mode, 2001, &wrong_sign)
            .is_err());
    }
}
#[test]
fn challenge_expiry_version_ciphertext_and_scope_fail_before_session() {
    let f = Fixture::new();
    let challenge = Challenge::make(&f.joined, &f.mode, REQUEST, SECOND, 2000).unwrap();
    assert!(challenge
        .answer(&f.joined, &f.mode, 1999, &f.second)
        .is_err());
    assert!(challenge
        .answer(&f.joined, &f.mode, challenge.expires_at, &f.second)
        .is_err());
    let mut altered = challenge.clone();
    altered.encrypted[40] ^= 1;
    assert!(altered.authenticate(&f.joined, &f.mode, &f.second).is_err());
    assert!(altered.answer(&f.joined, &f.mode, 2001, &f.second).is_err());
    altered = challenge.clone();
    altered.version = 2;
    assert!(altered.digest().is_err());
    altered = challenge.clone();
    altered.authorization[0] ^= 1;
    assert!(altered.answer(&f.joined, &f.mode, 2001, &f.second).is_err());
    altered = challenge.clone();
    altered.device.device_id = ROOT.into();
    assert!(altered.answer(&f.joined, &f.mode, 2001, &f.second).is_err());
}
#[test]
fn proof_cannot_move_to_another_challenge_or_mutate_nonce_or_signature() {
    let f = Fixture::new();
    let challenge = Challenge::make(&f.joined, &f.mode, REQUEST, SECOND, 2000).unwrap();
    let proof = challenge
        .answer(&f.joined, &f.mode, 2001, &f.second)
        .unwrap();
    let other = Challenge::make(&f.joined, &f.mode, REQUEST, SECOND, 2000).unwrap();
    assert!(proof.verify(&other).is_err());
    for field in ["secret", "signature", "challenge"] {
        let mut value = serde_json::to_value(&proof).unwrap();
        let byte = value[field][0].as_u64().unwrap();
        value[field][0] = serde_json::json!((byte + 1) % 256);
        let modified: Proof = serde_json::from_value(value).unwrap();
        assert!(modified.verify(&challenge).is_err());
    }
}
#[test]
fn revocation_does_not_allow_old_phase_to_activate_or_new_phase_read_old_envelope() {
    let f = Fixture::new();
    let challenge = Challenge::make(&f.joined, &f.mode, REQUEST, SECOND, 2000).unwrap();
    let event = make_event(
        &f.joined,
        "revoke-event".into(),
        DeviceAction::Revoke {
            device_id: SECOND.into(),
            grant_hash: f.joined.grant_hash().unwrap().to_vec(),
        },
        2001,
        &f.root,
    )
    .unwrap();
    let revoked = f.joined.apply(&event).unwrap();
    assert!(challenge
        .answer(&revoked, &f.mode, 2002, &f.second)
        .is_err());
    assert!(Challenge::make(&revoked, &f.mode, REQUEST, SECOND, 2002).is_err());
}
#[test]
fn session_tokens_are_encrypted_to_exact_device_and_bound_context() {
    let f = Fixture::new();
    let challenge = Challenge::make(&f.joined, &f.mode, REQUEST, SECOND, 2000).unwrap();
    let session = Session {
        id: MODE.into(),
        account: ACCOUNT.into(),
        device: SECOND.into(),
        authorization: challenge.authorization,
        mode: challenge.mode,
        access_token: "synthetic-access-token".into(),
        refresh_token: "synthetic-refresh-token".into(),
        expires_at: 300000,
        refresh_expires_at: 3000000,
    };
    let envelope = Envelope::seal(&challenge, &session).unwrap();
    let wire = serde_json::to_vec(&envelope).unwrap();
    assert!(!String::from_utf8(wire)
        .unwrap()
        .contains("synthetic-access-token"));
    let opened = envelope.open(&challenge, &f.second).unwrap();
    assert_eq!(opened.access_token, session.access_token);
    assert!(envelope.open(&challenge, &f.root).is_err());
    let mut changed = envelope.clone();
    changed.encrypted[50] ^= 1;
    assert!(changed.open(&challenge, &f.second).is_err());
    let other = Challenge::make(&f.joined, &f.mode, REQUEST, SECOND, 2000).unwrap();
    assert!(envelope.open(&other, &f.second).is_err());
}
#[test]
fn enable_cancellation_has_a_separate_signature_and_exact_original_digest() {
    let f = Fixture::new();
    let cancel = EnableCancel::make(f.mode.clone(), f.joined.anchor(), &f.root).unwrap();
    cancel.verify(f.joined.anchor()).unwrap();
    let mut wrong = cancel.clone();
    wrong.signature = wrong.event.signature.clone();
    assert!(wrong.verify(f.joined.anchor()).is_err());
    wrong = cancel.clone();
    wrong.event.id = REQUEST.into();
    assert!(wrong.verify(f.joined.anchor()).is_err());
    assert!(EnableCancel::make(f.mode, f.joined.anchor(), &f.second).is_err());
}
#[test]
fn activation_cancellation_binds_all_fields_credential_and_original_phase() {
    let f = Fixture::new();
    let token = "synthetic-credential-at-least-thirty-two-characters";
    let cancel =
        ActivationCancel::make(&f.joined, &f.mode, REQUEST, token, SECOND, &f.second).unwrap();
    cancel.verify(&f.joined, &f.mode, token).unwrap();
    assert!(cancel
        .verify(
            &f.joined,
            &f.mode,
            "synthetic-different-credential-at-least-thirty-two"
        )
        .is_err());
    for field in [
        "version",
        "id",
        "origin",
        "account",
        "device",
        "authorization",
        "mode",
        "token_hash",
        "signature",
    ] {
        let mut value = serde_json::to_value(&cancel).unwrap();
        match field {
            "version" => value[field] = serde_json::json!(2),
            "id" | "account" => value[field] = serde_json::json!(MODE),
            "origin" => value[field] = serde_json::json!("https://other.invalid"),
            "device" => value[field]["device_id"] = serde_json::json!(ROOT),
            _ => {
                let n = value[field][0].as_u64().unwrap();
                value[field][0] = serde_json::json!((n + 1) % 256);
            }
        }
        let changed: ActivationCancel = serde_json::from_value(value).unwrap();
        assert!(
            changed.verify(&f.joined, &f.mode, token).is_err(),
            "{field}"
        );
    }
    let revoke = make_event(
        &f.joined,
        "cancel-revoke".into(),
        DeviceAction::Revoke {
            device_id: SECOND.into(),
            grant_hash: f.joined.grant_hash().unwrap().to_vec(),
        },
        2000,
        &f.root,
    )
    .unwrap();
    let revoked = f.joined.apply(&revoke).unwrap();
    assert!(cancel.verify(&revoked, &f.mode, token).is_err());
    assert!(ActivationCancel::make(&f.joined, &f.mode, REQUEST, token, SECOND, &f.root).is_err());
    assert!(
        ActivationCancel::make(&f.joined, &f.mode, REQUEST, "short", SECOND, &f.second).is_err()
    );
    let wire = serde_json::to_string(&cancel).unwrap();
    assert!(!wire.contains(token));
}
#[test]
fn inspection_is_scoped_and_cannot_authorize_cancellation() {
    let f = Fixture::new();
    let token = "synthetic-inspection-credential-at-least-thirty-two";
    let request = Inspection::make(&f.joined, &f.mode, REQUEST, token, SECOND, &f.second).unwrap();
    request.verify(&f.joined, &f.mode, token).unwrap();
    assert!(request.intent.verify(&f.joined, &f.mode, token).is_err());
    let mut cancel = request.intent.clone();
    cancel.signature = request.signature.clone();
    assert!(cancel.verify(&f.joined, &f.mode, token).is_err());
    assert!(request
        .verify(
            &f.joined,
            &f.mode,
            "synthetic-another-token-at-least-thirty-two"
        )
        .is_err());
    let mut changed = request.clone();
    changed.intent.id = MODE.into();
    assert!(changed.verify(&f.joined, &f.mode, token).is_err());
    changed = request.clone();
    changed.intent.signature[0] = 1;
    assert!(changed.verify(&f.joined, &f.mode, token).is_err());
}
#[test]
fn closure_binds_original_inspection_and_distinguishes_accepted_from_cancelled() {
    let f = Fixture::new();
    let token = "synthetic-inspection-credential-at-least-thirty-two";
    let request = Inspection::make(&f.joined, &f.mode, REQUEST, token, SECOND, &f.second).unwrap();
    let closed = Closure::make(&request, Some([1; 32]), true, ClosedReason::SessionEnded).unwrap();
    closed.verify(&request).unwrap();
    let mut changed = closed.clone();
    changed.request[0] ^= 1;
    assert!(changed.verify(&request).is_err());
    changed = closed.clone();
    changed.device = f.joined.anchor().root.clone();
    assert!(changed.verify(&request).is_err());
    changed = closed.clone();
    changed.reason = ClosedReason::Cancelled;
    assert!(changed.verify(&request).is_err());
    changed = closed.clone();
    changed.version = 2;
    assert!(changed.verify(&request).is_err());
    assert!(Closure::make(&request, None, false, ClosedReason::Expired).is_err());
    Closure::make(&request, None, false, ClosedReason::Cancelled).unwrap();
}
