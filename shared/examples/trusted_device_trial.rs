use liteseal_shared::{crypto, trusted_device::*};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = crypto::generate_keypair()?;
    let second = crypto::generate_keypair()?;
    let pinned = DeviceState::pin(Anchor {
        origin: "https://isolated.example".into(),
        account: "synthetic-account".into(),
        root: DeviceIdentity::from_keys("original".into(), &root),
    })?;
    let intent = make_intent(
        pinned.anchor(),
        "join-trial".into(),
        "secondary".into(),
        crypto::random_challenge()?,
        1000,
        &second,
    )?;
    let challenge = make_challenge(&pinned, &intent, 1001, &root)?;
    let proof = answer_challenge(&pinned, &intent, &challenge, 1002, &second)?;
    let grant = make_event(
        &pinned,
        "grant-trial".into(),
        DeviceAction::Grant {
            intent: Box::new(intent),
            challenge: Box::new(challenge),
            proof,
        },
        1003,
        &root,
    )?;
    let active = pinned.apply_live(&grant, 1004)?;
    assert_eq!(
        active.secondary().unwrap().encryption_key,
        second.public_key
    );
    assert_eq!(active.apply(&grant)?, active);
    let revoke = make_event(
        &active,
        "revoke-trial".into(),
        DeviceAction::Revoke {
            device_id: "secondary".into(),
            grant_hash: grant.hash(),
        },
        2000,
        &root,
    )?;
    let revoked = active.apply(&revoke)?;
    assert!(revoked.secondary().is_none());
    assert_eq!(revoked.apply(&grant)?, revoked);
    println!(
        "{}",
        serde_json::json!({"status":"passed", "mode":"offline_protocol_trial",
        "independent_keys": true, "encryption_and_signing_proof": true, "grant": true,
        "exact_retry": true, "revoke": true, "old_retry_does_not_resurrect": true,
        "network_requests": 0, "second_device_login_enabled": false})
    );
    Ok(())
}
