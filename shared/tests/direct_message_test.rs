use liteseal_shared::{
    crypto::{self, KeyPair},
    direct_message::*,
    protocol::AckOutcome,
    trusted_device::*,
};
struct Account {
    root: KeyPair,
    second: KeyPair,
    initial: DeviceState,
    joined: DeviceState,
}
impl Account {
    fn new(name: &str) -> Self {
        let root = crypto::generate_keypair().unwrap();
        let second = crypto::generate_keypair().unwrap();
        let initial = DeviceState::pin(Anchor {
            origin: "https://synthetic.example".into(),
            account: name.into(),
            root: DeviceIdentity::from_keys(format!("{name}-root"), &root),
        })
        .unwrap();
        let intent = make_intent(
            initial.anchor(),
            format!("{name}-join"),
            format!("{name}-second"),
            crypto::random_challenge().unwrap(),
            1000,
            &second,
        )
        .unwrap();
        let challenge = make_challenge(&initial, &intent, 1001, &root).unwrap();
        let proof = answer_challenge(&initial, &intent, &challenge, 1002, &second).unwrap();
        let event = make_event(
            &initial,
            format!("{name}-grant"),
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
        Self {
            root,
            second,
            initial,
            joined,
        }
    }
    fn revoke(&self) -> DeviceState {
        self.joined
            .apply(
                &make_event(
                    &self.joined,
                    "revoke".into(),
                    DeviceAction::Revoke {
                        device_id: self.joined.secondary().unwrap().device_id.clone(),
                        grant_hash: self.joined.grant_hash().unwrap().to_vec(),
                    },
                    3000,
                    &self.root,
                )
                .unwrap(),
            )
            .unwrap()
    }
}
fn header(sender: &DeviceState, peer: &DeviceState, device: &str, id: &str) -> Header {
    Header::new(
        sender,
        peer,
        device,
        MessageSpec {
            id: id.into(),
            sequence: 1,
            previous: vec![],
            sent_at: 2000,
            kind: Kind::Text,
        },
    )
    .unwrap()
}
fn batch(a: &Account, b: &Account) -> Batch {
    Batch::make(
        header(
            &a.joined,
            &b.joined,
            &a.joined.anchor().root.device_id,
            "message",
        ),
        &a.joined,
        &b.joined,
        &a.root,
        "中文 🦭 hello".as_bytes(),
    )
    .unwrap()
}
fn resign(batch: &mut Batch, keys: &KeyPair) {
    batch.signature = crypto::sign(&batch.signing_bytes().unwrap(), &keys.ed25519_sk).unwrap();
}

#[test]
fn root_and_secondary_complete_audiences_round_trip_and_original_wire_retry() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    for own in [&a.initial, &a.joined] {
        for peer in [&b.initial, &b.joined] {
            let mut sources = vec![(&a.root, &own.anchor().root.device_id)];
            if let Some(member) = own.secondary() {
                sources.push((&a.second, &member.device_id));
            }
            for (keys, device) in sources {
                let header = header(own, peer, device, "same-original-id");
                let batch = Batch::make(header, own, peer, keys, "中文 🦭".as_bytes()).unwrap();
                batch.verify(own, peer).unwrap();
                batch.verify_next(None).unwrap();
                assert_eq!(
                    batch.payloads.len(),
                    if own.secondary().is_some() { 1 } else { 0 }
                        + if peer.secondary().is_some() { 2 } else { 1 }
                );
                for payload in &batch.payloads {
                    let target = if payload.account == "alice" {
                        if payload.device == a.initial.anchor().root.device_id {
                            &a.root
                        } else {
                            &a.second
                        }
                    } else if payload.device == b.initial.anchor().root.device_id {
                        &b.root
                    } else {
                        &b.second
                    };
                    assert_eq!(
                        batch
                            .open(own, peer, &payload.account, &payload.device, target)
                            .unwrap(),
                        "中文 🦭".as_bytes()
                    );
                }
                assert_eq!(
                    batch.open(own, peer, "alice", device, keys),
                    Err(DirectError::Recipient)
                );
                let wire = batch.to_wire().unwrap();
                let retry = Batch::from_wire(&wire).unwrap();
                assert_eq!(wire, retry.to_wire().unwrap());
                assert_eq!(batch.digest().unwrap(), retry.digest().unwrap());
            }
        }
    }
}
#[test]
fn every_header_directory_and_ciphertext_field_is_signed() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let original = batch(&a, &b);
    let changes: [fn(&mut Batch); 12] = [
        |m| m.header.id = "another".into(),
        |m| m.header.sent_at += 1,
        |m| m.header.kind = Kind::Voice,
        |m| {
            m.header.sequence = 2;
            m.header.previous = vec![7; 32];
        },
        |m| m.header.origin = "https://other.example".into(),
        |m| m.header.sender_directory.revision += 1,
        |m| m.header.sender_directory.head[0] ^= 1,
        |m| m.header.peer_directory.anchor_hash[0] ^= 1,
        |m| m.header.peer_directory.members[0].authorization_hash[0] ^= 1,
        |m| m.commitment[0] ^= 1,
        |m| m.payloads[1].ciphertext[45] ^= 1,
        |m| m.signature[0] ^= 1,
    ];
    for change in changes {
        let mut modified = original.clone();
        change(&mut modified);
        assert!(modified.verify(&a.joined, &b.joined).is_err());
    }
}
#[test]
fn omissions_duplicates_extra_devices_reordering_and_untrusted_materialized_directory_fail() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let original = batch(&a, &b);
    let mut missing = original.clone();
    missing.payloads.remove(0);
    assert!(missing.verify(&a.joined, &b.joined).is_err());
    let mut duplicate = original.clone();
    duplicate.payloads[1] = duplicate.payloads[0].clone();
    assert!(duplicate.verify(&a.joined, &b.joined).is_err());
    let mut extra = original.clone();
    extra.payloads.push(extra.payloads[0].clone());
    assert!(extra.verify(&a.joined, &b.joined).is_err());
    let mut reorder = original.clone();
    reorder.payloads.swap(0, 1);
    assert!(reorder.verify(&a.joined, &b.joined).is_err());
    let mut forged = original.clone();
    forged.header.peer_directory.members[0]
        .device
        .encryption_key = [8; 32];
    resign(&mut forged, &a.root);
    assert_eq!(
        forged.verify(&a.joined, &b.joined),
        Err(DirectError::Directory)
    );
}
#[test]
fn signed_transplant_and_divergent_plaintext_copy_fail_inner_context_and_commitment() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let original = batch(&a, &b);
    let mut transplant = original.clone();
    transplant.header.id = "transplanted".into();
    resign(&mut transplant, &a.root);
    transplant.verify(&a.joined, &b.joined).unwrap();
    assert_eq!(
        transplant.open(
            &a.joined,
            &b.joined,
            "bob",
            &b.initial.anchor().root.device_id,
            &b.root
        ),
        Err(DirectError::Proof)
    );
    let different = Batch::make(
        original.header.clone(),
        &a.joined,
        &b.joined,
        &a.root,
        b"different",
    )
    .unwrap();
    let mut fork = original.clone();
    let index = fork
        .payloads
        .iter()
        .position(|p| p.account == "bob" && p.device == b.initial.anchor().root.device_id)
        .unwrap();
    fork.payloads[index] = different.payloads[index].clone();
    resign(&mut fork, &a.root);
    fork.verify(&a.joined, &b.joined).unwrap();
    assert_eq!(
        fork.open(
            &a.joined,
            &b.joined,
            "bob",
            &b.initial.anchor().root.device_id,
            &b.root
        ),
        Err(DirectError::Proof)
    );
    assert_eq!(
        fork.open(
            &a.joined,
            &b.joined,
            "alice",
            &a.joined.secondary().unwrap().device_id,
            &a.second
        )
        .unwrap(),
        "中文 🦭 hello".as_bytes()
    );
}
#[test]
fn revoked_or_rejoined_devices_cannot_match_current_snapshots_or_decrypt_old_audience() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let original = batch(&a, &b);
    let revoked = b.revoke();
    assert_eq!(
        original.verify(&a.joined, &revoked),
        Err(DirectError::Directory)
    );
    let new_key = crypto::generate_keypair().unwrap();
    let intent = make_intent(
        revoked.anchor(),
        "new-join".into(),
        "new-device".into(),
        crypto::random_challenge().unwrap(),
        3100,
        &new_key,
    )
    .unwrap();
    let challenge = make_challenge(&revoked, &intent, 3101, &b.root).unwrap();
    let proof = answer_challenge(&revoked, &intent, &challenge, 3102, &new_key).unwrap();
    let rejoined = revoked
        .apply(
            &make_event(
                &revoked,
                "new-grant".into(),
                DeviceAction::Grant {
                    intent: Box::new(intent),
                    challenge: Box::new(challenge),
                    proof,
                },
                3103,
                &b.root,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        original.verify(&a.joined, &rejoined),
        Err(DirectError::Directory)
    );
    assert_eq!(
        original.open(
            &a.joined,
            &b.joined,
            "bob",
            &rejoined.secondary().unwrap().device_id,
            &new_key
        ),
        Err(DirectError::Recipient)
    );
    let mut old_source = header(
        &a.joined,
        &b.joined,
        &a.joined.secondary().unwrap().device_id,
        "secondary",
    );
    old_source.sender_directory = Directory::from_state(&a.revoke());
    assert!(Batch::make(old_source, &a.revoke(), &b.joined, &a.second, b"no").is_err());
    // Existing accepted history can be verified only against its exact old evidence.
    original.verify(&a.joined, &b.joined).unwrap();
}
#[test]
fn chain_is_shared_by_copies_and_membership_epoch_changes_require_fresh_head() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let first = Batch::make(
        header(
            &a.joined,
            &b.initial,
            &a.initial.anchor().root.device_id,
            "before-join",
        ),
        &a.joined,
        &b.initial,
        &a.root,
        b"before join",
    )
    .unwrap();
    let head = first.chain_head().unwrap();
    let mut next_header = first.header.clone();
    next_header.id = "next".into();
    next_header.sequence = 2;
    next_header.previous = head.digest.to_vec();
    let next = Batch::make(next_header, &a.joined, &b.initial, &a.root, b"next").unwrap();
    next.verify_next(Some(&head)).unwrap();
    assert_eq!(next.verify_next(None), Err(DirectError::Chain));
    assert_eq!(first.verify_next(Some(&head)), Err(DirectError::Chain));
    let mut wrong = head.clone();
    wrong.digest[0] ^= 1;
    assert_eq!(next.verify_next(Some(&wrong)), Err(DirectError::Chain));
    let fresh = Batch::make(
        header(
            &a.joined,
            &b.joined,
            &a.initial.anchor().root.device_id,
            "new-epoch",
        ),
        &a.joined,
        &b.joined,
        &a.root,
        b"first in epoch",
    )
    .unwrap();
    assert_ne!(fresh.header.epoch().unwrap(), head.epoch);
    assert_eq!(
        fresh
            .open(
                &a.joined,
                &b.joined,
                "bob",
                &b.joined.secondary().unwrap().device_id,
                &b.second
            )
            .unwrap(),
        b"first in epoch"
    );
    assert_eq!(
        first.open(
            &a.joined,
            &b.initial,
            "bob",
            &b.joined.secondary().unwrap().device_id,
            &b.second
        ),
        Err(DirectError::Recipient)
    );
    fresh.verify_next(None).unwrap();
    assert_eq!(fresh.verify_next(Some(&head)), Err(DirectError::Chain));
}
#[test]
fn body_wire_version_fields_signature_and_key_limits_are_bounded() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let h = header(
        &a.joined,
        &b.joined,
        &a.initial.anchor().root.device_id,
        "limits",
    );
    assert!(Batch::make(
        h.clone(),
        &a.joined,
        &b.joined,
        &a.root,
        &vec![b'a'; MAX_BODY + 1]
    )
    .is_err());
    assert!(Batch::make(h.clone(), &a.joined, &b.joined, &a.root, b"").is_err());
    assert!(Batch::make(h.clone(), &a.joined, &b.joined, &a.root, &[255]).is_err());
    let maximal = Batch::make(
        h.clone(),
        &a.joined,
        &b.joined,
        &a.root,
        &vec![b'a'; MAX_BODY],
    )
    .unwrap();
    assert!(maximal.to_wire().unwrap().len() < MAX_WIRE);
    assert_eq!(
        maximal
            .open(
                &a.joined,
                &b.joined,
                "bob",
                &b.initial.anchor().root.device_id,
                &b.root
            )
            .unwrap()
            .len(),
        MAX_BODY
    );
    assert!(Batch::from_wire(&vec![b' '; MAX_WIRE + 1]).is_err());
    let mut value = serde_json::to_value(&maximal).unwrap();
    value["extra"] = serde_json::json!(true);
    assert!(Batch::from_wire(&serde_json::to_vec(&value).unwrap()).is_err());
    value.as_object_mut().unwrap().remove("extra");
    value["header"]["version"] = serde_json::json!(4);
    assert!(Batch::from_wire(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut bad = maximal.clone();
    bad.signature.clear();
    assert!(bad.verify(&a.joined, &b.joined).is_err());
    let wrong = crypto::generate_keypair().unwrap();
    let mut swapped = KeyPair {
        public_key: a.root.public_key,
        secret_key: wrong.secret_key,
        ed25519_pk: a.root.ed25519_pk,
        ed25519_sk: a.root.ed25519_sk,
    };
    assert!(Batch::make(h.clone(), &a.joined, &b.joined, &swapped, b"mismatch").is_err());
    swapped.secret_key = a.root.secret_key;
    swapped.ed25519_sk = wrong.ed25519_sk;
    assert!(Batch::make(h, &a.joined, &b.joined, &swapped, b"mismatch").is_err());
}
#[test]
fn independently_signed_ack_binds_target_stage_digest_and_outcome() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let original = batch(&a, &b);
    let target = &b.initial.anchor().root.device_id;
    for outcome in [AckOutcome::Processed, AckOutcome::Rejected] {
        let ack = Ack::make(
            &original, &a.joined, &b.joined, "bob", target, &b.root, outcome,
        )
        .unwrap();
        ack.verify(&original, &a.joined, &b.joined).unwrap();
        let retry = Ack::from_wire(&ack.to_wire().unwrap()).unwrap();
        assert_eq!(retry, ack);
        let mut tampered = ack.clone();
        tampered.outcome = if outcome == AckOutcome::Processed {
            AckOutcome::Rejected
        } else {
            AckOutcome::Processed
        };
        assert!(tampered.verify(&original, &a.joined, &b.joined).is_err());
        let mut transplanted = ack.clone();
        transplanted.authorization_hash[0] ^= 1;
        assert!(transplanted
            .verify(&original, &a.joined, &b.joined)
            .is_err());
        let mut wrong = ack.clone();
        wrong.device = b.joined.secondary().unwrap().device_id.clone();
        assert!(wrong.verify(&original, &a.joined, &b.joined).is_err());
        assert!(
            Ack::make(&original, &a.joined, &b.joined, "bob", target, &a.root, outcome).is_err()
        );
        let mut modified = original.clone();
        modified.header.id = "another".into();
        resign(&mut modified, &a.root);
        assert!(ack.verify(&modified, &a.joined, &b.joined).is_err());
    }
    let own = Ack::make(
        &original,
        &a.joined,
        &b.joined,
        "alice",
        &a.joined.secondary().unwrap().device_id,
        &a.second,
        AckOutcome::Processed,
    )
    .unwrap();
    own.verify(&original, &a.joined, &b.joined).unwrap();
    let mut unauthenticated = original.clone();
    unauthenticated.signature[0] ^= 1;
    assert!(Ack::make(
        &unauthenticated,
        &a.joined,
        &b.joined,
        "bob",
        target,
        &b.root,
        AckOutcome::Rejected
    )
    .is_err());
    assert!(Ack::from_wire(&vec![0; MAX_ACK_WIRE + 1]).is_err());
}
#[test]
fn salted_commitments_do_not_expose_deterministic_body_hashes() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let first = batch(&a, &b);
    let second = batch(&a, &b);
    assert_ne!(first.commitment, second.commitment);
    assert_ne!(first.digest().unwrap(), second.digest().unwrap());
    assert_ne!(first.payloads[0].ciphertext, first.payloads[1].ciphertext);
    assert_eq!(
        first.header.epoch().unwrap(),
        second.header.epoch().unwrap()
    );
}
