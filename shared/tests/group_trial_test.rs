#[path = "../examples/group_trial/support.rs"]
mod support;
use liteseal_shared::{crypto, group::*};
use support::{change, envelope, join, Participant};

fn three() -> (
    Participant,
    Participant,
    Participant,
    GroupState,
    Vec<GroupChange>,
) {
    let alice = Participant::new("alice");
    let bob = Participant::new("bob");
    let carol = Participant::new("carol");
    let create = change(
        None,
        &alice,
        GroupAction::Create {
            name: "private".into(),
            owner: alice.identity(),
        },
        1000,
    );
    let initial = pin_creation(&create, &alice.identity()).unwrap();
    let add_bob = join(&initial, &alice, &bob, 1001);
    let two = validate_submission(Some(&initial), &add_bob, 1001).unwrap();
    let add_carol = join(&two, &alice, &carol, 1002);
    let three = validate_submission(Some(&two), &add_carol, 1002).unwrap();
    (alice, bob, carol, three, vec![create, add_bob, add_carol])
}
#[test]
fn ordered_offline_replay_is_consistent_and_does_not_use_current_invite_expiry() {
    let (alice, _, _, state, events) = three();
    let rename = change(
        Some(&state),
        &alice,
        GroupAction::Rename {
            name: "renamed 🔐".into(),
        },
        1003,
    );
    let latest = validate_submission(Some(&state), &rename, 1003).unwrap();
    let mut replay = None;
    for event in events.iter().chain(std::iter::once(&rename)) {
        replay = Some(apply_change(replay.as_ref(), event).unwrap());
    }
    assert_eq!(replay.unwrap(), latest);
    assert_eq!(
        apply_change(Some(&latest), &rename),
        Err(GroupError::StaleRevision)
    );
    assert!(validate_submission(Some(&state), &rename, 100_000).is_err());
    let initial = apply_change(None, &events[0]).unwrap();
    let GroupAction::Join { invite, .. } = &events[1].action else {
        panic!("join")
    };
    assert!(validate_invite(&initial, invite, invite.expires_at).is_err());
    // Historical replay still succeeds at the event's signed join time.
    assert!(apply_change(Some(&initial), &events[1]).is_ok());
}
#[test]
fn owner_cannot_add_a_member_without_that_members_acceptance_signature() {
    let (alice, _, _, state, _) = three();
    let dave = Participant::new("dave");
    let false_root = change(
        None,
        &dave,
        GroupAction::Create {
            name: "impersonated".into(),
            owner: dave.identity(),
        },
        1000,
    );
    assert_eq!(
        pin_creation(&false_root, &alice.identity()),
        Err(GroupError::Unauthorized)
    );
    let mut add = join(&state, &alice, &dave, 1003);
    if let GroupAction::Join { acceptance, .. } = &mut add.action {
        acceptance.signature =
            crypto::sign(&acceptance.signing_bytes(), &alice.keys.ed25519_sk).unwrap();
    }
    add.signature = crypto::sign(&add.signing_bytes(), &dave.keys.ed25519_sk).unwrap();
    assert_eq!(
        apply_change(Some(&state), &add),
        Err(GroupError::InvalidSignature)
    );
    let mut add = join(&state, &alice, &dave, 1003);
    if let GroupAction::Join { invite, .. } = &mut add.action {
        invite.member.public_key[0] ^= 1;
    }
    add.signature = crypto::sign(&add.signing_bytes(), &dave.keys.ed25519_sk).unwrap();
    assert!(apply_change(Some(&state), &add).is_err());
}
#[test]
fn nonowners_cannot_rename_remove_or_close_and_owner_must_close_to_exit() {
    let (alice, bob, _, state, _) = three();
    for action in [
        GroupAction::Rename {
            name: "takeover".into(),
        },
        GroupAction::Remove {
            user_id: "carol".into(),
        },
        GroupAction::Close,
    ] {
        assert_eq!(
            apply_change(Some(&state), &change(Some(&state), &bob, action, 1003)),
            Err(GroupError::Unauthorized)
        );
    }
    assert_eq!(
        apply_change(
            Some(&state),
            &change(Some(&state), &alice, GroupAction::Leave, 1003)
        ),
        Err(GroupError::Unauthorized)
    );
    let left = apply_change(
        Some(&state),
        &change(Some(&state), &bob, GroupAction::Leave, 1003),
    )
    .unwrap();
    assert!(left.member("bob").is_none());
    let closed = apply_change(
        Some(&left),
        &change(Some(&left), &alice, GroupAction::Close, 1004),
    )
    .unwrap();
    assert!(closed.closed());
    assert!(apply_change(
        Some(&closed),
        &change(
            Some(&closed),
            &alice,
            GroupAction::Rename {
                name: "reopen".into()
            },
            1005
        )
    )
    .is_err());
}
#[test]
fn removal_excludes_future_payloads_and_new_members_cannot_decrypt_old_payloads() {
    let (alice, bob, carol, state, _) = three();
    let old_bob = envelope(&state, &alice, &bob, "old", "old private text", None);
    let old_carol = envelope(&state, &alice, &carol, "old", "old private text", None);
    validate_batch(&state, &[old_bob.clone(), old_carol.clone()]).unwrap();
    let removed = apply_change(
        Some(&state),
        &change(
            Some(&state),
            &alice,
            GroupAction::Remove {
                user_id: "bob".into(),
            },
            1003,
        ),
    )
    .unwrap();
    let new_carol = envelope(
        &removed,
        &alice,
        &carol,
        "new",
        "future text",
        Some(&old_carol),
    );
    validate_batch(&removed, std::slice::from_ref(&new_carol)).unwrap();
    validate_chain(&new_carol, Some(&old_carol)).unwrap();
    assert!(crypto::decrypt(
        &new_carol.ciphertext,
        &alice.keys.public_key,
        &bob.keys.secret_key
    )
    .is_err());
    let mut invalid = old_bob.clone();
    invalid.epoch = removed.epoch();
    invalid.membership_hash = removed.revision_hash().to_vec();
    invalid.signature = crypto::sign(&invalid.signing_bytes(), &alice.keys.ed25519_sk).unwrap();
    assert_eq!(
        validate_envelope(&removed, &invalid),
        Err(GroupError::Unauthorized)
    );
    let mut removed_sender = envelope(&state, &bob, &carol, "removed-sender", "blocked", None);
    removed_sender.epoch = removed.epoch();
    removed_sender.membership_hash = removed.revision_hash().to_vec();
    removed_sender.signature =
        crypto::sign(&removed_sender.signing_bytes(), &bob.keys.ed25519_sk).unwrap();
    assert_eq!(
        validate_envelope(&removed, &removed_sender),
        Err(GroupError::Unauthorized)
    );
    let dave = Participant::new("dave");
    let joined = apply_change(Some(&removed), &join(&removed, &alice, &dave, 1004)).unwrap();
    assert!(crypto::decrypt(
        &old_carol.ciphertext,
        &alice.keys.public_key,
        &dave.keys.secret_key
    )
    .is_err());
    let new_dave = envelope(&joined, &alice, &dave, "after-join", "future text", None);
    assert_eq!(
        crypto::decrypt(
            &new_dave.ciphertext,
            &alice.keys.public_key,
            &dave.keys.secret_key
        )
        .unwrap(),
        b"future text"
    );
}
#[test]
fn batch_requires_every_current_recipient_exactly_once() {
    let (alice, bob, carol, state, _) = three();
    let for_bob = envelope(&state, &alice, &bob, "one-message", "text", None);
    let for_carol = envelope(&state, &alice, &carol, "one-message", "text", None);
    validate_batch(&state, &[for_bob.clone(), for_carol.clone()]).unwrap();
    assert_eq!(
        validate_batch(&state, std::slice::from_ref(&for_bob)),
        Err(GroupError::InvalidRecipients)
    );
    assert_eq!(
        validate_batch(&state, &[for_bob.clone(), for_bob]),
        Err(GroupError::InvalidRecipients)
    );
    let another = envelope(&state, &alice, &bob, "other-message", "text", None);
    assert_eq!(
        validate_batch(&state, &[for_carol, another]),
        Err(GroupError::InvalidRecipients)
    );
}
#[test]
fn rejoining_starts_a_new_recipient_incarnation_without_importing_its_old_chain() {
    let (alice, bob, _, state, _) = three();
    let old = envelope(&state, &alice, &bob, "old", "before leave", None);
    let left = apply_change(
        Some(&state),
        &change(Some(&state), &bob, GroupAction::Leave, 1003),
    )
    .unwrap();
    let rejoined = apply_change(Some(&left), &join(&left, &alice, &bob, 1004)).unwrap();
    let fresh = envelope(&rejoined, &alice, &bob, "fresh", "after rejoin", None);
    validate_envelope(&rejoined, &fresh).unwrap();
    validate_chain(&fresh, None).unwrap();
    assert_ne!(old.recipient_join_epoch, fresh.recipient_join_epoch);
    assert_eq!(
        validate_chain(&fresh, Some(&old)),
        Err(GroupError::InvalidChain)
    );
    let imported = envelope(
        &rejoined,
        &alice,
        &bob,
        "wrong-chain",
        "after rejoin",
        Some(&old),
    );
    assert_eq!(
        validate_chain(&imported, None),
        Err(GroupError::InvalidChain)
    );
}
#[test]
fn signatures_bind_group_membership_routing_and_ciphertext() {
    let (alice, bob, _, state, _) = three();
    let original = envelope(&state, &alice, &bob, "signed", "text", None);
    validate_envelope(&state, &original).unwrap();
    for field in 0..12 {
        let mut changed = original.clone();
        match field {
            0 => changed.message_id = "other".into(),
            1 => changed.group_id = "other-group".into(),
            2 => changed.epoch += 1,
            3 => changed.membership_hash[0] ^= 1,
            4 => changed.sender_device_id = "other-device".into(),
            5 => changed.sender_join_epoch += 1,
            6 => changed.recipient_user_id = "carol".into(),
            7 => changed.recipient_join_epoch += 1,
            8 => changed.sender_seq += 1,
            9 => changed.prev_hash = vec![1; 32],
            10 => changed.sent_at += 1,
            _ => changed.ciphertext[0] ^= 1,
        }
        assert!(
            validate_envelope(&state, &changed).is_err(),
            "field {field}"
        );
    }
    let mut renamed = change(
        Some(&state),
        &alice,
        GroupAction::Rename {
            name: "first".into(),
        },
        1003,
    );
    renamed.action = GroupAction::Rename {
        name: "tampered".into(),
    };
    assert_eq!(
        apply_change(Some(&state), &renamed),
        Err(GroupError::InvalidSignature)
    );
}
#[test]
fn group_limit_identity_uniqueness_and_bounded_metadata_are_enforced() {
    let (alice, bob, _, mut state, _) = three();
    let duplicate = join(&state, &alice, &bob, 1003);
    assert!(apply_change(Some(&state), &duplicate).is_err());
    for number in 3..10 {
        let member = Participant::new(&format!("member-{number}"));
        let event = join(&state, &alice, &member, 1000 + number);
        state = apply_change(Some(&state), &event).unwrap();
    }
    assert_eq!(state.members().len(), MAX_GROUP_MEMBERS);
    let extra = Participant::new("extra");
    assert!(apply_change(Some(&state), &join(&state, &alice, &extra, 2000)).is_err());
    assert!(apply_change(
        Some(&state),
        &change(
            Some(&state),
            &alice,
            GroupAction::Rename {
                name: "unsafe\nname".into()
            },
            2000
        )
    )
    .is_err());
    let mut envelope = envelope(&state, &alice, &bob, "too-large", "text", None);
    envelope.ciphertext = vec![0; MAX_GROUP_TEXT_BYTES + 41];
    assert!(validate_envelope(&state, &envelope).is_err());
}
