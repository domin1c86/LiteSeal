#[path = "../examples/group_trial/support.rs"]
mod support;
use liteseal_shared::{collaboration::Member, crypto, group::*, group_extension as e};
use support::{change, envelope, join, Participant};
fn fixture() -> (Participant, Participant, Participant, GroupState) {
    let a = Participant::new("alice");
    let b = Participant::new("bob");
    let c = Participant::new("carol");
    let create = change(
        None,
        &a,
        GroupAction::Create {
            name: "group".into(),
            owner: a.identity(),
        },
        1,
    );
    let first = pin_creation(&create, &a.identity()).unwrap();
    let second = apply_change(Some(&first), &join(&first, &a, &b, 2)).unwrap();
    let state = apply_change(Some(&second), &join(&second, &a, &c, 3)).unwrap();
    (a, b, c, state)
}
fn root(
    a: &Participant,
    b: &Participant,
    c: &Participant,
    state: &GroupState,
    content: &e::Content,
) -> e::Submission {
    let roots = vec![
        envelope(state, a, b, "root-message", e::PLACEHOLDER, None),
        envelope(state, a, c, "root-message", e::PLACEHOLDER, None),
    ];
    let action = match content {
        e::Content::Activity(_) => e::Action::Activity,
        e::Content::Attachment(x) => e::Action::Attachment {
            blob: x.blob.clone(),
            size: x.size,
            hash: x.hash.clone(),
        },
    };
    e::make(
        state,
        &Member::from(state.member(&a.user).unwrap()),
        "root-message".into(),
        "event-root".into(),
        None,
        action,
        Some(content),
        roots,
        &a.keys,
        1000,
    )
    .unwrap()
}
fn activity() -> e::Content {
    e::Content::Activity(e::Activity {
        title: "活动 🦭".into(),
        start_at: 1900000000000,
        timezone: "Asia/Singapore".into(),
        location: "线上".into(),
        description: "description".into(),
    })
}
#[test]
fn roots_are_legacy_safe_and_all_signed_fields_and_cipher_hashes_are_bound() {
    let (a, b, c, state) = fixture();
    let submission = root(&a, &b, &c, &state, &activity());
    e::validate_submission(&state, &submission).unwrap();
    for r in &submission.roots {
        let recipient = if r.recipient_user_id == b.user {
            &b
        } else {
            &c
        };
        assert_eq!(
            crypto::decrypt(
                &r.ciphertext,
                &a.keys.public_key,
                &recipient.keys.secret_key
            )
            .unwrap(),
            e::PLACEHOLDER.as_bytes()
        );
    }
    let mut mutations = vec![];
    let mut m = submission.clone();
    m.event.object = "other-root".into();
    mutations.push(m);
    let mut m = submission.clone();
    m.event.actor.joined += 1;
    mutations.push(m);
    let mut m = submission.clone();
    m.event.at += 1;
    mutations.push(m);
    let mut m = submission.clone();
    m.event.roots[0].hash[0] ^= 1;
    mutations.push(m);
    let mut m = submission.clone();
    m.boxes[0].ciphertext[0] ^= 1;
    mutations.push(m);
    let mut m = submission.clone();
    m.roots.pop();
    mutations.push(m);
    for m in mutations {
        assert!(e::validate_submission(&state, &m).is_err());
    }
}
#[test]
fn responses_replace_and_close_cancel_and_rejoin_reject_old_permissions() {
    let (a, b, c, state) = fixture();
    let first = root(&a, &b, &c, &state, &activity());
    let initial = e::transition(None, &state, &first.event).unwrap();
    let actor = Member::from(state.member(&b.user).unwrap());
    let respond = e::make(
        &state,
        &actor,
        initial.id.clone(),
        "respond-1".into(),
        Some(&initial),
        e::Action::Respond {
            answer: e::Answer::Maybe,
        },
        None,
        vec![],
        &b.keys,
        1001,
    )
    .unwrap();
    let updated = e::transition(Some(&initial), &state, &respond.event).unwrap();
    assert_eq!(updated.responses[&b.user], e::Answer::Maybe);
    let changed = e::make(
        &state,
        &actor,
        updated.id.clone(),
        "respond-2".into(),
        Some(&updated),
        e::Action::Respond {
            answer: e::Answer::Yes,
        },
        None,
        vec![],
        &b.keys,
        1002,
    )
    .unwrap();
    let updated = e::transition(Some(&updated), &state, &changed.event).unwrap();
    assert_eq!(updated.responses.len(), 1);
    assert!(e::make(
        &state,
        &actor,
        updated.id.clone(),
        "close-bob".into(),
        Some(&updated),
        e::Action::Close,
        None,
        vec![],
        &b.keys,
        1003
    )
    .is_err());
    let owner = Member::from(state.member(&a.user).unwrap());
    let closed = e::make(
        &state,
        &owner,
        updated.id.clone(),
        "close".into(),
        Some(&updated),
        e::Action::Close,
        None,
        vec![],
        &a.keys,
        1003,
    )
    .unwrap();
    let closed = e::transition(Some(&updated), &state, &closed.event).unwrap();
    assert!(closed.closed && !closed.cancelled);
    assert!(e::make(
        &state,
        &actor,
        closed.id.clone(),
        "late-response".into(),
        Some(&closed),
        e::Action::Respond {
            answer: e::Answer::No
        },
        None,
        vec![],
        &b.keys,
        1004
    )
    .is_err());
    let cancelled = e::make(
        &state,
        &owner,
        closed.id.clone(),
        "cancel".into(),
        Some(&closed),
        e::Action::Cancel,
        None,
        vec![],
        &a.keys,
        1004,
    )
    .unwrap();
    assert!(
        e::transition(Some(&closed), &state, &cancelled.event)
            .unwrap()
            .cancelled
    );
    let removed = apply_change(
        Some(&state),
        &change(
            Some(&state),
            &a,
            GroupAction::Remove {
                user_id: b.user.clone(),
            },
            1005,
        ),
    )
    .unwrap();
    let rejoined = apply_change(Some(&removed), &join(&removed, &a, &b, 1006)).unwrap();
    let actor = Member::from(rejoined.member(&b.user).unwrap());
    assert!(e::make(
        &rejoined,
        &actor,
        initial.id.clone(),
        "rejoin-response".into(),
        Some(&initial),
        e::Action::Respond {
            answer: e::Answer::Yes
        },
        None,
        vec![],
        &b.keys,
        1007
    )
    .is_err());
}
#[test]
fn encrypted_attachment_descriptor_bounds_and_public_commitments_match() {
    let (a, b, c, state) = fixture();
    let (cipher, key) = crypto::encrypt_attachment(b"group attachment").unwrap();
    let content = e::Content::Attachment(e::Attachment {
        version: 1,
        blob: "blob".into(),
        name: "file.bin".into(),
        size: 16,
        mime: "application/octet-stream".into(),
        duration_ms: None,
        key,
        hash: liteseal_shared::collaboration::digest(&cipher),
    });
    let submission = root(&a, &b, &c, &state, &content);
    let boxed = submission
        .boxes
        .iter()
        .find(|x| x.member.user == b.user)
        .unwrap();
    let plaintext =
        crypto::decrypt(&boxed.ciphertext, &a.keys.public_key, &b.keys.secret_key).unwrap();
    let decoded: e::Content = serde_json::from_slice(&plaintext).unwrap();
    e::validate_content(&submission.event, &decoded).unwrap();
    if let e::Content::Attachment(mut d) = decoded {
        d.duration_ms = Some(60001);
        assert!(e::validate_content(&submission.event, &e::Content::Attachment(d)).is_err());
    }
}
