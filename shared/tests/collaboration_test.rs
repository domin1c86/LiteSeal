#[allow(dead_code)]
#[path = "../examples/group_trial/support.rs"]
mod support;
use liteseal_shared::{collaboration::*, crypto, group::*};
use support::{change, join, Participant};
fn setup() -> (Participant, Participant, GroupState) {
    let a = Participant::new("owner");
    let b = Participant::new("bob");
    let root = change(
        None,
        &a,
        GroupAction::Create {
            name: "test".into(),
            owner: a.identity(),
        },
        1000,
    );
    let initial = pin_creation(&root, &a.identity()).unwrap();
    let added = join(&initial, &a, &b, 1001);
    let state = apply_change(Some(&initial), &added).unwrap();
    (a, b, state)
}
fn event(group: &GroupState, actor: &Participant, action: Action, prior: Option<&Object>) -> Event {
    let audience = prior
        .filter(|p| matches!(p.action, Action::Poll { .. }))
        .map(|p| {
            p.audience
                .iter()
                .filter(|m| members(group).contains(m))
                .cloned()
                .collect()
        })
        .unwrap_or_else(|| members(group));
    let mut e = Event {
        version: 1,
        id: format!("event-{}", prior.map_or(1, |p| p.revision + 1)),
        group: group.group_id().into(),
        epoch: group.epoch(),
        membership_hash: group.revision_hash().to_vec(),
        actor: Member::from(group.member(&actor.user).unwrap()),
        object: prior.map_or("event-1".into(), |p| p.id.clone()),
        revision: prior.map_or(1, |p| p.revision + 1),
        previous: prior.map_or(vec![], |p| p.head.clone()),
        at: 1002,
        action,
        audience,
        slots: vec![],
        signature: vec![],
    };
    if matches!(e.action, Action::Pin { .. }) {
        e.object = e.group.clone();
    }
    if matches!(
        e.action,
        Action::Mention | Action::Poll { .. } | Action::Pin { .. }
    ) {
        e.slots = e
            .audience
            .iter()
            .map(|m| Slot {
                member: m.clone(),
                hash: vec![1; 32],
            })
            .collect();
    }
    e.signature = crypto::sign(&e.signing_bytes(), &actor.keys.ed25519_sk).unwrap();
    e
}
#[test]
fn poll_votes_replace_and_closed_or_rejoined_members_cannot_modify() {
    let (a, b, g) = setup();
    let root = event(
        &g,
        &a,
        Action::Poll {
            options: vec!["one".into(), "two".into()],
        },
        None,
    );
    let p = transition(None, &g, &root).unwrap();
    let v = event(
        &g,
        &b,
        Action::Vote {
            option: "one".into(),
        },
        Some(&p),
    );
    let p = transition(Some(&p), &g, &v).unwrap();
    let v = event(
        &g,
        &b,
        Action::Vote {
            option: "two".into(),
        },
        Some(&p),
    );
    let p = transition(Some(&p), &g, &v).unwrap();
    assert_eq!(p.votes.len(), 1);
    assert_eq!(p.votes["bob"], "two");
    assert!(transition(Some(&p), &g, &v).is_err());
    let close = event(&g, &b, Action::Close, Some(&p));
    assert!(transition(Some(&p), &g, &close).is_err());
    let close = event(&g, &a, Action::Close, Some(&p));
    let closed = transition(Some(&p), &g, &close).unwrap();
    assert!(transition(
        Some(&closed),
        &g,
        &event(
            &g,
            &b,
            Action::Vote {
                option: "one".into()
            },
            Some(&closed)
        )
    )
    .is_err());
    let remove = change(
        Some(&g),
        &a,
        GroupAction::Remove {
            user_id: b.user.clone(),
        },
        1003,
    );
    let removed = apply_change(Some(&g), &remove).unwrap();
    let added = join(&removed, &a, &b, 1004);
    let rejoined = apply_change(Some(&removed), &added).unwrap();
    assert!(transition(
        Some(&p),
        &rejoined,
        &event(
            &rejoined,
            &b,
            Action::Vote {
                option: "one".into()
            },
            Some(&p)
        )
    )
    .is_err());
}
#[test]
fn encrypted_content_mapping_mentions_and_pin_permissions_are_bound() {
    let (a, b, g) = setup();
    let root = event(
        &g,
        &a,
        Action::Poll {
            options: vec!["one".into(), "two".into()],
        },
        None,
    );
    let mut reserved = root.clone();
    reserved.id = g.group_id().into();
    reserved.object = g.group_id().into();
    reserved.signature = crypto::sign(&reserved.signing_bytes(), &a.keys.ed25519_sk).unwrap();
    assert!(transition(None, &g, &reserved).is_err());
    let good = Content::Poll {
        question: "question".into(),
        options: vec![
            OptionText {
                id: "one".into(),
                text: "A".into(),
            },
            OptionText {
                id: "two".into(),
                text: "B".into(),
            },
        ],
    };
    validate_content(&root, &good).unwrap();
    let mut tampered = root.clone();
    tampered.object = "other".into();
    assert!(tampered.verify(&g).is_err());
    let bad = Content::Poll {
        question: "question".into(),
        options: vec![
            OptionText {
                id: "one".into(),
                text: "A".into(),
            },
            OptionText {
                id: "two".into(),
                text: " A ".into(),
            },
        ],
    };
    assert!(validate_content(&root, &bad).is_err());
    let mention = event(&g, &a, Action::Mention, None);
    let member = Member::from(g.member("bob").unwrap());
    validate_content(
        &mention,
        &Content::Mention {
            text: "hello".into(),
            mentions: vec![member.clone()],
        },
    )
    .unwrap();
    assert!(validate_content(
        &mention,
        &Content::Mention {
            text: "hello".into(),
            mentions: vec![member.clone(), member]
        }
    )
    .is_err());
    assert!(transition(
        None,
        &g,
        &event(&g, &b, Action::Pin { target_hash: None }, None)
    )
    .is_err());
    let pin = event(&g, &a, Action::Pin { target_hash: None }, None);
    transition(None, &g, &pin).unwrap();
}
