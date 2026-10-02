//! Included by the batch test fixture; not a standalone Cargo test target.
use super::*;
use liteseal_shared::direct_operation::{self as op, Action, Operation};
fn original(a: &Account, b: &Account) -> Batch {
    Batch::make(
        header(&a.joined, &b.joined, "alice-root", "original"),
        &a.joined,
        &b.joined,
        &a.root,
        b"old text",
    )
    .unwrap()
}
fn edit(original: Batch, a: &Account, b: &Account, peer: &DeviceState, id: &str) -> Operation {
    let digest = original.digest().unwrap();
    Operation::make(
        original,
        (&a.joined, &b.joined),
        (&a.joined, peer),
        &a.root,
        op::Header {
            version: 1,
            id: id.into(),
            original: digest,
            action: Action::Edit,
            base: 0,
            revision: 1,
            created_at: 2000,
        },
        Some("编辑 中文 🦭"),
    )
    .unwrap()
}
#[test]
fn signed_edit_roundtrip_uses_exact_original_devices_and_author_key() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let operation = edit(original(&a, &b), &a, &b, &b.joined, "edit");
    assert_eq!(operation.payloads.len(), 4);
    for (account, device, keys, state) in [
        ("alice", "alice-root", &a.root, &a.joined),
        ("alice", "alice-second", &a.second, &a.joined),
        ("bob", "bob-root", &b.root, &b.joined),
        ("bob", "bob-second", &b.second, &b.joined),
    ] {
        let member = Directory::from_state(state)
            .members
            .into_iter()
            .find(|m| m.device.device_id == device)
            .unwrap();
        assert_eq!(
            operation
                .open(
                    &a.joined,
                    &b.joined,
                    account,
                    device,
                    member.authorization_hash,
                    keys
                )
                .unwrap()
                .as_deref(),
            Some("编辑 中文 🦭")
        );
    }
    let wire = operation.to_wire().unwrap();
    assert!(!String::from_utf8_lossy(&wire).contains("编辑 中文"));
    assert_eq!(
        Operation::from_wire(&wire).unwrap().to_wire().unwrap(),
        wire
    );
    assert!(Operation::make(
        operation.original.clone(),
        (&a.joined, &b.joined),
        (&a.joined, &b.joined),
        &a.second,
        operation.header.clone(),
        Some("wrong author")
    )
    .is_err());
}
#[test]
fn signature_target_revision_and_ciphertext_tampering_are_rejected() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let valid = edit(original(&a, &b), &a, &b, &b.joined, "edit");
    for mode in 0..6 {
        let mut changed = valid.clone();
        match mode {
            0 => changed.header.id = "moved".into(),
            1 => {
                changed.header.base = 1;
                changed.header.revision = 2;
            }
            2 => {
                changed.payloads.pop();
            }
            3 => changed.payloads[0].ciphertext[0] ^= 1,
            4 => changed.signature[0] ^= 1,
            _ => changed.header.original[0] ^= 1,
        };
        assert!(changed
            .verify_current(&a.joined, &b.joined, &a.joined, &b.joined)
            .is_err());
    }
    let mut bad = valid.clone();
    bad.signature.clear();
    assert!(bad.to_wire().is_err());
    assert!(Operation::from_wire(&vec![0; op::MAX_WIRE + 1]).is_err());
}
#[test]
fn removed_recipient_is_excluded_and_historical_copy_stays_readable() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let old = original(&a, &b);
    let before = edit(old.clone(), &a, &b, &b.joined, "before");
    let revoked = b.revoke();
    let after = edit(old, &a, &b, &revoked, "after");
    assert_eq!(after.payloads.len(), 3);
    assert!(!after.payloads.iter().any(|p| p.device == "bob-second"));
    assert!(before
        .verify_current(&a.joined, &b.joined, &a.joined, &revoked)
        .is_err());
    let authority = b.joined.grant_hash().unwrap().try_into().unwrap();
    assert!(after
        .open(
            &a.joined,
            &b.joined,
            "bob",
            "bob-second",
            authority,
            &b.second
        )
        .is_err());
    assert!(before
        .open(
            &a.joined,
            &b.joined,
            "bob",
            "bob-second",
            authority,
            &b.second
        )
        .unwrap()
        .is_some());
}
#[test]
fn retraction_has_no_edit_text_and_media_edit_is_rejected() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let original = original(&a, &b);
    let header = op::Header {
        version: 1,
        id: "retract".into(),
        original: original.digest().unwrap(),
        action: Action::Retract,
        base: 0,
        revision: 1,
        created_at: 2000,
    };
    let retraction = Operation::make(
        original.clone(),
        (&a.joined, &b.joined),
        (&a.joined, &b.joined),
        &a.root,
        header.clone(),
        None,
    )
    .unwrap();
    assert!(Operation::make(
        original,
        (&a.joined, &b.joined),
        (&a.joined, &b.joined),
        &a.root,
        header,
        Some("not allowed")
    )
    .is_err());
    assert!(retraction
        .open(
            &a.joined,
            &b.joined,
            "alice",
            "alice-root",
            a.joined.anchor().hash().try_into().unwrap(),
            &a.root
        )
        .unwrap()
        .is_none());
    let mut h = super::header(&a.joined, &b.joined, "alice-root", "media");
    h.kind = Kind::Attachment;
    let media = Batch::make(
        h,
        &a.joined,
        &b.joined,
        &a.root,
        b"synthetic encrypted descriptor",
    )
    .unwrap();
    let header = op::Header {
        version: 1,
        id: "edit-media".into(),
        original: media.digest().unwrap(),
        action: Action::Edit,
        base: 0,
        revision: 1,
        created_at: 2000,
    };
    assert!(Operation::make(
        media,
        (&a.joined, &b.joined),
        (&a.joined, &b.joined),
        &a.root,
        header,
        Some("not text original")
    )
    .is_err());
}
