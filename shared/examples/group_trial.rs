//! Runs only synthetic participants in memory; never reads account files or connects to a relay.
#[path = "group_trial/support.rs"]
mod support;
use liteseal_shared::{crypto, group::*};
use support::{change, envelope, join, Participant};

fn main() {
    let alice = Participant::new("alice");
    let bob = Participant::new("bob");
    let carol = Participant::new("carol");
    let dave = Participant::new("dave");
    let create = change(
        None,
        &alice,
        GroupAction::Create {
            name: "小群技术验证".into(),
            owner: alice.identity(),
        },
        1000,
    );
    let initial = pin_creation(&create, &alice.identity()).unwrap();
    let add_bob = join(&initial, &alice, &bob, 1001);
    let two = validate_submission(Some(&initial), &add_bob, 1001).unwrap();
    let add_carol = join(&two, &alice, &carol, 1002);
    let three = validate_submission(Some(&two), &add_carol, 1002).unwrap();
    let old_bob = envelope(&three, &alice, &bob, "old-message", "群文字 🔐", None);
    let old_carol = envelope(&three, &alice, &carol, "old-message", "群文字 🔐", None);
    validate_batch(&three, &[old_bob.clone(), old_carol.clone()]).unwrap();
    assert_eq!(
        crypto::decrypt(
            &old_bob.ciphertext,
            &alice.keys.public_key,
            &bob.keys.secret_key
        )
        .unwrap(),
        "群文字 🔐".as_bytes()
    );
    let remove_bob = change(
        Some(&three),
        &alice,
        GroupAction::Remove {
            user_id: "bob".into(),
        },
        1003,
    );
    let removed = validate_submission(Some(&three), &remove_bob, 1003).unwrap();
    let after_removal = envelope(
        &removed,
        &alice,
        &carol,
        "new-message",
        "移除后文字",
        Some(&old_carol),
    );
    validate_batch(&removed, std::slice::from_ref(&after_removal)).unwrap();
    validate_chain(&after_removal, Some(&old_carol)).unwrap();
    assert!(crypto::decrypt(
        &after_removal.ciphertext,
        &alice.keys.public_key,
        &bob.keys.secret_key
    )
    .is_err());
    let add_dave = join(&removed, &alice, &dave, 1004);
    let latest = validate_submission(Some(&removed), &add_dave, 1004).unwrap();
    assert!(crypto::decrypt(
        &old_carol.ciphertext,
        &alice.keys.public_key,
        &dave.keys.secret_key
    )
    .is_err());
    let mut replay = initial;
    for event in [&add_bob, &add_carol, &remove_bob, &add_dave] {
        replay = apply_change(Some(&replay), event).unwrap();
    }
    assert_eq!(replay, latest);
    println!(
        "群成员版本链与邀请双签名验证通过；最终 {} 人，版本 {}。",
        latest.members().len(),
        latest.epoch()
    );
    println!("移除成员无法解密之后密文；新成员无法解密加入前密文；离线重放状态一致。");
    println!("此程序是内存技术验证，尚未接入群聊服务端或 Windows 界面。");
}
