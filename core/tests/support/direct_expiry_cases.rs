use super::*;
use liteseal_core::trusted_devices::messages::expiry_trial::Trial;
use liteseal_shared::disappearing_message::Packet;

#[test]
fn signed_deadline_visibility_reopen_replay_clock_rollback_and_chain_proofs() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut source = open(&work.0, "source", &a, false, &p);
    let mut target = open(&work.0, "target", &b, false, &p);
    seed(&mut source, &[&a, &b]);
    seed(&mut target, &[&a, &b]);
    prepare(
        &mut source,
        "bob",
        "00000000-0000-4000-8000-000000000101",
        b"temporary synthetic body",
        &a.root,
    );
    source
        .begin_publish("00000000-0000-4000-8000-000000000101", 0, &a.root)
        .unwrap();
    let first = source
        .original("00000000-0000-4000-8000-000000000101", &a.root)
        .unwrap();
    let packet = Packet::make(first.clone(), 1_000, &a.root, &a.joined, &b.joined).unwrap();
    let wire = packet.to_wire().unwrap();
    assert!(
        Batch::from_wire(&wire).is_err(),
        "old codec must fail closed"
    );
    let decoded = Packet::from_wire(&wire).unwrap();
    decoded.verify(&a.joined, &b.joined).unwrap();
    let mut tampered = packet.clone();
    tampered.expires_at += 1;
    assert!(tampered.verify(&a.joined, &b.joined).is_err());
    let mut target = Trial::new(target);
    assert!(target
        .receive(&tampered, &accepted(&first), &b.root)
        .is_err());
    target.receive(&packet, &accepted(&first), &b.root).unwrap();
    let initial_ack = target
        .pending_acks(&b.root)
        .unwrap()
        .into_iter()
        .map(|a| a.to_wire().unwrap())
        .collect::<Vec<_>>();
    assert!(target
        .search(
            "00000000-0000-4000-8000-000000000101",
            "synthetic",
            2999,
            &b.root
        )
        .unwrap());
    assert!(target
        .notification("00000000-0000-4000-8000-000000000101", 2999, &b.root)
        .unwrap());
    assert!(target
        .export_body("00000000-0000-4000-8000-000000000101", 2999, &b.root)
        .unwrap()
        .is_some());
    assert!(target
        .body("00000000-0000-4000-8000-000000000101", 3000, &b.root)
        .unwrap()
        .is_none());
    assert!(!target
        .search(
            "00000000-0000-4000-8000-000000000101",
            "synthetic",
            3000,
            &b.root
        )
        .unwrap());
    assert!(!target
        .notification("00000000-0000-4000-8000-000000000101", 3000, &b.root)
        .unwrap());
    assert!(target
        .export_body("00000000-0000-4000-8000-000000000101", 3000, &b.root)
        .unwrap()
        .is_none());
    assert_eq!(
        target
            .proof("00000000-0000-4000-8000-000000000101", &b.root)
            .unwrap()
            .to_wire()
            .unwrap(),
        wire
    );
    target.receive(&packet, &accepted(&first), &b.root).unwrap();
    assert_eq!(
        target
            .pending_acks(&b.root)
            .unwrap()
            .into_iter()
            .map(|a| a.to_wire().unwrap())
            .collect::<Vec<_>>(),
        initial_ack
    );
    drop(target);
    let mut target = Trial::new(open(&work.0, "target", &b, false, &p));
    assert!(
        target
            .body("00000000-0000-4000-8000-000000000101", 2001, &b.root)
            .unwrap()
            .is_none(),
        "reopen and clock rollback cannot resurrect"
    );
    source.confirm_accepted(&accepted(&first), &a.root).unwrap();
    prepare(
        &mut source,
        "bob",
        "00000000-0000-4000-8000-000000000102",
        b"next synthetic body",
        &a.root,
    );
    source
        .begin_publish("00000000-0000-4000-8000-000000000102", 0, &a.root)
        .unwrap();
    let next = source
        .original("00000000-0000-4000-8000-000000000102", &a.root)
        .unwrap();
    let next_packet = Packet::make(next.clone(), 10_000, &a.root, &a.joined, &b.joined).unwrap();
    target
        .receive(&next_packet, &accepted(&next), &b.root)
        .unwrap();
    assert!(target
        .body("00000000-0000-4000-8000-000000000102", 3000, &b.root)
        .unwrap()
        .is_some());
    assert_eq!(target.pending_acks(&b.root).unwrap().len(), 2);
}

#[test]
fn offline_arrival_past_expiry_and_restored_old_sqlite_are_rejected() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut source = open(&work.0, "source", &a, false, &p);
    let mut target = open(&work.0, "target", &b, false, &p);
    seed(&mut source, &[&a, &b]);
    seed(&mut target, &[&a, &b]);
    prepare(
        &mut source,
        "bob",
        "00000000-0000-4000-8000-000000000103",
        b"offline synthetic body",
        &a.root,
    );
    source
        .begin_publish("00000000-0000-4000-8000-000000000103", 0, &a.root)
        .unwrap();
    let batch = source
        .original("00000000-0000-4000-8000-000000000103", &a.root)
        .unwrap();
    let packet = Packet::make(batch.clone(), 1000, &a.root, &a.joined, &b.joined).unwrap();
    assert!(Packet::make(batch.clone(), 0, &a.root, &a.joined, &b.joined).is_err());
    assert!(Packet::make(batch.clone(), i64::MAX, &a.root, &a.joined, &b.joined).is_err());
    let mut target = Trial::new(target);
    target.receive(&packet, &accepted(&batch), &b.root).unwrap();
    drop(target);
    let db = work.0.join("target.db");
    let prior = work.0.join("prior.db");
    fs::copy(&db, &prior).unwrap();
    let mut target = Trial::new(open(&work.0, "target", &b, false, &p));
    assert!(target
        .body("00000000-0000-4000-8000-000000000103", 5000, &b.root)
        .unwrap()
        .is_none());
    assert_eq!(target.pending_acks(&b.root).unwrap().len(), 1);
    drop(target);
    // Owned isolated fixture paths only, with the DB closed before restoration.
    fs::copy(&prior, &db).unwrap();
    let owner = Owner::new(
        &b.initial.anchor().origin,
        "bob",
        &b.initial.anchor().root.device_id,
        &b.root,
    )
    .unwrap();
    assert!(Store::open(&db, owner, p.witness(&db).unwrap()).is_err());
}

#[test]
fn attachment_cache_access_stops_at_the_signed_deadline_without_removing_proof() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut target = open(&work.0, "target", &b, false, &p);
    seed(&mut target, &[&a, &b]);
    let header = Header::new(
        &a.joined,
        &b.joined,
        &a.initial.anchor().root.device_id,
        MessageSpec {
            id: "00000000-0000-4000-8000-000000000104".into(),
            sequence: 1,
            previous: vec![],
            sent_at: 2000,
            kind: Kind::Attachment,
        },
    )
    .unwrap();
    let (descriptor, ciphertext) = liteseal_shared::direct_media::Descriptor::encrypt(
        header.id.clone(),
        "synthetic.txt".into(),
        b"synthetic file",
        Kind::Attachment,
        None,
    )
    .unwrap();
    let body = zeroize::Zeroizing::new(descriptor.to_body(Kind::Attachment).unwrap());
    let batch = Batch::make(header, &a.joined, &b.joined, &a.root, &body).unwrap();
    let packet = Packet::make(batch.clone(), 1000, &a.root, &a.joined, &b.joined).unwrap();
    let wire = packet.to_wire().unwrap();
    let mut target = Trial::new(target);
    target.receive(&packet, &accepted(&batch), &b.root).unwrap();
    assert_eq!(
        &*target
            .attachment(
                "00000000-0000-4000-8000-000000000104",
                &ciphertext,
                2999,
                &b.root
            )
            .unwrap()
            .unwrap(),
        b"synthetic file"
    );
    let mut corrupted = ciphertext.clone();
    corrupted[0] ^= 1;
    assert!(target
        .attachment(
            "00000000-0000-4000-8000-000000000104",
            &corrupted,
            2999,
            &b.root
        )
        .is_err());
    assert!(target
        .attachment(
            "00000000-0000-4000-8000-000000000104",
            &ciphertext,
            3000,
            &b.root
        )
        .unwrap()
        .is_none());
    assert!(target
        .attachment(
            "00000000-0000-4000-8000-000000000104",
            &ciphertext,
            2500,
            &b.root
        )
        .unwrap()
        .is_none());
    assert_eq!(
        target
            .proof("00000000-0000-4000-8000-000000000104", &b.root)
            .unwrap()
            .to_wire()
            .unwrap(),
        wire
    );
    assert_eq!(target.pending_acks(&b.root).unwrap().len(), 1);
}
