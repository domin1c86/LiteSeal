use liteseal_shared::{
    crypto::{self, KeyPair},
    direct_message::{Batch, Directory, Header as MessageHeader, Kind, MessageSpec},
    direct_operation::{self as op, Action, Operation},
    history_transfer::{Envelope, Evidence, Header, Record, LIFETIME},
    trusted_device::*,
};

const ID: &str = "00000000-0000-4000-8000-000000000001";
const TRANSFER: &str = "00000000-0000-4000-8000-000000000002";
struct Account {
    root: KeyPair,
    joined_key: KeyPair,
    initial: DeviceState,
    joined: DeviceState,
}
impl Account {
    fn new(account: &str) -> Self {
        let root = crypto::generate_keypair().unwrap();
        let joined_key = crypto::generate_keypair().unwrap();
        let initial = DeviceState::pin(Anchor {
            origin: "https://synthetic.example".into(),
            account: account.into(),
            root: DeviceIdentity::from_keys(format!("{account}-root"), &root),
        })
        .unwrap();
        let intent = make_intent(
            initial.anchor(),
            format!("{account}-join"),
            format!("{account}-second"),
            crypto::random_challenge().unwrap(),
            1000,
            &joined_key,
        )
        .unwrap();
        let challenge = make_challenge(&initial, &intent, 1001, &root).unwrap();
        let proof = answer_challenge(&initial, &intent, &challenge, 1002, &joined_key).unwrap();
        let grant = make_event(
            &initial,
            format!("{account}-grant"),
            DeviceAction::Grant {
                intent: Box::new(intent),
                challenge: Box::new(challenge),
                proof,
            },
            1003,
            &root,
        )
        .unwrap();
        let joined = initial.apply(&grant).unwrap();
        Self {
            root,
            joined_key,
            initial,
            joined,
        }
    }
    fn revoked(&self) -> DeviceState {
        self.joined
            .apply(
                &make_event(
                    &self.joined,
                    "revoke".into(),
                    DeviceAction::Revoke {
                        device_id: self.joined.secondary().unwrap().device_id.clone(),
                        grant_hash: self.joined.grant_hash().unwrap().to_vec(),
                    },
                    5000,
                    &self.root,
                )
                .unwrap(),
            )
            .unwrap()
    }
}
fn original(a: &Account, b: &Account) -> Batch {
    Batch::make(
        MessageHeader::new(
            &a.initial,
            &b.initial,
            &a.initial.anchor().root.device_id,
            MessageSpec {
                id: ID.into(),
                sequence: 1,
                previous: vec![],
                sent_at: 2000,
                kind: Kind::Text,
            },
        )
        .unwrap(),
        &a.initial,
        &b.initial,
        &a.root,
        "旧历史 中文 🦭".as_bytes(),
    )
    .unwrap()
}
fn record(a: &Account, b: &Account) -> Record {
    Record {
        original: original(a, b),
        sender: Evidence {
            anchor: a.initial.anchor().clone(),
            events: vec![],
        },
        peer: Evidence {
            anchor: b.initial.anchor().clone(),
            events: vec![],
        },
        accepted_at: 2001,
        operations: vec![],
        text: Some("旧历史 中文 🦭".into()),
        media: None,
    }
}
fn header(a: &Account, b: &Account, records: &[Record]) -> Header {
    let directory = Directory::from_state(&a.joined);
    Header {
        version: 1,
        id: TRANSFER.into(),
        origin: a.initial.anchor().origin.clone(),
        account: a.initial.anchor().account.clone(),
        source: a.initial.anchor().root.clone(),
        target: directory
            .members
            .iter()
            .find(|m| m.device.device_id.ends_with("second"))
            .unwrap()
            .clone(),
        directory,
        peer: b.initial.anchor().account.clone(),
        created_at: 3000,
        expires_at: 3000 + LIFETIME,
        selection: records.iter().map(|r| r.reference().unwrap()).collect(),
    }
}
#[test]
fn old_history_is_explicitly_reencrypted_for_current_joined_device() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let records = vec![record(&a, &b)];
    assert!(records[0]
        .original
        .open(
            &a.initial,
            &b.initial,
            "alice",
            "alice-second",
            &a.joined_key
        )
        .is_err());
    let transfer = Envelope::make(header(&a, &b, &records), &a.joined, &a.root, records).unwrap();
    let wire = transfer.to_wire().unwrap();
    assert!(!wire
        .windows("旧历史".len())
        .any(|p| p == "旧历史".as_bytes()));
    let restored = Envelope::from_wire(&wire).unwrap();
    assert_eq!(restored.to_wire().unwrap(), wire);
    assert_eq!(restored.digest().unwrap(), transfer.digest().unwrap());
    let opened = restored.open(&a.joined, &a.joined_key, 3001).unwrap();
    assert_eq!(opened[0].text.as_deref(), Some("旧历史 中文 🦭"));
    assert!(restored.open(&a.joined, &a.root, 3001).is_err());
    assert!(restored.open(&b.joined, &b.joined_key, 3001).is_err());
    assert!(restored.open(&a.initial, &a.joined_key, 3001).is_err());
    assert!(restored.open(&a.revoked(), &a.joined_key, 5001).is_err());
    assert!(restored.open(&a.joined, &a.joined_key, 2999).is_err());
    assert!(restored
        .open(&a.joined, &a.joined_key, 3000 + LIFETIME)
        .is_err());
}
#[test]
fn media_copy_authenticates_original_descriptor_cache_and_selection_budget() {
    use liteseal_shared::{direct_media::Descriptor, history_transfer::Media};
    let a = Account::new("alice");
    let b = Account::new("bob");
    let bytes = "明确授权的媒体 中文 🦭".as_bytes();
    let (descriptor, ciphertext) = Descriptor::encrypt(
        ID.into(),
        "历史文件.bin".into(),
        bytes,
        Kind::Attachment,
        None,
    )
    .unwrap();
    let mut r = record(&a, &b);
    let mut message = r.original.header.clone();
    message.kind = Kind::Attachment;
    r.original = Batch::make(
        message,
        &a.initial,
        &b.initial,
        &a.root,
        &descriptor.to_body(Kind::Attachment).unwrap(),
    )
    .unwrap();
    r.text = None;
    r.media = Some(Media {
        descriptor,
        ciphertext: Some(ciphertext),
    });
    assert!(r.bounded_plain_size(10).is_err());
    let size = r.bounded_plain_size(128 * 1024).unwrap();
    assert_eq!(size, serde_json::to_vec(&r).unwrap().len());
    let records = vec![r.clone()];
    let transfer = Envelope::make(header(&a, &b, &records), &a.joined, &a.root, records).unwrap();
    let opened = transfer.open(&a.joined, &a.joined_key, 3001).unwrap();
    let media = opened[0].media.as_ref().unwrap();
    assert_eq!(
        media
            .descriptor
            .decrypt(Kind::Attachment, media.ciphertext.as_ref().unwrap())
            .unwrap(),
        bytes
    );
    r.media.as_mut().unwrap().ciphertext.as_mut().unwrap()[0] ^= 1;
    let records = vec![r];
    assert!(Envelope::make(header(&a, &b, &records), &a.joined, &a.root, records).is_err());
}
#[test]
fn selected_original_proof_plaintext_revision_and_root_authority_are_bound() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    for mode in 0..7 {
        let mut records = vec![record(&a, &b)];
        let mut h = header(&a, &b, &records);
        match mode {
            0 => records[0].text = Some("substituted plaintext".into()),
            1 => h.peer = "mallory".into(),
            2 => h.selection[0].digest[0] ^= 1,
            3 => h.selection[0].operation_revision = 1,
            4 => {
                h.selection.push(h.selection[0].clone());
                records.push(records[0].clone());
            }
            5 => records[0].original.signature[0] ^= 1,
            _ => h.expires_at += 1,
        }
        assert!(
            Envelope::make(h, &a.joined, &a.root, records).is_err(),
            "mode {mode}"
        );
    }
    let records = vec![record(&a, &b)];
    assert!(Envelope::make(header(&a, &b, &records), &a.joined, &a.joined_key, records).is_err());
    let records = vec![record(&a, &b)];
    let mut transfer =
        Envelope::make(header(&a, &b, &records), &a.joined, &a.root, records).unwrap();
    transfer.header.peer = "mallory".into();
    assert!(transfer.verify(&a.joined).is_err());
    let records = vec![record(&a, &b)];
    let transfer = Envelope::make(header(&a, &b, &records), &a.joined, &a.root, records).unwrap();
    let mut wire = transfer.to_wire().unwrap();
    let end = wire.len() - 1;
    wire[end] ^= 1;
    assert!(Envelope::from_wire(&wire).is_err());
    assert!(Envelope::from_wire(b"LSEALH01").is_err());
}
#[test]
fn edits_and_retractions_keep_original_author_evidence_and_selected_revision() {
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut r = record(&a, &b);
    let edit = Operation::make(
        r.original.clone(),
        (&a.initial, &b.initial),
        (&a.initial, &b.initial),
        &a.root,
        op::Header {
            version: 1,
            id: "edit".into(),
            original: r.original.digest().unwrap(),
            action: Action::Edit,
            base: 0,
            revision: 1,
            created_at: 2500,
        },
        Some("编辑后的历史"),
    )
    .unwrap();
    r.operations.push(edit);
    r.text = Some("编辑后的历史".into());
    let records = vec![r];
    let transfer = Envelope::make(
        header(&a, &b, &records),
        &a.joined,
        &a.root,
        records.clone(),
    )
    .unwrap();
    let received =
        liteseal_shared::history_transfer::Received::make(&transfer.offer(), 3001, &a.joined_key)
            .unwrap();
    received.verify(&transfer.offer()).unwrap();
    assert!(
        liteseal_shared::history_transfer::Received::make(&transfer.offer(), 3001, &a.root)
            .is_err()
    );
    assert_eq!(
        transfer.open(&a.joined, &a.joined_key, 3001).unwrap()[0]
            .text
            .as_deref(),
        Some("编辑后的历史")
    );
    let mut r = records[0].clone();
    r.text = Some("旧历史 中文 🦭".into());
    let wrong = vec![r];
    assert!(Envelope::make(header(&a, &b, &wrong), &a.joined, &a.root, wrong).is_err());
    let mut r = records[0].clone();
    r.operations.push(
        Operation::make(
            r.original.clone(),
            (&a.initial, &b.initial),
            (&a.initial, &b.initial),
            &a.root,
            op::Header {
                version: 1,
                id: "retract".into(),
                original: r.original.digest().unwrap(),
                action: Action::Retract,
                base: 1,
                revision: 2,
                created_at: 2600,
            },
            None,
        )
        .unwrap(),
    );
    r.text = None;
    let records = vec![r];
    let transfer = Envelope::make(header(&a, &b, &records), &a.joined, &a.root, records).unwrap();
    let opened = transfer.open(&a.joined, &a.joined_key, 3001).unwrap();
    assert!(opened[0].text.is_none());
    assert_eq!(opened[0].operations.len(), 2);
}
