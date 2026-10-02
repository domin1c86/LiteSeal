use liteseal_shared::{
    crypto::{self, KeyPair},
    direct_media::*,
    direct_message::{Batch, Header, Kind, MessageSpec},
    trusted_device::{Anchor, DeviceIdentity, DeviceState},
};
const ID: &str = "01234567-89ab-4cde-8fab-0123456789ab";
fn states() -> (KeyPair, KeyPair, DeviceState, DeviceState) {
    let a = crypto::generate_keypair().unwrap();
    let b = crypto::generate_keypair().unwrap();
    let state = |account: &str, keys: &KeyPair| {
        DeviceState::pin(Anchor {
            origin: "https://synthetic.example".into(),
            account: account.into(),
            root: DeviceIdentity::from_keys(format!("{account}-root"), keys),
        })
        .unwrap()
    };
    let as_ = state("alice", &a);
    let bs = state("bob", &b);
    (a, b, as_, bs)
}
fn header(a: &DeviceState, b: &DeviceState, kind: Kind) -> Header {
    Header::new(
        a,
        b,
        &a.anchor().root.device_id,
        MessageSpec {
            id: ID.into(),
            sequence: 1,
            previous: vec![],
            sent_at: 2000,
            kind,
        },
    )
    .unwrap()
}
#[test]
fn encrypted_descriptor_and_separate_binding_round_trip_without_changing_text_wire() {
    let (a, b, as_, bs) = states();
    let bytes = "中文文件内容 🦭".as_bytes();
    let (descriptor, cipher) = Descriptor::encrypt(
        ID.into(),
        "独立文件.txt".into(),
        bytes,
        Kind::Attachment,
        None,
    )
    .unwrap();
    let value = Submission::make(
        header(&as_, &bs, Kind::Attachment),
        &as_,
        &bs,
        &a,
        &descriptor,
    )
    .unwrap();
    let wire = value.to_wire().unwrap();
    assert!(!wire
        .windows(descriptor.name.len())
        .any(|s| s == descriptor.name.as_bytes()));
    let retry = Submission::from_wire(&wire).unwrap();
    let rebound = Submission::bind(value.batch.clone(), &descriptor, &a).unwrap();
    assert_eq!(rebound.to_wire().unwrap(), wire);
    assert_eq!(wire, retry.to_wire().unwrap());
    assert_eq!(value.digest().unwrap(), retry.digest().unwrap());
    value.verify(&as_, &bs).unwrap();
    let body = value
        .batch
        .open(&as_, &bs, "bob", &bs.anchor().root.device_id, &b)
        .unwrap();
    let opened = Descriptor::from_body(&value.batch.header, &body).unwrap();
    assert_eq!(opened.name, "独立文件.txt");
    assert_eq!(opened.decrypt(Kind::Attachment, &cipher).unwrap(), bytes);
    assert_eq!(opened.reference().unwrap(), value.object);
    let inner_wire = value.batch.to_wire().unwrap();
    assert_eq!(
        Batch::from_wire(&inner_wire).unwrap().digest().unwrap(),
        value.batch.digest().unwrap()
    );
    let text = Batch::make(
        header(&as_, &bs, Kind::Text),
        &as_,
        &bs,
        &a,
        b"existing text",
    )
    .unwrap();
    let text_wire = text.to_wire().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&text_wire).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 4);
    assert!(json.get("object").is_none());
    assert_eq!(
        text_wire,
        Batch::from_wire(&text_wire).unwrap().to_wire().unwrap()
    );
    assert!(Submission::make(text.header, &as_, &bs, &a, &descriptor).is_err());
}
#[test]
fn all_public_media_binding_and_encrypted_batch_fields_are_authenticated() {
    let (a, _, as_, bs) = states();
    let (d, _) = Descriptor::encrypt(
        ID.into(),
        "file.bin".into(),
        b"bytes",
        Kind::Attachment,
        None,
    )
    .unwrap();
    let value = Submission::make(header(&as_, &bs, Kind::Attachment), &as_, &bs, &a, &d).unwrap();
    for field in 0..8 {
        let mut changed = value.clone();
        match field {
            0 => changed.object.size += 1,
            1 => changed.object.hash[0] ^= 1,
            2 => changed.batch.header.id = "11234567-89ab-4cde-8fab-0123456789ab".into(),
            3 => changed.batch.header.sent_at += 1,
            4 => changed.batch.commitment[0] ^= 1,
            5 => changed.batch.payloads[0].ciphertext[0] ^= 1,
            6 => changed.signature[0] ^= 1,
            _ => changed.version += 1,
        }
        assert!(changed.verify(&as_, &bs).is_err());
    }
    let (_, _, wrong, _) = states();
    assert!(value.verify(&wrong, &bs).is_err());
    let mut json = serde_json::to_value(&value).unwrap();
    json["path"] = "C:/injected".into();
    assert!(Submission::from_wire(&serde_json::to_vec(&json).unwrap()).is_err());
    let wire = value.to_wire().unwrap();
    assert!(Submission::from_wire(&wire[..wire.len() - 1]).is_err());
    assert!(Submission::from_wire(&vec![0; MAX_SUBMISSION + 1]).is_err());
}
#[test]
fn metadata_identity_key_length_kind_and_cipher_authentication_reject_bad_input() {
    let (a, _, as_, bs) = states();
    let (d, cipher) = Descriptor::encrypt(
        ID.into(),
        "image.png".into(),
        b"\x89PNG\r\n\x1a\ncontent",
        Kind::Attachment,
        None,
    )
    .unwrap();
    let h = header(&as_, &bs, Kind::Attachment);
    let body = d.to_body(Kind::Attachment).unwrap();
    let mut wrong = h.clone();
    wrong.id = "11234567-89ab-4cde-8fab-0123456789ab".into();
    assert!(Descriptor::from_body(&wrong, &body).is_err());
    wrong = h.clone();
    wrong.kind = Kind::Voice;
    assert!(Descriptor::from_body(&wrong, &body).is_err());
    for field in ["key", "version", "name", "extra"] {
        let mut json = serde_json::to_value(&d).unwrap();
        json[field] = match field {
            "key" => serde_json::json!([1, 2]),
            "version" => 2.into(),
            "name" => "../escape".into(),
            _ => true.into(),
        };
        assert!(Descriptor::from_body(&h, &serde_json::to_vec(&json).unwrap()).is_err());
    }
    assert!(Descriptor::from_body(&h, &vec![b' '; MAX_DESCRIPTOR + 1]).is_err());
    let mut damaged = cipher.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    assert!(d.decrypt(Kind::Attachment, &damaged).is_err());
    let mut forged = d.clone();
    forged.hash = Reference {
        size: damaged.len() as u64,
        hash: sha2::Sha256::digest(&damaged).into(),
    }
    .hash;
    assert!(forged.decrypt(Kind::Attachment, &damaged).is_err());
    assert!(d
        .decrypt(Kind::Attachment, &cipher[..cipher.len() - 1])
        .is_err());
    let mut forged = d.clone();
    forged.mime = "image/jpeg".into();
    assert!(forged.decrypt(Kind::Attachment, &cipher).is_err());
    assert!(Submission::make(h, &as_, &bs, &crypto::generate_keypair().unwrap(), &d).is_err());
    let _ = a;
}
#[test]
fn exact_twenty_mib_zero_file_chunk_edges_and_reordered_ciphertext() {
    let bytes = vec![9; MAX_FILE];
    let (d, cipher) =
        Descriptor::encrypt(ID.into(), "edge.bin".into(), &bytes, Kind::Attachment, None).unwrap();
    let reference = d.reference().unwrap();
    assert_eq!(reference.chunk_len(0).unwrap(), CHUNK);
    assert_eq!(reference.chunk_len(20).unwrap(), 40);
    assert!(reference.chunk_len(-1).is_err());
    assert!(reference.chunk_len(21).is_err());
    assert!(reference.chunk_len(i32::MAX).is_err());
    assert_eq!(d.decrypt(Kind::Attachment, &cipher).unwrap(), bytes);
    let mut reordered = cipher.clone();
    for i in 0..CHUNK {
        reordered.swap(i, i + CHUNK);
    }
    assert!(d.decrypt(Kind::Attachment, &reordered).is_err());
    assert!(Descriptor::encrypt(
        ID.into(),
        "too-large.bin".into(),
        &vec![0; MAX_FILE + 1],
        Kind::Attachment,
        None
    )
    .is_err());
    let (empty, cipher) =
        Descriptor::encrypt(ID.into(), "empty.bin".into(), &[], Kind::Attachment, None).unwrap();
    assert_eq!(empty.reference().unwrap().chunk_len(0).unwrap(), 40);
    assert!(empty.decrypt(Kind::Attachment, &cipher).unwrap().is_empty());
}
#[test]
fn voice_metadata_has_sixty_second_limit_and_requires_bounded_webm_opus() {
    let bytes = b"\x1a\x45\xdf\xa3webm---A_OPUS---OpusHead";
    let (d, cipher) = Descriptor::encrypt(
        ID.into(),
        "voice.webm".into(),
        bytes,
        Kind::Voice,
        Some(60000),
    )
    .unwrap();
    assert_eq!(d.decrypt(Kind::Voice, &cipher).unwrap(), bytes);
    for duration in [None, Some(0), Some(60001)] {
        assert!(
            Descriptor::encrypt(ID.into(), "voice.webm".into(), bytes, Kind::Voice, duration)
                .is_err()
        );
    }
    assert!(Descriptor::encrypt(
        ID.into(),
        "voice.webm".into(),
        b"not audio",
        Kind::Voice,
        Some(100)
    )
    .is_err());
    let mut too_large = vec![0; MAX_VOICE + 1];
    too_large[..bytes.len()].copy_from_slice(bytes);
    assert!(Descriptor::encrypt(
        ID.into(),
        "voice.webm".into(),
        &too_large,
        Kind::Voice,
        Some(100)
    )
    .is_err());
    assert!(Descriptor::encrypt(
        ID.into(),
        "file.bin".into(),
        b"file",
        Kind::Attachment,
        Some(100)
    )
    .is_err());
}
use sha2::Digest;
