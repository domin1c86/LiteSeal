use liteseal_shared::{
    backup_crypto::{validate_identity, Decryptor, Encryptor},
    crypto,
};
const PASSWORD: &[u8] = b"independent long backup password";
#[test]
fn authenticated_stream_rejects_damage_and_requires_final_and_eof() {
    let mut bytes = Vec::new();
    {
        let mut e = Encryptor::new(&mut bytes, PASSWORD).unwrap();
        e.push("中文 🦭".as_bytes(), false).unwrap();
        e.push(b"last", true).unwrap();
    }
    let mut d = Decryptor::new(bytes.as_slice(), PASSWORD).unwrap();
    assert_eq!(d.next_chunk().unwrap().unwrap(), "中文 🦭".as_bytes());
    assert_eq!(d.next_chunk().unwrap().unwrap(), b"last");
    assert!(d.ended());
    assert!(d.next_chunk().unwrap().is_none());
    let mut wrong = Decryptor::new(bytes.as_slice(), b"wrong backup password").unwrap();
    assert!(wrong.next_chunk().is_err());
    let mut cases = Vec::new();
    let mut damaged = bytes.clone();
    damaged[72] ^= 1;
    cases.push(damaged);
    cases.push(bytes[..bytes.len() - 1].to_vec());
    let mut extra = bytes.clone();
    extra.push(0);
    cases.push(extra);
    let first_end = 64 + 4 + u32::from_le_bytes(bytes[64..68].try_into().unwrap()) as usize;
    cases.push(bytes[..first_end].to_vec());
    let mut duplicate = bytes.clone();
    duplicate.splice(first_end..first_end, bytes[64..first_end].iter().copied());
    cases.push(duplicate);
    for case in cases {
        let mut d = Decryptor::new(case.as_slice(), PASSWORD).unwrap();
        let mut rejected = false;
        loop {
            match d.next_chunk() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => {
                    rejected = true;
                    break;
                }
            }
        }
        assert!(rejected);
    }
    let mut bad_header = bytes.clone();
    bad_header[16] = 255;
    assert!(Decryptor::new(bad_header.as_slice(), PASSWORD).is_err());
}
#[test]
fn identities_require_both_matching_public_private_pairs() {
    let a = crypto::generate_keypair().unwrap();
    let b = crypto::generate_keypair().unwrap();
    assert!(validate_identity(&a.public_key, &a.secret_key, &a.ed25519_pk, &a.ed25519_sk).is_ok());
    assert!(validate_identity(&b.public_key, &a.secret_key, &a.ed25519_pk, &a.ed25519_sk).is_err());
    assert!(validate_identity(&a.public_key, &a.secret_key, &a.ed25519_pk, &b.ed25519_sk).is_err());
}
