use liteseal_shared::{crypto, reaction::Reaction};

#[test]
fn attachment_authentication_rejects_tampering_wrong_keys_and_truncation() {
    let (encrypted,key)=crypto::encrypt_attachment(b"\xe4\xb8\xad\xe6\x96\x87 attachment").unwrap();
    assert_eq!(crypto::decrypt_attachment(&encrypted,&key).unwrap(),b"\xe4\xb8\xad\xe6\x96\x87 attachment");
    let mut tampered=encrypted.clone();*tampered.last_mut().unwrap()^=1;
    assert!(crypto::decrypt_attachment(&tampered,&key).is_err());
    assert!(crypto::decrypt_attachment(&encrypted,&[0;32]).is_err());
    assert!(crypto::decrypt_attachment(&encrypted[..39],&key).is_err());
    let (empty,empty_key)=crypto::encrypt_attachment(b"").unwrap();
    assert_eq!(empty.len(),40);
    assert_eq!(crypto::decrypt_attachment(&empty,&empty_key).unwrap(),b"");
}

#[test]
fn reaction_signature_binds_actor_target_peer_revision_and_ciphertext() {
    let keys=crypto::generate_keypair().unwrap();
    let mut event=Reaction{id:"event".into(),target_id:"original".into(),conversation_id:"conversation".into(),actor:"alice".into(),device:"device".into(),peer:"bob".into(),revision:1,ciphertext:vec![1,2,3],signature:vec![]};
    event.signature=crypto::sign(&event.signing_bytes(),&keys.ed25519_sk).unwrap();
    assert!(crypto::verify_with_public_key(&event.signing_bytes(),&event.signature,&keys.ed25519_pk).unwrap());
    for field in 0..5 {
        let mut changed=event.clone();
        match field {0=>changed.actor="mallory".into(),1=>changed.target_id="other".into(),2=>changed.peer="mallory".into(),3=>changed.revision+=1,_=>changed.ciphertext.push(4)};
        assert!(!crypto::verify_with_public_key(&changed.signing_bytes(),&changed.signature,&keys.ed25519_pk).unwrap());
    }
}
