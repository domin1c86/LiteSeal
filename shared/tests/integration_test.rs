use liteseal_shared::crypto;
use liteseal_shared::types::Message;

const ALICE_MSG: &[u8] = b"Hello Bob, this is a secret message from Alice.";
const BOB_MSG: &[u8] = b"Hi Alice, received your message loud and clear!";

// [S8.1] 加密模块测试

#[test]
fn test_full_encryption_flow_alice_to_bob() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let ciphertext = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();
    let plaintext = crypto::decrypt(&ciphertext, &alice.public_key, &bob.secret_key).unwrap();

    assert_eq!(plaintext, ALICE_MSG);
}

#[test]
fn test_full_encryption_flow_bob_to_alice() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let ciphertext = crypto::encrypt(BOB_MSG, &alice.public_key, &bob.secret_key).unwrap();
    let plaintext = crypto::decrypt(&ciphertext, &bob.public_key, &alice.secret_key).unwrap();

    assert_eq!(plaintext, BOB_MSG);
}

#[test]
fn test_bidirectional_encrypted_conversation() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let ct1 = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();
    let ct2 = crypto::encrypt(BOB_MSG, &alice.public_key, &bob.secret_key).unwrap();

    let pt1 = crypto::decrypt(&ct1, &alice.public_key, &bob.secret_key).unwrap();
    let pt2 = crypto::decrypt(&ct2, &bob.public_key, &alice.secret_key).unwrap();

    assert_eq!(pt1, ALICE_MSG);
    assert_eq!(pt2, BOB_MSG);
}

#[test]
fn test_wrong_recipient_fails_decryption() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();
    let eve = crypto::generate_keypair().unwrap();

    let ciphertext = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();

    let result = crypto::decrypt(&ciphertext, &alice.public_key, &eve.secret_key);
    assert!(result.is_err());
}

#[test]
fn test_wrong_sender_fails_decryption() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();
    let eve = crypto::generate_keypair().unwrap();

    let ciphertext = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();

    let result = crypto::decrypt(&ciphertext, &eve.public_key, &bob.secret_key);
    assert!(result.is_err());
}

#[test]
fn test_tampered_ciphertext_detection() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let mut ciphertext = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();

    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0xFF;

    let result = crypto::decrypt(&ciphertext, &alice.public_key, &bob.secret_key);
    assert!(result.is_err());
}

#[test]
fn test_tampered_nonce_detection() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let mut ciphertext = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();

    ciphertext[0] ^= 0xFF;

    let result = crypto::decrypt(&ciphertext, &alice.public_key, &bob.secret_key);
    assert!(result.is_err());
}

#[test]
fn test_truncated_ciphertext_rejected() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let ciphertext = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();

    let result = crypto::decrypt(&ciphertext[..10], &alice.public_key, &bob.secret_key);
    assert!(result.is_err());
}

#[test]
fn test_empty_plaintext_encryption() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let ciphertext = crypto::encrypt(b"", &bob.public_key, &alice.secret_key).unwrap();
    let plaintext = crypto::decrypt(&ciphertext, &alice.public_key, &bob.secret_key).unwrap();

    assert_eq!(plaintext, b"");
}

#[test]
fn test_large_message_encryption() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let large_msg = vec![0xABu8; 100_000];

    let ciphertext = crypto::encrypt(&large_msg, &bob.public_key, &alice.secret_key).unwrap();
    let plaintext = crypto::decrypt(&ciphertext, &alice.public_key, &bob.secret_key).unwrap();

    assert_eq!(plaintext, large_msg);
}

// [S8.1] 签名模块测试

#[test]
fn test_sign_and_verify_with_public_key() {
    let alice = crypto::generate_keypair().unwrap();

    let signature = crypto::sign(ALICE_MSG, &alice.ed25519_sk).unwrap();
    let valid = crypto::verify_with_public_key(ALICE_MSG, &signature, &alice.ed25519_pk).unwrap();

    assert!(valid);
}

#[test]
fn test_tampered_message_fails_signature_verification() {
    let alice = crypto::generate_keypair().unwrap();

    let signature = crypto::sign(ALICE_MSG, &alice.ed25519_sk).unwrap();

    let tampered_msg = b"This is NOT the original message";
    let valid =
        crypto::verify_with_public_key(tampered_msg, &signature, &alice.ed25519_pk).unwrap();

    assert!(!valid);
}

#[test]
fn test_tampered_signature_fails_verification() {
    let alice = crypto::generate_keypair().unwrap();

    let mut signature = crypto::sign(ALICE_MSG, &alice.ed25519_sk).unwrap();
    signature[0] ^= 0xFF;

    let valid = crypto::verify_with_public_key(ALICE_MSG, &signature, &alice.ed25519_pk).unwrap();

    assert!(!valid);
}

// [S8.1] 消息序列化测试

#[test]
fn test_message_serialization_roundtrip() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let ciphertext = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();
    let signature = crypto::sign(&ciphertext, &alice.ed25519_sk).unwrap();

    let msg = Message {
        id: "msg-001".to_string(),
        conversation_id: "conv-alice-bob".to_string(),
        sender_id: "alice".to_string(),
        sender_device_id: "device-alice-1".to_string(),
        sender_seq: 1,
        timestamp: 1700000000000,
        message_type: "text".to_string(),
        ciphertext: ciphertext.clone(),
        signature: signature.clone(),
        prev_hash: vec![0u8; 32],
    };

    let json = serde_json::to_string(&msg).unwrap();
    let deserialized: Message = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.id, msg.id);
    assert_eq!(deserialized.conversation_id, msg.conversation_id);
    assert_eq!(deserialized.sender_id, msg.sender_id);
    assert_eq!(deserialized.ciphertext, msg.ciphertext);
    assert_eq!(deserialized.signature, msg.signature);
    assert_eq!(deserialized.prev_hash, msg.prev_hash);

    let decrypted =
        crypto::decrypt(&deserialized.ciphertext, &alice.public_key, &bob.secret_key).unwrap();
    assert_eq!(decrypted, ALICE_MSG);

    let sig_valid = crypto::verify_with_public_key(
        &deserialized.ciphertext,
        &deserialized.signature,
        &alice.ed25519_pk,
    )
    .unwrap();
    assert!(sig_valid);
}

// [S8.2] 集成测试 - 端到端加密流程

#[test]
fn test_end_to_end_encrypted_message_delivery() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let plaintext = b"Top secret: meeting at 3pm";

    let ciphertext = crypto::encrypt(plaintext, &bob.public_key, &alice.secret_key).unwrap();
    let signature = crypto::sign(&ciphertext, &alice.ed25519_sk).unwrap();

    let msg = Message {
        id: "msg-e2e-001".to_string(),
        conversation_id: "conv-e2e".to_string(),
        sender_id: "alice".to_string(),
        sender_device_id: "device-1".to_string(),
        sender_seq: 1,
        timestamp: 1700000000000,
        message_type: "text".to_string(),
        ciphertext,
        signature,
        prev_hash: vec![],
    };

    let serialized = serde_json::to_string(&msg).unwrap();
    let relayed: Message = serde_json::from_str(&serialized).unwrap();

    let sig_valid =
        crypto::verify_with_public_key(&relayed.ciphertext, &relayed.signature, &alice.ed25519_pk)
            .unwrap();
    assert!(
        sig_valid,
        "Signature verification should pass for relayed message"
    );

    let decrypted =
        crypto::decrypt(&relayed.ciphertext, &alice.public_key, &bob.secret_key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_relay_tampering_detected_by_signature() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let ciphertext = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();
    let signature = crypto::sign(&ciphertext, &alice.ed25519_sk).unwrap();

    let mut msg = Message {
        id: "msg-tamper-001".to_string(),
        conversation_id: "conv-tamper".to_string(),
        sender_id: "alice".to_string(),
        sender_device_id: "device-1".to_string(),
        sender_seq: 1,
        timestamp: 1700000000000,
        message_type: "text".to_string(),
        ciphertext,
        signature,
        prev_hash: vec![],
    };

    if let Some(byte) = msg.ciphertext.last_mut() {
        *byte ^= 0x01;
    }

    let serialized = serde_json::to_string(&msg).unwrap();
    let relayed: Message = serde_json::from_str(&serialized).unwrap();

    let sig_valid =
        crypto::verify_with_public_key(&relayed.ciphertext, &relayed.signature, &alice.ed25519_pk)
            .unwrap();
    assert!(
        !sig_valid,
        "Tampered ciphertext should fail signature verification"
    );
}

#[test]
fn test_multiple_messages_in_conversation() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let messages: Vec<&[u8]> = vec![
        b"First message",
        b"Second message",
        b"Third message with special chars: !@#$%^&*()",
    ];

    let mut relayed_messages = Vec::new();

    for (i, plaintext) in messages.iter().enumerate() {
        let ciphertext = crypto::encrypt(plaintext, &bob.public_key, &alice.secret_key).unwrap();
        let signature = crypto::sign(&ciphertext, &alice.ed25519_sk).unwrap();

        let msg = Message {
            id: format!("msg-multi-{}", i),
            conversation_id: "conv-multi".to_string(),
            sender_id: "alice".to_string(),
            sender_device_id: "device-1".to_string(),
            sender_seq: i as i64 + 1,
            timestamp: 1700000000000 + i as i64 * 1000,
            message_type: "text".to_string(),
            ciphertext,
            signature,
            prev_hash: vec![],
        };

        let json = serde_json::to_string(&msg).unwrap();
        relayed_messages.push(json);
    }

    for (i, json) in relayed_messages.iter().enumerate() {
        let msg: Message = serde_json::from_str(json).unwrap();

        let decrypted =
            crypto::decrypt(&msg.ciphertext, &alice.public_key, &bob.secret_key).unwrap();
        assert_eq!(decrypted, messages[i]);

        let sig_valid =
            crypto::verify_with_public_key(&msg.ciphertext, &msg.signature, &alice.ed25519_pk)
                .unwrap();
        assert!(sig_valid);
    }
}

// [S8.3] E2E测试 - 完整消息发送接收流程

#[test]
fn test_complete_message_lifecycle() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let plaintext = b"Complete lifecycle test message";

    let ciphertext = crypto::encrypt(plaintext, &bob.public_key, &alice.secret_key).unwrap();

    let signature = crypto::sign(&ciphertext, &alice.ed25519_sk).unwrap();

    let msg = Message {
        id: "msg-lifecycle-001".to_string(),
        conversation_id: "conv-lifecycle".to_string(),
        sender_id: "alice".to_string(),
        sender_device_id: "device-alice-1".to_string(),
        sender_seq: 1,
        timestamp: 1700000000000,
        message_type: "text".to_string(),
        ciphertext,
        signature,
        prev_hash: vec![0u8; 32],
    };

    let wire_format = serde_json::to_string(&msg).unwrap();

    let received: Message = serde_json::from_str(&wire_format).unwrap();

    assert_eq!(received.id, msg.id);
    assert_eq!(received.sender_id, "alice");

    let sig_valid = crypto::verify_with_public_key(
        &received.ciphertext,
        &received.signature,
        &alice.ed25519_pk,
    )
    .unwrap();
    assert!(sig_valid, "Signature must be valid on receipt");

    let decrypted =
        crypto::decrypt(&received.ciphertext, &alice.public_key, &bob.secret_key).unwrap();
    assert_eq!(decrypted, plaintext);

    let ack_json = serde_json::json!({
        "type": "ack",
        "message_id": received.id
    });
    assert_eq!(ack_json["message_id"], "msg-lifecycle-001");
}

#[test]
fn test_concurrent_encryption_independence() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();
    let charlie = crypto::generate_keypair().unwrap();

    let ct_bob = crypto::encrypt(b"msg for bob", &bob.public_key, &alice.secret_key).unwrap();
    let ct_charlie =
        crypto::encrypt(b"msg for charlie", &charlie.public_key, &alice.secret_key).unwrap();

    let pt_bob = crypto::decrypt(&ct_bob, &alice.public_key, &bob.secret_key).unwrap();
    let pt_charlie = crypto::decrypt(&ct_charlie, &alice.public_key, &charlie.secret_key).unwrap();

    assert_eq!(pt_bob, b"msg for bob");
    assert_eq!(pt_charlie, b"msg for charlie");

    let cross_result = crypto::decrypt(&ct_bob, &alice.public_key, &charlie.secret_key);
    assert!(
        cross_result.is_err(),
        "Charlie should not decrypt Bob's message"
    );
}

#[test]
fn test_key_uniqueness() {
    let kp1 = crypto::generate_keypair().unwrap();
    let kp2 = crypto::generate_keypair().unwrap();

    assert_ne!(kp1.public_key, kp2.public_key);
    assert_ne!(kp1.secret_key, kp2.secret_key);
    assert_ne!(kp1.ed25519_pk, kp2.ed25519_pk);
    assert_ne!(kp1.ed25519_sk, kp2.ed25519_sk);
}

#[test]
fn test_encrypted_ciphertext_is_not_plaintext() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let ciphertext = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();

    assert!(ciphertext.len() > ALICE_MSG.len());
    assert!(!ciphertext.windows(ALICE_MSG.len()).any(|w| w == ALICE_MSG));
}

#[test]
fn test_same_plaintext_different_ciphertext() {
    let alice = crypto::generate_keypair().unwrap();
    let bob = crypto::generate_keypair().unwrap();

    let ct1 = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();
    let ct2 = crypto::encrypt(ALICE_MSG, &bob.public_key, &alice.secret_key).unwrap();

    assert_ne!(
        ct1, ct2,
        "Same plaintext should produce different ciphertexts due to random nonces"
    );

    let pt1 = crypto::decrypt(&ct1, &alice.public_key, &bob.secret_key).unwrap();
    let pt2 = crypto::decrypt(&ct2, &alice.public_key, &bob.secret_key).unwrap();
    assert_eq!(pt1, pt2);
    assert_eq!(pt1, ALICE_MSG);
}
