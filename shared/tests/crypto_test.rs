#[test]
fn test_keypair_generation() {
    let keypair = liteseal_shared::crypto::generate_keypair().unwrap();
    assert_eq!(keypair.public_key.len(), 32);
    assert_eq!(keypair.secret_key.len(), 32);
    assert_eq!(keypair.ed25519_pk.len(), 32);
    assert_eq!(keypair.ed25519_sk.len(), 64);
    // Signing keys must not be derived from the encryption secret.
    assert_ne!(&keypair.ed25519_sk[..32], &keypair.secret_key[..]);
}

#[test]
fn test_encrypt_decrypt() {
    let sender = liteseal_shared::crypto::generate_keypair().unwrap();
    let receiver = liteseal_shared::crypto::generate_keypair().unwrap();

    let plaintext = b"Hello, LiteSeal!";
    let ciphertext =
        liteseal_shared::crypto::encrypt(plaintext, &receiver.public_key, &sender.secret_key)
            .unwrap();

    let decrypted =
        liteseal_shared::crypto::decrypt(&ciphertext, &sender.public_key, &receiver.secret_key)
            .unwrap();

    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_sign_verify_with_public_key() {
    let keypair = liteseal_shared::crypto::generate_keypair().unwrap();
    let message = b"Test message";

    let signature = liteseal_shared::crypto::sign(message, &keypair.ed25519_sk).unwrap();
    let valid =
        liteseal_shared::crypto::verify_with_public_key(message, &signature, &keypair.ed25519_pk)
            .unwrap();

    assert!(valid);
}

#[test]
fn malformed_signature_lengths_are_rejected_safely() {
    let keypair = liteseal_shared::crypto::generate_keypair().unwrap();
    let message = b"length checked";

    assert!(!liteseal_shared::crypto::verify_with_public_key(
        message,
        &[0_u8; 63],
        &keypair.ed25519_pk,
    )
    .unwrap());
    assert!(!liteseal_shared::crypto::verify_with_public_key(
        message,
        &[0_u8; 65],
        &keypair.ed25519_pk,
    )
    .unwrap());
}
