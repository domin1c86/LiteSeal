#[test]
fn test_keypair_generation() {
    let keypair = liteseal_shared::crypto::generate_keypair().unwrap();
    assert_eq!(keypair.public_key.len(), 32);
    assert_eq!(keypair.secret_key.len(), 32);
}

#[test]
fn test_encrypt_decrypt() {
    let sender = liteseal_shared::crypto::generate_keypair().unwrap();
    let receiver = liteseal_shared::crypto::generate_keypair().unwrap();

    let plaintext = b"Hello, LiteSeal!";
    let ciphertext = liteseal_shared::crypto::encrypt(
        plaintext,
        &receiver.public_key,
        &sender.secret_key,
    )
    .unwrap();

    let decrypted = liteseal_shared::crypto::decrypt(
        &ciphertext,
        &sender.public_key,
        &receiver.secret_key,
    )
    .unwrap();

    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_sign_verify() {
    let keypair = liteseal_shared::crypto::generate_keypair().unwrap();
    let message = b"Test message";

    let signature = liteseal_shared::crypto::sign(message, &keypair.secret_key).unwrap();
    let valid =
        liteseal_shared::crypto::verify(message, &signature, &keypair.secret_key).unwrap();

    assert!(valid);
}
