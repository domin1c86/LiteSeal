use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    #[error("Failed to initialize libsodium")]
    InitError,
    #[error("Encryption failed")]
    EncryptionError,
    #[error("Decryption failed")]
    DecryptionError,
    #[error("Signing failed")]
    SigningError,
    #[error("Verification failed")]
    VerificationError,
}

pub struct KeyPair {
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
    pub ed25519_pk: [u8; 32],
    pub ed25519_sk: [u8; 64],
}

static INIT: std::sync::OnceLock<Result<(), CryptoError>> = std::sync::OnceLock::new();

fn init_sodium() -> Result<(), CryptoError> {
    INIT.get_or_init(|| {
        unsafe {
            let ret = libsodium_sys::sodium_init();
            if ret < 0 {
                return Err(CryptoError::InitError);
            }
        }
        Ok(())
    })
    .clone()
}

pub fn generate_keypair() -> Result<KeyPair, CryptoError> {
    init_sodium()?;

    let mut pk = [0u8; 32];
    let mut sk = [0u8; 32];

    unsafe {
        let result = libsodium_sys::crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        if result != 0 {
            return Err(CryptoError::InitError);
        }
    }

    // The signing keypair is independent of the encryption keypair: never
    // reuse one secret across primitives.
    let mut ed_pk = [0u8; 32];
    let mut ed_sk = [0u8; 64];

    unsafe {
        let result = libsodium_sys::crypto_sign_keypair(ed_pk.as_mut_ptr(), ed_sk.as_mut_ptr());
        if result != 0 {
            return Err(CryptoError::InitError);
        }
    }

    Ok(KeyPair {
        public_key: pk,
        secret_key: sk,
        ed25519_pk: ed_pk,
        ed25519_sk: ed_sk,
    })
}

pub fn encrypt(
    plaintext: &[u8],
    recipient_pk: &[u8; 32],
    sender_sk: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    init_sodium()?;

    let nonce = generate_nonce()?;
    let mut ciphertext = vec![0u8; plaintext.len() + libsodium_sys::crypto_box_MACBYTES as usize];

    unsafe {
        let result = libsodium_sys::crypto_box_easy(
            ciphertext.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len() as u64,
            nonce.as_ptr(),
            recipient_pk.as_ptr(),
            sender_sk.as_ptr(),
        );
        if result != 0 {
            return Err(CryptoError::EncryptionError);
        }
    }

    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt(
    ciphertext: &[u8],
    sender_pk: &[u8; 32],
    recipient_sk: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    init_sodium()?;

    if ciphertext.len() < 24 {
        return Err(CryptoError::DecryptionError);
    }

    let nonce = &ciphertext[..24];
    let encrypted = &ciphertext[24..];

    if encrypted.len() < libsodium_sys::crypto_box_MACBYTES as usize {
        return Err(CryptoError::DecryptionError);
    }

    let mut plaintext = vec![0u8; encrypted.len() - libsodium_sys::crypto_box_MACBYTES as usize];

    unsafe {
        let result = libsodium_sys::crypto_box_open_easy(
            plaintext.as_mut_ptr(),
            encrypted.as_ptr(),
            encrypted.len() as u64,
            nonce.as_ptr(),
            sender_pk.as_ptr(),
            recipient_sk.as_ptr(),
        );
        if result != 0 {
            return Err(CryptoError::DecryptionError);
        }
    }

    Ok(plaintext)
}

pub fn sign(message: &[u8], ed25519_sk: &[u8; 64]) -> Result<Vec<u8>, CryptoError> {
    init_sodium()?;

    let mut signature = [0u8; 64];

    unsafe {
        let result = libsodium_sys::crypto_sign_detached(
            signature.as_mut_ptr(),
            std::ptr::null_mut(),
            message.as_ptr(),
            message.len() as u64,
            ed25519_sk.as_ptr(),
        );
        if result != 0 {
            return Err(CryptoError::SigningError);
        }
    }

    Ok(signature.to_vec())
}

pub fn verify_with_public_key(
    message: &[u8],
    signature: &[u8],
    ed25519_pk: &[u8; 32],
) -> Result<bool, CryptoError> {
    init_sodium()?;

    // libsodium's detached verification API receives a raw signature pointer
    // and assumes it addresses exactly crypto_sign_BYTES bytes. Rejecting any
    // other length here prevents an out-of-bounds read for malformed input.
    if signature.len() != libsodium_sys::crypto_sign_BYTES as usize {
        return Ok(false);
    }

    unsafe {
        let result = libsodium_sys::crypto_sign_verify_detached(
            signature.as_ptr(),
            message.as_ptr(),
            message.len() as u64,
            ed25519_pk.as_ptr(),
        );
        Ok(result == 0)
    }
}

fn generate_nonce() -> Result<[u8; 24], CryptoError> {
    let mut nonce = [0u8; 24];
    unsafe {
        libsodium_sys::randombytes_buf(nonce.as_mut_ptr() as *mut std::ffi::c_void, 24);
    }
    Ok(nonce)
}
