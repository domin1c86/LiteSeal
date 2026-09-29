//! Versioned password-protected file streams. No chat wire protocol changes.
use libsodium_sys as s;
use std::io::{Read, Write};

pub const CHUNK: usize = 1024 * 1024;
const MAGIC: &[u8; 8] = b"LSEALB01";
const OPS: u64 = 3;
const MEM: usize = 256 * 1024 * 1024;
const HEADER_LEN: usize = 8 + 8 + 8 + 16 + 24;
type Result<T> = std::result::Result<T, String>;
fn invalid() -> String {
    "备份口令错误或文件损坏".into()
}
fn io(_: std::io::Error) -> String {
    "备份文件读写失败，请检查权限与空间".into()
}

struct Secret([u8; 32]);
impl Drop for Secret {
    fn drop(&mut self) {
        unsafe { s::sodium_memzero(self.0.as_mut_ptr().cast(), self.0.len()) }
    }
}
struct State(s::crypto_secretstream_xchacha20poly1305_state);
impl State {
    fn new() -> Self {
        Self(unsafe { std::mem::zeroed() })
    }
}
impl Drop for State {
    fn drop(&mut self) {
        unsafe {
            s::sodium_memzero(
                (&mut self.0 as *mut s::crypto_secretstream_xchacha20poly1305_state).cast(),
                std::mem::size_of_val(&self.0),
            )
        }
    }
}
fn derive(password: &[u8], salt: &[u8]) -> Result<Secret> {
    if password.len() < 12 || password.len() > 1024 || salt.len() != 16 {
        return Err("备份口令须为 12–1024 字节".into());
    }
    let mut key = Secret([0; 32]);
    if unsafe { s::sodium_init() } < 0 {
        return Err("无法初始化备份加密".into());
    }
    if unsafe {
        s::crypto_pwhash(
            key.0.as_mut_ptr(),
            32,
            password.as_ptr().cast(),
            password.len() as u64,
            salt.as_ptr(),
            OPS,
            MEM,
            s::crypto_pwhash_ALG_ARGON2ID13 as i32,
        )
    } != 0
    {
        return Err("备份密钥派生失败，需要 256 MiB 可用内存".into());
    }
    Ok(key)
}

pub struct Encryptor<W: Write> {
    writer: W,
    state: State,
    header: [u8; HEADER_LEN],
}
impl<W: Write> Encryptor<W> {
    pub fn new(mut writer: W, password: &[u8]) -> Result<Self> {
        let mut header = [0; HEADER_LEN];
        header[..8].copy_from_slice(MAGIC);
        header[8..16].copy_from_slice(&OPS.to_le_bytes());
        header[16..24].copy_from_slice(&(MEM as u64).to_le_bytes());
        if unsafe { s::sodium_init() } < 0 {
            return Err(invalid());
        }
        unsafe { s::randombytes_buf(header[24..40].as_mut_ptr().cast(), 16) };
        let key = derive(password, &header[24..40])?;
        let mut state = State::new();
        if unsafe {
            s::crypto_secretstream_xchacha20poly1305_init_push(
                &mut state.0,
                header[40..].as_mut_ptr(),
                key.0.as_ptr(),
            )
        } != 0
        {
            return Err(invalid());
        }
        writer.write_all(&header).map_err(io)?;
        Ok(Self {
            writer,
            state,
            header,
        })
    }
    pub fn push(&mut self, bytes: &[u8], final_chunk: bool) -> Result<()> {
        if bytes.len() > CHUNK {
            return Err("备份块过大".into());
        }
        let mut cipher = vec![0; bytes.len() + 17];
        if unsafe {
            s::crypto_secretstream_xchacha20poly1305_push(
                &mut self.state.0,
                cipher.as_mut_ptr(),
                std::ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len() as u64,
                self.header.as_ptr(),
                self.header.len() as u64,
                if final_chunk {
                    s::crypto_secretstream_xchacha20poly1305_TAG_FINAL
                } else {
                    s::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
                } as u8,
            )
        } != 0
        {
            return Err(invalid());
        }
        self.writer
            .write_all(&(cipher.len() as u32).to_le_bytes())
            .map_err(io)?;
        self.writer.write_all(&cipher).map_err(io)
    }
}

pub struct Decryptor<R: Read> {
    reader: R,
    state: State,
    header: [u8; HEADER_LEN],
    ended: bool,
}
impl<R: Read> Decryptor<R> {
    pub fn new(mut reader: R, password: &[u8]) -> Result<Self> {
        let mut header = [0; HEADER_LEN];
        reader.read_exact(&mut header).map_err(|_| invalid())?;
        // Bound unauthenticated parameters before allocating KDF memory.
        if &header[..8] != MAGIC
            || header[8..16] != OPS.to_le_bytes()
            || header[16..24] != (MEM as u64).to_le_bytes()
        {
            return Err("不支持的备份版本或加密参数".into());
        }
        let key = derive(password, &header[24..40])?;
        let mut state = State::new();
        if unsafe {
            s::crypto_secretstream_xchacha20poly1305_init_pull(
                &mut state.0,
                header[40..].as_ptr(),
                key.0.as_ptr(),
            )
        } != 0
        {
            return Err(invalid());
        }
        Ok(Self {
            reader,
            state,
            header,
            ended: false,
        })
    }
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        if self.ended {
            return Ok(None);
        }
        let mut length = [0; 4];
        self.reader.read_exact(&mut length).map_err(|_| invalid())?;
        let length = u32::from_le_bytes(length) as usize;
        if !(17..=CHUNK + 17).contains(&length) {
            return Err(invalid());
        }
        let mut cipher = vec![0; length];
        self.reader.read_exact(&mut cipher).map_err(|_| invalid())?;
        let mut plain = vec![0; length - 17];
        let mut tag = 0;
        if unsafe {
            s::crypto_secretstream_xchacha20poly1305_pull(
                &mut self.state.0,
                plain.as_mut_ptr(),
                std::ptr::null_mut(),
                &mut tag,
                cipher.as_ptr(),
                length as u64,
                self.header.as_ptr(),
                self.header.len() as u64,
            )
        } != 0
        {
            return Err(invalid());
        }
        if tag == s::crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8 {
            let mut extra = [0];
            if self.reader.read(&mut extra).map_err(io)? != 0 {
                return Err(invalid());
            }
            self.ended = true;
        } else if tag != s::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8 {
            return Err(invalid());
        }
        Ok(Some(plain))
    }
    pub fn ended(&self) -> bool {
        self.ended
    }
}

/// Check both private/public pairs without exporting the private material.
pub fn validate_identity(pk: &[u8], sk: &[u8], signing_pk: &[u8], signing_sk: &[u8]) -> Result<()> {
    if pk.len() != 32 || sk.len() != 32 || signing_pk.len() != 32 || signing_sk.len() != 64 {
        return Err("备份身份密钥长度无效".into());
    }
    if unsafe { s::sodium_init() } < 0 {
        return Err(invalid());
    }
    let mut derived = [0; 32];
    let mut ed_pk = [0; 32];
    let mut ed_sk = [0; 64];
    let good = unsafe {
        s::crypto_scalarmult_base(derived.as_mut_ptr(), sk.as_ptr()) == 0
            && s::crypto_sign_seed_keypair(
                ed_pk.as_mut_ptr(),
                ed_sk.as_mut_ptr(),
                signing_sk.as_ptr(),
            ) == 0
            && s::sodium_memcmp(derived.as_ptr().cast(), pk.as_ptr().cast(), 32) == 0
            && s::sodium_memcmp(ed_pk.as_ptr().cast(), signing_pk.as_ptr().cast(), 32) == 0
            && s::sodium_memcmp(ed_sk.as_ptr().cast(), signing_sk.as_ptr().cast(), 64) == 0
    };
    unsafe { s::sodium_memzero(ed_sk.as_mut_ptr().cast(), 64) };
    if !good {
        return Err("备份公私钥不匹配".into());
    }
    Ok(())
}
