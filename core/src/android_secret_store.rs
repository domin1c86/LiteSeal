//! Android-only native adapter. The function pointer is installed by JNI before
//! UniFFI; it is never part of the JS API. No private bytes traverse JSI.
use crate::secret_store::SecretStore;
use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::OnceLock,
};
use zeroize::Zeroizing;
const MAX_BYTES: usize = 8 * 1024 * 1024;
type Provider = unsafe extern "C" fn(u32, *const u8, usize, *mut u8, usize, *mut usize) -> i32;
static PROVIDER: OnceLock<Provider> = OnceLock::new();
/// # Safety
/// JNI must install a process-lifetime native function which obeys the bounded
/// input/output contract. The shell must not expose this symbol to JavaScript.
#[no_mangle]
pub unsafe extern "C" fn liteseal_install_android_secret_provider(
    provider: Option<Provider>,
) -> i32 {
    match provider {
        Some(provider) if PROVIDER.set(provider).is_ok() => 0,
        _ => -1,
    }
}
fn bad() -> String {
    "Android 原生密钥保护不可用；未降级为明文存储".into()
}
pub(crate) fn native(operation: u32, input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() > MAX_BYTES + if operation == 2 { 34 } else { 0 } {
        return Err(bad());
    }
    let provider = PROVIDER.get().ok_or_else(bad)?;
    let capacity = if matches!(operation, 3..=7) {
        64 * 1024
    } else {
        input.len() + 64
    };
    let mut output = Zeroizing::new(vec![0; capacity]);
    let mut length = 0;
    let code = unsafe {
        provider(
            operation,
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut length,
        )
    };
    if code != 0 || length > output.len() {
        return Err(bad());
    }
    Ok(output[..length].to_vec())
}
pub(crate) fn protect(bytes: &[u8]) -> Result<Vec<u8>, String> {
    native(1, bytes)
}
pub(crate) fn unprotect(bytes: &[u8]) -> Result<Vec<u8>, String> {
    native(2, bytes)
}
pub struct AndroidSecretStore {
    pub(crate) path: PathBuf,
}
impl SecretStore for AndroidSecretStore {
    fn save(&self, bytes: &[u8]) -> Result<(), String> {
        let encrypted = protect(bytes)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| bad())?;
        }
        if self.path.exists()
            && !std::fs::symlink_metadata(&self.path)
                .map_err(|_| bad())?
                .file_type()
                .is_file()
        {
            return Err(bad());
        }
        let temporary = self
            .path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|_| bad())?;
            file.write_all(&encrypted).map_err(|_| bad())?;
            file.sync_all().map_err(|_| bad())?;
            drop(file);
            std::fs::rename(&temporary, &self.path).map_err(|_| bad())?;
            if let Some(parent) = self.path.parent() {
                std::fs::File::open(parent)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| bad())?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
    fn load(&self) -> Result<Vec<u8>, String> {
        let metadata = std::fs::symlink_metadata(&self.path).map_err(|_| bad())?;
        if !metadata.file_type().is_file() || metadata.len() > (MAX_BYTES + 64) as u64 {
            return Err(bad());
        }
        let mut encrypted = Vec::new();
        std::fs::File::open(&self.path)
            .map_err(|_| bad())?
            .take((MAX_BYTES + 65) as u64)
            .read_to_end(&mut encrypted)
            .map_err(|_| bad())?;
        if encrypted.len() > MAX_BYTES + 64 {
            return Err(bad());
        }
        unprotect(&encrypted)
    }
    fn clear(&self) -> Result<(), String> {
        if self.path.exists() {
            if !std::fs::symlink_metadata(&self.path)
                .map_err(|_| bad())?
                .file_type()
                .is_file()
            {
                return Err(bad());
            }
            std::fs::remove_file(&self.path).map_err(|_| bad())?;
        }
        Ok(())
    }
}
