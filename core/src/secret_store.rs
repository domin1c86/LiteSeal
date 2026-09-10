pub trait SecretStore {
    fn save(&self, bytes: &[u8]) -> Result<(), String>;
    fn load(&self) -> Result<Vec<u8>, String>;
    fn clear(&self) -> Result<(), String>;
}

/// Protect local draft/message bytes without writing a separate file.
pub fn protect_local(bytes: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        WindowsDpapiSecretStore::protect(bytes)
    }
    #[cfg(not(windows))]
    {
        let _ = bytes;
        Err("Local payload protection is unavailable on this platform".into())
    }
}

pub fn unprotect_local(bytes: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        WindowsDpapiSecretStore::unprotect(bytes)
    }
    #[cfg(not(windows))]
    {
        let _ = bytes;
        Err("Local payload protection is unavailable on this platform".into())
    }
}

pub fn secret_store(path: std::path::PathBuf) -> Box<dyn SecretStore + Send + Sync> {
    #[cfg(windows)]
    {
        Box::new(WindowsDpapiSecretStore { path })
    }
    #[cfg(not(windows))]
    {
        Box::new(UnsupportedSecretStore { path })
    }
}

#[cfg(windows)]
pub struct WindowsDpapiSecretStore {
    path: std::path::PathBuf,
}

#[cfg(windows)]
impl WindowsDpapiSecretStore {
    fn protect(bytes: &[u8]) -> Result<Vec<u8>, String> {
        use std::ptr::null_mut;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{
            CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        };

        let input = CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };

        let ok = unsafe {
            CryptProtectData(
                &input,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err("DPAPI encryption failed".to_string());
        }
        let encrypted =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            LocalFree(output.pbData as _);
        }
        Ok(encrypted)
    }

    fn unprotect(bytes: &[u8]) -> Result<Vec<u8>, String> {
        use std::ptr::null_mut;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        };

        let input = CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };

        let ok = unsafe {
            CryptUnprotectData(
                &input,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err("DPAPI decryption failed".to_string());
        }
        let decrypted =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            LocalFree(output.pbData as _);
        }
        Ok(decrypted)
    }
}

#[cfg(windows)]
impl SecretStore for WindowsDpapiSecretStore {
    fn save(&self, bytes: &[u8]) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let encrypted = Self::protect(bytes)?;
        std::fs::write(&self.path, encrypted).map_err(|e| e.to_string())
    }

    fn load(&self) -> Result<Vec<u8>, String> {
        let encrypted = std::fs::read(&self.path).map_err(|e| e.to_string())?;
        Self::unprotect(&encrypted)
    }

    fn clear(&self) -> Result<(), String> {
        if self.path.exists() {
            std::fs::remove_file(&self.path).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

#[cfg(not(windows))]
pub struct UnsupportedSecretStore {
    path: std::path::PathBuf,
}

#[cfg(not(windows))]
impl SecretStore for UnsupportedSecretStore {
    fn save(&self, _bytes: &[u8]) -> Result<(), String> {
        Err(format!(
            "Secret store is not implemented for this platform: {}",
            self.path.display()
        ))
    }

    fn load(&self) -> Result<Vec<u8>, String> {
        Err(format!(
            "Secret store is not implemented for this platform: {}",
            self.path.display()
        ))
    }

    fn clear(&self) -> Result<(), String> {
        Ok(())
    }
}

pub struct IosKeychainSecretStore;
pub struct AndroidKeystoreSecretStore;
pub struct MacKeychainSecretStore;
