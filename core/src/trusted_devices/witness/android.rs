//! External Android Keystore ledger. Public witness records live in generational
//! key aliases, outside restorable SQLite/app files; no JS API or reset fallback.
use super::{SecureCell, SecureStore};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};
pub struct AndroidStore {
    binding: [u8; 32],
    lock_path: PathBuf,
}
fn bad() -> String {
    "Android 外部高水位不可用，未重置原状态".into()
}
impl AndroidStore {
    pub fn open(database: &Path, namespace: Option<uuid::Uuid>) -> Result<Self, String> {
        let absolute = std::fs::canonicalize(database).map_err(|_| bad())?;
        let mut hash = Sha256::new();
        hash.update(b"LiteSeal/android-witness/v1\0");
        hash.update(absolute.to_str().ok_or_else(bad)?.as_bytes());
        if let Some(namespace) = namespace {
            hash.update(namespace.as_bytes());
        }
        Ok(Self {
            binding: hash.finalize().into(),
            lock_path: absolute.with_extension("native-witness.lock"),
        })
    }
}
struct Cell<'a> {
    store: &'a AndroidStore,
    _lock: File,
}
impl SecureStore for AndroidStore {
    fn binding(&self) -> [u8; 32] {
        self.binding
    }
    fn lock(&self) -> Result<Box<dyn SecureCell + '_>, String> {
        if self.lock_path.exists()
            && !std::fs::symlink_metadata(&self.lock_path)
                .map_err(|_| bad())?
                .is_file()
        {
            return Err(bad());
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .map_err(|_| bad())?;
        file.lock().map_err(|_| bad())?;
        Ok(Box::new(Cell {
            store: self,
            _lock: file,
        }))
    }
}
impl SecureCell for Cell<'_> {
    fn read(&mut self) -> Result<Option<Vec<u8>>, String> {
        let bytes = crate::android_secret_store::native(5, &self.store.binding)?;
        if bytes.len() > 4096 {
            return Err(bad());
        }
        Ok((!bytes.is_empty()).then_some(bytes))
    }
    fn write(&mut self, value: &[u8]) -> Result<(), String> {
        if value.is_empty() || value.len() > 4096 {
            return Err(bad());
        }
        let mut bytes = Vec::with_capacity(32 + value.len());
        bytes.extend_from_slice(&self.store.binding);
        bytes.extend_from_slice(value);
        crate::android_secret_store::native(6, &bytes).map(|_| ())
    }
}
