//! Private native-store lifetime. Production targets persist after profile
//! deletion; explicit isolated tests clean only targets they created/registered.
use super::Witness;
#[cfg(windows)]
use std::{collections::HashMap, path::PathBuf, sync::Mutex};
use std::{path::Path, sync::Arc};
#[derive(Clone)]
pub struct Protection(Arc<Inner>);
struct Inner {
    namespace: Option<uuid::Uuid>,
    cleanup_on_drop: bool,
    #[cfg(windows)]
    stores: Mutex<HashMap<PathBuf, Arc<super::windows::WindowsStore>>>,
}
impl Default for Protection {
    fn default() -> Self {
        Self::create(None, false)
    }
}
impl Protection {
    fn create(namespace: Option<uuid::Uuid>, cleanup_on_drop: bool) -> Self {
        Self(Arc::new(Inner {
            namespace,
            cleanup_on_drop,
            #[cfg(windows)]
            stores: Mutex::new(HashMap::new()),
        }))
    }
    /// Share this value across all synthetic in-process reopenings. Final drop
    /// cleans only exact native targets and does not remove any filesystem data.
    pub fn isolated_test() -> Self {
        Self::create(Some(uuid::Uuid::new_v4()), true)
    }
    /// Sidecar short tests reuse an explicit namespace across process restarts.
    /// They must perform explicit cleanup after all test processes have stopped.
    pub fn isolated_process(namespace: uuid::Uuid) -> Self {
        Self::create(Some(namespace), false)
    }
    pub fn is_isolated(&self) -> bool {
        self.0.namespace.is_some()
    }
    pub fn witness(&self, database: &Path) -> Result<Witness, String> {
        #[cfg(windows)]
        {
            let mut stores = self.0.stores.lock().map_err(|_| "设备安全存储锁不可用")?;
            let store = match stores.get(database) {
                Some(store) => store.clone(),
                None => {
                    let store = Arc::new(match self.0.namespace {
                        Some(namespace) => {
                            super::windows::WindowsStore::isolated(database, namespace)?
                        }
                        None => super::windows::WindowsStore::open(database)?,
                    });
                    stores.insert(database.to_path_buf(), store.clone());
                    store
                }
            };
            Ok(Witness::new(database, store))
        }
        #[cfg(not(windows))]
        {
            let _ = database;
            Err("此平台不支持设备外部安全存储".into())
        }
    }
    /// Call after all task handles close and profile files were removed. Keep
    /// production heads so restoring older active task files cannot revive them.
    pub fn release_database(&self, database: &Path) -> Result<(), String> {
        #[cfg(windows)]
        {
            let mut stores = self.0.stores.lock().map_err(|_| "设备安全存储锁不可用")?;
            if let Some(store) = stores.get(database) {
                if self.is_isolated() {
                    store.clear_isolated()?;
                }
            }
            stores.remove(database);
        }
        #[cfg(not(windows))]
        {
            let _ = database;
        }
        Ok(())
    }
    pub fn clear_isolated(&self) -> Result<(), String> {
        if !self.is_isolated() {
            return Err("生产高水位不能清理或重置".into());
        }
        #[cfg(windows)]
        {
            let mut stores = self.0.stores.lock().map_err(|_| "设备安全存储锁不可用")?;
            for store in stores.values() {
                store.clear_isolated()?;
            }
            stores.clear();
        }
        Ok(())
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        if self.cleanup_on_drop && self.namespace.is_some() {
            #[cfg(windows)]
            if let Ok(stores) = self.stores.get_mut() {
                for store in stores.values() {
                    let _ = store.clear_isolated();
                }
            }
        }
    }
}
