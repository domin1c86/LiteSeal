//! Isolated joining identities. Nothing here replaces the normal keystore.
//! Private records have no public Serialize/Debug implementation; only views leave Rust.
use crate::{backup, keystore::KeystoreData, secret_store};
use liteseal_shared::{crypto, trusted_device::canonical_origin};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_PROFILES: usize = 8;
const MAX_KEYFILE: u64 = 32768;
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    domain: String,
    version: u8,
    id: String,
    task_id: String,
    username: String,
    name: String,
    identity: KeystoreData,
}
pub struct JoinProfile {
    record: Record,
}
#[derive(Debug, Serialize)]
pub struct ProfileView {
    pub id: String,
    pub origin: String,
    pub username: String,
    pub device_name: String,
    pub local_device_id: String,
    pub encryption_fingerprint: String,
    pub signing_fingerprint: String,
}
#[derive(Debug, Serialize)]
pub struct ProfileListing {
    pub id: String,
    pub profile: Option<ProfileView>,
    pub error: Option<String>,
}
fn invalid() -> String {
    "加入设备档案不可用、身份不匹配或文件损坏".into()
}
fn io(_: std::io::Error) -> String {
    "加入设备档案存储不可用".into()
}
fn identifier(id: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(id)
        .ok()
        .is_none_or(|v| v.to_string() != id)
    {
        return Err(invalid());
    }
    Ok(())
}
fn plain_path(path: &Path, directory: bool) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(io)?;
    if meta.file_type().is_symlink() || meta.is_dir() != directory {
        return Err(invalid());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
    }
    Ok(())
}
impl JoinProfile {
    pub fn task_id(&self) -> &str {
        &self.record.task_id
    }
    pub fn view(&self) -> ProfileView {
        ProfileView {
            id: self.record.id.clone(),
            origin: self.record.identity.server_url.clone(),
            username: self.record.username.clone(),
            device_name: self.record.name.clone(),
            local_device_id: self.record.identity.device_id.clone(),
            encryption_fingerprint: hex::encode(Sha256::digest(&self.record.identity.public_key)),
            signing_fingerprint: hex::encode(Sha256::digest(&self.record.identity.ed25519_pk)),
        }
    }
    pub fn keys(&self) -> Result<crypto::KeyPair, String> {
        backup::identity_keys(&self.record.identity).map_err(|_| invalid())
    }
    pub fn owner(&self) -> Result<super::tasks::TaskOwner, String> {
        super::tasks::TaskOwner::for_join(
            &self.record.identity.server_url,
            &self.record.username,
            &self.record.identity.device_id,
            &self.keys()?,
        )
    }
    fn validate(&self, expected: &str) -> Result<(), String> {
        let r = &self.record;
        identifier(expected)?;
        identifier(&r.task_id)?;
        if r.domain != "LiteSeal/join-profile/v1"
            || r.version != 1
            || r.id != expected
            || r.identity.user_id != format!("join:{}", r.username)
            || !r.identity.token.is_empty()
            || !r.identity.refresh_token.is_empty()
            || r.username != r.username.trim()
            || r.username.is_empty()
            || r.username.len() > 128
            || r.username.chars().any(char::is_control)
            || r.name != r.name.trim()
            || r.name.is_empty()
            || r.name.chars().count() > 80
            || r.name.chars().any(char::is_control)
            || canonical_origin(&r.identity.server_url).map_err(|_| invalid())?
                != r.identity.server_url
        {
            return Err(invalid());
        }
        self.owner()?;
        Ok(())
    }
}
pub struct JoinProfileStore {
    root: PathBuf,
}
impl JoinProfileStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
    fn ids(&self) -> Result<Vec<String>, String> {
        if !self.root.exists() {
            return Ok(vec![]);
        }
        plain_path(&self.root, true)?;
        let mut ids = vec![];
        for entry in fs::read_dir(&self.root).map_err(io)? {
            let name = entry.map_err(io)?.file_name();
            if let Some(id) = name.to_str().filter(|id| identifier(id).is_ok()) {
                ids.push(id.to_string());
            }
            if ids.len() > MAX_PROFILES {
                return Err("加入设备档案数量超过上限".into());
            }
        }
        ids.sort();
        Ok(ids)
    }
    fn directory(&self, id: &str) -> Result<PathBuf, String> {
        identifier(id)?;
        plain_path(&self.root, true)?;
        let directory = self.root.join(id);
        plain_path(&directory, true)?;
        Ok(directory)
    }
    pub fn database(&self, id: &str) -> Result<PathBuf, String> {
        self.bound_database(id, false)
    }
    fn bound_database(&self, id: &str, initialize: bool) -> Result<PathBuf, String> {
        let profile = self.load(id)?;
        let path = self.directory(id)?.join("tasks.db");
        let existing = path.exists();
        if existing == initialize {
            return Err("加入档案的任务数据库缺失或已存在，未重新生成申请".into());
        }
        if existing {
            plain_path(&path, false)?;
        }
        let digest = Sha256::digest(
            serde_json::to_vec(&(profile.view(), profile.task_id())).map_err(|_| invalid())?,
        )
        .to_vec();
        let mut conn = if initialize {
            rusqlite::Connection::open(&path)
        } else {
            rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        }
        .map_err(|_| io_error())?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|_| io_error())?;
        if existing {
            let saved: Vec<u8> = conn
                .query_row(
                    "SELECT digest FROM join_identity_binding WHERE id=1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| invalid())?;
            if saved != digest {
                return Err(invalid());
            }
        } else {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|_| io_error())?;
            tx.execute_batch("CREATE TABLE join_identity_binding (id INTEGER PRIMARY KEY CHECK(id=1),digest BLOB NOT NULL CHECK(length(digest)=32))").map_err(|_|io_error())?;
            tx.execute(
                "INSERT INTO join_identity_binding(id,digest) VALUES(1,?1)",
                [digest],
            )
            .map_err(|_| io_error())?;
            tx.commit().map_err(|_| io_error())?;
        }
        Ok(path)
    }
    pub fn load(&self, id: &str) -> Result<JoinProfile, String> {
        let path = self.directory(id)?.join("identity.bin");
        plain_path(&path, false)?;
        let mut encrypted = vec![];
        fs::File::open(path)
            .map_err(io)?
            .take(MAX_KEYFILE + 1)
            .read_to_end(&mut encrypted)
            .map_err(io)?;
        if encrypted.len() as u64 > MAX_KEYFILE {
            return Err(invalid());
        }
        let mut plain = secret_store::unprotect_local(&encrypted).map_err(|_| invalid())?;
        let record = serde_json::from_slice::<Record>(&plain).map_err(|_| invalid());
        plain.zeroize();
        let profile = JoinProfile { record: record? };
        profile.validate(id)?;
        Ok(profile)
    }
    pub fn list(&self) -> Result<Vec<ProfileListing>, String> {
        Ok(self
            .ids()?
            .into_iter()
            .map(|id| match self.load(&id) {
                Ok(profile) => ProfileListing {
                    id,
                    profile: Some(profile.view()),
                    error: None,
                },
                Err(error) => ProfileListing {
                    id,
                    profile: None,
                    error: Some(error),
                },
            })
            .collect())
    }
    pub fn create(&self, origin: &str, username: &str, name: &str) -> Result<JoinProfile, String> {
        let origin = canonical_origin(origin.trim()).map_err(|_| invalid())?;
        let mut keys = crypto::generate_keypair().map_err(|_| invalid())?;
        let id = uuid::Uuid::new_v4().to_string();
        let profile = JoinProfile {
            record: Record {
                domain: "LiteSeal/join-profile/v1".into(),
                version: 1,
                id: id.clone(),
                task_id: uuid::Uuid::new_v4().to_string(),
                username: username.trim().into(),
                name: name.trim().into(),
                identity: KeystoreData {
                    user_id: format!("join:{}", username.trim()),
                    token: String::new(),
                    refresh_token: String::new(),
                    device_id: uuid::Uuid::new_v4().to_string(),
                    server_url: origin,
                    public_key: keys.public_key.to_vec(),
                    secret_key: keys.secret_key.to_vec(),
                    ed25519_pk: keys.ed25519_pk.to_vec(),
                    ed25519_sk: keys.ed25519_sk.to_vec(),
                },
            },
        };
        keys.secret_key.zeroize();
        keys.ed25519_sk.zeroize();
        profile.validate(&id)?;
        fs::create_dir_all(&self.root).map_err(io)?;
        plain_path(&self.root, true)?;
        let guard = self.root.join("allocation.db");
        if guard.exists() {
            plain_path(&guard, false)?;
        }
        let mut conn = rusqlite::Connection::open(guard).map_err(|_| io_error())?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|_| io_error())?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS allocation_guard (id INTEGER PRIMARY KEY)")
            .map_err(|_| io_error())?;
        // An independent SQLite write lock serializes the filesystem quota across processes.
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| io_error())?;
        if self.ids()?.len() >= MAX_PROFILES {
            return Err("最多保留八个加入档案，请先整理已取消或过期的档案".into());
        }
        let directory = self.root.join(&id);
        fs::create_dir(&directory).map_err(io)?;
        let mut plain = serde_json::to_vec(&profile.record).map_err(|_| invalid())?;
        let result = secret_store::secret_store(directory.join("identity.bin"))
            .save(&plain)
            .map_err(|_| io_error());
        plain.zeroize();
        result?;
        let database = self.bound_database(&id, true)?;
        let keys = profile.keys()?;
        let mut tasks = super::tasks::DeviceTaskStore::open(&database, profile.owner()?, &keys)?;
        tasks.prepare_join_with_id(profile.task_id(), &profile.view().device_name, &keys)?;
        drop(tasks);
        tx.commit().map_err(|_| io_error())?;
        Ok(profile)
    }
    /// Call only after all tasks are safely closed and their SQLite handles dropped.
    pub fn remove(&self, id: &str) -> Result<(), String> {
        let directory = self.directory(id)?;
        let names = ["identity.bin", "tasks.db", "tasks.db-wal", "tasks.db-shm"];
        let mut files = fs::read_dir(&directory)
            .map_err(io)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(io)?;
        for entry in &files {
            if !entry
                .file_name()
                .to_str()
                .is_some_and(|name| names.contains(&name))
            {
                return Err("档案含未知文件，已保留全部内容".into());
            }
            plain_path(&entry.path(), false)?;
        }
        // Keep the protected key until database/cache removal has succeeded.
        files.sort_by_key(|entry| entry.file_name() == "identity.bin");
        // Explicit files only: no recursive deletion, links, or caller supplied paths.
        for entry in files {
            fs::remove_file(entry.path()).map_err(io)?;
        }
        fs::remove_dir(directory).map_err(io)
    }
    pub fn remove_empty(&self, id: &str) -> Result<(), String> {
        let directory = self.directory(id)?;
        if fs::read_dir(&directory).map_err(io)?.next().is_some() {
            return Err("档案包含数据，不能作为空档案删除".into());
        }
        fs::remove_dir(directory).map_err(io)
    }
    pub fn exists(&self, id: &str) -> Result<bool, String> {
        identifier(id)?;
        if !self.root.exists() {
            return Ok(false);
        }
        plain_path(&self.root, true)?;
        match fs::symlink_metadata(self.root.join(id)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(io(error)),
        }
    }
}
fn io_error() -> String {
    "加入设备档案存储不可用".into()
}
