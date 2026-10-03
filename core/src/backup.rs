//! Portable archives contain a clean SQLite history snapshot and a token-free
//! identity. Recovery is an independent offline store, never a live client.
use crate::{db::repository::MessageRepository, groups::GroupStore, keystore::KeystoreData};
use liteseal_shared::{
    backup_crypto::{self, Decryptor, Encryptor, CHUNK},
    crypto,
    group::GroupIdentity,
};
use rusqlite::{params, types::Value, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
pub use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, String>;
fn db(_: rusqlite::Error) -> String {
    "备份数据库格式、身份范围或数据校验失败".into()
}
fn io(_: std::io::Error) -> String {
    "备份文件读写失败，请检查权限与磁盘空间".into()
}
pub fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::SeqCst) {
        Err("备份操作已取消".into())
    } else {
        Ok(())
    }
}

#[derive(Clone, Default, Serialize, Deserialize, Debug, zeroize::Zeroize)]
pub struct Summary {
    pub messages: u64,
    pub groups: u64,
    pub attachments: u64,
    pub missing_attachments: u64,
    pub skipped_attachments: u64,
}
#[derive(Serialize, Deserialize, zeroize::Zeroize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    identity: KeystoreData,
    summary: Summary,
    database_bytes: u64,
}
pub struct WorkDirectory(pub PathBuf);
impl WorkDirectory {
    pub fn create(parent: &Path) -> Result<Self> {
        fs::create_dir_all(parent).map_err(io)?;
        let path = parent.join(format!("liteseal-archive-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).map_err(io)?;
        Ok(Self(path))
    }
}
impl Drop for WorkDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub fn group_identity(identity: &KeystoreData) -> GroupIdentity {
    GroupIdentity {
        user_id: identity.user_id.clone(),
        device_id: identity.device_id.clone(),
        public_key: identity.public_key.clone(),
        signing_key: identity.ed25519_pk.clone(),
    }
}
pub fn identity_keys(identity: &KeystoreData) -> Result<crypto::KeyPair> {
    backup_crypto::validate_identity(
        &identity.public_key,
        &identity.secret_key,
        &identity.ed25519_pk,
        &identity.ed25519_sk,
    )?;
    Ok(crypto::KeyPair {
        public_key: identity
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| "密钥无效")?,
        secret_key: identity
            .secret_key
            .as_slice()
            .try_into()
            .map_err(|_| "密钥无效")?,
        ed25519_pk: identity
            .ed25519_pk
            .as_slice()
            .try_into()
            .map_err(|_| "密钥无效")?,
        ed25519_sk: identity
            .ed25519_sk
            .as_slice()
            .try_into()
            .map_err(|_| "密钥无效")?,
    })
}
fn validate_identity(identity: &KeystoreData) -> Result<()> {
    identity_keys(identity)?;
    if identity.user_id.is_empty()
        || identity.user_id.len() > 128
        || identity.device_id.is_empty()
        || identity.device_id.len() > 128
        || !identity.token.is_empty()
        || !identity.refresh_token.is_empty()
    {
        return Err("备份身份不完整或包含登录凭据".into());
    }
    crate::api::normalize_server_url(&identity.server_url)?;
    Ok(())
}
fn clean_schema(path: &Path, identity: &KeystoreData) -> Result<String> {
    drop(
        MessageRepository::new(path.to_str().ok_or("备份路径无效")?)
            .map_err(|_| "无法初始化备份数据库")?,
    );
    let group = GroupStore::open(
        path.to_str().ok_or("备份路径无效")?,
        &identity.server_url,
        group_identity(identity),
    )?;
    Ok(group.backup_scope().to_owned())
}
fn exists(conn: &Connection, table: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [table],
        |r| r.get(0),
    )
    .map_err(db)
}
fn columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .map_err(db)?
        .query_map([], |r| r.get(1))
        .map_err(db)?
        .collect::<std::result::Result<_, _>>()
        .map_err(db)
}

// Every identifier below is code-owned. Unknown tables, schemas and jobs never
// cross into the reconstructed archive; source SQL is never executed.
const USER_TABLES: &[&str] = &[
    "conversation_preferences",
    "conversation_notifications",
    "typing_preferences",
    "personal_organizer",
    "local_reactions",
    "read_receipt_settings",
    "local_read_receipts",
    "local_receipt_seen",
    "locally_deleted_messages",
    "local_message_reads",
];
const MESSAGE_TABLES: &[&str] = &[
    "outgoing_chains",
    "incoming_chain_versions",
    "outgoing_delivery",
    "outgoing_payloads",
    "attachments",
];
const GROUP_TABLES: &[&str] = &[
    "local_group_roots",
    "local_group_events",
    "local_group_heads",
    "local_group_messages",
    "local_group_hidden",
    "local_group_preferences",
    "local_group_drafts",
    "local_collab_log",
    "local_collab_cursor",
    "local_extension_log",
    "local_extension_cursor",
];
fn copy_table(
    source: &Connection,
    target: &Connection,
    table: &str,
    filter: &str,
    arg: &str,
    cancel: &AtomicBool,
) -> Result<()> {
    if !exists(source, table)? {
        return Ok(());
    }
    let names = columns(target, table)?;
    if columns(source, table)? != names {
        return Err("备份数据库版本不兼容".into());
    }
    let list = names
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!("SELECT {list} FROM \"{table}\" WHERE {filter} ORDER BY rowid");
    let mut query = source.prepare(&sql).map_err(db)?;
    let mut rows = if query.parameter_count() == 0 {
        query.query([])
    } else {
        query.query([arg])
    }
    .map_err(db)?;
    let insert = format!(
        "INSERT INTO \"{table}\" ({list}) VALUES ({})",
        vec!["?"; names.len()].join(",")
    );
    let mut statement = target.prepare(&insert).map_err(db)?;
    while let Some(row) = rows.next().map_err(db)? {
        check_cancel(cancel)?;
        let values = (0..names.len())
            .map(|i| row.get::<_, Value>(i))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        statement
            .execute(rusqlite::params_from_iter(values))
            .map_err(db)?;
    }
    Ok(())
}
fn select_messages(source: &Connection, identity: &KeystoreData) -> Result<()> {
    source.execute_batch("CREATE TEMP TABLE archive_message_ids(id TEXT PRIMARY KEY); CREATE TEMP TABLE archive_conversations(id TEXT PRIMARY KEY);").map_err(db)?;
    let mut query = source
        .prepare("SELECT id,conversation_id,sender_id,sender_device_id,local_state FROM messages")
        .map_err(db)?;
    let mut rows = query.query([]).map_err(db)?;
    while let Some(row) = rows.next().map_err(db)? {
        let id: String = row.get(0).map_err(db)?;
        let conversation: String = row.get(1).map_err(db)?;
        let sender: String = row.get(2).map_err(db)?;
        let device: String = row.get(3).map_err(db)?;
        let state: String = row.get(4).map_err(db)?;
        if sender == identity.user_id {
            if device != identity.device_id
                || !conversation.starts_with("dm:")
                || matches!(state.as_str(), "pending" | "queued" | "failed")
            {
                continue;
            }
            let payloads: Option<String> = source
                .query_row(
                    "SELECT payloads FROM outgoing_payloads WHERE message_id=?1",
                    [&id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(db)?;
            if let Some(payloads) = payloads {
                let payloads: Vec<liteseal_shared::protocol::EncryptedPayload> =
                    serde_json::from_str(&payloads)
                        .map_err(|_| db(rusqlite::Error::InvalidQuery))?;
                if payloads.is_empty()
                    || payloads.iter().any(|p| {
                        crate::chat::canonical_conversation_id(
                            &identity.user_id,
                            &p.recipient_user_id,
                        ) != conversation
                    })
                {
                    return Err("消息不属于当前备份身份".into());
                }
            } else {
                let parts: Vec<_> = conversation.split(':').collect();
                if parts.len() != 3 || !parts[1..].contains(&identity.user_id.as_str()) {
                    continue;
                }
            }
        } else if conversation != crate::chat::canonical_conversation_id(&identity.user_id, &sender)
        {
            continue;
        }
        source
            .execute("INSERT INTO archive_message_ids VALUES(?1)", [&id])
            .map_err(db)?;
        source
            .execute(
                "INSERT OR IGNORE INTO archive_conversations VALUES(?1)",
                [&conversation],
            )
            .map_err(db)?;
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct AttachmentDescriptor {
    pub version: u32,
    pub id: String,
    pub name: String,
    pub size: usize,
    pub mime: String,
    pub key: Vec<u8>,
}
/// Authenticated metadata, tied to the archived original message.
pub fn attachment_plain(
    conn: &Connection,
    identity: &KeystoreData,
    message: &str,
) -> Result<(AttachmentDescriptor, Vec<u8>)> {
    let (metadata,cipher):(Vec<u8>,Vec<u8>)=conn.query_row("SELECT metadata,ciphertext FROM attachment_transfers WHERE user_id=?1 AND message_id=?2 AND direction='download'",params![identity.user_id,message],|r|Ok((r.get(0)?,r.get(1)?))).map_err(db)?;
    let keys = identity_keys(identity)?;
    let descriptor: AttachmentDescriptor = serde_json::from_slice(
        &crypto::decrypt(&metadata, &keys.public_key, &keys.secret_key)
            .map_err(|_| "附件元数据认证失败")?,
    )
    .map_err(|_| "附件元数据无效")?;
    if descriptor.version != 1 || descriptor.size > 20 * 1024 * 1024 || descriptor.key.len() != 32 {
        return Err("附件格式无效".into());
    }
    let (sender, conversation, body): (String, String, Vec<u8>) = conn
        .query_row(
            "SELECT sender_id,conversation_id,ciphertext FROM messages WHERE id=?1",
            [message],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(db)?;
    let peer = if sender == identity.user_id {
        let parts: Vec<_> = conversation.split(':').collect();
        parts
            .iter()
            .skip(1)
            .find(|p| **p != identity.user_id)
            .ok_or("附件会话无效")?
            .to_string()
    } else {
        sender
    };
    let pk: Vec<u8> = conn
        .query_row(
            "SELECT public_key FROM contacts WHERE user_id=?1",
            [peer],
            |r| r.get(0),
        )
        .map_err(db)?;
    let pk: [u8; 32] = pk.try_into().map_err(|_| "联系人密钥无效")?;
    let bytes = crypto::decrypt(&body, &pk, &keys.secret_key).map_err(|_| "附件消息认证失败")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "附件消息无效")?;
    let original: AttachmentDescriptor = serde_json::from_str(
        text.strip_prefix("\u{1e}LiteSeal:2:")
            .ok_or("附件消息无效")?,
    )
    .map_err(|_| "附件消息无效")?;
    if descriptor.id != original.id
        || descriptor.key != original.key
        || descriptor.size != original.size
        || descriptor.name != original.name
        || descriptor.mime != original.mime
    {
        return Err("附件与原消息不匹配".into());
    }
    let bytes = crypto::decrypt_attachment(&cipher, &descriptor.key).map_err(|_| "附件认证失败")?;
    if bytes.len() != descriptor.size {
        return Err("附件长度无效".into());
    }
    Ok((descriptor, bytes))
}

fn rebuild(
    source: &Connection,
    path: &Path,
    identity: &KeystoreData,
    include_attachments: bool,
    cancel: &AtomicBool,
    restoring: bool,
    version: u32,
) -> Result<Summary> {
    validate_identity(identity)?;
    if version != 3 {
        crate::trusted_devices::messages::require_backup_support(source, identity)?;
    }
    let scope = clean_schema(path, identity)?;
    let target = Connection::open(path).map_err(db)?;
    target
        .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; BEGIN IMMEDIATE;")
        .map_err(db)?;
    select_messages(source, identity)?;
    copy_table(source, &target, "contacts", "1", "", cancel)?;
    copy_table(
        source,
        &target,
        "messages",
        "id IN (SELECT id FROM archive_message_ids)",
        "",
        cancel,
    )?;
    copy_table(
        source,
        &target,
        "conversations",
        "id IN (SELECT id FROM archive_conversations)",
        "",
        cancel,
    )?;
    for table in USER_TABLES {
        let filter = if matches!(*table, "local_reactions" | "local_read_receipts") {
            "user_id=?1 AND seq>0"
        } else {
            "user_id=?1"
        };
        copy_table(source, &target, table, filter, &identity.user_id, cancel)?;
    }
    for table in MESSAGE_TABLES {
        copy_table(
            source,
            &target,
            table,
            "message_id IN (SELECT id FROM archive_message_ids)",
            "",
            cancel,
        )?;
    }
    copy_table(
        source,
        &target,
        "local_message_operations",
        "user_id=?1 AND status='accepted' AND target_id IN (SELECT id FROM archive_message_ids)",
        &identity.user_id,
        cancel,
    )?;
    for table in GROUP_TABLES {
        let filter = if *table == "local_group_messages" {
            "scope=?1 AND status IN ('accepted','received','seen')"
        } else {
            "scope=?1"
        };
        copy_table(source, &target, table, filter, &scope, cancel)?;
    }
    // Drafts are history/settings; task tables stay empty in the trusted schema.
    let mut summary = Summary {
        messages: target
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .map_err(db)?,
        groups: target
            .query_row("SELECT COUNT(*) FROM local_group_roots", [], |r| r.get(0))
            .map_err(db)?,
        ..Summary::default()
    };
    let mut query=source.prepare("SELECT id,user_id,peer_id,message_id,metadata,ciphertext,offset,direction FROM attachment_transfers WHERE user_id=?1").map_err(db)?;
    let mut rows = query.query([&identity.user_id]).map_err(db)?;
    while let Some(row) = rows.next().map_err(db)? {
        check_cancel(cancel)?;
        let direction: String = row.get(7).map_err(db)?;
        let id: String = row.get(0).map_err(db)?;
        let message: String = row.get(3).map_err(db)?;
        let known: bool = target
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE id=?1)",
                [&message],
                |r| r.get(0),
            )
            .map_err(db)?;
        if direction != "download" || !known {
            summary.skipped_attachments += 1;
            continue;
        }
        let offset: i64 = row.get(6).map_err(db)?;
        let cipher: Vec<u8> = row.get(5).map_err(db)?;
        if !include_attachments
            || offset != cipher.len() as i64
            || attachment_plain(source, identity, &message).is_err()
        {
            summary.skipped_attachments += 1;
            continue;
        }
        // All fields are inserted as values into our schema, never from source SQL.
        let values = (0..8)
            .map(|i| row.get::<_, Value>(i))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        target.execute("INSERT INTO attachment_transfers(id,user_id,peer_id,message_id,metadata,ciphertext,offset,direction) VALUES(?,?,?,?,?,?,?,?)",rusqlite::params_from_iter(values)).map_err(db)?;
        let _ = id;
        summary.attachments += 1;
    }
    let mut q = target
        .prepare(
            "SELECT ciphertext,sender_id,conversation_id FROM messages WHERE message_type='text'",
        )
        .map_err(db)?;
    let mut rows = q.query([]).map_err(db)?;
    let keys = identity_keys(identity)?;
    while let Some(row) = rows.next().map_err(db)? {
        let sender: String = row.get(1).map_err(db)?;
        let conv: String = row.get(2).map_err(db)?;
        let peer = if sender == identity.user_id {
            conv.split(':')
                .skip(1)
                .find(|p| *p != identity.user_id)
                .unwrap_or("")
                .to_string()
        } else {
            sender
        };
        let pk: Option<Vec<u8>> = target
            .query_row(
                "SELECT public_key FROM contacts WHERE user_id=?1",
                [peer],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        if let Some(pk) = pk.and_then(|p| <[u8; 32]>::try_from(p).ok()) {
            let body: Vec<u8> = row.get(0).map_err(db)?;
            if let Ok(bytes) = crypto::decrypt(&body, &pk, &keys.secret_key) {
                if bytes.starts_with(b"\x1eLiteSeal:2:") {
                    summary.missing_attachments += 1;
                }
            }
        }
    }
    summary.missing_attachments = summary
        .missing_attachments
        .saturating_sub(summary.attachments);
    drop(rows);
    drop(q);
    target.execute_batch("COMMIT;").map_err(db)?;
    let groups = GroupStore::open(
        path.to_str().ok_or("备份路径无效")?,
        &identity.server_url,
        group_identity(identity),
    )?;
    let mut q = target
        .prepare("SELECT group_id FROM local_group_roots WHERE scope=?1")
        .map_err(db)?;
    for id in q
        .query_map([&scope], |r| r.get::<_, String>(0))
        .map_err(db)?
    {
        groups.extension_validate(&id.map_err(db)?, &keys)?;
    }
    let count:u64=target.query_row("SELECT COUNT(*) FROM local_extension_log WHERE scope=?1 AND content IS NOT NULL AND json_extract(header,'$.action.kind')='attachment'",[&scope],|r|r.get(0)).map_err(db)?;
    let mut included = 0;
    if exists(source, "group_attachment_cache")? {
        let mut q=source.prepare("SELECT scope,user_id,group_id,id,joined,metadata,ciphertext,offset,direction,root FROM group_attachment_cache WHERE scope=?1 AND user_id=?2").map_err(db)?;
        let mut rows = q.query(params![scope, identity.user_id]).map_err(db)?;
        while let Some(row) = rows.next().map_err(db)? {
            check_cancel(cancel)?;
            let group: String = row.get(2).map_err(db)?;
            let blob: String = row.get(3).map_err(db)?;
            let root: String = row.get(9).map_err(db)?;
            let known:bool=target.query_row("SELECT EXISTS(SELECT 1 FROM local_group_messages WHERE scope=?1 AND group_id=?2 AND message_id=?3)",params![scope,group,root],|r|r.get(0)).map_err(db)?;
            if !include_attachments
                || !known
                || row.get::<_, String>(8).map_err(db)? != "download"
                || groups
                    .media_cache_verify_row(
                        &group,
                        &root,
                        &blob,
                        &row.get::<_, Vec<u8>>(5).map_err(db)?,
                        &row.get::<_, Vec<u8>>(6).map_err(db)?,
                        row.get(7).map_err(db)?,
                        &keys,
                    )
                    .is_err()
            {
                if restoring {
                    return Err("恢复群附件缓存范围、完整性或认证无效".into());
                }
                summary.skipped_attachments += 1;
                continue;
            }
            let values = (0..10)
                .map(|i| row.get::<_, Value>(i))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(db)?;
            target
                .execute(
                    "INSERT INTO group_attachment_cache VALUES(?,?,?,?,?,?,?,?,?,?)",
                    rusqlite::params_from_iter(values),
                )
                .map_err(db)?;
            included += 1;
        }
    }
    summary.attachments += included;
    summary.missing_attachments += count.saturating_sub(included);
    if version == 3 {
        let direct = crate::trusted_devices::messages::archive::rebuild(
            source,
            &target,
            identity,
            include_attachments,
            cancel,
            restoring,
        )?;
        summary.messages += direct.messages;
        summary.attachments += direct.attachments;
        summary.missing_attachments += direct.missing_attachments;
        summary.skipped_attachments += direct.skipped_attachments;
    }
    Ok(summary)
}

pub fn export(
    db_path: &Path,
    identity: KeystoreData,
    password: &[u8],
    include_attachments: bool,
    destination: &Path,
    cancel: &AtomicBool,
    progress: impl Fn(u64, u64),
) -> Result<Summary> {
    export_guarded(
        db_path,
        identity,
        password,
        include_attachments,
        destination,
        cancel,
        &std::sync::Mutex::new(()),
        progress,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn export_guarded(
    db_path: &Path,
    identity: KeystoreData,
    password: &[u8],
    include_attachments: bool,
    destination: &Path,
    cancel: &AtomicBool,
    commit_gate: &std::sync::Mutex<()>,
    progress: impl Fn(u64, u64),
) -> Result<Summary> {
    export_inner(
        db_path,
        identity,
        None,
        password,
        include_attachments,
        destination,
        cancel,
        commit_gate,
        progress,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn export_direct_guarded(
    db_path: &Path,
    identity: KeystoreData,
    store: &mut crate::trusted_devices::messages::Store,
    password: &[u8],
    include_attachments: bool,
    destination: &Path,
    cancel: &AtomicBool,
    commit_gate: &std::sync::Mutex<()>,
    progress: impl Fn(u64, u64),
) -> Result<Summary> {
    export_inner(
        db_path,
        identity,
        Some(store),
        password,
        include_attachments,
        destination,
        cancel,
        commit_gate,
        progress,
    )
}
#[allow(clippy::too_many_arguments)]
fn export_inner(
    db_path: &Path,
    identity: KeystoreData,
    direct: Option<&mut crate::trusted_devices::messages::Store>,
    password: &[u8],
    include_attachments: bool,
    destination: &Path,
    cancel: &AtomicBool,
    commit_gate: &std::sync::Mutex<()>,
    progress: impl Fn(u64, u64),
) -> Result<Summary> {
    let mut identity = Zeroizing::new(identity);
    identity.token.clear();
    identity.refresh_token.clear();
    validate_identity(&identity)?;
    check_cancel(cancel)?;
    if destination.exists() {
        return Err("备份目标已存在，请选择新文件".into());
    }
    let work = WorkDirectory::create(&std::env::temp_dir())?;
    let source =
        Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(db)?;
    let mut snapshot = Connection::open(work.0.join("snapshot.db")).map_err(db)?;
    let version = if let Some(store) = direct {
        store.backup_snapshot(&mut snapshot, &identity, cancel)?;
        3
    } else {
        let backup = rusqlite::backup::Backup::new(&source, &mut snapshot).map_err(db)?;
        loop {
            check_cancel(cancel)?;
            match backup.step(128).map_err(db)? {
                rusqlite::backup::StepResult::Done => break,
                rusqlite::backup::StepResult::More => {}
                _ => return Err("数据库忙，请稍后重试备份".into()),
            }
        }
        2
    };
    let clean = work.0.join("history.db");
    if version == 3 {
        clean_schema(&work.0.join("snapshot.db"), &identity)?;
    }
    let summary = rebuild(
        &snapshot,
        &clean,
        &identity,
        include_attachments,
        cancel,
        false,
        version,
    )?;
    drop(snapshot);
    let total = fs::metadata(&clean).map_err(io)?.len();
    if !(512..=8 * 1024 * 1024 * 1024).contains(&total) {
        return Err("备份数据库大小不支持（上限 8 GiB）".into());
    }
    let metadata = Zeroizing::new(Manifest {
        version,
        identity: (*identity).clone(),
        summary: summary.clone(),
        database_bytes: total,
    });
    let manifest = Zeroizing::new(serde_json::to_vec(&*metadata).map_err(|_| "备份清单失败")?);
    let parent = destination.parent().ok_or("备份路径无效")?;
    let output = WorkDirectory::create(parent)?;
    let temporary = output.0.join("backup.partial");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(io)?;
    {
        let mut encoder = Encryptor::new(&mut file, password)?;
        encoder.push(&manifest, false)?;
        let mut reader = File::open(&clean).map_err(io)?;
        let mut buffer = vec![0; CHUNK];
        let mut completed = 0;
        loop {
            check_cancel(cancel)?;
            let count = reader.read(&mut buffer).map_err(io)?;
            if count == 0 {
                break;
            }
            encoder.push(&buffer[..count], false)?;
            completed += count as u64;
            progress(completed, total);
        }
        encoder.push(&[], true)?;
    }
    file.sync_all().map_err(io)?;
    drop(file);
    let _commit = commit_gate.lock().map_err(|_| "备份提交锁不可用")?;
    check_cancel(cancel)?;
    // Same volume, atomic no-replace creation. A competing existing destination
    // cannot be overwritten; the private temporary directory is removed on drop.
    fs::hard_link(&temporary, destination).map_err(io)?;
    Ok(summary)
}

pub struct Restored {
    pub directory: WorkDirectory,
    pub identity: Zeroizing<KeystoreData>,
    pub summary: Summary,
    pub version: u32,
}
pub fn restore(
    input: &Path,
    password: &[u8],
    parent: &Path,
    cancel: &AtomicBool,
    progress: impl Fn(u64, u64),
) -> Result<Restored> {
    check_cancel(cancel)?;
    let mut decoder = Decryptor::new(File::open(input).map_err(io)?, password)?;
    let header = Zeroizing::new(decoder.next_chunk()?.ok_or("备份缺少清单")?);
    let manifest: Zeroizing<Manifest> =
        Zeroizing::new(serde_json::from_slice(&header).map_err(|_| "备份清单无效")?);
    let identity = Zeroizing::new(manifest.identity.clone());
    validate_identity(&identity)?;
    if !matches!(manifest.version, 1..=3)
        || manifest.database_bytes > 8 * 1024 * 1024 * 1024
        || manifest.database_bytes < 512
    {
        return Err("备份大小或版本不支持".into());
    }
    let directory = WorkDirectory::create(parent)?;
    let raw = directory.0.join("input.db");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&raw)
        .map_err(io)?;
    let mut completed = 0;
    while let Some(bytes) = decoder.next_chunk()? {
        check_cancel(cancel)?;
        if decoder.ended() {
            if !bytes.is_empty() {
                return Err("备份结束标记无效".into());
            }
            break;
        }
        completed += bytes.len() as u64;
        if completed > manifest.database_bytes {
            return Err("备份数据库长度无效".into());
        }
        file.write_all(&bytes).map_err(io)?;
        progress(completed, manifest.database_bytes);
    }
    if !decoder.ended() || completed != manifest.database_bytes {
        return Err("备份文件不完整".into());
    }
    file.sync_all().map_err(io)?;
    drop(file);
    let source = Connection::open_with_flags(&raw, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(db)?;
    source
        .execute_batch("PRAGMA trusted_schema=OFF;")
        .map_err(db)?;
    let check: String = source
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(db)?;
    if check != "ok" {
        return Err("备份数据库损坏".into());
    }
    // Reconstruct from code-owned schema even for an authenticated malicious file.
    let summary = rebuild(
        &source,
        &directory.0.join("history.db"),
        &identity,
        true,
        cancel,
        true,
        manifest.version,
    )?;
    if summary.messages != manifest.summary.messages
        || summary.groups != manifest.summary.groups
        || summary.attachments != manifest.summary.attachments
    {
        return Err("备份内容或身份范围不一致".into());
    }
    drop(source);
    fs::remove_file(raw).map_err(io)?;
    crate::keystore::save_keypair_to(&directory.0.join("identity.bin"), (*identity).clone())?;
    check_cancel(cancel)?;
    Ok(Restored {
        directory,
        identity,
        summary: manifest.summary.clone(),
        version: manifest.version,
    })
}
