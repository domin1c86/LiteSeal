//! Offline archive operations have no HTTP/WebSocket calls and no job runners.
use crate::AppState;
use liteseal_core::{
    backup::{self, Restored, Summary, Zeroizing},
    groups::GroupStore,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
type Result<T> = std::result::Result<T, String>;
#[derive(Clone, Serialize)]
pub struct JobView {
    pub id: String,
    pub state: String,
    pub completed: u64,
    pub total: u64,
    pub summary: Option<Summary>,
    pub error: Option<String>,
    pub restorable: bool,
}
struct Job {
    view: JobView,
    cancel: Arc<AtomicBool>,
    archive: Option<Arc<Archive>>,
}
struct Archive {
    app: AppState,
    restored: Restored,
}
#[derive(Default)]
pub struct Runtime {
    jobs: HashMap<String, Job>,
    active: Option<String>,
    worker: Option<String>,
}
pub fn invalidate(runtime: &Arc<Mutex<Runtime>>) -> Result<()> {
    let mut runtime = runtime.lock().map_err(|_| "备份任务锁不可用")?;
    for job in runtime.jobs.values_mut() {
        job.cancel.store(true, Ordering::SeqCst);
        job.archive = None;
        job.view.restorable = false;
        if job.view.state == "running" {
            job.view.state = "cancelled".into();
        }
    }
    runtime.active = None;
    Ok(())
}
pub fn reset(state: &AppState) -> Result<()> {
    let _guard = state.backup_commit.lock().map_err(|_| "备份提交锁不可用")?;
    invalidate(&state.backup_runtime)
}
fn create(state: &AppState) -> Result<(String, Arc<AtomicBool>)> {
    let mut runtime = state
        .backup_runtime
        .lock()
        .map_err(|_| "备份任务锁不可用")?;
    if runtime.worker.is_some()
        || runtime.active.is_some()
        || runtime.jobs.values().any(|job| job.view.state == "running")
    {
        return Err("请先关闭恢复档案或等待当前备份任务结束".into());
    }
    runtime.jobs.clear();
    let id = uuid::Uuid::new_v4().to_string();
    runtime.worker = Some(id.clone());
    let cancel = Arc::new(AtomicBool::new(false));
    runtime.jobs.insert(
        id.clone(),
        Job {
            view: JobView {
                id: id.clone(),
                state: "running".into(),
                completed: 0,
                total: 0,
                summary: None,
                error: None,
                restorable: false,
            },
            cancel: cancel.clone(),
            archive: None,
        },
    );
    Ok((id, cancel))
}
fn progress(runtime: &Arc<Mutex<Runtime>>, id: &str, completed: u64, total: u64) {
    if let Ok(mut runtime) = runtime.lock() {
        if let Some(job) = runtime.jobs.get_mut(id) {
            job.view.completed = completed;
            job.view.total = total;
        }
    }
}
fn finish(
    runtime: &Arc<Mutex<Runtime>>,
    id: &str,
    result: Result<(Summary, Option<Arc<Archive>>)>,
) {
    if let Ok(mut runtime) = runtime.lock() {
        if runtime.worker.as_deref() == Some(id) {
            runtime.worker = None;
        }
        if let Some(job) = runtime.jobs.get_mut(id) {
            if job.cancel.load(Ordering::SeqCst) {
                job.view.state = "cancelled".into();
                return;
            }
            match result {
                Ok((summary, archive)) => {
                    job.view.state = "completed".into();
                    job.view.summary = Some(summary);
                    job.view.restorable = archive.is_some();
                    job.archive = archive;
                }
                Err(error) => {
                    job.view.state = "failed".into();
                    job.view.error = Some(error);
                }
            }
        }
    }
}
pub fn start_export(
    state: &AppState,
    path: String,
    password: String,
    include_attachments: bool,
) -> Result<String> {
    let _identity_gate = state.backup_commit.lock().map_err(|_| "备份提交锁不可用")?;
    let identity = Zeroizing::new(state.identity()?);
    let db = state.db_path.clone();
    let password = Zeroizing::new(password);
    let (id, cancel) = create(state)?;
    let runtime = state.backup_runtime.clone();
    let gate = state.backup_commit.clone();
    let task_id = id.clone();
    tokio::task::spawn_blocking(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            backup::export_guarded(
                &db,
                (*identity).clone(),
                password.as_bytes(),
                include_attachments,
                &PathBuf::from(path),
                &cancel,
                &gate,
                |n, total| progress(&runtime, &task_id, n, total),
            )
        }))
        .unwrap_or_else(|_| Err("备份任务异常终止".into()))
        .map(|summary| (summary, None));
        finish(&runtime, &task_id, result);
    });
    Ok(id)
}
pub fn start_restore(
    state: &AppState,
    path: String,
    parent: String,
    password: String,
) -> Result<String> {
    let (id, cancel) = create(state)?;
    let runtime = state.backup_runtime.clone();
    let task_id = id.clone();
    let password = Zeroizing::new(password);
    tokio::task::spawn_blocking(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let restored = backup::restore(
                &PathBuf::from(path),
                password.as_bytes(),
                &PathBuf::from(parent),
                &cancel,
                |n, total| progress(&runtime, &task_id, n, total),
            )?;
            let app = AppState::with_keystore(
                restored
                    .directory
                    .0
                    .join("history.db")
                    .to_str()
                    .ok_or("恢复路径无效")?,
                Some(restored.directory.0.join("identity.bin")),
            )?;
            let summary = restored.summary.clone();
            let archive = Arc::new(Archive { app, restored });
            validate_archive(&archive, &cancel)?;
            Ok((summary, Some(archive)))
        }))
        .unwrap_or_else(|_| Err("恢复任务异常终止".into()));
        finish(&runtime, &task_id, result);
    });
    Ok(id)
}
pub fn status(state: &AppState, id: &str) -> Result<JobView> {
    state
        .backup_runtime
        .lock()
        .map_err(|_| "备份任务锁不可用")?
        .jobs
        .get(id)
        .map(|job| job.view.clone())
        .ok_or("备份任务已失效".into())
}
pub fn cancel(state: &AppState, id: &str) -> Result<()> {
    let _guard = state.backup_commit.lock().map_err(|_| "备份提交锁不可用")?;
    let mut runtime = state
        .backup_runtime
        .lock()
        .map_err(|_| "备份任务锁不可用")?;
    if runtime.active.as_deref() == Some(id) {
        runtime.active = None;
    }
    let job = runtime.jobs.get_mut(id).ok_or("备份任务已失效")?;
    job.cancel.store(true, Ordering::SeqCst);
    job.archive = None;
    job.view.restorable = false;
    if job.view.state == "running" {
        job.view.state = "cancelled".into();
    }
    Ok(())
}
fn archive(state: &AppState, id: &str) -> Result<Arc<Archive>> {
    let runtime = state
        .backup_runtime
        .lock()
        .map_err(|_| "恢复档案锁不可用")?;
    if runtime.active.as_deref() != Some(id) {
        return Err("恢复档案未打开或已关闭".into());
    }
    runtime
        .jobs
        .get(id)
        .and_then(|job| job.archive.clone())
        .ok_or("恢复档案已失效".into())
}
pub fn open(state: &AppState, id: &str) -> Result<Value> {
    {
        let mut runtime = state
            .backup_runtime
            .lock()
            .map_err(|_| "恢复档案锁不可用")?;
        if !runtime.jobs.get(id).is_some_and(|job| {
            job.view.state == "completed"
                && job.archive.is_some()
                && !job.cancel.load(Ordering::SeqCst)
        }) {
            return Err("恢复档案未完成或已失效".into());
        }
        runtime.active = Some(id.into());
    }
    info(state, id)
}
pub fn info(state: &AppState, id: &str) -> Result<Value> {
    let archive = archive(state, id)?;
    let saved = &archive.restored.identity;
    Ok(
        json!({"id":id,"user_id":saved.user_id,"device_id":saved.device_id,"server_url":saved.server_url,"fingerprint":liteseal_core::contacts::fingerprint(&saved.public_key),"signing_fingerprint":liteseal_core::contacts::fingerprint(&saved.ed25519_pk),"summary":archive.restored.summary}),
    )
}
fn connection(archive: &Archive) -> Result<rusqlite::Connection> {
    rusqlite::Connection::open_with_flags(
        archive.restored.directory.0.join("history.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| "恢复档案不可读".into())
}
fn store(archive: &Archive) -> Result<GroupStore> {
    let identity = &archive.restored.identity;
    GroupStore::open(
        archive
            .restored
            .directory
            .0
            .join("history.db")
            .to_str()
            .ok_or("恢复路径无效")?,
        &identity.server_url,
        backup::group_identity(identity),
    )
}
fn conversations_inner(archive: &Archive, after: Option<&str>) -> Result<Value> {
    let conn = connection(archive)?;
    let identity = &archive.restored.identity;
    let groups = store(archive)?;
    let mut q=conn.prepare("SELECT conversation_id AS id,'direct' AS kind FROM messages UNION SELECT group_id,'group' FROM local_group_roots UNION SELECT 'dm:'||CASE WHEN ?1<peer_id THEN ?1||':'||peer_id ELSE peer_id||':'||?1 END,'direct' FROM conversation_preferences WHERE user_id=?1 ORDER BY id").map_err(|_|"恢复会话不可读")?;
    let rows = q
        .query_map([&identity.user_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(|_| "恢复会话不可读")?;
    let mut items = Vec::new();
    let mut next = None;
    for row in rows {
        let (id, kind) = row.map_err(|_| "恢复会话不可读")?;
        if after.is_some_and(|a| id.as_str() <= a) {
            continue;
        }
        if items.len() == 100 {
            next = items
                .last()
                .and_then(|v: &Value| v["id"].as_str().map(str::to_owned));
            break;
        }
        let name = if kind == "group" {
            groups.state(&id)?.name().to_string()
        } else {
            let peer = id
                .split(':')
                .skip(1)
                .find(|s| *s != identity.user_id)
                .unwrap_or("");
            archive
                .app
                .client
                .db
                .lock()
                .map_err(|_| "恢复数据锁不可用")?
                .get_contact(peer)
                .map_err(|_| "恢复联系人不可读")?
                .map_or_else(|| peer.to_string(), |p| p.username)
        };
        items.push(json!({"id":id,"kind":kind,"name":name}));
    }
    Ok(json!({"items":items,"next":next}))
}
pub fn conversations(state: &AppState, id: &str, after: Option<&str>) -> Result<Value> {
    let archive = archive(state, id)?;
    conversations_inner(&archive, after)
}
fn page_inner(
    archive: &Archive,
    kind: &str,
    conversation: &str,
    before_time: Option<i64>,
    before_id: Option<&str>,
    before_group: Option<i64>,
) -> Result<Value> {
    let saved = &archive.restored.identity;
    let keys = backup::identity_keys(saved)?;
    if kind == "group" {
        let groups = store(archive)?;
        groups.state(conversation)?;
        let page = groups.history(conversation, before_group, &keys)?;
        let ids = page
            .messages
            .iter()
            .map(|m| m.id.clone())
            .collect::<Vec<_>>();
        let collaboration = groups.collaboration_view_messages(conversation, Some(&ids), &keys)?;
        let extensions = groups.extension_view(conversation, &ids, &keys)?;
        let draft = groups.draft(conversation, &keys)?;
        return Ok(
            json!({"messages":page.messages.into_iter().map(|m|json!({"id":m.id,"sender":m.sender_user_id,"timestamp":m.sent_at,"text":m.text,"status":m.status})).collect::<Vec<_>>(),"next_group":page.next_before,"collaboration":collaboration,"extensions":extensions,"draft":draft}),
        );
    }
    if kind != "direct" || before_time.is_some() != before_id.is_some() {
        return Err("恢复历史游标无效".into());
    }
    let peer = conversation
        .split(':')
        .skip(1)
        .find(|p| *p != saved.user_id)
        .ok_or("恢复会话无效")?;
    if liteseal_core::chat::canonical_conversation_id(&saved.user_id, peer) != conversation {
        return Err("恢复会话身份不匹配".into());
    }
    let (mut rows, contact) = {
        let repository = archive
            .app
            .client
            .db
            .lock()
            .map_err(|_| "恢复数据锁不可用")?;
        (
            repository
                .get_visible_message_page(conversation, 51, &saved.user_id, before_time, before_id)
                .map_err(|_| "恢复历史不可读")?,
            repository
                .get_contact(peer)
                .map_err(|_| "恢复联系人不可读")?,
        )
    };
    let more = rows.len() > 50;
    rows.truncate(50);
    let next = if more {
        rows.last().map(|m| json!({"time":m.timestamp,"id":m.id}))
    } else {
        None
    };
    let operations =
        super::message_operations::views(Some(conversation.to_string()), &archive.app)?;
    let mut messages = Vec::new();
    for row in rows.into_iter().rev() {
        let latest = operations
            .iter()
            .filter(|o| o.target_id == row.id && o.status == "accepted")
            .max_by_key(|o| (o.kind == "revoke", o.revision));
        let text = if latest.is_some_and(|o| o.kind == "revoke") {
            "[已撤回]".into()
        } else if row.local_state == "integrity_failed" {
            "[消息完整性异常]".into()
        } else if let Some(content) = latest.and_then(|o| o.content.clone()) {
            content
        } else if let Some(contact) = &contact {
            let pk: [u8; 32] = contact
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| "联系人密钥无效")?;
            crypto_plain(&row.ciphertext, &pk, &keys.secret_key)
                .unwrap_or_else(|_| "[无法解密的历史消息]".into())
        } else {
            "[联系人密钥不可用]".into()
        };
        let bytes = super::attachments::public_plaintext(text.into_bytes())?;
        messages.push(json!({"id":row.id,"sender":row.sender_id,"timestamp":row.timestamp,"text":String::from_utf8(bytes).map_err(|_|"消息编码无效")?,"status":row.local_state}));
    }
    let reactions = super::reactions::views(&archive.app, conversation.to_string())?;
    let preference = archive
        .app
        .client
        .db
        .lock()
        .map_err(|_| "恢复数据锁不可用")?
        .conversation_preferences(&saved.user_id)
        .map_err(|_| "恢复偏好不可读")?
        .into_iter()
        .find(|p| p.peer_id == peer);
    let draft = preference
        .as_ref()
        .filter(|p| !p.draft.is_empty())
        .map(|p| {
            crypto_plain(&p.draft, &keys.public_key, &keys.secret_key).and_then(|text| {
                serde_json::from_str::<Value>(&text)
                    .map(|v| v["text"].as_str().unwrap_or("").to_owned())
                    .map_err(|_| "恢复草稿格式无效".into())
            })
        })
        .transpose()?;
    Ok(json!({"messages":messages,"next":next,"reactions":reactions,"draft":draft}))
}
fn crypto_plain(bytes: &[u8], pk: &[u8; 32], sk: &[u8; 32]) -> Result<String> {
    String::from_utf8(liteseal_shared::crypto::decrypt(bytes, pk, sk).map_err(|_| "历史解密失败")?)
        .map_err(|_| "消息编码无效".into())
}
pub fn page(
    state: &AppState,
    id: &str,
    kind: &str,
    conversation: &str,
    before_time: Option<i64>,
    before_id: Option<&str>,
    before_group: Option<i64>,
) -> Result<Value> {
    let archive = archive(state, id)?;
    page_inner(
        &archive,
        kind,
        conversation,
        before_time,
        before_id,
        before_group,
    )
}
fn validate_archive(archive: &Archive, cancel: &AtomicBool) -> Result<()> {
    // Exercise every group page, including hidden payload domains, via the same
    // authenticated local projection used by the offline reader.
    let groups = store(archive)?;
    let conn = connection(archive)?;
    let keys = backup::identity_keys(&archive.restored.identity)?;
    let mut q = conn
        .prepare("SELECT group_id FROM local_group_roots")
        .map_err(|_| "恢复群目录无效")?;
    let ids = q
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|_| "恢复群目录无效")?;
    for id in ids {
        backup::check_cancel(cancel)?;
        let id = id.map_err(|_| "恢复群目录无效")?;
        groups.state(&id)?;
        groups.extension_validate(&id, &keys)?;
        groups.draft(&id, &keys)?;
        let mut before = None;
        loop {
            backup::check_cancel(cancel)?;
            let page = groups.history(&id, before, &keys)?;
            let ids = page
                .messages
                .iter()
                .map(|m| m.id.clone())
                .collect::<Vec<_>>();
            groups.collaboration_view_messages(&id, Some(&ids), &keys)?;
            before = page.next_before;
            if before.is_none() {
                break;
            }
        }
    }
    Ok(())
}
pub fn export_attachment(state: &AppState, id: &str, message: &str, path: &str) -> Result<String> {
    let archive = archive(state, id)?;
    let saved = &archive.restored.identity;
    let conn = connection(&archive)?;
    let visible:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM messages m WHERE m.id=?1 AND NOT EXISTS(SELECT 1 FROM locally_deleted_messages d WHERE d.user_id=?2 AND d.message_id=m.id))",rusqlite::params![message,saved.user_id],|r|r.get(0)).map_err(|_|"恢复附件不可读")?;
    if !visible {
        return Err("附件原消息不可用".into());
    }
    let (conversation,): (String,) = conn
        .query_row(
            "SELECT conversation_id FROM messages WHERE id=?1",
            [message],
            |r| Ok((r.get(0)?,)),
        )
        .map_err(|_| "附件消息不可读")?;
    if super::message_operations::views(Some(conversation), &archive.app)?
        .iter()
        .any(|o| o.target_id == message && o.status == "accepted" && o.kind == "revoke")
    {
        return Err("附件原消息已撤回".into());
    }
    let (descriptor, bytes) = backup::attachment_plain(&conn, saved, message)?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| "附件目标已存在或不可写")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "附件保存失败")?;
    Ok(descriptor.mime)
}
pub fn export_group_attachment(
    state: &AppState,
    id: &str,
    group: &str,
    message: &str,
    path: &str,
) -> Result<String> {
    let archive = archive(state, id)?;
    let keys = backup::identity_keys(&archive.restored.identity)?;
    let (descriptor, bytes) = store(&archive)?.media_archive_read(group, message, &keys)?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| "附件目标已存在或不可写")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "附件保存失败")?;
    Ok(descriptor.mime)
}
