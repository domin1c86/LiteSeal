use crate::AppState;
use liteseal_core::{api, chat, db::repository::ScheduledMessage, keystore::KeystoreData};
use liteseal_shared::protocol::EncryptedPayload;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
const MAX_TEXT: usize = 4096;
#[derive(Serialize, Deserialize)]
struct Content {
    text: String,
    public_key: Vec<u8>,
    signing_key: Option<Vec<u8>>,
}
#[derive(Serialize)]
pub struct View {
    id: String,
    peer_id: String,
    due_at: i64,
    text: String,
    state: String,
    error: String,
    sealed: bool,
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn rows(state: &AppState, saved: &KeystoreData) -> Result<Vec<ScheduledMessage>, String> {
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .scheduled_messages(&saved.user_id, &saved.device_id)
        .map_err(|e| e.to_string())
}
fn store(state: &AppState, saved: &KeystoreData, task: &ScheduledMessage) -> Result<(), String> {
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .save_scheduled_message(&saved.user_id, &saved.device_id, task)
        .map_err(|e| e.to_string())
}
fn content(saved: &KeystoreData, task: &ScheduledMessage) -> Result<Content, String> {
    serde_json::from_slice(&chat::decrypt_message(
        task.body.clone(),
        saved.public_key.clone(),
        saved.secret_key.clone(),
    )?)
    .map_err(|_| "定时任务内容损坏".into())
}
fn sealed(state: &AppState, saved: &KeystoreData, task: &ScheduledMessage) -> Result<bool, String> {
    let message = state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .get_message(&task.id)
        .map_err(|e| e.to_string())?;
    if let Some(message) = message {
        if message.sender_id != saved.user_id
            || message.sender_device_id != saved.device_id
            || message.conversation_id
                != chat::canonical_conversation_id(&saved.user_id, &task.peer_id)
        {
            return Err("定时消息编号与身份不匹配".into());
        }
        Ok(true)
    } else {
        Ok(false)
    }
}
fn view(state: &AppState, saved: &KeystoreData, task: ScheduledMessage) -> Result<View, String> {
    let text = content(saved, &task)?.text;
    let is_sealed = sealed(state, saved, &task)?;
    Ok(View {
        id: task.id,
        peer_id: task.peer_id,
        due_at: task.due_at,
        text,
        state: task.state,
        error: task.error,
        sealed: is_sealed,
    })
}
pub async fn list(state: &AppState) -> Result<Vec<View>, String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let saved = state.identity()?;
    rows(state, &saved)?
        .into_iter()
        .map(|task| view(state, &saved, task))
        .collect()
}
pub async fn save(
    state: &AppState,
    id: Option<String>,
    peer: String,
    text: String,
    due_at: i64,
) -> Result<View, String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let timestamp = now();
    if text.trim().is_empty()
        || text.len() > MAX_TEXT
        || due_at < timestamp + 5000
        || due_at > timestamp + 30 * 24 * 60 * 60 * 1000
    {
        return Err("仅支持 4096 UTF-8 字节内的文字，时间需在 5 秒后至 30 天内".into());
    }
    let saved = state.identity()?;
    let tasks = rows(state, &saved)?;
    if peer == saved.user_id || peer.is_empty() {
        return Err("请选择其他联系人".into());
    }
    let id = match id {
        Some(id) => {
            uuid::Uuid::parse_str(&id).map_err(|_| "无效定时任务编号")?;
            if let Some(previous) = tasks.iter().find(|row| row.id == id) {
                if sealed(state, &saved, previous)?
                    || !["scheduled", "missed", "failed"].contains(&previous.state.as_str())
                {
                    return Err("任务已进入发件箱，不能修改；请沿用原消息重试".into());
                }
            } else {
                if tasks.len() >= 100 {
                    return Err("最多保留 100 个任务".into());
                }
                if state
                    .client
                    .db
                    .lock()
                    .map_err(|e| e.to_string())?
                    .get_message(&id)
                    .map_err(|e| e.to_string())?
                    .is_some()
                {
                    return Err("编号已属于其他消息".into());
                }
            }
            id
        }
        None => {
            if tasks.len() >= 100 {
                return Err("最多保留 100 个任务，请移除已提交记录".into());
            }
            uuid::Uuid::new_v4().to_string()
        }
    };
    let peer_record = state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .get_contact(&peer)
        .map_err(|e| e.to_string())?
        .ok_or("联系人不存在")?;
    if peer_record.key_changed || peer_record.public_key.len() != 32 {
        return Err("请先核对联系人身份".into());
    }
    let body = chat::encrypt_message(
        serde_json::to_vec(&Content {
            text: text.trim().into(),
            public_key: peer_record.public_key,
            signing_key: peer_record.ed25519_pk,
        })
        .map_err(|e| e.to_string())?,
        saved.public_key.clone(),
        saved.secret_key.clone(),
    )?;
    let task = ScheduledMessage {
        id,
        peer_id: peer,
        due_at,
        body,
        state: "scheduled".into(),
        error: String::new(),
    };
    store(state, &saved, &task)?;
    view(state, &saved, task)
}
pub async fn cancel(state: &AppState, id: String, remove_submitted: bool) -> Result<(), String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let saved = state.identity()?;
    let task = rows(state, &saved)?
        .into_iter()
        .find(|task| task.id == id)
        .ok_or("任务不存在")?;
    if (task.state == "submitted") != remove_submitted {
        return Err("任务状态已改变，请刷新后再处理".into());
    }
    if task.state != "submitted" && sealed(state, &saved, &task)? {
        return Err("消息已进入发件箱，取消任务不能撤销它；请在聊天中处理原消息".into());
    }
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .delete_scheduled_message(&saved.user_id, &saved.device_id, &id)
        .map_err(|e| e.to_string())
}
pub async fn suspend(state: &AppState) -> Result<(), String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    *state.scheduled_tick.lock().map_err(|e| e.to_string())? = None;
    Ok(())
}
pub async fn connect(
    state: &AppState,
    server: String,
    user: String,
    token: String,
    device: String,
) -> Result<(), String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    *state.scheduled_tick.lock().map_err(|e| e.to_string())? = None;
    state
        .client
        .connect_relay(server, user, token, device)
        .await
}
pub async fn disconnect(state: &AppState) -> Result<(), String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    *state.scheduled_tick.lock().map_err(|e| e.to_string())? = None;
    state.client.disconnect().await;
    Ok(())
}
async fn publish(
    state: &AppState,
    saved: &KeystoreData,
    task: &ScheduledMessage,
) -> Result<(), String> {
    if sealed(state, saved, task)? {
        state.client.retry_message(task.id.clone()).await?;
        return Ok(());
    }
    let content = content(saved, task)?;
    let peer = state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .get_contact(&task.peer_id)
        .map_err(|e| e.to_string())?
        .ok_or("联系人已删除")?;
    if peer.key_changed
        || peer.public_key != content.public_key
        || peer.ed25519_pk != content.signing_key
    {
        return Err("联系人身份已变化，请核对后重新安排任务".into());
    }
    let devices: Vec<_> = api::get_user_devices(
        saved.server_url.clone(),
        task.peer_id.clone(),
        saved.token.clone(),
    )
    .await?
    .into_iter()
    .filter(|device| !device.revoked)
    .collect();
    if devices.len() != 1
        || devices[0].public_key != content.public_key
        || content
            .signing_key
            .as_ref()
            .is_some_and(|key| *key != devices[0].ed25519_pk)
    {
        return Err("收件设备身份不符合定时任务保存的身份".into());
    }
    let body = format!(
        "\u{1e}LiteSeal:1:{}",
        serde_json::json!({"text":content.text})
    )
    .into_bytes();
    let ciphertext =
        chat::encrypt_message(body.clone(), content.public_key, saved.secret_key.clone())?;
    let signature = chat::sign_message(ciphertext.clone(), saved.ed25519_sk.clone())?;
    let device = &devices[0];
    let encrypted =
        chat::encrypt_message(body, device.public_key.clone(), saved.secret_key.clone())?;
    let signed = chat::sign_message(encrypted.clone(), saved.ed25519_sk.clone())?;
    super::chat::send_message(
        saved.user_id.clone(),
        ciphertext,
        signature,
        saved.device_id.clone(),
        vec![EncryptedPayload {
            recipient_user_id: task.peer_id.clone(),
            recipient_device_id: device.id.clone(),
            ciphertext: encrypted,
            signature: signed,
        }],
        Some(task.id.clone()),
        state,
    )
    .await?;
    Ok(())
}
async fn execute(
    state: &AppState,
    saved: &KeystoreData,
    task: &mut ScheduledMessage,
) -> Result<(), String> {
    task.state = "sending".into();
    task.error.clear();
    store(state, saved, task)?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        publish(state, saved, task),
    )
    .await
    .unwrap_or_else(|_| Err("定时发送超时，请检查原消息后手动处理".into()));
    match result {
        Ok(()) => task.state = "submitted".into(),
        Err(error) => {
            task.state = if sealed(state, saved, task)? {
                "needs_retry"
            } else {
                "failed"
            }
            .into();
            task.error = error;
        }
    }
    store(state, saved, task)
}
pub async fn send_now(state: &AppState, id: String) -> Result<View, String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let saved = state.identity()?;
    if !state
        .client
        .relay_connected_as(&saved.user_id, &saved.device_id)
        .await
    {
        return Err("仅在当前账号联网时可发送定时任务".into());
    }
    let mut task = rows(state, &saved)?
        .into_iter()
        .find(|task| task.id == id)
        .ok_or("任务不存在")?;
    if task.state == "submitted" {
        return Err("此任务已经提交，不能再次发送".into());
    }
    execute(state, &saved, &mut task).await?;
    view(state, &saved, task)
}
pub async fn process(state: &AppState) -> Result<usize, String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let saved = state.identity()?;
    if !state
        .client
        .relay_connected_as(&saved.user_id, &saved.device_id)
        .await
    {
        *state.scheduled_tick.lock().map_err(|e| e.to_string())? = None;
        return Err("定时执行已暂停，当前账号未联网".into());
    }
    process_locked(state, now()).await
}
#[cfg(test)]
async fn process_at(state: &AppState, timestamp: i64) -> Result<usize, String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    process_locked(state, timestamp).await
}
async fn process_locked(state: &AppState, timestamp: i64) -> Result<usize, String> {
    let saved = state.identity()?;
    let key = format!("{}:{}", saved.user_id, saved.device_id);
    let previous = state
        .scheduled_tick
        .lock()
        .map_err(|e| e.to_string())?
        .replace((key.clone(), timestamp));
    let continuous = previous.is_some_and(|(previous_key, last)| {
        previous_key == key && timestamp >= last && timestamp - last <= 30_000
    });
    let mut changed = 0;
    for mut task in rows(state, &saved)? {
        if task.state == "submitted"
            && state
                .client
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .get_message(&task.id)
                .map_err(|e| e.to_string())?
                .is_some_and(|message| message.local_state == "failed")
        {
            task.state = "needs_retry".into();
            task.error = "原消息发件失败，请检查聊天中的状态后重试原消息".into();
            store(state, &saved, &task)?;
            changed += 1;
        } else if task.state == "sending" {
            task.state = if sealed(state, &saved, &task)? {
                "needs_retry"
            } else {
                "missed"
            }
            .into();
            task.error = "上次执行中断，请检查原消息后手动处理".into();
            store(state, &saved, &task)?;
            changed += 1;
        } else if task.state == "scheduled" && task.due_at <= timestamp {
            if !continuous {
                task.state = "missed".into();
                task.error = "计划时间已错过，请选择立即发送、重新安排或取消".into();
                store(state, &saved, &task)?;
            } else {
                execute(state, &saved, &mut task).await?;
                changed += 1;
                break;
            }
            changed += 1;
        }
    }
    Ok(changed)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use liteseal_core::db::models::ContactModel;
    use liteseal_shared::{crypto, protocol::SignedEnvelopeV2};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::{accept_async, tungstenite::Message};

    struct Fixture {
        state: Option<AppState>,
        directory: std::path::PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.state.take();
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
    fn fixture(peer: &crypto::KeyPair) -> Fixture {
        let directory =
            std::env::temp_dir().join(format!("liteseal-scheduled-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let state = AppState::with_keystore(
            directory.join("data.db").to_str().unwrap(),
            Some(directory.join("keys.bin")),
        )
        .unwrap();
        let own = crypto::generate_keypair().unwrap();
        state
            .save_identity(KeystoreData {
                user_id: "alice".into(),
                device_id: "device-a".into(),
                token: "test-token".into(),
                refresh_token: "refresh".into(),
                server_url: "http://127.0.0.1:9".into(),
                public_key: own.public_key.to_vec(),
                secret_key: own.secret_key.to_vec(),
                ed25519_pk: own.ed25519_pk.to_vec(),
                ed25519_sk: own.ed25519_sk.to_vec(),
            })
            .unwrap();
        state
            .client
            .db
            .lock()
            .unwrap()
            .insert_contact(&ContactModel {
                user_id: "bob".into(),
                username: "Bob".into(),
                public_key: peer.public_key.to_vec(),
                ed25519_pk: Some(peer.ed25519_pk.to_vec()),
                trust_state: "verified".into(),
                fingerprint: "test".into(),
                key_changed: false,
                added_at: 0,
            })
            .unwrap();
        Fixture {
            state: Some(state),
            directory,
        }
    }
    #[tokio::test]
    async fn missed_tasks_remain_encrypted_editable_and_do_not_allocate_a_chain() {
        let peer = crypto::generate_keypair().unwrap();
        let fixture = fixture(&peer);
        let state = fixture.state.as_ref().unwrap();
        let due = now() + 6000;
        let id = uuid::Uuid::new_v4().to_string();
        save(
            state,
            Some(id.clone()),
            "bob".into(),
            "private scheduled text".into(),
            due,
        )
        .await
        .unwrap();
        save(
            state,
            Some(id.clone()),
            "bob".into(),
            "private scheduled text".into(),
            due,
        )
        .await
        .unwrap();
        let saved = state.identity().unwrap();
        let tasks = rows(state, &saved).unwrap();
        assert_eq!(tasks.len(), 1);
        assert!(!tasks[0].body.windows(7).any(|bytes| bytes == b"private"));
        assert!(state
            .client
            .db
            .lock()
            .unwrap()
            .get_message(&id)
            .unwrap()
            .is_none());
        assert_eq!(process_at(state, due + 1).await.unwrap(), 1);
        assert_eq!(list(state).await.unwrap()[0].state, "missed");
        assert!(state
            .client
            .db
            .lock()
            .unwrap()
            .get_message(&id)
            .unwrap()
            .is_none());
        assert_eq!(process_at(state, due + 1000).await.unwrap(), 0);
        save(
            state,
            Some(id.clone()),
            "bob".into(),
            "rescheduled".into(),
            now() + 60000,
        )
        .await
        .unwrap();
        let mut interrupted = rows(state, &saved).unwrap().remove(0);
        interrupted.state = "sending".into();
        store(state, &saved, &interrupted).unwrap();
        suspend(state).await.unwrap();
        process_at(state, due + 2000).await.unwrap();
        assert_eq!(list(state).await.unwrap()[0].state, "missed");
        cancel(state, id, false).await.unwrap();
        assert!(list(state).await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn changed_contact_identity_prevents_sealing_a_scheduled_message() {
        let peer = crypto::generate_keypair().unwrap();
        let fixture = fixture(&peer);
        let state = fixture.state.as_ref().unwrap();
        let scheduled = save(
            state,
            None,
            "bob".into(),
            "identity-bound".into(),
            now() + 6000,
        )
        .await
        .unwrap();
        let saved = state.identity().unwrap();
        let mut task = rows(state, &saved).unwrap().remove(0);
        let mut contact = state
            .client
            .db
            .lock()
            .unwrap()
            .get_contact("bob")
            .unwrap()
            .unwrap();
        contact.public_key = crypto::generate_keypair().unwrap().public_key.to_vec();
        state
            .client
            .db
            .lock()
            .unwrap()
            .insert_contact(&contact)
            .unwrap();
        execute(state, &saved, &mut task).await.unwrap();
        assert_eq!(task.state, "failed");
        assert!(task.error.contains("身份已变化"));
        assert!(state
            .client
            .db
            .lock()
            .unwrap()
            .get_message(&scheduled.id)
            .unwrap()
            .is_none());
    }
    #[tokio::test]
    async fn execution_retry_and_reopening_preserve_one_message_and_envelope() {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let peer = crypto::generate_keypair().unwrap();
            let mut fixture = fixture(&peer); let state = fixture.state.as_ref().unwrap();
            let api_listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut saved=state.identity().unwrap();saved.server_url=format!("http://{}",api_listener.local_addr().unwrap());state.save_identity(saved.clone()).unwrap();
            let response=serde_json::json!([{"id":"device-b","name":"test","public_key":peer.public_key.to_vec(),"ed25519_pk":peer.ed25519_pk.to_vec(),"revoked":false}]).to_string();
            let api_task=tokio::spawn(async move {
                let (mut stream,_)=api_listener.accept().await.unwrap();
                let mut request=Vec::new();let mut chunk=[0u8;4096];
                while !request.windows(4).any(|part|part==b"\r\n\r\n") { let count=stream.read(&mut chunk).await.unwrap();assert!(count>0);request.extend_from_slice(&chunk[..count]); }
                assert!(String::from_utf8(request).unwrap().contains("/users/bob/devices"));
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",response.len(),response).as_bytes()).await.unwrap();
            });
            let ws_listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let ws_url=format!("http://{}",ws_listener.local_addr().unwrap());
            let (envelope_tx,mut envelope_rx)=tokio::sync::mpsc::unbounded_channel();
            let relay=tokio::spawn(async move {
                let (stream,_)=ws_listener.accept().await.unwrap();let mut ws=accept_async(stream).await.unwrap();
                let _=ws.next().await.unwrap().unwrap();ws.send(Message::Text("{\"type\":\"auth_ok\"}".into())).await.unwrap();
                while let Some(frame)=ws.next().await {
                    let frame=frame.unwrap();if frame.is_close(){break;}
                    if let Message::Text(text)=frame {
                        let body:serde_json::Value=serde_json::from_str(&text).unwrap();
                        envelope_tx.send(serde_json::from_value::<SignedEnvelopeV2>(body["envelopes"][0].clone()).unwrap()).unwrap();
                    }
                }
            });
            state.client.connect_relay(ws_url,"alice".into(),"test-token".into(),"device-a".into()).await.unwrap();
            let due=now()+6000;
            let task=save(state,None,"bob".into(),"send once".into(),due).await.unwrap();
            assert_eq!(process_at(state,due-1).await.unwrap(),0);
            assert_eq!(process_at(state,due).await.unwrap(),1);
            let first=envelope_rx.recv().await.unwrap();assert_eq!(first.sender_seq,1);assert_eq!(first.message_id,task.id);
            let signing_key: [u8;32]=saved.ed25519_pk.clone().try_into().unwrap();
            assert!(crypto::verify_with_public_key(&first.signing_bytes().unwrap(),&first.signature,&signing_key).unwrap());
            let received=chat::decrypt_message(first.ciphertext.clone(),saved.public_key.clone(),peer.secret_key.to_vec()).unwrap();
            assert_eq!(String::from_utf8(received).unwrap(),"\u{1e}LiteSeal:1:{\"text\":\"send once\"}");
            let mut interrupted=rows(state,&saved).unwrap().remove(0);interrupted.state="sending".into();store(state,&saved,&interrupted).unwrap();
            suspend(state).await.unwrap();assert_eq!(process_at(state,due+1).await.unwrap(),1);
            assert_eq!(list(state).await.unwrap()[0].state,"needs_retry");
            assert!(save(state,Some(task.id.clone()),"bob".into(),"changed".into(),now()+60000).await.is_err());
            assert!(cancel(state,task.id.clone(),false).await.is_err());
            assert_eq!(send_now(state,task.id.clone()).await.unwrap().state,"submitted");
            let retry=envelope_rx.recv().await.unwrap();assert_eq!(first,retry);
            assert_eq!(state.client.get_local_messages("dm:alice:bob",50,0).unwrap().len(),1);
            state.client.disconnect().await;relay.await.unwrap();api_task.await.unwrap();
            fixture.state.take();
            let reopened=AppState::with_keystore(fixture.directory.join("data.db").to_str().unwrap(),Some(fixture.directory.join("keys.bin"))).unwrap();
            assert_eq!(process_at(&reopened,due+1000).await.unwrap(),0);
            assert_eq!(list(&reopened).await.unwrap()[0].state,"submitted");
            drop(reopened);
        }).await.unwrap();
    }
}
