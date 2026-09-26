use crate::AppState;
use std::sync::OnceLock;
static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

pub fn enabled(state: &AppState) -> Result<bool, String> {
    let user = state.identity()?.user_id;
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .typing_enabled(&user)
        .map_err(|e| e.to_string())
}

pub async fn set_enabled(state: &AppState, value: bool) -> Result<(), String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let user = state.identity()?.user_id;
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .set_typing_enabled(&user, value)
        .map_err(|e| e.to_string())
}

pub async fn send(state: &AppState, peer: String, active: bool) -> Result<(), String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let saved = state.identity()?;
    if peer == saved.user_id || peer.len() > 128 {
        return Err("无效联系人".into());
    }
    {
        let db = state.client.db.lock().map_err(|e| e.to_string())?;
        if active
            && !db
                .typing_enabled(&saved.user_id)
                .map_err(|e| e.to_string())?
        {
            return Err("正在输入提示已关闭".into());
        }
        if db.get_contact(&peer).map_err(|e| e.to_string())?.is_none() {
            return Err("联系人不存在".into());
        }
    }
    state.client.send_typing(&saved.user_id, peer, active).await
}
