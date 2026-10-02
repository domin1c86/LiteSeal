//! Root formal credentials come from the protected current-session record;
//! the existing DPAPI identity remains the source of immutable private keys.
use crate::AppState;
use liteseal_core::{
    keystore::KeystoreData,
    trusted_devices::activation::{jobs::Owner, refresh::jobs::Store},
};
use liteseal_shared::trusted_device::{canonical_origin, Anchor, DeviceIdentity};
pub(super) fn store(state: &AppState, saved: &KeystoreData) -> Result<Option<Store>, String> {
    if state.db_path.to_str() == Some(":memory:") {
        return Ok(None);
    }
    let witness = state.device_witness(&state.db_path)?;
    let conn = rusqlite::Connection::open_with_flags(
        &state.db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| "原正式会话存储不可用")?;
    let table:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_control_tasks')",[],|r|r.get(0)).map_err(|_|"原正式会话存储不可用")?;
    let initialized=table&&conn.query_row("SELECT EXISTS(SELECT 1 FROM device_control_tasks WHERE kind='session_refresh_current')",[],|r|r.get::<_,bool>(0)).map_err(|_|"原正式会话存储不可用")?;
    drop(conn);
    if !initialized {
        // A prepared device task can already have native protection before
        // its root is confirmed. Validate that protection without pinning or
        // requiring a current formal session that does not exist yet.
        if witness.has_record()? {
            let mut trust = liteseal_core::trusted_devices::DeviceTrustStore::open(&state.db_path)?;
            trust.protect(witness)?;
        }
        return Ok(None);
    }
    let keys = liteseal_core::backup::identity_keys(saved)?;
    let anchor = Anchor {
        origin: canonical_origin(&saved.server_url).map_err(|_| "原服务器范围无效")?,
        account: saved.user_id.clone(),
        root: DeviceIdentity::from_keys(saved.device_id.clone(), &keys),
    };
    Store::open(
        &state.db_path,
        Owner::new(anchor, &saved.device_id, &keys)?,
        &keys,
        witness,
    )
    .map(Some)
}
pub(crate) fn overlay(state: &AppState, mut saved: KeystoreData) -> Result<KeystoreData, String> {
    if let Some(mut store) = store(state, &saved)? {
        let keys = liteseal_core::backup::identity_keys(&saved)?;
        if let Some(session) = store.credentials(&keys)? {
            saved.token = session.access_token.clone();
            saved.refresh_token = session.refresh_token.clone();
        }
    }
    Ok(saved)
}
pub(crate) fn clear(state: &AppState, saved: &KeystoreData) -> Result<(), String> {
    if let Some(mut store) = store(state, saved)? {
        let keys = liteseal_core::backup::identity_keys(saved)?;
        if store.current_view(&keys)?.is_some() {
            store.clear_local(&keys)?;
        }
    }
    Ok(())
}
