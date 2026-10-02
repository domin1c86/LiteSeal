//! Bind public SQLite ordering metadata in the existing native-protected table.
//! Legacy message projections did not cover rowid; read boundaries must do so.
use super::{db, invalid};
use rusqlite::{params, Connection};
const KIND: &str = "direct_v3_order";
fn scope(owner: &str) -> String {
    format!("order:{owner}")
}
pub(super) fn insert(conn: &Connection, owner: &str, id: &str, cursor: i64) -> Result<(), String> {
    if cursor <= 0 {
        return Err(invalid());
    }
    let body = serde_json::to_vec(&serde_json::json!({"cursor":cursor})).map_err(|_| invalid())?;
    conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,1,?3,1,?4)",params![scope(owner),id,KIND,body]).map_err(db)?;
    Ok(())
}
pub(super) fn check(conn: &Connection, owner: &str) -> Result<(), String> {
    let bad: bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM direct_v3_records r LEFT JOIN device_control_tasks t ON t.scope=?2 AND t.id=r.id WHERE r.scope=?1 AND (t.id IS NULL OR t.kind!=?3 OR t.revision!=1 OR t.terminal!=1 OR json_extract(CAST(t.body AS TEXT),'$.cursor') IS NOT r.rowid))",params![owner,scope(owner),KIND],|r|r.get(0)).map_err(db)?;
    if bad {
        return Err("单聊 v3 本机历史顺序已变化，未更新已读或通知状态".into());
    }
    Ok(())
}
pub(super) fn initialize(conn: &Connection, owner: &str) -> Result<(), String> {
    let mut query=conn.prepare("SELECT r.id,r.rowid FROM direct_v3_records r WHERE r.scope=?1 AND NOT EXISTS(SELECT 1 FROM device_control_tasks t WHERE t.scope=?2 AND t.id=r.id)").map_err(db)?;
    let missing = query
        .query_map(params![owner, scope(owner)], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    for (id, cursor) in missing {
        insert(conn, owner, &id, cursor)?;
    }
    check(conn, owner)
}
