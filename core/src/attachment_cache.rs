pub const GROUP_SCHEMA:&str="CREATE TABLE IF NOT EXISTS group_attachment_cache(scope TEXT NOT NULL,user_id TEXT NOT NULL,group_id TEXT NOT NULL,id TEXT NOT NULL,joined INTEGER NOT NULL,metadata BLOB NOT NULL,ciphertext BLOB NOT NULL,offset INTEGER NOT NULL,direction TEXT NOT NULL,root TEXT NOT NULL DEFAULT '',PRIMARY KEY(scope,id));";
pub fn bytes(conn: &rusqlite::Connection, user: &str) -> rusqlite::Result<i64> {
    let direct:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='attachment_transfers' AND type='table')",[],|r|r.get(0))?;
    let groups:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='group_attachment_cache' AND type='table')",[],|r|r.get(0))?;
    let media:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='direct_v3_media_chunks' AND type='table')",[],|r|r.get(0))?;
    let group: i64 = if groups {
        conn.query_row(
        "SELECT COALESCE(SUM(length(ciphertext)),0) FROM group_attachment_cache WHERE user_id=?1",
        [user],
        |r| r.get(0),
    )?
    } else {
        0
    };
    Ok(group
        + if media {
            conn.query_row("SELECT COALESCE(SUM(length(ciphertext)),0) FROM direct_v3_media_chunks WHERE account=?1",[user],|r|r.get::<_,i64>(0))?
        } else {
            0
        }
        + if direct {
            conn.query_row("SELECT COALESCE(SUM(length(ciphertext)),0) FROM attachment_transfers WHERE user_id=?1",[user],|r|r.get::<_,i64>(0))?
        } else {
            0
        })
}
