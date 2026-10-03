//! Immutable signed operations and authenticated mutable intent/state. No edit
//! plaintext or key crosses the public task view or persists in task rows.
use super::*;
use liteseal_shared::direct_operation::{Outcome, Receipt};
const MAX_TASKS: usize = 128;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Task {
    domain: String,
    scope: String,
    id: String,
    target: String,
    revision: u64,
    state: TaskState,
    attempted: bool,
    cancel_requested: bool,
    operation_revision: u64,
    digest: [u8; 32],
    size: usize,
    hashes: Vec<[u8; 32]>,
    receipt: Option<Receipt>,
}
#[derive(Debug, Serialize)]
pub struct TaskView {
    pub id: String,
    pub target: String,
    pub peer: String,
    pub revision: u64,
    pub operation_revision: u64,
    pub action: Action,
    pub state: TaskState,
    pub digest: [u8; 32],
    pub cancel_requested: bool,
}
pub struct PrepareOperation<'a> {
    pub id: &'a str,
    pub target: &'a str,
    pub created_at: i64,
    pub action: Action,
    pub text: Option<&'a str>,
}
fn scope(owner: &Owner) -> String {
    format!("operation-task:{}", owner.scope())
}
fn wires(owner: &Owner) -> String {
    format!("operation-task-wire:{}", owner.scope())
}
fn view(task: &Task, operation: &Operation) -> TaskView {
    TaskView {
        id: task.id.clone(),
        target: task.target.clone(),
        peer: operation.original.header.peer.clone(),
        revision: task.revision,
        operation_revision: task.operation_revision,
        action: operation.header.action,
        state: task.state,
        digest: task.digest,
        cancel_requested: task.cancel_requested,
    }
}
fn load(
    conn: &Connection,
    owner: &Owner,
    id: &str,
    keys: &KeyPair,
) -> Result<Option<(Task, Operation)>, String> {
    let Some((revision, body)) = super::row(conn, &scope(owner), id)? else {
        return Ok(None);
    };
    let task: Task = decode(&body, keys)?;
    uuid(id)?;
    uuid(&task.target)?;
    if task.domain != "LiteSeal/direct-operation-task/v1"
        || task.scope != scope(owner)
        || task.id != id
        || task.revision != revision
        || revision > 1_000_000
        || task.size == 0
        || task.size > op::MAX_WIRE
        || task.hashes.len() != task.size.div_ceil(CHUNK)
        || !(1..=op::MAX_EVENTS as u64).contains(&task.operation_revision)
        || task.receipt.is_some() != (task.state == TaskState::Accepted)
        || task.cancel_requested && !task.attempted
        || task.state == TaskState::Prepared && task.attempted
    {
        return Err(invalid());
    }
    let mut wire = Vec::with_capacity(task.size);
    for (part, hash) in task.hashes.iter().enumerate() {
        let (revision, bytes) =
            super::row(conn, &wires(owner), &format!("{id}:{part:02}"))?.ok_or_else(invalid)?;
        if revision != task.operation_revision
            || bytes.len() != CHUNK.min(task.size - part * CHUNK)
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != *hash
        {
            return Err(invalid());
        }
        wire.extend(bytes);
    }
    let operation = Operation::from_wire(&wire).map_err(|_| invalid())?;
    if operation.header.id != id
        || operation.original.header.id != task.target
        || operation.header.revision != task.operation_revision
        || operation.digest().map_err(|_| invalid())? != task.digest
        || owner.role(&operation.original)? != "authored"
    {
        return Err(invalid());
    }
    let (sender, peer) = evidence(conn, &operation.original)?;
    operation
        .verify_original(&sender, &peer)
        .map_err(|_| invalid())?;
    drop(Zeroizing::new(
        operation
            .open(
                &sender,
                &peer,
                &owner.account,
                &owner.device.device_id,
                owner.member(&sender)?,
                keys,
            )
            .map_err(|_| invalid())?,
    ));
    let original = record(conn, &owner.scope(), &task.target)?.ok_or_else(invalid)?;
    let (batch, _) = checked_record(conn, owner, &original, keys)?;
    if original.outcome != "processed"
        || batch.digest().map_err(|_| invalid())? != operation.header.original
    {
        return Err(invalid());
    }
    if let Some(receipt) = &task.receipt {
        if receipt.id != id
            || receipt.digest != task.digest
            || receipt.revision != task.operation_revision
            || receipt.order <= 0
            || !(1..=8_640_000_000_000_000).contains(&receipt.accepted_at)
        {
            return Err(invalid());
        }
        let m = meta(
            conn,
            owner,
            &super::id(&task.target, task.operation_revision),
            keys,
        )?
        .ok_or_else(invalid)?;
        let (saved, _) = open(conn, owner, &m, keys)?;
        if saved.digest().map_err(|_| invalid())? != task.digest
            || m.order != receipt.order
            || m.accepted_at != receipt.accepted_at
        {
            return Err(invalid());
        }
    }
    Ok(Some((task, operation)))
}
fn all(conn: &Connection, owner: &Owner, keys: &KeyPair) -> Result<Vec<(Task, Operation)>, String> {
    let mut query = conn
        .prepare("SELECT id FROM device_control_tasks WHERE scope=?1 ORDER BY rowid LIMIT 129")
        .map_err(db)?;
    let ids = query
        .query_map([scope(owner)], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    if ids.len() > MAX_TASKS {
        return Err(invalid());
    }
    ids.into_iter()
        .map(|id| load(conn, owner, &id, keys)?.ok_or_else(invalid))
        .collect()
}
fn save(conn: &Connection, owner: &Owner, task: &mut Task, keys: &KeyPair) -> Result<(), String> {
    task.revision = task
        .revision
        .checked_add(1)
        .filter(|r| *r <= 1_000_000)
        .ok_or_else(invalid)?;
    put(conn, &scope(owner), &task.id, task.revision, task, keys)
}
impl Store {
    pub fn operation_peer(&mut self, target: &str, keys: &KeyPair) -> Result<String, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let row = record(conn, &owner.scope(), target)?.ok_or_else(invalid)?;
            let (batch, _) = checked_record(conn, &owner, &row, keys)?;
            if row.role != "authored" || row.outcome != "processed" {
                return Err(invalid());
            }
            Ok(batch.header.peer)
        })
    }
    pub fn operation_tasks(&mut self, keys: &KeyPair) -> Result<Vec<TaskView>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            all(conn, &owner, keys)
                .map(|rows| rows.iter().map(|(task, op)| view(task, op)).collect())
        })
    }
    /// Keep immutable wire/id evidence after removing a terminal task from the
    /// bounded active list; the same operation id can never be reused.
    pub fn clear_operation_task(
        &mut self,
        id: &str,
        expected: u64,
        keys: &KeyPair,
    ) -> Result<(), String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let (task, _) = load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if task.revision != expected
                || !matches!(task.state, TaskState::Accepted | TaskState::Cancelled)
            {
                return Err(conflict());
            }
            conn.execute(
                "DELETE FROM device_control_tasks WHERE scope=?1 AND id=?2",
                params![scope(&owner), id],
            )
            .map_err(db)?;
            Ok(())
        })
    }
    pub fn operation_task(&mut self, id: &str, keys: &KeyPair) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let (task, operation) = load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            Ok(view(&task, &operation))
        })
    }
    pub fn operation_original(&mut self, id: &str, keys: &KeyPair) -> Result<Operation, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            load(conn, &owner, id, keys)?
                .map(|(_, op)| op)
                .ok_or_else(invalid)
        })
    }
    pub fn prepare_operation(
        &mut self,
        request: PrepareOperation<'_>,
        keys: &KeyPair,
    ) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        uuid(request.id)?;
        uuid(request.target)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn|{
            if let Some((task,operation))=load(conn,&owner,request.id,keys)? {
                let (sender,peer)=evidence(conn,&operation.original)?;
                let text=Zeroizing::new(operation.open(&sender,&peer,&owner.account,&owner.device.device_id,owner.member(&sender)?,keys).map_err(|_|invalid())?);
                if task.target!=request.target||operation.header.action!=request.action||operation.header.created_at!=request.created_at||text.as_deref()!=request.text||task.cancel_requested||task.state==TaskState::Cancelled{return Err(conflict());}
                return Ok(view(&task,&operation));
            }
            let tasks=all(conn,&owner,keys)?;
            if tasks.len()>=MAX_TASKS{return Err("本机操作任务达到 128 项上限".into());}
            if tasks.iter().any(|(task,_)|task.target==request.target&&!matches!(task.state,TaskState::Accepted|TaskState::Cancelled)){return Err("原消息仍有未完成操作，请保留原任务".into());}
            if conn.query_row("SELECT EXISTS(SELECT 1 FROM device_control_tasks WHERE scope IN (?1,?2) AND id=?3)",params![super::wires(&owner),wires(&owner),format!("{}:00",request.id)],|r|r.get::<_,bool>(0)).map_err(db)?{return Err(conflict());}
            if conn.query_row("SELECT EXISTS(SELECT 1 FROM direct_v3_hidden WHERE scope=?1 AND id=?2)",params![owner.scope(),request.target],|r|r.get::<_,bool>(0)).map_err(db)?{return Err("原消息已隐藏，不能创建操作".into());}
            let row=record(conn,&owner.scope(),request.target)?.ok_or_else(invalid)?;
            if request.created_at < row.accepted_at || request.created_at - row.accepted_at > 48*60*60*1000 {return Err("已超过首次接收后的 48 小时操作期限".into());}
            let (original,_)=checked_record(conn,&owner,&row,keys)?;
            if row.role!="authored"||row.outcome!="processed"{return Err("只允许原发送设备操作已认证的原消息".into());}
            let (base,action,_)=projection(conn,&owner,&original,keys)?;
            if super::super::history_transfer::updates(conn,&owner,keys)?.get(request.target).is_some_and(|(revision,_)|*revision>base) {return Err("请先补收原操作日志；授权副本不授予操作准备权限".into())}
            if action==Some(Action::Retract){return Err("原消息已撤回".into());}
            let (old_sender,old_peer)=evidence(conn,&original)?;
            let sender=current(conn,&owner.origin,&owner.account)?;owner.member(&sender)?;
            let peer=current(conn,&owner.origin,&original.header.peer)?;
            let operation=Operation::make(original,(&old_sender,&old_peer),(&sender,&peer),keys,op::Header{version:1,id:request.id.into(),original:row.digest.try_into().map_err(|_|invalid())?,action:request.action,base,revision:base.checked_add(1).ok_or_else(invalid)?,created_at:request.created_at},request.text).map_err(|_|invalid())?;
            let wire=operation.to_wire().map_err(|_|invalid())?;
            let bytes: i64=conn.query_row("SELECT COALESCE(SUM(length(body)),0) FROM device_control_tasks WHERE scope=?1",[wires(&owner)],|r|r.get(0)).map_err(db)?;
            if bytes + wire.len() as i64 > LIMIT {return Err("本机原操作任务证据达到 32 MiB 上限，请保留原数据".into());}
            let task=Task{domain:"LiteSeal/direct-operation-task/v1".into(),scope:scope(&owner),id:request.id.into(),target:request.target.into(),revision:0,state:TaskState::Prepared,attempted:false,cancel_requested:false,operation_revision:operation.header.revision,digest:operation.digest().map_err(|_|invalid())?,size:wire.len(),hashes:wire.chunks(CHUNK).map(|b|Sha256::digest(b).into()).collect(),receipt:None};
            for (part,body) in wire.chunks(CHUNK).enumerate(){conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,1,?5)",params![wires(&owner),format!("{}:{part:02}",task.id),task.operation_revision,KIND,body]).map_err(db)?;}
            put(conn,&scope(&owner),&task.id,0,&task,keys)?;
            Ok(view(&task,&operation))
        })
    }
    pub fn begin_operation_publish(
        &mut self,
        id: &str,
        expected: u64,
        keys: &KeyPair,
    ) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let (mut task, operation) = load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if task.revision != expected
                || task.cancel_requested
                || !matches!(task.state, TaskState::Prepared | TaskState::Publishing)
            {
                return Err(conflict());
            }
            let (old_sender, old_peer) = evidence(conn, &operation.original)?;
            let sender = current(conn, &owner.origin, &owner.account)?;
            let peer = current(conn, &owner.origin, &operation.original.header.peer)?;
            if operation
                .verify_current(&old_sender, &old_peer, &sender, &peer)
                .is_err()
            {
                if task.state == TaskState::Conflict {
                    return Ok(view(&task, &operation));
                }
                task.state = TaskState::Conflict;
            } else {
                if task.state == TaskState::Publishing {
                    return Ok(view(&task, &operation));
                }
                task.state = TaskState::Publishing;
                task.attempted = true;
            }
            save(conn, &owner, &mut task, keys)?;
            Ok(view(&task, &operation))
        })
    }
    pub fn request_operation_cancel(
        &mut self,
        id: &str,
        expected: u64,
        keys: &KeyPair,
    ) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let (mut task, operation) = load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if task.revision != expected {
                return Err(conflict());
            }
            if matches!(task.state, TaskState::Accepted | TaskState::Cancelled)
                || task.cancel_requested
            {
                return Ok(view(&task, &operation));
            }
            if task.attempted {
                task.cancel_requested = true;
                task.state = TaskState::Publishing;
            } else {
                task.state = TaskState::Cancelled;
            }
            save(conn, &owner, &mut task, keys)?;
            Ok(view(&task, &operation))
        })
    }
    pub fn confirm_operation_result(
        &mut self,
        id: &str,
        expected: u64,
        response: &api::AuthenticatedOperationResult,
        keys: &KeyPair,
    ) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let (mut task, operation) = load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if task.revision != expected
                || response.origin != owner.origin
                || response.account != owner.account
                || response.device != owner.device.device_id
                || response.digest != task.digest
            {
                return Err(conflict());
            }
            match &response.outcome {
                Outcome::Unknown { id: remote, digest }
                    if *remote == task.id
                        && *digest == task.digest
                        && !matches!(task.state, TaskState::Accepted | TaskState::Cancelled) =>
                {
                    return Ok(view(&task, &operation))
                }
                Outcome::Cancelled { id: remote, digest }
                    if *remote == task.id
                        && *digest == task.digest
                        && task.state != TaskState::Accepted =>
                {
                    if task.state == TaskState::Cancelled {
                        return Ok(view(&task, &operation));
                    }
                    if !task.attempted {
                        return Err(conflict());
                    }
                    task.state = TaskState::Cancelled;
                }
                Outcome::Accepted { receipt }
                    if receipt.id == task.id
                        && receipt.digest == task.digest
                        && receipt.revision == task.operation_revision =>
                {
                    if task.state == TaskState::Accepted {
                        if task.receipt.as_ref() != Some(receipt) {
                            return Err(invalid());
                        }
                        return Ok(view(&task, &operation));
                    }
                    if !task.attempted || task.state == TaskState::Cancelled {
                        return Err(conflict());
                    }
                    let authority = owner.member(&current(conn, &owner.origin, &owner.account)?)?;
                    persist_event(
                        conn,
                        &owner,
                        &Event {
                            order: receipt.order,
                            accepted_at: receipt.accepted_at,
                            operation: operation.clone(),
                        },
                        authority,
                        keys,
                    )?;
                    task.state = TaskState::Accepted;
                    task.receipt = Some(receipt.clone());
                }
                _ => return Err(invalid()),
            }
            save(conn, &owner, &mut task, keys)?;
            Ok(view(&task, &operation))
        })
    }
}
