import { useEffect, useState } from "react";
import { getDesktopApi } from "../lib/desktopApi";
import type { ScheduledTask } from "../../../electron/contracts";

function localTime(timestamp: number) {
  const date = new Date(timestamp);
  return new Date(timestamp - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}
const labels: Record<string,string> = { scheduled:"等待计划时间",missed:"已错过时间，需要处理",failed:"准备失败，需要处理",sending:"执行中",needs_retry:"发件箱结果待确认",submitted:"已提交到发件箱（不等于送达）" };

export function ScheduledMessages({ peerId, initialText, online, revision, onChanged }: { peerId: string; initialText: string; online: boolean; revision: number; onChanged: () => void }) {
  const [open,setOpen] = useState(false);
  const [tasks,setTasks] = useState<ScheduledTask[]>([]);
  const [text,setText] = useState("");
  const [time,setTime] = useState("");
  const [editing,setEditing] = useState<string | undefined>();
  const [newId,setNewId] = useState(()=>crypto.randomUUID());
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState("");
  async function reload() { setTasks((await getDesktopApi().list_scheduled_messages({})).filter(task=>task.peer_id===peerId)); }
  useEffect(() => {
    let active=true;
    void getDesktopApi().list_scheduled_messages({}).then(rows=>{if(active)setTasks(rows.filter(task=>task.peer_id===peerId));}).catch(failure=>{if(active)setError(String(failure));});
    return()=>{active=false;};
  },[peerId,revision]);
  async function action(work:()=>Promise<unknown>) {
    setBusy(true);setError("");
    try { await work(); await reload(); onChanged(); }
    catch(failure){setError(String(failure));}
    finally{setBusy(false);}
  }
  return <section aria-label="本机定时消息" style={{padding:"6px 24px"}}>
    <button onClick={()=>{ if(!open){setText(initialText);setTime(localTime(Date.now()+5*60_000));setEditing(undefined);} setOpen(value=>!value); }}>本机定时文字 · {tasks.length} 个任务</button>
    {tasks.some(task=>["missed","failed","needs_retry"].includes(task.state)) && <p role="status">有定时任务需要处理，未自动补发。</p>}
    {open && <div>
      <p>应用持续运行且联网时执行，收起或锁定后已安排的任务仍可执行；错过时间需手动处理。这里只安排文字副本，不含引用、转发或附件，也不会清空当前草稿。</p>
      <label>定时文字 <textarea value={text} disabled={busy} onChange={event=>setText(event.target.value)} /></label>
      <label>本机计划时间 <input type="datetime-local" value={time} disabled={busy} onChange={event=>setTime(event.target.value)} /></label>
      <button disabled={busy || !text.trim() || !time} onClick={()=>void action(async()=>{
        await getDesktopApi().save_scheduled_message({id:editing ?? newId,peerId,text,dueAt:new Date(time).getTime()});
        setEditing(undefined);setNewId(crypto.randomUUID());setText("");
      })}>{editing ? "保存修改" : "保存定时任务"}</button>
      {editing && <button disabled={busy} onClick={()=>{setEditing(undefined);setText("");}}>取消编辑</button>}
      <button disabled={busy} onClick={()=>void action(reload)}>刷新任务</button>
      {tasks.map(task=><div key={task.id} style={{borderTop:"1px solid var(--border)",padding:8}}>
        <p>{new Date(task.due_at).toLocaleString()} · {labels[task.state] ?? task.state}</p>
        <p style={{whiteSpace:"pre-wrap"}}>{task.text}</p>
        {task.error && <p role="alert">{task.error}</p>}
        {!task.sealed && ["scheduled","missed","failed"].includes(task.state) && <button disabled={busy} onClick={()=>{setEditing(task.id);setText(task.text);setTime(localTime(Math.max(task.due_at,Date.now()+5*60_000)));}}>修改文字/时间</button>}
        {task.state!=="submitted" && <button disabled={busy || !online || task.state==="sending"} onClick={()=>{
          if(window.confirm(task.sealed ? "沿用原消息编号重试？若服务端已接受，不会创建第二条消息。" : "现在发送这条定时文字？")) void action(()=>getDesktopApi().send_scheduled_now({id:task.id}));
        }}>{task.sealed ? "重试原消息" : "立即发送"}</button>}
        {(!task.sealed || task.state==="submitted") && <button disabled={busy} onClick={()=>void action(()=>getDesktopApi().cancel_scheduled_message({id:task.id,removeSubmitted:task.state==="submitted"}))}>{task.state==="submitted" ? "移除任务记录（保留消息）" : "取消定时任务"}</button>}
      </div>)}
    </div>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
