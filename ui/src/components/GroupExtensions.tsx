import { useEffect,useState } from "react";
import type { GroupActivity,GroupExtensionCommand,GroupMember,GroupExtensions } from "../../../electron/contracts";
import { getDesktopApi } from "../lib/desktopApi";
import { AttachmentCard } from "./Attachments";
export function ActivityCard({activity:a,members=[],userId="",submit}:{activity:GroupActivity;members?:GroupMember[];userId?:string;submit?:(command:GroupExtensionCommand)=>Promise<void>}){
  const [busy,setBusy]=useState(false),[error,setError]=useState(""),[confirmation,setConfirmation]=useState<"close"|"cancel"|null>(null);
  const name=(id:string)=>members.find(m=>m.user_id===id)?.name??id;
  async function act(command:GroupExtensionCommand){setBusy(true);setError("");try{await submit?.(command);setConfirmation(null);}catch(e){setError(String(e));}finally{setBusy(false);}}
  const answers={yes:"参加",no:"不参加",maybe:"待定"};
  return <section className="group-activity" aria-label="活动邀请"><strong>{a.title}</strong><p>{new Date(a.start_at).toLocaleString()} · 创建时区 {a.timezone}</p>{a.location&&<p>地点：{a.location}</p>}{a.description&&<p className="group-activity-description">{a.description}</p>}<p>发起人：{name(a.creator)} · {a.cancelled?"活动已取消":a.closed?"报名已关闭，活动仍有效":"报名开放"}</p>
    <div className="group-actions">{Object.entries(answers).map(([answer,label])=><button key={answer} aria-pressed={a.responses[userId]===answer} disabled={!submit||busy||a.closed||!a.eligible} onClick={()=>void act({kind:"respond",activity:a.id,revision:a.revision,answer:answer as "yes"|"no"|"maybe"})}>{label} ({Object.values(a.responses).filter(v=>v===answer).length})</button>)}</div>
    {a.eligible&&!a.responses[userId]&&<p>你尚未回应</p>}
    <details><summary>实名报名状态</summary><ul>{a.participants.map(id=><li key={id}>{name(id)}：{a.responses[id]?answers[a.responses[id]]:"未回应"}{a.departed.includes(id)?"（已离开）":""}</li>)}</ul></details>
    {submit&&a.can_manage&&!a.cancelled&&<div className="group-actions">{!a.closed&&<button disabled={busy} onClick={()=>setConfirmation("close")}>关闭报名</button>}<button disabled={busy} onClick={()=>setConfirmation("cancel")}>取消活动</button></div>}
    {confirmation&&<div role="group" aria-label="确认活动操作"><p>{confirmation==="close"?"关闭后成员不能改选，活动仍有效。此操作不可撤销。":"取消活动会同时关闭报名。此操作不可撤销。"}</p><button disabled={busy} onClick={()=>void act({kind:confirmation,activity:a.id,revision:a.revision})}>确认{confirmation==="close"?"关闭报名":"取消活动"}</button><button disabled={busy} onClick={()=>setConfirmation(null)}>返回</button></div>}{error&&<p role="alert">{error}</p>}
  </section>;
}
export function GroupExtensionCard({groupId,messageId,members,userId}:{groupId:string;messageId:string;members:GroupMember[];userId:string}){
  const [view,setView]=useState<GroupExtensions|null>(null),[error,setError]=useState("");
  useEffect(()=>{let alive=true;const load=()=>getDesktopApi().get_group_extensions({groupId,messageIds:[messageId]}).then(v=>{if(alive)setView(v);}).catch(e=>{if(alive)setError(String(e));});void load();const timer=setInterval(()=>void load(),10000);window.addEventListener("liteseal-groups-changed",load);return()=>{alive=false;clearInterval(timer);window.removeEventListener("liteseal-groups-changed",load);};},[groupId,messageId]);
  const file=view?.attachments.find(f=>f.id===messageId),activity=view?.activities.find(a=>a.id===messageId);
  if(file)return <div><strong>{file.name}</strong><p>{(file.size/1024).toFixed(1)} KiB{file.duration_ms?` · ${Math.ceil(file.duration_ms/1000)} 秒`:""}</p><AttachmentCard target={{kind:"group",id:groupId}} messageId={messageId} name={file.name} image={file.mime.startsWith("image/")} audio={file.mime==="audio/webm"&&!!file.duration_ms}/></div>;
  if(activity)return <ActivityCard activity={activity} members={members} userId={userId} submit={async command=>{try{await getDesktopApi().submit_group_extension({groupId,command});}finally{await getDesktopApi().sync_group_extensions({groupId});setView(await getDesktopApi().get_group_extensions({groupId,messageIds:[messageId]}));}}}/>;
  return <p>群附件或活动详情尚未取得，或版本暂不支持。{error&&<span role="alert">{error}</span>}</p>;
}
export function ActivityComposer({groupId,onSent}:{groupId:string;onSent:()=>void}){
  const [title,setTitle]=useState(""),[start,setStart]=useState(""),[location,setLocation]=useState(""),[description,setDescription]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState("");
  return <details className="group-activity-composer"><summary>创建活动邀请</summary><form onSubmit={async event=>{event.preventDefault();setBusy(true);setError("");try{const start_at=new Date(start).getTime();if(!Number.isFinite(start_at))throw new Error("开始时间无效");await getDesktopApi().submit_group_extension({groupId,command:{kind:"activity",title:title.trim(),start_at,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,location,description}});setTitle("");setStart("");setLocation("");setDescription("");onSent();}catch(e){setError(String(e));}finally{setBusy(false);}}}><label>标题<input aria-label="活动标题" required maxLength={100} disabled={busy} value={title} onChange={e=>setTitle(e.target.value)}/></label><label>开始时间<input aria-label="活动开始时间" type="datetime-local" required disabled={busy} value={start} onChange={e=>setStart(e.target.value)}/></label><label>地点（可选）<input maxLength={200} disabled={busy} value={location} onChange={e=>setLocation(e.target.value)}/></label><label>说明（可选）<textarea maxLength={1000} disabled={busy} value={description} onChange={e=>setDescription(e.target.value)}/></label><p>创建后内容固定。实名报名可改选，发起人或群主可关闭报名或取消活动。开始时间不会自动停止报名。</p><button disabled={busy||!title.trim()||!start}>发布活动</button>{error&&<p role="alert">{error}；原任务保留，请处理待发扩展任务。</p>}</form></details>;
}
