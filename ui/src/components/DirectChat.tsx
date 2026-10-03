import {useEffect,useRef,useState} from "react";
import {getDesktopApi} from "../lib/desktopApi";
import "./direct-chat.css";
import {useDirectDraft} from "../hooks/useDirectDraft";
import {DirectMediaComposer,DirectMediaCard} from "./DirectMedia";
import {DirectMessageOperations,DirectOperationTasks} from "./DirectOperations";
import {DirectStorage} from "./DirectStorage";
import {HistoryTransfers} from "./HistoryTransfers";
import {AudioCallPanel} from "./AudioCallPanel";
import type {DirectSnapshot,DirectPeer,DirectHistory,DirectCondition,DirectProgress} from "../../../electron/contracts";
const conditions:Record<DirectCondition,string>={paused:"原媒体传输已暂停",uploading:"正在上传原媒体分块",uploaded:"原媒体上传已完成",downloading:"正在下载原媒体分块",cached:"附件已完整认证",failed:"附件认证失败，原消息保留",unavailable:"原附件远端不可用",prepared:"原发送编号已保存",accepted:"服务端已接受原消息",cancelled:"原任务已确认取消",syncing:"正在校验授权目录，请继续原任务",needs_trust:"请先核对对方账号与原设备根指纹",conflict:"原目录或任务冲突，请查询原结果，不会重签",retry:"原结果尚未确认，请继续原编号",session_required:"正式会话需要恢复或续期，原任务保留",unsupported:"此协议或消息类型尚不支持，原数据保留",idle:"暂时没有新消息",received:"新消息已认证并保存",acknowledged:"已确认本机保存结果"};
export default function DirectChat({onFlushReady,obscured=false}:{onFlushReady?:(flush:()=>Promise<void>)=>void;obscured?:boolean}){
  const [view,setView]=useState<DirectSnapshot|null>(null),[messages,setMessages]=useState<DirectHistory["messages"]>([]),[cursor,setCursor]=useState<number|null>(null);
  const [account,setAccount]=useState(""),[candidate,setCandidate]=useState<DirectPeer|null>(null),[fingerprint,setFingerprint]=useState(""),[peer,setPeer]=useState("");
  const draft=useDirectDraft();
  useEffect(()=>{onFlushReady?.(async()=>{if(peer)await draft.flush();});});
  const [busy,setBusy]=useState(false),[error,setError]=useState(""),[status,setStatus]=useState("");
  const live=useRef(false),paused=useRef(false),epoch=useRef(0),operation=useRef<number|null>(null),pendingRefresh=useRef(false);
  const selectedPeer=useRef("");
  const current=(n:number)=>live.current&&!paused.current&&epoch.current===n;
  async function run(work?:(n:number)=>Promise<void>,append=false,replace=false){
    if(!live.current||paused.current||operation.current!==null&&!replace){if(!work)pendingRefresh.current=true;return;}
    const n=replace?++epoch.current:epoch.current;operation.current=n;setBusy(true);setError("");
    try{await work?.(n);if(!current(n))return;const [next,history]=await Promise.all([getDesktopApi().get_direct_chat({}),getDesktopApi().get_direct_history({account:selectedPeer.current||null,before:append?cursor:null})]);if(!current(n))return;
      setView(next);setCursor(history.next_cursor);setMessages(old=>append?[...old,...history.messages.filter(row=>!old.some(m=>m.id===row.id))]:history.messages);
    }catch(e){if(current(n)){setError(String(e));if(work){try{const next=await getDesktopApi().get_direct_chat({});if(current(n))setView(next);}catch{/* Original result remains unknown; no replacement task is prepared. */}}}}
    finally{if(operation.current===n)operation.current=null;if(current(n)){setBusy(false);if(pendingRefresh.current){pendingRefresh.current=false;void run();}}}
  }
  useEffect(()=>{live.current=true;paused.current=false;epoch.current++;operation.current=null;void run();
    const stop=()=>{paused.current=true;epoch.current++;operation.current=null;pendingRefresh.current=false;selectedPeer.current="";setView(null);setMessages([]);setCandidate(null);setFingerprint("");draft.pause();setAccount("");setPeer("");setStatus("");setError("聊天已暂停，请解锁后重新打开原档案");setBusy(false);};
    const changed=()=>{void run();};const progress=(event:Event)=>{const result=(event as CustomEvent<{task:DirectProgress|null;poll:{condition:DirectCondition}|null;media?:{condition:DirectCondition}|null;operation?:{condition:DirectCondition}|null;operation_poll?:{condition:DirectCondition}|null;errors?:string[]}>).detail;if(!paused.current){const condition=result?.operation?.condition??result?.media?.condition??result?.poll?.condition??result?.task?.condition??result?.operation_poll?.condition;if(condition)setStatus(conditions[condition]);if(result?.errors?.length)setError(result.errors.join("；"));}};
    window.addEventListener("liteseal-device-paused",stop);window.addEventListener("liteseal-app-locked",stop);window.addEventListener("liteseal-direct-changed",changed);window.addEventListener("liteseal-direct-status",progress);
    return()=>{live.current=false;epoch.current++;window.removeEventListener("liteseal-device-paused",stop);window.removeEventListener("liteseal-app-locked",stop);window.removeEventListener("liteseal-direct-changed",changed);window.removeEventListener("liteseal-direct-status",progress);};
  },[]);
  async function inspect(){const n=epoch.current;setCandidate(null);setFingerprint("");await run(async()=>{const result=await getDesktopApi().inspect_direct_peer({account:account.trim()});if(current(n))setCandidate(result);});}
  async function choose(value:string){let n=epoch.current;try{if(peer)await draft.flush();if(!current(n))return;n=++epoch.current;operation.current=null;selectedPeer.current=value;setPeer(value);setMessages([]);setCursor(null);if(value)await draft.load(value);else draft.pause();if(current(n))await run();}catch(e){if(current(n))setError(String(e));}}
  useEffect(()=>{const scope=view?.notification_scope;if(!scope||paused.current)return;
    let active=true;const api=getDesktopApi();
    const context=()=>{void api.set_direct_notification_context({scope,activeAccount:!obscured&&document.visibilityState==="visible"&&document.hasFocus()?peer||null:null}).catch(()=>{});};
    const target=async()=>{if(obscured||paused.current)return;const n=epoch.current;try{const next=await api.take_direct_notification_target({scope});if(active&&current(n)&&next)await choose(next.peer);}catch{/* A changed or locked scope cannot route an old notification. */}};
    const focus=()=>{context();void target();};context();void target();
    window.addEventListener("focus",focus);window.addEventListener("blur",context);document.addEventListener("visibilitychange",context);window.addEventListener("liteseal-direct-notification-target",focus);
    return()=>{active=false;window.removeEventListener("focus",focus);window.removeEventListener("blur",context);document.removeEventListener("visibilitychange",context);window.removeEventListener("liteseal-direct-notification-target",focus);void api.set_direct_notification_context({scope,activeAccount:null}).catch(()=>{});};
  },[view?.notification_scope,peer,obscured]);
  async function send(){const n=epoch.current;await run(async()=>{const saved=await draft.flush();try{const prepared=await getDesktopApi().prepare_direct_text({account:peer,text:saved.text,draftRevision:saved.revision});if(!current(n))return;setStatus(conditions[prepared.condition]);if(prepared.task){await draft.consumed(saved.revision,saved.version,prepared.task.id);const progress=await getDesktopApi().direct_task_step({id:prepared.task.id});if(current(n))setStatus(conditions[progress.condition]);}}catch(e){if(current(n)){try{await draft.consumed(saved.revision,saved.version);}catch{/* Read failure keeps local text and original task. */}}throw e;}});}
  return <section aria-label="v3 文字聊天" className="direct-chat"><h2>文字聊天</h2>
    {view&&<><details><summary>分享本账号的原设备根身份</summary><p>账号 {view.identity.account} · {view.identity.origin}</p><p>根指纹 {view.identity.root_fingerprint}</p><p>当前设备 {view.device}</p></details>
      <details><summary>核对新的聊天账号</summary><p>从对方原设备独立取得完整根指纹后核对。查询候选身份不会自动信任它。</p><label>对方账号编号<input aria-label="对方账号编号" value={account} disabled={busy||paused.current} onChange={e=>{setAccount(e.target.value);setCandidate(null);setFingerprint("");}} maxLength={128}/></label>
        <button disabled={busy||paused.current||!view.can_network||!account.trim()} onClick={()=>void inspect()}>查询对方根身份</button>
        {candidate&&<><p>候选账号 {candidate.account} · {candidate.origin}</p><p>根指纹 {candidate.root_fingerprint}</p><p>加密指纹 {candidate.encryption_fingerprint}</p><p>签名指纹 {candidate.signing_fingerprint}</p><label>从对方原设备取得的完整根指纹<input aria-label="核对对方根指纹" maxLength={64} value={fingerprint} disabled={busy||paused.current} onChange={e=>setFingerprint(e.target.value.trim())}/></label><button disabled={busy||paused.current||fingerprint!==candidate.root_fingerprint} onClick={()=>void run(async n=>{await getDesktopApi().confirm_direct_peer({account:candidate.account,fingerprint});if(!current(n))return;setCandidate(null);setFingerprint("");await choose(candidate.account);})}>确认对方原设备根身份</button></>}
      </details>
      <ul aria-label="v3 会话列表">{view.conversations.map(c=><li key={c.peer}><button disabled={busy||paused.current} aria-pressed={peer===c.peer} onClick={()=>void choose(c.peer)}>{c.peer}</button><span> · 未读 {c.unread}{c.muted?" · 已静音":""}{c.has_draft?" · 有草稿":""}</span></li>)}</ul>
      <label>聊天账号<select aria-label="聊天账号" value={peer} disabled={busy||paused.current} onChange={e=>void choose(e.target.value)}><option value="">所有会话历史（请选择账号发送）</option>{view.peers.map(p=><option key={p.account} value={p.account}>{p.account}</option>)}</select></label>
      {peer&&view.conversations.filter(c=>c.peer===peer).map(c=><div key={c.peer}><p>此会话未读 {c.unread}。标记已读包含当前页及更早历史，之后到达的消息保留未读。</p><button disabled={busy||paused.current||!messages.length} onClick={()=>void run(()=>getDesktopApi().mark_direct_read({account:peer,throughId:messages[0].id}))}>将此页及更早消息标记已读</button><button disabled={busy||paused.current} onClick={()=>void run(()=>getDesktopApi().set_direct_muted({account:peer,revision:c.revision,muted:!c.muted}))}>{c.muted?"取消此会话静音":"静音此会话"}</button></div>)}
      <label>文字<textarea aria-label="v3 消息正文" value={draft.text} disabled={busy||paused.current||!draft.ready} onChange={e=>draft.edit(e.target.value)} maxLength={65536}/></label><button disabled={busy||paused.current||!view.can_network||!peer||!draft.text||!draft.ready||!!draft.error||view.tasks.some(t=>t.peer===peer&&!["accepted","cancelled"].includes(t.state))} onClick={()=>void send()}>发送加密文字</button>
      {peer&&<DirectMediaComposer key={`media:${view.notification_scope}:${peer}`} scope={view.notification_scope} account={peer} online={view.can_network} paused={obscured||paused.current} onChanged={()=>void run()}/>}
      <DirectOperationTasks view={view} paused={obscured||paused.current} onChanged={()=>void run()}/>
      <AudioCallPanel key={`audio:${view.notification_scope}`} scope={view.notification_scope} peer={peer} online={view.can_network} paused={obscured||paused.current}/>
      <DirectStorage key={`storage:${view.notification_scope}`} scope={view.notification_scope} paused={obscured||paused.current} onChanged={()=>void run()}/>
      <HistoryTransfers key={`history:${view.notification_scope}:${peer}`} scope={view.notification_scope} account={peer} originals={messages} online={view.can_network} paused={obscured||paused.current}/>
      <details><summary>原发送任务（{view.tasks.length}）</summary>{view.tasks.map(task=><div key={task.id} aria-label="v3 原发送任务"><p>{task.peer} · {task.state} · 原编号 {task.id}{task.cancel_requested?" · 已请求取消":""}</p>
        {!["accepted","cancelled"].includes(task.state)&&<><button disabled={busy||paused.current} onClick={()=>void run(async n=>{const progress=await getDesktopApi().direct_task_step({id:task.id});if(current(n))setStatus(conditions[progress.condition]);})}>继续原发送任务</button><button disabled={paused.current||task.cancel_requested} onClick={()=>void run(async n=>{await getDesktopApi().cancel_direct_task({id:task.id});if(current(n))setStatus("取消意图已保存，请继续原任务确认结果");},false,true)}>取消原发送任务</button></>}
        {task.state==="accepted"&&<button disabled={busy||paused.current} onClick={()=>{if(window.confirm("整理这个已确认的任务？消息历史保留。"))void run(()=>getDesktopApi().forget_direct_task({id:task.id}));}}>整理原发送结果</button>}
      </div>)}</details>
    </>}
    <div style={{display:"flex",gap:"8px",flexWrap:"wrap"}}><button disabled={busy||paused.current} onClick={()=>void run()}>刷新文字历史</button><button disabled={busy||paused.current||cursor===null} onClick={()=>void run(undefined,true)}>加载更早的文字</button></div>
    {peer&&<p role="status">{!draft.ready?"正在核对草稿状态…":draft.saving?"正在加密保存草稿…":draft.dirty?"当前正文尚未保存":"草稿已保存在此档案"}</p>}{draft.error&&<p role="alert">{draft.error}</p>}{peer&&<button disabled={busy||paused.current||!draft.ready} onClick={()=>void run(async()=>{await draft.flush();})}>保存此账号草稿</button>}{peer&&<button disabled={busy||paused.current} onClick={()=>{if(!draft.dirty||window.confirm("重新读取已保存草稿？此处未保存正文会被替换，请先保留需要的文字。"))void draft.load(peer);}}>重新读取草稿</button>}<ol aria-label="v3 文字历史">{messages.map(message=><li key={message.id} data-own={message.role!=="incoming"}><p>{message.role!=="incoming"?"发给":"来自"} {message.peer} · {new Date(message.sent_at).toLocaleString()}</p>{message.transferred_update?<p>后续变更来自原设备授权，请查看下方授权副本。</p>:message.retracted?<p>消息已撤回</p>:message.media&&view?<DirectMediaCard scope={view.notification_scope} info={message.media} paused={obscured||paused.current}/>:<p style={{whiteSpace:"pre-wrap"}}>{message.text??"正文不可用或认证失败，原记录保留"}</p>}{message.operation_revision&&!message.retracted?<small>已编辑 · 版本 {message.operation_revision}</small>:null}{view&&<DirectMessageOperations key={view.notification_scope+message.id} scope={view.notification_scope} device={view.device} message={message} pending={view.operations.some(t=>t.target===message.id&&!["accepted","cancelled"].includes(t.state))} paused={obscured||paused.current||!view.can_network} onChanged={()=>void run()}/>}<button disabled={busy||paused.current} onClick={()=>{if(window.confirm("从此档案隐藏这条消息？补收不会重新显示正文。"))void run(()=>getDesktopApi().hide_direct_message({id:message.id}));}}>在本机隐藏</button></li>)}</ol>
    {status&&<p role="status">{status}</p>}{error&&<p role="alert">{error}</p>}
  </section>;
}
