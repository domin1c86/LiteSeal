import { useEffect,useRef,useState } from "react";
import { getDesktopApi } from "../lib/desktopApi";
import type { ActivationTask,ActivationProgress,RootMessagingSnapshot } from "../../../electron/contracts";
const stages:Record<ActivationTask["stage"],string>={prepared:"切换申请已保存",started:"正在查询原切换",proving:"正在完成原切换",conflict:"原切换发生冲突",complete:"单聊 v3 已启用",cancelled:"切换申请已取消",ineligible:"原身份资格已失效",ended:"原申请已结束"};
const outcomes:Record<ActivationProgress["condition"],string>={complete:"原切换已确认启用，不能撤回",cancelled:"原切换已确认取消",ineligible:"原身份资格已失效",needs_password:"需完成原设备会话验证",session_required:"原设备会话不可用，请先恢复正式会话后查询原切换",retry:"连接未完成，保留原切换继续查询或重试",conflict:"原目录或旧待收队列发生冲突，请先查询原状态，不会自动重签",pending:"原切换仍待处理",ended:"原申请已结束"};
const terminal=(task:ActivationTask)=>["complete","cancelled","ineligible","ended"].includes(task.stage);
export default function RootMessagingPanel({onClose}:{onClose:()=>void}){
  const [view,setView]=useState<RootMessagingSnapshot|null>(null),[confirmed,setConfirmed]=useState(false),[busy,setBusy]=useState(false),[status,setStatus]=useState(""),[error,setError]=useState("");
  const live=useRef(false),paused=useRef(false),epoch=useRef(0),operation=useRef<number|null>(null);
  const current=(n:number)=>live.current&&!paused.current&&epoch.current===n;
  async function run(work?:()=>Promise<string|void>,replace=false){
    if(!live.current||paused.current||operation.current!==null&&!replace)return;
    const n=replace?++epoch.current:epoch.current;operation.current=n;setBusy(true);setError("");
    try{const message=await work?.();if(!current(n))return;if(message)setStatus(message);const next=await getDesktopApi().get_root_messaging({});if(current(n)){setView(next);setConfirmed(false);}}
    catch(failure){if(current(n))setError(String(failure));}
    finally{if(operation.current===n)operation.current=null;if(current(n))setBusy(false);}
  }
  useEffect(()=>{live.current=true;paused.current=false;epoch.current++;operation.current=null;void run();
    const stop=()=>{paused.current=true;epoch.current++;operation.current=null;setView(null);setConfirmed(false);setBusy(false);setStatus("");setError("原设备切换已暂停，请解锁后重新打开");};
    window.addEventListener("liteseal-app-locked",stop);window.addEventListener("liteseal-device-paused",stop);
    return()=>{live.current=false;epoch.current++;window.removeEventListener("liteseal-app-locked",stop);window.removeEventListener("liteseal-device-paused",stop);};
  },[]);
  const pending=view&&Object.values(view.pending).some(n=>n>0);
  const active=view?.tasks.some(task=>!terminal(task));
  return <section aria-label="原设备单聊协议切换">
    <h3>原设备单聊协议切换</h3>
    <p>启用单聊 v3 后，旧版客户端不能继续单聊，切换不能撤回。群功能和已有历史保留。当前消息界面仍待接入新协议，启用后单聊会暂停。</p>
    <button disabled={busy||paused.current} onClick={()=>void run()}>刷新本机切换状态</button>
    <button disabled={busy||paused.current} onClick={()=>void run(async()=>{const result=await getDesktopApi().check_root_messaging({});return result.admission==="v3"?"已校验原设备签署的启用配置":"已查询远端状态，原任务保留";})}>查询远端启用状态</button>
    <button onClick={onClose}>收起协议切换</button>
    {view&&<>
      <p>{view.admission==="v3"?"单聊 v3 已启用，旧单聊发送已暂停":view.admission==="switching"?"原切换待确认，新的旧单聊任务已暂停":"当前继续使用旧单聊协议"}</p>
      <p>原设备完整指纹</p><code>{view.root_fingerprint}</code>
      <p>待处理：单聊 {view.pending.messages}，上传 {view.pending.uploads}，定时 {view.pending.scheduled}，编辑/撤回 {view.pending.operations}，回应 {view.pending.reactions}，回执 {view.pending.receipts}</p>
      {pending&&<p role="status">请先处理这些原任务，再准备切换；不会删除任务或历史。</p>}
      {view.tasks.map(task=><div key={task.id} aria-label="原切换任务"><p>{stages[task.stage]} · 原编号 {task.id}{task.cancel_requested?" · 取消请求已保存":""}</p>
        {!terminal(task)&&<>
          <button disabled={busy||paused.current} onClick={()=>void run(async()=>outcomes[(await getDesktopApi().root_messaging_step({id:task.id})).condition])}>{task.cancel_requested?"确认原切换取消结果":"查询或继续原切换"}</button>
          <button disabled={paused.current||task.cancel_requested} onClick={()=>{setConfirmed(false);void run(async()=>{const result=await getDesktopApi().cancel_root_messaging({id:task.id});return result.stage==="cancelled"?"未发布的原切换申请已取消":"取消意图已保存，请继续原切换确认结果";},true);}}>取消原切换申请</button>
        </>}
        {["cancelled","ineligible","ended"].includes(task.stage)&&<button disabled={busy||paused.current} onClick={()=>{if(window.confirm("整理这个已明确结束的原切换任务？身份和历史保留。"))void run(()=>getDesktopApi().forget_root_messaging({id:task.id}));}}>整理切换终态任务</button>}
      </div>)}
      {view.admission==="legacy"&&<><label><input type="checkbox" disabled={busy||!!active||!!pending||paused.current} checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/>已核对原设备指纹，确认不可撤回的切换和单聊暂停</label>
        <button disabled={busy||!!active||!!pending||!confirmed||paused.current} onClick={()=>{const fingerprint=view.root_fingerprint;setConfirmed(false);void run(async()=>{await getDesktopApi().prepare_root_messaging({confirmedFingerprint:fingerprint});return "原切换已保存，继续该编号完成启用；新的旧单聊任务已暂停";});}}>准备原设备协议切换</button></>}
    </>}
    {status&&<p role="status">{status}</p>}{error&&<p role="alert">{error}</p>}
  </section>;
}
