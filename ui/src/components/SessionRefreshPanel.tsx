import { useEffect,useRef,useState } from "react";
import PanelDialog from "./PanelDialog";
import { getDesktopApi } from "../lib/desktopApi";
import type { RefreshTarget,RefreshSnapshot,RefreshTask,RefreshProgress } from "../../../electron/contracts";
const stages:Record<RefreshTask["stage"],string>={prepared:"原续期已保存",started:"查询原续期",proving:"原证明已保存",conflict:"原续期冲突",complete:"原续期已完成",cancelled:"未发送续期已取消",ended:"原登录家族已退出"};
const outcomes:Record<RefreshProgress["condition"],string>={complete:"原续期完成，正式能力保留在 Rust",cancelled:"未发送的原续期已取消",ended:"原登录家族退出已确认，身份和历史保留",superseded:"当前登录已变化，原任务保留；请明确处理原家族",ineligible:"原设备资格已失效，原任务和历史保留",retry:"结果未确认，请继续原编号，不会自动重建",conflict:"原目录或任务冲突，请查询原任务，不会重签",pending:"原续期仍待处理"};
const terminal=(task:RefreshTask)=>["complete","cancelled","ended"].includes(task.stage);
export default function SessionRefreshPanel({target,onClose}:{target:RefreshTarget;onClose:()=>void}){
  const scope=JSON.stringify(target);
  const [view,setView]=useState<RefreshSnapshot|null>(null),[busy,setBusy]=useState(false),[status,setStatus]=useState(""),[error,setError]=useState("");
  const live=useRef(false),paused=useRef(false),epoch=useRef(0),operation=useRef<number|null>(null);
  const current=(n:number)=>live.current&&!paused.current&&epoch.current===n;
  async function run(work?:()=>Promise<string|void>,replace=false){
    if(!live.current||paused.current||operation.current!==null&&!replace)return;
    const n=replace?++epoch.current:epoch.current;operation.current=n;setBusy(true);setError("");
    try{const message=await work?.();if(current(n)&&message)setStatus(message);}catch(failure){if(current(n))setError(String(failure));}
    if(current(n)){try{const next=await getDesktopApi().get_session_refresh({target});if(current(n)&&JSON.stringify(next.target)===scope)setView(next);}catch(failure){if(current(n))setError(String(failure));}}
    if(operation.current===n)operation.current=null;if(current(n))setBusy(false);
  }
  useEffect(()=>{live.current=true;paused.current=false;epoch.current++;operation.current=null;setView(null);setStatus("");void run();
    const stop=()=>{paused.current=true;epoch.current++;operation.current=null;setView(null);setBusy(false);setStatus("");setError("续期任务已暂停，请解锁后重新打开");};
    const changed=()=>{void run();};window.addEventListener("liteseal-app-locked",stop);window.addEventListener("liteseal-device-paused",stop);window.addEventListener("liteseal-session-refresh-changed",changed);
    return()=>{live.current=false;epoch.current++;window.removeEventListener("liteseal-app-locked",stop);window.removeEventListener("liteseal-device-paused",stop);window.removeEventListener("liteseal-session-refresh-changed",changed);};
  },[scope]);
  return <PanelDialog label="正式会话续期" onClose={onClose} wide><section aria-label="正式会话续期">
    <p>当前选中的档案会在到期前自动续期，其他档案只由明确操作驱动。锁定、休眠、停止使用或本机退出后停止调度。口令、私钥和正式能力保留在 Rust。</p>
    <p>取消未发送申请只撤销该任务；取消已发送申请会退出该登录家族及续期后继，原身份和历史保留，独立登录不受影响。</p>
    <button disabled={busy||paused.current} onClick={()=>void run()}>查询本机续期状态</button>
    {view&&<><p>{view.current?`${view.current.has_credentials?"本机有正式会话":"本机已退出"} · ${view.current.eligible?"原设备资格仍有效":"原设备资格已失效"}`:"尚未保存正式会话，请先完成原正式登录"}</p>
      {view.current&&<p>账号 {view.current.account} · 设备 {view.current.device} · 代次 {view.current.generation}</p>}
      <button disabled={busy||paused.current||!view.current?.has_credentials||!view.current?.eligible||view.tasks.some(t=>t.current&&!terminal(t))} onClick={()=>void run(async()=>{await getDesktopApi().prepare_session_refresh({target});return "原续期编号已保存，继续原任务完成";})}>准备会话续期</button>
      {view.tasks.map(task=><div key={task.id} aria-label="原续期任务"><p>{stages[task.stage]} · 原编号 {task.id}{!task.current?" · 当前代次已变化":""}{task.cancel_requested?" · 取消意图已保存":""}</p>
        {(!terminal(task)||task.cancel_requested&&task.stage==="complete")&&<button disabled={busy||paused.current} onClick={()=>void run(async()=>outcomes[(await getDesktopApi().session_refresh_step({target,id:task.id})).condition])}>继续原续期任务</button>}
        {!["cancelled","ended"].includes(task.stage)&&!task.cancel_requested&&<button disabled={paused.current} onClick={()=>{
          const exit=task.stage!=="prepared";if(exit&&!window.confirm("确认退出这个原登录家族及所有续期后继？原身份、历史和独立登录保留。"))return;
          void run(async()=>{const next=await getDesktopApi().cancel_session_refresh({target,id:task.id,confirmedFamilyExit:exit});return next.stage==="cancelled"?"未发送的原续期已取消":"退出意图已保存，请继续原任务确认远端结果";},true);
        }}>{task.stage==="prepared"?"取消未发送续期":"退出原登录家族"}</button>}
        {((terminal(task)&&!task.cancel_requested)||["cancelled","ended"].includes(task.stage))?<button disabled={busy||paused.current} onClick={()=>{if(window.confirm("整理已确认的这个续期任务？当前身份和历史保留。"))void run(()=>getDesktopApi().forget_session_refresh({target,id:task.id}));}}>整理续期结果</button>:null}
      </div>)}
    </>}{status&&<p role="status">{status}</p>}{error&&<p role="alert">{error}</p>}
  </section></PanelDialog>;
}
