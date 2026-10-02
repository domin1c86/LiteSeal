import { useEffect, useRef, useState } from "react";
import PanelDialog from "./PanelDialog";
import { getDesktopApi } from "../lib/desktopApi";
import type { ActivationTask, ActivationProgress, RootSessionSnapshot } from "../../../electron/contracts";
const terminal=(task:ActivationTask)=>["complete","cancelled","ineligible","ended"].includes(task.stage);
const outcomes:Record<ActivationProgress["condition"],string>={complete:"原正式会话已确认，请明确保存到原身份",cancelled:"原申请已取消",ineligible:"原设备资格已失效",needs_password:"请提供原账号密码继续原申请",session_required:"需恢复原正式会话",retry:"连接未完成，请查询或重试原编号",conflict:"原申请发生冲突，请查询原状态",pending:"原申请仍待处理",ended:"原申请已结束"};
export default function RootSessionPanel({onClose,initialUsername=""}:{onClose:()=>void;initialUsername?:string}){
  const [view,setView]=useState<RootSessionSnapshot|null>(null),[username,setUsername]=useState(initialUsername),[password,setPassword]=useState(""),[busy,setBusy]=useState(false),[status,setStatus]=useState(""),[error,setError]=useState("");
  const live=useRef(false),paused=useRef(false),epoch=useRef(0),operation=useRef<number|null>(null);
  const current=(n:number)=>live.current&&!paused.current&&epoch.current===n;
  async function run(work?:()=>Promise<string|void>,replace=false){
    if(!live.current||paused.current||operation.current!==null&&!replace)return;
    const n=replace?++epoch.current:epoch.current;operation.current=n;setBusy(true);setError("");
    try{const message=await work?.();if(!current(n))return;if(message)setStatus(message);const next=await getDesktopApi().get_root_session({});if(current(n))setView(next);}
    catch(failure){if(current(n))setError(String(failure));}
    finally{if(operation.current===n)operation.current=null;if(current(n))setBusy(false);}
  }
  useEffect(()=>{live.current=true;paused.current=false;epoch.current++;operation.current=null;void run();
    const stop=()=>{paused.current=true;epoch.current++;operation.current=null;setPassword("");setView(null);setBusy(false);setStatus("");setError("原正式会话恢复已暂停，请解锁后重新打开");};
    window.addEventListener("liteseal-app-locked",stop);window.addEventListener("liteseal-device-paused",stop);
    return()=>{live.current=false;epoch.current++;window.removeEventListener("liteseal-app-locked",stop);window.removeEventListener("liteseal-device-paused",stop);};
  },[]);
  return <PanelDialog label="恢复原设备正式会话" onClose={onClose} wide><section aria-label="原设备正式会话恢复">
    <p>使用本机保留的原身份和原密钥恢复已启用 v3 的原设备。保存后可重新打开应用查看原历史；新协议消息后台尚未接入。</p>
    <button disabled={busy||paused.current} onClick={()=>void run()}>刷新原会话任务</button>
    {view&&<><p>原设备指纹</p><code>{view.root_fingerprint}</code><p>{view.has_local_credentials?"本机保留会话凭据，在线有效性需查询":"本机已退出，原身份与密钥保留"}</p>
      <label>原账号名<input aria-label="原账号名" value={username} disabled={busy||paused.current} autoComplete="username" onChange={e=>setUsername(e.target.value)}/></label>
      <label>原账号密码<input aria-label="原账号密码" type="password" value={password} disabled={busy||paused.current} autoComplete="current-password" onChange={e=>setPassword(e.target.value)}/></label>
      <button disabled={busy||paused.current||!username.trim()||view.tasks.some(t=>!terminal(t))} onClick={()=>{setPassword("");void run(async()=>{await getDesktopApi().prepare_root_session({username:username.trim()});return "原申请已保存，请继续该编号完成验证";});}}>准备原会话恢复</button>
      {view.tasks.map(task=><div key={task.id} aria-label="原会话恢复任务"><p>{task.stage} · 原编号 {task.id}{task.cancel_requested?" · 已请求取消":""}</p>
        <button disabled={busy||paused.current} onClick={()=>void run(async()=>outcomes[(await getDesktopApi().inspect_root_session({id:task.id})).condition])}>查询原正式会话</button>
        {!terminal(task)&&<><button disabled={busy||paused.current} onClick={()=>{const supplied=password;setPassword("");void run(async()=>outcomes[(await getDesktopApi().root_session_step({id:task.id,...(supplied?{password:supplied}:{})})).condition]);}}>继续原会话申请</button>
          <button disabled={paused.current||task.cancel_requested} onClick={()=>{setPassword("");void run(async()=>{const next=await getDesktopApi().cancel_root_session({id:task.id});return next.stage==="cancelled"?"原申请已取消":"取消意图已保存，请继续查询原申请";},true);}}>取消原会话申请</button></>}
        {task.stage==="complete"&&<button disabled={busy||paused.current} onClick={()=>{setPassword("");void run(async()=>{await getDesktopApi().save_root_session({id:task.id});return "原正式凭据已保存，原身份和历史保留；请重新打开应用查看历史";});}}>保存原正式会话</button>}
        {["cancelled","ineligible","ended"].includes(task.stage)&&<button disabled={busy||paused.current} onClick={()=>{if(window.confirm("整理已明确结束的原会话任务？原身份和历史保留。"))void run(()=>getDesktopApi().forget_root_session({id:task.id}));}}>整理原会话终态任务</button>}
      </div>)}
    </>}{status&&<p role="status">{status}</p>}{error&&<p role="alert">{error}</p>}
  </section></PanelDialog>;
}
