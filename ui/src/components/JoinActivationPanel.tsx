import { useEffect, useRef, useState } from "react";
import { getDesktopApi } from "../lib/desktopApi";
import SessionRefreshPanel from "./SessionRefreshPanel";
import type { ActivationProgress, ActivationTask, JoinActivationSnapshot } from "../../../electron/contracts";

const stages: Record<ActivationTask["stage"], string> = { prepared:"申请已保存", started:"正在查询原申请", proving:"原证明已保存", conflict:"原申请冲突", complete:"正式会话已确认", cancelled:"已确认取消", ineligible:"原授权已失效", ended:"原申请已结束" };
const outcomes: Record<ActivationProgress["condition"], string> = { complete:"原正式会话已确认，可保存本机档案", cancelled:"原申请已确认取消", ineligible:"原授权阶段已失效，身份与历史保留", needs_password:"需要账号密码继续原申请", session_required:"凭据未确认，保留原申请查询结果", retry:"连接未完成，请继续查询原申请", conflict:"原申请冲突，请先查询或取消原申请", pending:"原申请仍待完成，可继续原证明", ended:"原申请已明确结束，可整理或显式准备新申请" };
const reasons = { cancelled:"取消已确认", expired:"原挑战已过期", directory_changed:"授权目录已变化", credentials_changed:"账号凭据已变化", session_ended:"原会话已结束" };
const terminal = (task:ActivationTask) => ["complete","cancelled","ineligible","ended"].includes(task.stage);

export default function JoinActivationPanel({ profileId, onClose }: { profileId:string; onClose:()=>void }) {
  const [view,setView]=useState<JoinActivationSnapshot|null>(null),[password,setPassword]=useState("");
  const [confirmed,setConfirmed]=useState(false),[busy,setBusy]=useState(false),[status,setStatus]=useState(""),[error,setError]=useState("");
  const live=useRef(false),paused=useRef(false),epoch=useRef(0),operation=useRef<number|null>(null);
  const [showRefresh,setShowRefresh]=useState(false);
  const current=(generation:number)=>live.current&&!paused.current&&generation===epoch.current;
  async function run(work?:()=>Promise<string|void>,replace=false) {
    if(!live.current||paused.current||operation.current!==null&&!replace)return;
    const generation=replace?++epoch.current:epoch.current;
    operation.current=generation;setBusy(true);setError("");
    try {
      const message=await work?.();if(!current(generation))return;
      if(message)setStatus(message);
      const result=await getDesktopApi().get_join_activation({profileId});
      if(current(generation)&&result.profile_id===profileId)setView(result);
    } catch(failure) {if(current(generation))setError(String(failure));}
    finally {if(operation.current===generation)operation.current=null;if(current(generation))setBusy(false);}
  }
  useEffect(()=>{
    live.current=true;paused.current=false;epoch.current++;operation.current=null;void run();
    const stop=()=>{paused.current=true;epoch.current++;operation.current=null;setView(null);setPassword("");setConfirmed(false);setBusy(false);setStatus("");setError("正式激活已暂停，请解锁后重新打开");};
    window.addEventListener("liteseal-app-locked",stop);window.addEventListener("liteseal-device-paused",stop);
    return()=>{live.current=false;epoch.current++;window.removeEventListener("liteseal-app-locked",stop);window.removeEventListener("liteseal-device-paused",stop);};
  },[profileId]);
  const pending=view?.tasks.find(task=>!terminal(task));
  const normal=view?.normal;
  const refresh=<>{normal&&<button disabled={paused.current} onClick={()=>setShowRefresh(true)}>管理这个档案的会话续期</button>}{showRefresh&&<SessionRefreshPanel target={{kind:"join",profileId}} onClose={()=>setShowRefresh(false)}/>}</>;
  const credentialTask=view?.tasks.find(task=>["prepared","started"].includes(task.stage)&&!task.cancel_requested);
  function step(task:ActivationTask) {
    const secret=password;setPassword("");
    void run(async()=>{const result=await getDesktopApi().join_activation_step({profileId,id:task.id,...(secret?{password:secret}:{})});return outcomes[result.condition];});
  }
  return <section aria-label="正式激活申请">
    {refresh}
    <h3>正式激活与本机档案</h3>
    <p>先由原设备明确启用单聊 v3，再使用此档案的原密钥完成账号验证。保存后保留独立会话档案，消息界面尚未开放。</p>
    <button disabled={busy||paused.current} onClick={()=>void run()}>刷新本机激活任务</button>
    <button onClick={onClose}>收起正式激活</button>
    {view&&<>
      {normal&&<div aria-label="正常会话档案">
        <p>{normal.device_name} · 账号 {normal.account} · 设备 {normal.device}</p>
        <p>{!normal.eligible?"原授权阶段已失效，本机身份保留":normal.has_saved_session?normal.access_expired?"访问凭据已过期，原会话档案保留":"本机会话已保存，使用前需要联网检查":"本机保存会话已清除，身份与历史保留"}</p>
        {normal.has_saved_session&&<button disabled={paused.current} onClick={()=>{if(window.confirm("清除本机保存的会话？独立密钥与历史仍保留，服务器会话需在授权设备上撤销。")){setPassword("");void run(async()=>{await getDesktopApi().clear_join_activation_session({profileId});return "本机保存会话已清除，原身份保留";},true);}}}>清除本机保存会话</button>}
      </div>}
      {!view.tasks.length&&<p>没有正式激活申请</p>}
      {view.tasks.map(task=><div key={task.id} aria-label="激活任务">
        <p>{stages[task.stage]} · 原申请编号 {task.id}{task.cancel_requested?" · 取消请求已保存":""}</p>
        {task.closed&&<p>{reasons[task.closed.reason]}{task.closed.accepted?"；原申请曾签发会话":"；原申请未签发会话"}</p>}
        {!["cancelled","ineligible","ended"].includes(task.stage)&&<button disabled={busy||paused.current} onClick={()=>void run(async()=>{const result=await getDesktopApi().inspect_join_activation({profileId,id:task.id});return outcomes[result.condition];})}>查询原激活结果</button>}
        {!terminal(task)&&<>
          <button disabled={busy||paused.current||task.stage==="conflict"&&!task.cancel_requested} onClick={()=>step(task)}>{task.cancel_requested?"确认激活取消结果":"继续原激活申请"}</button>
          <button disabled={paused.current||task.cancel_requested} onClick={()=>{setPassword("");void run(async()=>{await getDesktopApi().cancel_join_activation({profileId,id:task.id});return "取消意图已保存，继续原申请确认结果";},true);}}>取消原激活申请</button>
        </>}
        {task.stage==="complete"&&<button disabled={busy||paused.current} onClick={()=>void run(async()=>{await getDesktopApi().save_join_activation({profileId,id:task.id});return "已保存独立正常档案，原身份与历史保留";})}>保存本机会话档案</button>}
        {["cancelled","ineligible","ended"].includes(task.stage)&&<button disabled={busy||paused.current||normal?.has_saved_session} onClick={()=>{if(window.confirm("整理这个已明确结束的激活任务？密钥、正常档案和历史仍保留。"))void run(async()=>{await getDesktopApi().forget_join_activation({profileId,id:task.id});return "激活终态任务已整理";});}}>整理激活终态任务</button>}
      </div>)}
      {credentialTask&&<label>账号密码（仅本次原申请使用）<input type="password" autoComplete="off" aria-label="激活账号密码" disabled={busy||paused.current} value={password} onChange={e=>setPassword(e.target.value)} maxLength={1024}/></label>}
      <label><input type="checkbox" disabled={busy||!!pending||paused.current} checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/>已确认使用此档案准备新的正式激活申请</label>
      <button disabled={busy||!!pending||paused.current||!confirmed||normal?.has_saved_session&&!normal.access_expired} onClick={()=>{setConfirmed(false);setPassword("");void run(async()=>{await getDesktopApi().prepare_join_activation({profileId});return "新申请已保存，发送时继续该原编号";});}}>准备新的激活申请</button>
    </>}
    {status&&<p role="status">{status}</p>}{error&&<p role="alert">{error}</p>}
  </section>;
}
