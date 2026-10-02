import { useEffect, useRef, useState } from "react";
import PanelDialog from "./PanelDialog";
import JoinActivationPanel from "./JoinActivationPanel";
import { getDesktopApi } from "../lib/desktopApi";
import type { DeviceJoinListing, DeviceJoinSnapshot, DeviceProgress, DeviceTaskPhase } from "../../../electron/contracts";

const phases: Record<DeviceTaskPhase, string> = { draft:"待验证账号",awaiting_root_confirmation:"待核对原设备",awaiting_challenge:"等待原设备验证",awaiting_authorization:"等待原设备授权",prepared:"待发送",cancelling:"等待取消确认",conflict:"原申请冲突",complete:"授权已确认",cancelled:"申请已结束",expired:"申请已过期",revoked:"授权已撤销" };
const conditions: Record<DeviceProgress["condition"], string> = { advanced:"原申请已推进",waiting:"等待原设备，请在原设备管理页面继续操作",needs_password:"首次申请需要验证账号密码",needs_confirmation:"请核对原设备完整指纹",syncing:"正在校验授权目录，请继续原申请",retry:"连接未完成，保留原申请继续查询或重试",session_required:"账号验证或申请凭据已失效，请查询原申请；不会自动新建",unsupported:"服务器尚未启用设备授权",conflict:"原申请发生冲突，请查询或取消，不会自动重新签署",terminal:"申请状态已确认",unsigned_abandoned:"仅结束未签署的本机申请，没有确认远端删除；可能需要等待原申请过期" };
const terminal = (phase:DeviceTaskPhase) => ["complete","cancelled","expired","revoked"].includes(phase);
function validOrigin(input:string) { try { const url=new URL(input.trim());return ["http:","https:"].includes(url.protocol)&&!!url.host&&!url.username&&!url.password&&!url.search&&!url.hash&&url.pathname==="/"; } catch {return false;} }

export default function DeviceJoinPanel({ onClose, initialOrigin="http://localhost:3000", initialUsername="" }: { onClose:()=>void; initialOrigin?:string; initialUsername?:string }) {
  const [profiles,setProfiles]=useState<DeviceJoinListing[]>([]),[snapshot,setSnapshot]=useState<DeviceJoinSnapshot|null>(null);
  const [origin,setOrigin]=useState(initialOrigin),[username,setUsername]=useState(initialUsername),[name,setName]=useState("第二台 Windows");
  const [password,setPassword]=useState(""),[rootInput,setRootInput]=useState(""),[rootConfirmed,setRootConfirmed]=useState(false);
  const [busy,setBusy]=useState(false),[error,setError]=useState(""),[status,setStatus]=useState("");
  const [showActivation,setShowActivation]=useState(false);
  const mounted=useRef(false),paused=useRef(false),epoch=useRef(0),operation=useRef<number|null>(null),active=useRef<DeviceJoinSnapshot|null>(null);
  function apply(view:DeviceJoinSnapshot|null) { active.current=view;setSnapshot(view); }
  async function run(work:()=>Promise<void>, replace=false) {
    if(!mounted.current||paused.current||operation.current!==null&&!replace)return;
    const generation=replace?++epoch.current:epoch.current;
    operation.current=generation;setBusy(true);setError("");
    try {await work();} catch(failure) {if(mounted.current&&epoch.current===generation)setError(String(failure));}
    finally {if(operation.current===generation)operation.current=null;if(mounted.current&&epoch.current===generation)setBusy(false);}
  }
  const current=(generation:number)=>mounted.current&&!paused.current&&epoch.current===generation;
  async function refreshList() {const generation=epoch.current;const rows=await getDesktopApi().list_device_join_profiles({});if(current(generation))setProfiles(rows);}
  async function select(id:string) {
    setShowActivation(false);
    setPassword("");setRootInput("");setRootConfirmed(false);setStatus("");apply(null);
    await run(async()=>{const generation=epoch.current;const view=await getDesktopApi().get_device_join_profile({profileId:id});if(current(generation))apply(view);},true);
  }
  async function step(secret?:string) {
    const profile=active.current;if(!profile)return;
    setPassword("");
    await run(async()=>{
      const generation=epoch.current;
      const result=await getDesktopApi().device_join_step({profileId:profile.profile.id,...(secret?{password:secret}:{})});
      if(!current(generation))return;setStatus(conditions[result.condition]);
      const view=await getDesktopApi().get_device_join_profile({profileId:profile.profile.id});
      if(current(generation)){apply(view);if(view.join.task.phase!=="awaiting_root_confirmation"){setRootInput("");setRootConfirmed(false);}}
    });
  }
  useEffect(()=>{
    mounted.current=true;paused.current=false;epoch.current++;operation.current=null;void run(refreshList);
    const stop=()=>{paused.current=true;epoch.current++;operation.current=null;apply(null);setProfiles([]);setPassword("");setRootInput("");setRootConfirmed(false);setBusy(false);setStatus("");setError("加入流程已暂停，请解锁后重新打开");};
    window.addEventListener("liteseal-app-locked",stop);window.addEventListener("liteseal-device-paused",stop);
    const timer=setInterval(()=>{const phase=active.current?.join.task.phase;if(phase&&["awaiting_challenge","awaiting_authorization","cancelling"].includes(phase))void step();},5000);
    return()=>{mounted.current=false;epoch.current++;clearInterval(timer);window.removeEventListener("liteseal-app-locked",stop);window.removeEventListener("liteseal-device-paused",stop);};
  },[]);
  const task=snapshot?.join.task;
  const canCreate=validOrigin(origin)&&!!username.trim()&&new TextEncoder().encode(username.trim()).length<=128&&!!name.trim()&&Array.from(name.trim()).length<=80&&profiles.length<8;
  const normalized=rootInput.trim().toLowerCase();
  const correctRoot=!!task?.root_fingerprint&&/^[a-f0-9]{64}$/.test(normalized)&&normalized===task.root_fingerprint;
  return <PanelDialog label="加入另一台 Windows" wide onClose={onClose}>
    <p>生成独立设备密钥，由此 Windows 用户保护。完成原设备授权后可管理正式激活和本机会话档案；消息界面尚未开放，已有身份与历史保留。</p>
    <h3>本机加入档案</h3>
    <button disabled={busy||paused.current} onClick={()=>void run(refreshList)}>刷新加入档案</button>
    {profiles.map(row=><div key={row.id}><span>{row.profile?`${row.profile.device_name} · ${row.profile.username} · ${row.profile.origin}`:"档案不可用，数据已保留"}</span>
      {row.profile?<button disabled={paused.current} onClick={()=>void select(row.id)}>打开申请档案</button>:<button disabled={busy||paused.current} onClick={()=>void run(async()=>{await getDesktopApi().forget_device_join_profile({profileId:row.id});await refreshList();})}>清除空档案</button>}
    </div>)}
    {!profiles.length&&<p>没有本机加入档案</p>}
    {!snapshot&&<section aria-label="新建加入档案"><h3>新建独立档案</h3>
      <label>原服务器地址<input aria-label="加入服务器地址" value={origin} disabled={busy||paused.current} onChange={e=>setOrigin(e.target.value)}/></label>
      <label>原账号名<input aria-label="加入账号名" value={username} maxLength={128} disabled={busy||paused.current} onChange={e=>setUsername(e.target.value)}/></label>
      <label>此设备名称<input aria-label="加入设备名称" value={name} maxLength={80} disabled={busy||paused.current} onChange={e=>setName(e.target.value)}/></label>
      <button disabled={busy||paused.current||!canCreate} onClick={()=>void run(async()=>{
        const generation=epoch.current;const view=await getDesktopApi().create_device_join_profile({origin:origin.trim(),username:username.trim(),deviceName:name.trim()});
        if(!current(generation))return;apply(view);await refreshList();
      })}>创建独立加入档案</button>
      <p>最多保留八个档案。创建结果未确认时先刷新档案，不要重复创建；损坏密钥不会被重新生成或覆盖。</p>
    </section>}
    {snapshot&&task&&<>
      <h3>{snapshot.profile.device_name} · {phases[task.phase]}</h3>
      <p>{snapshot.profile.username} · {snapshot.profile.origin}</p>
      {snapshot.join.device_id&&<p>申请设备编号 {snapshot.join.device_id}</p>}
      <p>请在原设备核对这两组完整指纹：</p><p>此设备加密密钥指纹</p><code>{snapshot.profile.encryption_fingerprint}</code>
      <p>此设备签名密钥指纹</p><code>{snapshot.profile.signing_fingerprint}</code>
      {task.phase==="draft"&&<><label>原账号密码（只用于首次申请）<input type="password" autoComplete="off" aria-label="加入账号密码" value={password} disabled={busy} onChange={e=>setPassword(e.target.value)}/></label>
        <button disabled={busy||!password||new TextEncoder().encode(password).length>1024} onClick={()=>void step(password)}>验证账号并提交原申请</button></>}
      {task.root_fingerprint&&<><h3>原设备身份指纹</h3><code>{task.root_fingerprint}</code><p>{snapshot.join.root_origin} · 账号 {snapshot.join.root_account} · 设备 {snapshot.join.root_device}</p></>}
      {task.phase==="awaiting_root_confirmation"&&<section aria-label="原设备确认">
        <p>从原设备“管理设备授权”页面取得完整身份指纹，并在这里核对。服务器返回的指纹本身不代表可信。</p>
        <label>原设备提供的完整指纹<input aria-label="核对原设备指纹" value={rootInput} maxLength={128} disabled={busy} onChange={e=>{setRootInput(e.target.value);setRootConfirmed(false);}}/></label>
        {rootInput&&!correctRoot&&<p role="status">指纹不匹配，请保留原申请并重新核对</p>}
        <label><input type="checkbox" disabled={busy||!correctRoot} checked={rootConfirmed} onChange={e=>setRootConfirmed(e.target.checked)}/>已与原设备核对完整指纹</label>
        <button disabled={busy||!correctRoot||!rootConfirmed} onClick={()=>{
          const fingerprint=normalized;setRootInput("");setRootConfirmed(false);void run(async()=>{const generation=epoch.current;const view=await getDesktopApi().confirm_device_join_root({profileId:snapshot.profile.id,confirmedFingerprint:fingerprint});if(current(generation)){apply(view);setStatus("原设备指纹已确认，将继续原意向与证明");}});
        }}>确认原设备并继续</button>
      </section>}
      {!terminal(task.phase)&&<>
        <button disabled={busy} onClick={()=>void step()}>查询或继续原申请</button>
        <button disabled={task.phase==="cancelling"||paused.current} onClick={()=>void run(async()=>{const generation=epoch.current;const view=await getDesktopApi().cancel_device_join({profileId:snapshot.profile.id});if(current(generation)){apply(view);setStatus("取消请求已保存，继续查询确认结果");}},true)}>请求取消申请</button>
        {["draft","awaiting_root_confirmation"].includes(task.phase)&&<button disabled={busy} onClick={()=>{
          if(!window.confirm("仅放弃未签署的本机申请？这不确认远端删除，已有开始申请可能需要等待过期。"))return;
          void run(async()=>{const generation=epoch.current;const view=await getDesktopApi().abandon_device_join({profileId:snapshot.profile.id});if(current(generation))apply(view);});
        }}>仅放弃未签署申请</button>}
      </>}
      {snapshot.join.local_abandonment&&<p role="status">仅结束未签署的本机申请，没有确认远端删除；已有开始申请可能需要等待过期。</p>}
      {task.phase==="complete"&&<><p role="status">原设备授权已验签确认。此档案保留独立密钥，可管理正式激活申请；消息界面尚未开放。需要撤销时请在原设备操作。</p>
        {!showActivation?<button disabled={paused.current} onClick={()=>setShowActivation(true)}>管理正式激活申请</button>:<JoinActivationPanel key={snapshot.profile.id} profileId={snapshot.profile.id} onClose={()=>setShowActivation(false)}/>}</>}
      {["cancelled","expired","revoked"].includes(task.phase)&&<button disabled={busy} onClick={()=>{
        if(!window.confirm("删除这个已结束的本机加入档案和独立密钥？不会删除原身份或历史，也不代替远端撤销。"))return;
        void run(async()=>{const generation=epoch.current;await getDesktopApi().forget_device_join_profile({profileId:snapshot.profile.id});if(current(generation)){apply(null);setStatus("已整理结束的本机档案");}await refreshList();});
      }}>整理已结束档案</button>}
      <button disabled={busy} onClick={()=>{epoch.current++;apply(null);setPassword("");setRootInput("");setRootConfirmed(false);setStatus("");}}>准备另一份档案</button>
    </>}
    {status&&<p role="status">{status}</p>}{error&&<p role="alert">{error}</p>}
  </PanelDialog>;
}
