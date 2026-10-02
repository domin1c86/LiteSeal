import {useEffect,useRef,useState} from "react";
import PanelDialog from "./PanelDialog";
import {getDesktopApi} from "../lib/desktopApi";
import type {NormalProfileSnapshot,NormalProfileChoice} from "../../../electron/contracts";
export default function NormalProfilePanel({onClose}:{onClose:()=>void}){
  const [view,setView]=useState<NormalProfileSnapshot|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState("");
  const epoch=useRef(0),live=useRef(false),paused=useRef(false),running=useRef(false);
  async function run(work?:()=>Promise<NormalProfileSnapshot>){if(!live.current||paused.current||running.current)return;running.current=true;const n=epoch.current;setBusy(true);setError("");
    try{const next=await (work?work():getDesktopApi().get_normal_profile({}));if(live.current&&!paused.current&&epoch.current===n)setView(next);}
    catch(e){if(live.current&&epoch.current===n)setError(String(e));}
    finally{if(epoch.current===n){running.current=false;setBusy(false);}}
  }
  useEffect(()=>{live.current=true;paused.current=false;running.current=false;epoch.current++;void run();const stop=()=>{paused.current=true;epoch.current++;running.current=false;setView(null);setBusy(false);setError("档案选择已暂停，请解锁后重新打开");};window.addEventListener("liteseal-device-paused",stop);window.addEventListener("liteseal-app-locked",stop);return()=>{live.current=false;epoch.current++;window.removeEventListener("liteseal-device-paused",stop);window.removeEventListener("liteseal-app-locked",stop);};},[]);
  function select(choice:NormalProfileChoice){if(!view||!window.confirm(`使用“${choice.device_name}”作为本机选中档案？会停止旧档案后台，保留身份、历史和原任务。`))return;void run(()=>getDesktopApi().select_normal_profile({target:choice.target,generation:view.generation,scopeFingerprint:choice.scope_fingerprint}));}
  return <PanelDialog label="正常档案选择" onClose={onClose} wide><section aria-label="正常档案选择">
    <p>只使用你明确选中的身份。选择保存在本机，重启后核对同一身份和密钥；不会自动切换到其他档案。</p>
    <p>切换停止旧连接并保留原历史与任务。加入档案可自动续期；v3 聊天界面和消息后台仍待接入。</p>
    <button disabled={busy||paused.current} onClick={()=>void run()}>查询可用档案</button>
    {view&&<><p>当前：{view.selected?.device_name??"没有选中档案"} · 代次 {view.generation}</p>{view.error&&<p role="alert">{view.error}</p>}
      {view.profiles.map((row,index)=><div key={JSON.stringify(row.target)} aria-label="正常身份档案">{row.profile?<><h3>{row.profile.device_name}</h3><p>{row.profile.origin} · 账号 {row.profile.account} · 设备 {row.profile.device}</p><p>范围指纹 {row.profile.scope_fingerprint}</p><p>{row.profile.has_session?"本机有会话":"本机已退出"} · {row.profile.eligible?"本机授权有效":"授权已失效，保留历史"}</p><button disabled={busy||paused.current} onClick={()=>select(row.profile!)}>使用这个档案</button></>:<p>档案 {index+1} 不可用：{row.error}</p>}</div>)}
      <button disabled={busy||paused.current||!view.selected&&!view.error} onClick={()=>{if(window.confirm("停止使用当前档案？停止本机后台并保留身份、会话、历史和原任务；不会退出服务器登录家族。"))void run(()=>getDesktopApi().clear_normal_profile({generation:view.generation}));}}>停止使用当前档案</button>
    </>}{error&&<p role="alert">{error}</p>}
  </section></PanelDialog>;
}
