import {useState,useRef} from "react";
import type {NormalProfileSnapshot} from "../../../electron/contracts";
import NormalProfilePanel from "./NormalProfilePanel";
import SessionRefreshPanel from "./SessionRefreshPanel";
import DeviceJoinPanel from "./DeviceJoinPanel";
import BackupPanel from "./BackupPanel";
import DirectChat from "./DirectChat";
import RootSessionPanel from "./RootSessionPanel";
export default function NormalProfileHome({view,onLegacy}:{view:NormalProfileSnapshot;onLegacy?:()=>void}){
  const [panel,setPanel]=useState<"choice"|"refresh"|"join"|"archive"|"rootSession"|null>(null);
  const flush=useRef<()=>Promise<void>>(async()=>{});const [error,setError]=useState("");async function open(next:typeof panel){try{await flush.current();setPanel(next);setError("");}catch(e){setError(String(e));}} async function legacy(){try{await flush.current();onLegacy?.();}catch(e){setError(String(e));}}
  return <main style={{padding:"24px",maxWidth:"840px",margin:"0 auto",overflowWrap:"anywhere"}}><section><h1>本机档案</h1><p>{view.selected?`当前：${view.selected.device_name} · ${view.selected.account}`:"当前没有可用的选中档案"}</p>
    {view.error&&<p role="alert">{view.error}</p>}
    {view.selected&&<><p>设备 {view.selected.device} · {view.selected.origin}</p><p>{view.selected.has_session?"正式会话已保存":"本机已退出"} · {view.selected.eligible?"本机授权有效":"原授权已失效"}</p></>}
    <p>身份和历史保存在所选档案。核对对方原设备根指纹后开始文字聊天。</p>
    <div style={{display:"flex",flexWrap:"wrap",gap:"8px"}}><button onClick={()=>void open("choice")}>选择正常档案</button>{view.selected&&<button onClick={()=>void open("refresh")}>管理选中档案续期</button>}
    <button onClick={()=>void open("join")}>管理加入档案</button><button onClick={()=>void open("archive")}>打开离线恢复档案</button>{onLegacy&&<><button onClick={()=>void legacy()}>原设备旧历史与群聊</button><button onClick={()=>void open("rootSession")}>恢复原设备正式会话</button></>}</div>
    {view.selected?.protocol==="v3"&&<DirectChat key={view.selected.scope_fingerprint} obscured={panel!==null} onFlushReady={work=>{flush.current=work;}}/>}
    {error&&<p role="alert">{error}</p>}{panel==="choice"&&<NormalProfilePanel onClose={()=>setPanel(null)}/>}{panel==="refresh"&&view.selected&&<SessionRefreshPanel target={view.selected.target} onClose={()=>setPanel(null)}/>}
    {panel==="join"&&<DeviceJoinPanel onClose={()=>setPanel(null)}/>}{panel==="archive"&&<BackupPanel canExport={false} onClose={()=>setPanel(null)}/>}
    {panel==="rootSession"&&<RootSessionPanel onClose={()=>setPanel(null)}/>}
  </section></main>;
}
