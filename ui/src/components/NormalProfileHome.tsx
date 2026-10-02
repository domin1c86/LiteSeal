import {useState} from "react";
import type {NormalProfileSnapshot} from "../../../electron/contracts";
import NormalProfilePanel from "./NormalProfilePanel";
import SessionRefreshPanel from "./SessionRefreshPanel";
import DeviceJoinPanel from "./DeviceJoinPanel";
import BackupPanel from "./BackupPanel";
export default function NormalProfileHome({view}:{view:NormalProfileSnapshot}){
  const [panel,setPanel]=useState<"choice"|"refresh"|"join"|"archive"|null>(null);
  return <main style={{padding:"24px",maxWidth:"840px",margin:"0 auto",overflowWrap:"anywhere"}}><section><h1>本机档案</h1><p>{view.selected?`当前：${view.selected.device_name} · ${view.selected.account}`:"当前没有可用的选中档案"}</p>
    {view.error&&<p role="alert">{view.error}</p>}
    {view.selected&&<><p>设备 {view.selected.device} · {view.selected.origin}</p><p>{view.selected.has_session?"正式会话已保存":"本机已退出"} · {view.selected.eligible?"本机授权有效":"原授权已失效"}</p></>}
    <p>独立身份和历史保留在原档案。此界面可管理选择和续期；v3 消息后台与历史展示仍待接入。</p>
    <div style={{display:"flex",flexWrap:"wrap",gap:"8px"}}><button onClick={()=>setPanel("choice")}>选择正常档案</button>{view.selected&&<button onClick={()=>setPanel("refresh")}>管理选中档案续期</button>}
    <button onClick={()=>setPanel("join")}>管理加入档案</button><button onClick={()=>setPanel("archive")}>打开离线恢复档案</button></div>
    {panel==="choice"&&<NormalProfilePanel onClose={()=>setPanel(null)}/>}{panel==="refresh"&&view.selected&&<SessionRefreshPanel target={view.selected.target} onClose={()=>setPanel(null)}/>}
    {panel==="join"&&<DeviceJoinPanel onClose={()=>setPanel(null)}/>}{panel==="archive"&&<BackupPanel canExport={false} onClose={()=>setPanel(null)}/>}
  </section></main>;
}
