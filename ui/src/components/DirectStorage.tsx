import {useEffect,useRef,useState} from "react";
import {getDesktopApi} from "../lib/desktopApi";
import type {DirectMediaStorage} from "../../../electron/contracts";
const bytes=(n:number)=>n<1024?`${n} B`:n<1024*1024?`${(n/1024).toFixed(1)} KiB`:`${(n/1024/1024).toFixed(2)} MiB`;
export function DirectStorage({scope,paused,onChanged}:{scope:string;paused:boolean;onChanged:()=>void}){
  const [stats,setStats]=useState<DirectMediaStorage|null>(null),[account,setAccount]=useState(""),[busy,setBusy]=useState(false),[result,setResult]=useState("");
  const live=useRef(false),epoch=useRef(0),operation=useRef(false),api=getDesktopApi();
  const valid=(n:number)=>live.current&&!paused&&epoch.current===n;
  useEffect(()=>{live.current=true;return()=>{live.current=false;epoch.current++;};},[scope]);
  useEffect(()=>{epoch.current++;operation.current=false;setStats(null);setResult("");setBusy(false);setAccount("");},[paused,scope]);
  async function run(clear=false){if(paused||operation.current)return;operation.current=true;setBusy(true);setResult("");const n=epoch.current;
    try{
      if(clear){const removed=await api.clear_direct_media_cache({scope,account:account||null});if(!valid(n))return;setResult(`已移除 ${bytes(removed.removed_bytes)} 密文缓存，整理 ${removed.cleared_tasks} 个已完成或已取消任务；保留 ${removed.protected_tasks} 个待发或正在下载的任务。`);onChanged();}
      const next=await api.get_direct_media_storage({scope});if(valid(n)){setStats(next);if(account&&!next.peers.some(p=>p.peer===account))setAccount("");}
    }catch(e){if(valid(n))setResult(String(e));}finally{if(valid(n)){operation.current=false;setBusy(false);}}
  }
  const rows=stats?.peers.filter(p=>!account||p.peer===account)??[];
  const clearable=rows.reduce((sum,p)=>sum+p.clearable_bytes,0)+(account?0:stats?.orphan_bytes??0);
  return <details aria-label="当前档案媒体存储"><summary>媒体存储与整理</summary>
    <button disabled={busy||paused} onClick={()=>void run()}>读取媒体存储统计</button>
    {stats&&<><p>当前身份 v3 媒体密文：{bytes(stats.cache_bytes)}。与单聊、群附件共用的缓存：{bytes(stats.shared_cache_bytes)} / {bytes(stats.limit)}。</p>
      <p>档案数据库已分配：{bytes(stats.database_allocated)}；内部可复用：{bytes(stats.database_reusable)}；数据库及日志实际占用：{bytes(stats.disk_bytes)}。</p>
      <label>整理范围<select aria-label="v3 媒体整理会话" disabled={busy||paused} value={account} onChange={e=>setAccount(e.target.value)}><option value="">当前身份所有会话</option>{stats.peers.map(p=><option key={p.peer} value={p.peer}>{p.peer}</option>)}</select></label>
      <p>此范围可移除 {bytes(clearable)}；保护 {rows.reduce((sum,p)=>sum+p.protected_tasks,0)} 个待发或正在下载的任务。</p>
      <button disabled={busy||paused} onClick={()=>{if(window.confirm("整理此范围已完成或已取消的媒体缓存？待发和正在下载的任务会保留。未过期且仍有权限的附件可重新下载。"))void run(true);}}>整理可移除媒体缓存</button>
      <p>保留消息正文、隐藏标记和原发送结果。SQLite 空间可复用，磁盘文件未必缩小；远端过期或权限变化后可能无法重新下载。</p>
    </>}{result&&<p role="status">{result}</p>}
  </details>;
}
