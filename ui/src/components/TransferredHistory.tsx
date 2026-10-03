import {useEffect,useRef,useState} from "react";
import {getDesktopApi} from "../lib/desktopApi";
import type {TransferredHistory as Page} from "../../../electron/contracts";
export function TransferredHistory({scope,archive,account,paused=false}:{scope?:string;archive?:string;account?:string;paused?:boolean}){
  const [page,setPage]=useState<Page|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState("");const epoch=useRef(0),alive=useRef(false);
  const valid=(n:number)=>alive.current&&epoch.current===n&&!paused;
  async function refresh(append=false){if(paused||!scope&&!archive||archive&&!account)return;const n=epoch.current;setBusy(true);setError("");
    try {const api=getDesktopApi(),before=append?page?.next_cursor:null;const next=archive?await api.get_backup_transferred_history({id:archive,account:account!,before}):await api.get_transferred_history({scope:scope!,account:account||null,before});if(valid(n))setPage(old=>append&&old?{...next,messages:[...old.messages,...next.messages.filter(row=>!old.messages.some(r=>r.id===row.id))]}:next);
    }catch(e){if(valid(n))setError(String(e));}finally{if(valid(n))setBusy(false);}}
  useEffect(()=>{alive.current=true;epoch.current++;setPage(null);setError("");setBusy(false);if(!paused)void refresh();const stop=()=>{epoch.current++;setPage(null);setBusy(false);setError("");};const changed=()=>{void refresh();};window.addEventListener("liteseal-device-paused",stop);window.addEventListener("liteseal-app-locked",stop);window.addEventListener("liteseal-history-transferred",changed);window.addEventListener("liteseal-direct-changed",changed);return()=>{alive.current=false;epoch.current++;window.removeEventListener("liteseal-device-paused",stop);window.removeEventListener("liteseal-app-locked",stop);window.removeEventListener("liteseal-history-transferred",changed);window.removeEventListener("liteseal-direct-changed",changed);};},[scope,archive,account,paused]);
  return <details aria-label="授权迁移历史" style={{minWidth:0,overflowWrap:"anywhere"}}><summary>原设备授权迁移的历史{page?`（${page.messages.length}）`:""}</summary><p>这是原设备选择并认证的历史副本。保留原消息与变更证据，不产生投递 ACK、未读或作者权限。后续编辑或撤回需由原设备再次迁移；已取得的副本不能远程擦除。</p>
    <button disabled={busy||paused} onClick={()=>void refresh()}>刷新授权副本</button>{page?.next_cursor&&<button disabled={busy||paused} onClick={()=>void refresh(true)}>更早的授权副本</button>}
    {busy&&<p role="status">核对授权历史…</p>}{error&&<p role="alert">{error}</p>}{page&&!page.messages.length&&<p>此范围没有已导入的授权历史。</p>}
    <ol>{page?.messages.map(message=><li key={message.id}><p>{message.sender} · {new Date(message.sent_at).toLocaleString()}</p><small>受信原设备迁移 · 修订 {message.operation_revision}</small>
      {message.retracted?<p>消息已撤回</p>:message.media?<><strong>{message.media.name}</strong><p>{(message.media.size/1024).toFixed(1)} KiB · {message.media.cached?"授权包含完整认证缓存":"未包含完整缓存，请在原设备重新选择迁移"}</p>{message.media.cached&&<button disabled={busy||paused} onClick={async()=>{const n=epoch.current;try{const api=getDesktopApi();if(archive)await api.export_backup_transferred_media({id:archive,messageId:message.id});else await api.export_transferred_media({scope:scope!,id:message.id});}catch(e){if(valid(n))setError(String(e));}}}>保存迁移附件</button>}</>:<p style={{whiteSpace:"pre-wrap"}}>{message.text??"正文不可用"}</p>}
      {!archive&&<button disabled={busy||paused} onClick={async()=>{if(!window.confirm("仅在此档案隐藏授权副本？重新导入不会取消这个隐藏。"))return;const n=epoch.current;try{await getDesktopApi().hide_transferred_message({scope:scope!,id:message.id});if(valid(n))await refresh();}catch(e){if(valid(n))setError(String(e));}}}>隐藏授权副本</button>}
    </li>)}</ol>
  </details>;
}
