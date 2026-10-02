import {useEffect,useRef,useState} from "react";
import {getDesktopApi} from "../lib/desktopApi";
import {VoiceRecorder} from "./VoiceRecorder";
import type {DirectMediaInfo,DirectMediaTask} from "../../../electron/contracts";
function Preview({url,audio,name,onClose}:{url:string;audio:boolean;name:string;onClose:()=>void}){
  return <div>{audio?<audio controls src={url} aria-label={name} onError={onClose}/>:<img src={url} alt={name} style={{maxWidth:"min(100%,320px)",maxHeight:240}} onError={onClose} onLoad={e=>{if(e.currentTarget.naturalWidth*e.currentTarget.naturalHeight>40_000_000)onClose();}}/>}<button onClick={onClose}>关闭预览</button></div>;
}
export function DirectMediaComposer({scope,account,online,paused,onChanged}:{scope:string;account:string;online:boolean;paused:boolean;onChanged:()=>void}){
  const [tasks,setTasks]=useState<DirectMediaTask[]>([]),[busy,setBusy]=useState(false),[error,setError]=useState(""),[preview,setPreview]=useState<{url:string;audio:boolean;name:string}|null>(null);
  const alive=useRef(true),stopped=useRef(false),url=useRef<string|null>(null),generation=useRef(0);
  const [active,setActive]=useState<string|null>(null);
  const api=getDesktopApi();const close=()=>{const current=url.current;url.current=null;setPreview(null);if(current)void api.close_direct_media_preview({url:current}).catch(()=>{});};
  const current=(n:number)=>alive.current&&!paused&&generation.current===n;
  async function reload(){const n=generation.current;const rows=await api.get_direct_media_tasks({scope});if(current(n))setTasks(rows.filter(t=>t.peer===account&&!t.download&&t.phase!=="cancelled"));}
  useEffect(()=>{alive.current=true;void reload().catch(e=>setError(String(e)));return()=>{alive.current=false;stopped.current=true;generation.current++;if(url.current)void api.close_direct_media_preview({url:url.current}).catch(()=>{});};},[scope,account]);
  useEffect(()=>{if(paused){generation.current++;stopped.current=true;close();setTasks([]);setBusy(false);}},[paused]);
  useEffect(()=>{const changed=()=>{const n=generation.current;if(!paused)void reload().catch(e=>{if(current(n))setError(String(e));});};window.addEventListener("liteseal-direct-changed",changed);return()=>window.removeEventListener("liteseal-direct-changed",changed);},[scope,account,paused]);
  async function run(work:()=>Promise<unknown>){if(busy||paused)return;const n=generation.current;setBusy(true);setError("");try{await work();if(current(n)){await reload();onChanged();}}catch(e){if(current(n))setError(String(e));}finally{if(current(n)){setBusy(false);setActive(null);}}}
  async function stage(file:File){await run(()=>api.stage_direct_file({scope,account,file}));}
  async function send(task:DirectMediaTask){await run(async()=>{
    const n=generation.current;stopped.current=false;setActive(task.id);let next=task;close();
    while(next.phase==="staged"&&!stopped.current&&current(n)){
      const progress=await api.direct_media_step({scope,id:task.id});if(!current(n)||stopped.current)return;next=progress.task;setTasks(rows=>rows.map(t=>t.id===next.id?next:t));
      if(!["uploading","uploaded"].includes(progress.condition))throw new Error("原上传未确认，请保留任务继续或取消");
    }
    if(stopped.current||!current(n))return;
    const prepared=await api.prepare_direct_media({scope,id:task.id});if(!current(n)||stopped.current)return;
    if(!prepared.task)throw new Error("正在校验目录或需要正式会话，请继续原任务");
    let result;
    do {result=await api.direct_task_step({id:task.id});if(!current(n)||stopped.current)return;await reload();} while(result.condition==="uploading"&&current(n)&&!stopped.current);
    if(result.condition!=="accepted"&&result.condition!=="cancelled")throw new Error("原发布尚未确认；不会自动重签，请继续原任务");
  });}
  async function cancel(task:DirectMediaTask){stopped.current=true;const n=generation.current;try{await api.cancel_direct_media({scope,id:task.id});if(current(n)){await reload();onChanged();}}catch(e){if(current(n))setError(String(e));}}
  return <section aria-label="v3 加密媒体发送" onDragOver={e=>{if(e.dataTransfer.types.includes("Files"))e.preventDefault();}} onDrop={e=>{const file=e.dataTransfer.files[0];if(file){e.preventDefault();void stage(file);}}}>
    <p>文件与图片最大 20 MiB，语音最多 60 秒；可拖入一个文件。</p>
    <button disabled={busy||paused} onClick={()=>void run(()=>api.select_direct_media({scope,account}))}>选择加密文件或图片</button>
    <button disabled={busy||paused} onClick={()=>void run(()=>api.stage_direct_clipboard({scope,account}))}>粘贴图片</button>
    <VoiceRecorder key={scope+account} paused={paused||busy} onStaged={reload} stageClip={async(blob,durationMs)=>{if(paused)throw new Error("媒体已暂停");await api.stage_direct_voice({scope,account,blob,durationMs});}}/>
    {tasks.map(task=><div key={task.id} aria-label="v3 原媒体任务"><p>{task.name} · {(task.size/1024).toFixed(1)} KiB · {task.phase}{task.restoring?" · 正在重传原密文":""} · {task.id}</p><progress value={task.uploaded} max={task.total}/>
      <button disabled={busy||paused||!online} onClick={()=>void send(task)}>发送 / 继续原媒体任务</button>
      <button disabled={paused} onClick={()=>void cancel(task)}>取消原媒体任务</button>
      <button disabled={busy||paused} onClick={()=>void run(()=>api.clear_direct_media({scope,id:task.id}))}>清理已完成缓存</button>
      {["staged","uploaded"].includes(task.phase)&&["image/png","image/jpeg","image/webp","audio/webm"].includes(task.mime)&&<button disabled={busy||paused} onClick={()=>void run(async()=>{close();const n=generation.current;const opened=await api.export_direct_media({scope,id:task.id,preview:true,pending:true});if(!opened)return;if(current(n)){url.current=opened;setPreview({url:opened,audio:task.kind==="voice",name:task.name});}else void api.close_direct_media_preview({url:opened});})}>发送前预览 / 试听</button>}
    </div>)}
    {busy&&tasks.some(t=>t.id===active&&t.phase==="staged")&&<button onClick={()=>{stopped.current=true;}}>停止传输（保留原任务）</button>}
    {preview&&<Preview {...preview} onClose={close}/>}<button disabled={busy||paused} onClick={()=>void reload().catch(e=>setError(String(e)))}>刷新原媒体任务</button>{error&&<p role="alert">{error}</p>}
  </section>;
}
export function DirectMediaCard({scope,info,paused}:{scope:string;info:DirectMediaInfo;paused:boolean}){
  const [task,setTask]=useState<DirectMediaTask|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState(""),[preview,setPreview]=useState<string|null>(null);
  const alive=useRef(true),stopped=useRef(false),generation=useRef(0),url=useRef<string|null>(null);const api=getDesktopApi();
  const current=(n:number)=>alive.current&&!paused&&generation.current===n;
  const close=()=>{const value=url.current;url.current=null;setPreview(null);if(value)void api.close_direct_media_preview({url:value}).catch(()=>{});};
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;stopped.current=true;generation.current++;if(url.current)void api.close_direct_media_preview({url:url.current}).catch(()=>{});};},[scope,info.id]);
  useEffect(()=>{if(paused){stopped.current=true;generation.current++;close();setBusy(false);}},[paused]);
  async function read(previewing:boolean){if(busy||paused)return;const n=generation.current;setBusy(true);setError("");stopped.current=false;
    try{let next=await api.begin_direct_media_download({scope,id:info.id});while(next.phase==="downloading"&&current(n)&&!stopped.current){const progress=await api.direct_media_step({scope,id:info.id});if(!current(n)||stopped.current)return;next=progress.task;setTask(next);if(!["downloading","cached"].includes(progress.condition))throw new Error("附件不可用或未完整认证，原消息保留");}
      if(!current(n)||stopped.current)return;const opened=await api.export_direct_media({scope,id:info.id,preview:previewing});if(opened&&previewing){if(current(n)){close();url.current=opened;setPreview(opened);}else void api.close_direct_media_preview({url:opened});}
    }catch(e){if(current(n))setError(String(e));}finally{if(current(n))setBusy(false);}}
  return <div aria-label="v3 媒体消息"><p>{info.name} · {(info.size/1024).toFixed(1)} KiB{info.duration_ms?` · ${Math.ceil(info.duration_ms/1000)} 秒`:""}{info.cache==="unavailable"?" · 远端不可用":""}</p>
    <button disabled={busy||paused} onClick={()=>void read(false)}>下载并另存为</button>{["image/png","image/jpeg","image/webp","audio/webm"].includes(info.mime)&&<button disabled={busy||paused} onClick={()=>void read(true)}>{info.kind==="voice"?"认证后播放语音":"认证后预览图片"}</button>}
    {busy&&<><progress value={task?.downloaded??0} max={task?.total??1}/><button onClick={()=>{stopped.current=true;void api.cancel_direct_media({scope,id:info.id}).catch(e=>setError(String(e)));}}>取消下载</button></>}
    <button disabled={busy||paused} onClick={()=>{close();void api.clear_direct_media({scope,id:info.id}).catch(e=>setError(String(e)));}}>清理此附件缓存</button>
    {preview&&<Preview url={preview} audio={info.kind==="voice"} name={info.name} onClose={close}/>} {error&&<p role="alert">{error}</p>}
  </div>;
}
