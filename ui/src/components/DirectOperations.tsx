import {useEffect,useRef,useState} from "react";
import {getDesktopApi} from "../lib/desktopApi";
import type {DirectHistory,DirectOperationTask,DirectSnapshot,CommandMap} from "../../../electron/contracts";

function useWork(paused:boolean,onChanged:()=>void){
  const [busy,setBusy]=useState(false),[error,setError]=useState("");
  const gate=useRef({live:false,paused,revision:0});gate.current.paused=paused;
  useEffect(()=>{gate.current.live=true;return()=>{gate.current.live=false;gate.current.revision++;};},[]);
  const running=useRef(false);
  useEffect(()=>{if(paused){gate.current.revision++;running.current=false;setBusy(false);setError("");}},[paused]);
  async function run(work:(current:()=>boolean)=>Promise<void>,replace=false){
    if(running.current&&!replace||!gate.current.live||gate.current.paused)return;
    const revision=++gate.current.revision,current=()=>gate.current.live&&!gate.current.paused&&gate.current.revision===revision;
    running.current=true;setBusy(true);setError("");
    try{await work(current);}catch(e){if(current())setError(String(e));}
    finally{if(gate.current.revision===revision)running.current=false;if(current()){setBusy(false);onChanged();}}
  }
  return {busy,error,run};
}
export function DirectMessageOperations({scope,device,message,pending,paused,onChanged}:{scope:string;device:string;message:DirectHistory["messages"][number];pending:boolean;paused:boolean;onChanged:()=>void}){
  const [editing,setEditing]=useState(false),[text,setText]=useState("");
  // Keep the exact request id/time/body after an unknown preparation result.
  const [intent,setIntent]=useState<CommandMap["prepare_direct_operation"]["args"]|null>(null);
  const work=useWork(paused,onChanged);
  useEffect(()=>{if(paused||message.retracted){setText("");setEditing(false);setIntent(null);}},[paused,message.retracted]);
  const age=Date.now()-message.accepted_at;
  const allowed=message.role==="authored"&&message.sender_device===device&&message.outcome==="processed"&&!message.retracted&&age>=0&&age<=48*60*60*1000;
  if(!allowed)return null;
  async function submit(action:"edit"|"retract"){
    await work.run(async current=>{
      const request=intent??{scope,id:crypto.randomUUID(),target:message.id,createdAt:Date.now(),action,text:action==="edit"?text:null};
      setIntent(request);
      const prepared=await getDesktopApi().prepare_direct_operation(request);
      if(!current())return;
      if(!prepared.task)throw new Error("操作尚未准备："+prepared.condition+"；保留此处正文后重试");
      setIntent(null);setText("");setEditing(false);
      const result=await getDesktopApi().direct_operation_step({scope,id:prepared.task.id,revision:prepared.task.revision});
      if(current()&&!["accepted","cancelled"].includes(result.condition))throw new Error("原操作尚未确认："+result.condition+"；请在原编辑/撤回任务中继续或取消");
    });
  }
  return <div aria-label="v3 消息编辑撤回">
    {!editing&&!intent&&<><button disabled={paused||work.busy||pending||message.kind!=="text"} onClick={()=>{setText(message.text??"");setEditing(true);}}>编辑原文字</button><button disabled={paused||work.busy||pending} onClick={()=>{if(window.confirm("撤回这条原消息？接收设备补收后隐藏正文；已复制的内容不受影响。"))void submit("retract");}}>撤回原消息</button></>}
    {editing&&<><label>编辑文字<textarea aria-label="v3 编辑正文" value={text} maxLength={65536} disabled={paused||work.busy||!!intent} onChange={e=>setText(e.target.value)}/></label><button disabled={paused||work.busy||pending||!text} onClick={()=>void submit("edit")}>{intent?"重试原准备请求":"保存原消息编辑"}</button><button disabled={work.busy||!!intent} onClick={()=>{setText("");setEditing(false);}}>放弃此次编辑</button></>}
    {intent&&!editing&&<button disabled={paused||work.busy} onClick={()=>void submit(intent.action)}>重试原准备请求</button>}
    {work.error&&<p role="alert">{work.error}</p>}
  </div>;
}
export function DirectOperationTasks({view,paused,onChanged}:{view:DirectSnapshot;paused:boolean;onChanged:()=>void}){
  return <details><summary>原编辑/撤回任务（{view.operations.length}）</summary><p>只允许原发送设备在首次接收后 48 小时内操作。未知结果保留原编号；取消可能仍查到已接受结果。</p>{view.operations.map(task=><OperationTask key={task.id} scope={view.notification_scope} task={task} paused={paused} onChanged={onChanged}/>)}</details>;
}
function OperationTask({scope,task,paused,onChanged}:{scope:string;task:DirectOperationTask;paused:boolean;onChanged:()=>void}){
  const work=useWork(paused,onChanged),terminal=["accepted","cancelled"].includes(task.state);
  const args={scope,id:task.id,revision:task.revision};
  return <div aria-label="v3 原编辑撤回任务"><p>{task.action==="edit"?"编辑":"撤回"} · {task.state} · 原编号 {task.id}{task.cancel_requested?" · 已保存取消意图":""}</p>
    {!terminal&&<><button disabled={paused||work.busy} onClick={()=>void work.run(async()=>{const result=await getDesktopApi().direct_operation_step(args);if(!["accepted","cancelled"].includes(result.condition))throw new Error("原操作尚未确认："+result.condition);})}>继续原编辑/撤回任务</button><button disabled={paused||task.cancel_requested} onClick={()=>void work.run(async()=>{await getDesktopApi().cancel_direct_operation(args);},true)}>取消原编辑/撤回任务</button></>}
    {terminal&&<button disabled={paused||work.busy} onClick={()=>{if(window.confirm("整理已确认的操作任务？操作证据与消息历史保留。"))void work.run(()=>getDesktopApi().forget_direct_operation(args));}}>整理原编辑/撤回结果</button>}
    {work.error&&<p role="alert">{work.error}</p>}
  </div>;
}
