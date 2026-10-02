import { StrictMode } from "react";
import { root } from "./device-harness-root";
import JoinActivationPanel from "../src/components/JoinActivationPanel";
import PanelDialog from "../src/components/PanelDialog";
import type { ActivationTask, ActivationProgress, JoinActivationSnapshot, NormalJoinProfile } from "../../electron/contracts";
let view:JoinActivationSnapshot,serial=0,delayStep=false,delayGet=false;
let stepDeferred:((result:ActivationProgress)=>void)|null=null,getDeferred:((view:JoinActivationSnapshot)=>void)|null=null;
const calls:{name:string;args:any}[]=[];
const task=():ActivationTask=>({id:`original-activation-${++serial}`,revision:1,kind:"login",stage:"prepared",cancel_requested:false});
const normal=():NormalJoinProfile=>({id:view.profile_id,origin:"http://127.0.0.1:9",username:"Alice",device_name:"独立 Windows 🦭",account:"synthetic-original-account",device:"server-device-id",root_fingerprint:"b".repeat(64),encryption_fingerprint:"e".repeat(64),signing_fingerprint:"a".repeat(64),revision:1,has_saved_session:true,access_expired:false,eligible:true});
const api={
  get_join_activation:async(args:any)=>{calls.push({name:"get",args});return delayGet?new Promise<JoinActivationSnapshot>(resolve=>{getDeferred=resolve;}):structuredClone(view);},
  prepare_join_activation:async(args:any)=>{calls.push({name:"prepare",args});const job=task();view.tasks.push(job);return structuredClone(job);},
  join_activation_step:async(args:any)=>{calls.push({name:"step",args});if(delayStep)return new Promise<ActivationProgress>(resolve=>{stepDeferred=resolve;});const job=view.tasks.find(t=>t.id===args.id)!;job.stage=job.cancel_requested?"cancelled":"complete";return {task:structuredClone(job),condition:job.cancel_requested?"cancelled" as const:"complete" as const,http_status:null};},
  inspect_join_activation:async(args:any)=>{calls.push({name:"inspect",args});return {task:structuredClone(view.tasks.find(t=>t.id===args.id)!),condition:"retry" as const,http_status:null};},
  cancel_join_activation:async(args:any)=>{calls.push({name:"cancel",args});const job=view.tasks.find(t=>t.id===args.id)!;job.cancel_requested=true;job.revision++;job.stage="started";return structuredClone(job);},
  forget_join_activation:async(args:any)=>{calls.push({name:"forget",args});view.tasks=view.tasks.filter(t=>t.id!==args.id);},
  save_join_activation:async(args:any)=>{calls.push({name:"save",args});view.normal=normal();return structuredClone(view.normal);},
  clear_join_activation_session:async(args:any)=>{calls.push({name:"clear",args});view.normal!.has_saved_session=false;view.normal!.revision++;},
};
const reset=()=>{serial=0;view={profile_id:"accepted-profile",tasks:[],normal:null};calls.length=0;delayStep=false;delayGet=false;window.desktop=new Proxy(api,{get(target,key:keyof typeof api){if(!(key in target))throw new Error("activation attempted generic or normal session API "+String(key));return target[key];}}) as any;window.confirm=()=>true;};
const sleep=()=>new Promise(resolve=>setTimeout(resolve,90));
const check=(value:unknown,message:string)=>{if(!value)throw new Error(message);};
const button=(text:string)=>[...document.querySelectorAll<HTMLButtonElement>("button")].find(b=>b.textContent?.trim()===text);
async function click(text:string){check(button(text),"missing activation button "+text);button(text)!.click();await sleep();}
async function password(value:string){const input=document.querySelector<HTMLInputElement>('[aria-label="激活账号密码"]')!;check(input,"missing password");Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value")!.set!.call(input,value);input.dispatchEvent(new Event("input",{bubbles:true}));await sleep();}
let generation=0;
const panel=(id=view.profile_id)=>root.render(<StrictMode><PanelDialog key={++generation} label="激活测试" wide onClose={()=>root.render(<div>closed</div>)}><JoinActivationPanel profileId={id} onClose={()=>root.render(<div>closed</div>)}/></PanelDialog></StrictMode>);
(window as any).runActivationTests=async()=>{
  const results:string[]=[];reset();panel();await sleep();
  check(button("准备新的激活申请")!.disabled,"new request needs explicit confirmation");document.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click();await sleep();await click("准备新的激活申请");
  const id=view.tasks[0].id;check(button("准备新的激活申请")!.disabled,"pending request can be replaced");check(calls.find(c=>c.name==="prepare")!.args.profileId==="accepted-profile","wrong identity target");
  results.push("explicit original-profile preparation and one pending request");
  await password("synthetic-password");await click("继续原激活申请");check(!document.querySelector('[aria-label="激活账号密码"]'),"password remains after accepted proof");check(calls.find(c=>c.name==="step")!.args.id===id,"step changed original number");check(!calls.some(c=>c.name==="save"),"accepted proof automatically selected or saved session");
  await click("保存本机会话档案");check(document.body.textContent!.includes("server-device-id"),"server device scope absent");check(button("准备新的激活申请")!.disabled,"saved session allows parallel replacement");
  await click("清除本机保存会话");check(document.body.textContent!.includes("身份与历史保留"),"clearing removed identity boundary");
  results.push("password clearing, original retry and explicit normal profile save without account replacement");
  view.tasks[0].stage="ended";view.tasks[0].closed={reason:"session_ended",accepted:true};await click("刷新本机激活任务");check(document.body.textContent!.includes("原申请曾签发会话"),"ended accepted fact absent");await click("整理激活终态任务");check(!view.tasks.length,"ended task retained");check(!calls.filter(c=>c.name==="prepare").slice(1).length,"terminal automatically made new request");results.push("positive terminal facts, credential clearing and explicit cleanup without automatic reapplication");
  reset();view.tasks=[task()];panel();await sleep();delayStep=true;button("继续原激活申请")!.click();await sleep();check(!button("取消原激活申请")!.disabled,"in-flight step prevents cancel");await click("取消原激活申请");
  const old={...view.tasks[0],stage:"complete" as const,cancel_requested:false};stepDeferred!({task:old,condition:"complete",http_status:null});await sleep();check(!button("保存本机会话档案")&&document.body.textContent!.includes("取消请求已保存"),"late acceptance overwrote cancel intent");delayStep=false;await click("确认激活取消结果");check(document.body.textContent!.includes("已确认取消"),"cancel not confirmed");results.push("concurrent cancellation rejects late UI acceptance and keeps original request");
  reset();view.tasks=[{...task(),stage:"conflict"}];panel();await sleep();check(button("准备新的激活申请")!.disabled&&button("继续原激活申请")!.disabled,"conflict silently resigned");await click("查询原激活结果");check(!calls.some(c=>c.name==="prepare"),"unknown query generated new request");results.push("conflict and unknown result retain original task");
  reset();view.tasks=[task()];panel();await sleep();await password("synthetic-locked-secret");delayGet=true;button("刷新本机激活任务")!.click();await sleep();window.dispatchEvent(new Event("liteseal-device-paused"));getDeferred!(structuredClone(view));await sleep();check(!document.querySelector('[aria-label="激活账号密码"]')&&!document.body.textContent!.includes(view.tasks[0].id),"pause retained credentials or late task");results.push("system pause clears credentials and refuses late snapshot");
  reset();view.tasks=[task()];panel();await sleep();delayGet=true;button("刷新本机激活任务")!.click();await sleep();root.render(<div>closed</div>);await sleep();getDeferred!(structuredClone(view));await sleep();check(document.body.textContent==="closed","closed form accepted late snapshot");results.push("unmounted activation view ignores late response");
  return results;
};
(window as any).showActivationPanel=async()=>{reset();view.tasks=[task()];panel();await sleep();};
