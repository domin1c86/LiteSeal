import { StrictMode } from "react";
import { root } from "./device-harness-root";
import RootSessionPanel from "../src/components/RootSessionPanel";
import Login from "../src/components/Login";
import type { ActivationProgress,RootSessionSnapshot } from "../../electron/contracts";
let view:RootSessionSnapshot,delay=false,deferred:((value:ActivationProgress)=>void)|null=null;
const calls:{name:string;args:any}[]=[];
const api={
  get_root_session:async()=>structuredClone(view),
  prepare_root_session:async(args:any)=>{calls.push({name:"prepare",args});view.tasks.push({id:"original-root-login",revision:1,kind:"login",stage:"prepared",cancel_requested:false});return structuredClone(view.tasks[0]);},
  root_session_step:async(args:any)=>{calls.push({name:"step",args});if(delay)return new Promise<ActivationProgress>(resolve=>{deferred=resolve;});const task=view.tasks[0];task.stage=task.cancel_requested?"cancelled":"complete";return {task:structuredClone(task),condition:task.cancel_requested?"cancelled" as const:"complete" as const,http_status:null};},
  inspect_root_session:async(args:any)=>{calls.push({name:"inspect",args});return {task:structuredClone(view.tasks[0]),condition:"retry" as const,http_status:null};},
  cancel_root_session:async(args:any)=>{calls.push({name:"cancel",args});view.tasks[0].cancel_requested=true;view.tasks[0].stage="started";return structuredClone(view.tasks[0]);},
  forget_root_session:async(args:any)=>{calls.push({name:"forget",args});view.tasks=[];},
  save_root_session:async(args:any)=>{calls.push({name:"save",args});view.has_local_credentials=true;return {user_id:"same-root-user",device_id:"same-root-device",server_url:"http://127.0.0.1:1",public_key:[],ed25519_pk:[]};},
};
function reset(){view={root_fingerprint:"b".repeat(64),has_local_credentials:false,tasks:[]};calls.length=0;delay=false;window.confirm=()=>true;window.desktop=new Proxy(api,{get(target,key:keyof typeof api){if(!(key in target))throw new Error("root recovery attempted legacy/secret API "+String(key));return target[key];}}) as any;}
const sleep=()=>new Promise(resolve=>setTimeout(resolve,90));
const check=(value:unknown,message:string)=>{if(!value)throw new Error(message);};
const button=(text:string)=>[...document.querySelectorAll<HTMLButtonElement>("button")].find(b=>b.textContent?.trim()===text);
async function click(text:string){check(button(text),"missing root recovery button "+text);button(text)!.click();await sleep();}
async function input(label:string,value:string){const node=document.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!;check(node,"missing input "+label);Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value")!.set!.call(node,value);node.dispatchEvent(new Event("input",{bubbles:true}));await sleep();}
let generation=0;
const panel=()=>root.render(<StrictMode><RootSessionPanel key={++generation} initialUsername="synthetic-user" onClose={()=>root.render(<div>closed</div>)}/></StrictMode>);
(window as any).runRootSessionTests=async()=>{
  const results:string[]=[];
  reset();root.render(<Login onLogin={()=>{throw new Error("root recovery used legacy login callback");}}/>);await sleep();await click("恢复原设备正式会话");check(!!document.querySelector('section[aria-label="原设备正式会话恢复"]'),"login recovery entry absent");results.push("login entry preserves original root and avoids legacy login API");
  reset();panel();await sleep();check(!calls.length,"mount creates network recovery request");await click("准备原会话恢复");check(calls[0].args.username==="synthetic-user","preparation not username bound");check(button("准备原会话恢复")!.disabled,"pending request can be replaced");await input("原账号密码","synthetic-password");await click("继续原会话申请");check(calls.find(c=>c.name==="step")!.args.id==="original-root-login","retry changes task number");check(document.querySelector<HTMLInputElement>('input[type="password"]')!.value==="","password retained after step");check(!calls.some(c=>c.name==="save"),"completion automatically saves credentials");await click("保存原正式会话");check(view.has_local_credentials&&document.body.textContent!.includes("请重新打开应用"),"explicit save missing scope/result");results.push("durable original task, password clearing and explicit Rust credential save");
  reset();view.tasks=[{id:"original-root-login",revision:1,kind:"login",stage:"started",cancel_requested:false}];panel();await sleep();await click("查询原正式会话");check(!calls.some(c=>c.name==="prepare")&&document.body.textContent!.includes("重试原编号"),"unknown result creates request or terminal");results.push("unknown inspection keeps original request without reapplication");
  delay=true;button("继续原会话申请")!.click();await sleep();check(!button("取消原会话申请")!.disabled,"in-flight step blocks cancel");await click("取消原会话申请");deferred!({task:{...view.tasks[0],stage:"complete"},condition:"complete",http_status:null});await sleep();check(!button("保存原正式会话"),"late completion overrides cancel");delay=false;await click("继续原会话申请");await click("整理原会话终态任务");check(!view.tasks.length&&!calls.some(c=>c.name==="prepare"),"cleanup recreates request");results.push("cancel during network, reject late UI result and explicit terminal cleanup");
  reset();view.tasks=[{id:"original-root-login",revision:1,kind:"login",stage:"started",cancel_requested:false}];panel();await sleep();await input("原账号密码","must-clear");delay=true;button("继续原会话申请")!.click();await sleep();window.dispatchEvent(new Event("liteseal-app-locked"));deferred!({task:{...view.tasks[0],stage:"complete"},condition:"complete",http_status:null});await sleep();check(!document.querySelector('input[type="password"]')&&!document.body.textContent!.includes(view.root_fingerprint)&&!button("保存原正式会话"),"lock leaked password/fingerprint/late save");results.push("lock wipes fields and rejects late completion");
  return results;
};
(window as any).showRootSessionPanel=async()=>{reset();view.tasks=[{id:"original-root-login",revision:1,kind:"login",stage:"complete",cancel_requested:false}];panel();await sleep();};
