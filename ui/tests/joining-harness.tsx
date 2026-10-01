import { StrictMode } from "react";
import { root } from "./device-harness-root";
import DeviceJoinPanel from "../src/components/DeviceJoinPanel";
import Login from "../src/components/Login";
import type { DeviceJoinSnapshot,DeviceJoinListing,DeviceProgress,DeviceTaskPhase } from "../../electron/contracts";
const calls:{name:string;args:any}[]=[];
const profiles=new Map<string,DeviceJoinSnapshot>();let serial=0,unsupported=false,delayGet:string|null=null,delayStep=false;
let getDeferred:((value:DeviceJoinSnapshot)=>void)|null=null,stepDeferred:((value:DeviceProgress)=>void)|null=null;
let corrupt=false,empty=false;
const fingerprint="b".repeat(64);
function fixture(id:string,phase:DeviceTaskPhase="draft"):DeviceJoinSnapshot {
  return {profile:{id,origin:"http://127.0.0.1:9",username:"Alice",device_name:`加入 ${id} Windows 🦭`,local_device_id:`local-${id}`,encryption_fingerprint:(id==="second"?"c":"e").repeat(64),signing_fingerprint:(id==="second"?"d":"a").repeat(64)},
    join:{task:{id:`request-${id}`,kind:"join",phase,revision:0,request_id:`request-${id}`,event_id:null,root_fingerprint:phase==="draft"?null:fingerprint},local_abandonment:false,device_id:phase==="draft"?null:`server-${id}`,root_origin:phase==="draft"?null:"http://127.0.0.1:9",root_account:phase==="draft"?null:"synthetic-original",root_device:phase==="draft"?null:"original-device"},messaging_enabled:false};
}
const listing=():DeviceJoinListing[]=>corrupt?[{id:"empty-or-corrupt",profile:null,error:"档案不可用"}]:[...profiles.values()].map(row=>({id:row.profile.id,profile:row.profile,error:null}));
const api={
  list_device_join_profiles:async()=>listing(),
  create_device_join_profile:async(args:any)=>{calls.push({name:"create",args});const view=fixture(`profile-${++serial}`);view.profile.origin=args.origin;view.profile.username=args.username;view.profile.device_name=args.deviceName;profiles.set(view.profile.id,view);return structuredClone(view);},
  get_device_join_profile:async({profileId}:{profileId:string})=>{calls.push({name:"get",args:{profileId}});return delayGet===profileId?new Promise<DeviceJoinSnapshot>(resolve=>{getDeferred=resolve;}):structuredClone(profiles.get(profileId)!);},
  confirm_device_join_root:async(args:any)=>{calls.push({name:"confirm",args});if(args.confirmedFingerprint!==fingerprint)throw new Error("wrong root");const view=profiles.get(args.profileId)!;view.join.task.phase="awaiting_challenge";return structuredClone(view);},
  device_join_step:async(args:any)=>{
    calls.push({name:"step",args});const view=profiles.get(args.profileId)!;
    if(delayStep)return new Promise<DeviceProgress>(resolve=>{stepDeferred=resolve;});
    if(unsupported)return {task:structuredClone(view.join.task),condition:"unsupported" as const,http_status:404};
    if(view.join.task.phase==="draft") {
      if(!args.password)return {task:structuredClone(view.join.task),condition:"needs_password" as const,http_status:null};
      view.join.task.phase="awaiting_root_confirmation";view.join.task.root_fingerprint=fingerprint;view.join.device_id=`server-${args.profileId}`;view.join.root_account="synthetic-original";view.join.root_device="original-device";view.join.root_origin=view.profile.origin;
    } else if(view.join.task.phase==="awaiting_challenge")view.join.task.phase="awaiting_authorization";
    else if(view.join.task.phase==="awaiting_authorization")view.join.task.phase="complete";
    else if(view.join.task.phase==="cancelling")view.join.task.phase="cancelled";
    return {task:structuredClone(view.join.task),condition:(view.join.task.phase==="awaiting_root_confirmation"?"needs_confirmation":view.join.task.phase==="complete"||view.join.task.phase==="cancelled"?"terminal":"advanced") as DeviceProgress["condition"],http_status:null};
  },
  cancel_device_join:async({profileId}:{profileId:string})=>{calls.push({name:"cancel",args:{profileId}});const view=profiles.get(profileId)!;view.join.task.phase="cancelling";return structuredClone(view);},
  abandon_device_join:async({profileId}:{profileId:string})=>{calls.push({name:"abandon",args:{profileId}});const view=profiles.get(profileId)!;view.join.task.phase="cancelled";view.join.local_abandonment=true;return structuredClone(view);},
  forget_device_join_profile:async({profileId}:{profileId:string})=>{calls.push({name:"forget",args:{profileId}});if(corrupt){if(!empty)throw new Error("档案包含数据，不能作为空档案删除");corrupt=false;return;}profiles.delete(profileId);},
};
const install=()=>{window.desktop=new Proxy(api,{get(target,key:keyof typeof api){if(!(key in target))throw new Error("joining attempted ordinary or generic API "+String(key));return target[key];}}) as any;window.confirm=()=>true;};
const reset=()=>{profiles.clear();calls.length=0;serial=0;unsupported=false;delayGet=null;delayStep=false;corrupt=false;empty=false;install();};
const sleep=()=>new Promise(resolve=>setTimeout(resolve,90));
const check=(condition:unknown,message:string)=>{if(!condition)throw new Error(message);};
const button=(text:string)=>[...document.querySelectorAll<HTMLButtonElement>("button")].find(row=>row.textContent?.trim()===text);
async function click(text:string){check(button(text),"missing joining button "+text);button(text)!.click();await sleep();}
async function fill(label:string,value:string){const input=document.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!;check(input,"missing field "+label);Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value")!.set!.call(input,value);input.dispatchEvent(new Event("input",{bubbles:true}));await sleep();}
let generation=0;
const panel=()=>root.render(<StrictMode><DeviceJoinPanel key={++generation} initialUsername="Alice" onClose={()=>root.render(<div>closed</div>)}/></StrictMode>);
const open=async()=>{panel();await sleep();await click("打开申请档案");};
(window as any).runJoiningTests=async()=>{
  const results:string[]=[];reset();root.render(<StrictMode><Login key={++generation} onLogin={()=>{throw new Error("joining activated normal login");}}/></StrictMode>);await sleep();await click("加入另一台 Windows");
  check(document.querySelector('section[aria-label="新建加入档案"]'),"login joining entry missing");
  await fill("加入账号名","Alice");await fill("加入服务器地址","http://127.0.0.1:9/path");check(button("创建独立加入档案")!.disabled,"path origin accepted");
  await fill("加入服务器地址","http://127.0.0.1:9");await fill("加入设备名称","新 Windows <script> 🦭");await click("创建独立加入档案");
  check(calls.filter(row=>row.name==="create").length===1,"strict effect repeated profile creation");
  check(document.body.textContent!.includes("e".repeat(64))&&document.body.textContent!.includes("a".repeat(64)),"own dual fingerprints missing");results.push("login entry, strict lifecycle and explicit isolated profile creation");
  await fill("加入账号密码","synthetic-account-password");await click("验证账号并提交原申请");
  check(!document.querySelector('input[aria-label="加入账号密码"]'),"password retained after submitting");check(calls.find(row=>row.name==="step")!.args.profileId==="profile-1","wrong target");results.push("password clearing and original profile target");
  await fill("核对原设备指纹","c".repeat(64));check(button("确认原设备并继续")!.disabled,"wrong root accepted");
  await fill("核对原设备指纹",fingerprint);check(button("确认原设备并继续")!.disabled,"root unchecked accepted");document.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click();await sleep();await click("确认原设备并继续");
  check(calls.find(row=>row.name==="confirm")!.args.confirmedFingerprint===fingerprint,"candidate auto-confirmed");results.push("independent full original fingerprint and explicit confirmation");
  await click("查询或继续原申请");await click("查询或继续原申请");check(document.body.textContent!.includes("授权已验签确认"),"accepted evidence not displayed");
  check(!button("整理已结束档案")&&document.body.textContent!.includes("聊天激活尚未开放"),"authorized key can be erased or activated");results.push("verified authorization retains key without normal activation");
  panel();await sleep();await click("打开申请档案");check(calls.filter(row=>row.name==="create").length===1,"resume created another identity");check(document.body.textContent!.includes("授权已验签确认"),"resume lost original state");results.push("existing profile resume without new identity");
  reset();profiles.set("first",fixture("first","awaiting_authorization"));await open();delayStep=true;button("查询或继续原申请")!.click();await sleep();
  check(!button("请求取消申请")!.disabled,"cannot cancel pending network step");await click("请求取消申请");const old=structuredClone(profiles.get("first")!.join.task);old.phase="complete";stepDeferred!({task:old,condition:"terminal",http_status:null});await sleep();
  check(document.body.textContent!.includes("等待取消确认")&&!document.body.textContent!.includes("授权已验签确认"),"late step overrode cancellation");delayStep=false;await click("查询或继续原申请");await click("整理已结束档案");check(!profiles.size,"cancelled profile retained");results.push("concurrent cancellation rejects late acceptance UI and cleans ended profile");
  reset();profiles.set("first",fixture("first"));await open();unsupported=true;await fill("加入账号密码","synthetic-password");await click("验证账号并提交原申请");check(document.body.textContent!.includes("服务器尚未启用"),"unsupported missing");await click("仅放弃未签署申请");check(document.body.textContent!.includes("没有确认远端删除"),"local abandonment falsely remote cancellation");await click("整理已结束档案");results.push("unsupported server and explicit local abandonment boundary");
  reset();profiles.set("first",fixture("first"));profiles.set("second",fixture("second"));delayGet="first";panel();await sleep();button("打开申请档案")!.click();await sleep();
  const choices=[...document.querySelectorAll<HTMLButtonElement>("button")].filter(row=>row.textContent?.trim()==="打开申请档案");choices[1].click();await sleep();getDeferred!(structuredClone(profiles.get("first")!));await sleep();check(document.body.textContent!.includes("c".repeat(64))&&!document.body.textContent!.includes("e".repeat(64)),"late profile replaced selection");results.push("profile switch drops late public and task results");
  reset();profiles.set("first",fixture("first"));await open();await fill("加入账号密码","synthetic-secret");delayStep=true;button("验证账号并提交原申请")!.click();await sleep();window.dispatchEvent(new Event("liteseal-device-paused"));stepDeferred!({task:fixture("first","awaiting_root_confirmation").join.task,condition:"needs_confirmation",http_status:null});await sleep();
  check(!document.querySelector('input[type="password"]')&&!document.body.textContent!.includes(fingerprint),"pause retained secret or accepted late root");check(document.querySelector('[role="alert"]')?.textContent?.includes("暂停"),"pause absent");results.push("system pause clears credentials and drops delayed root");
  reset();corrupt=true;panel();await sleep();await click("清除空档案");check(document.querySelector('[role="alert"]')?.textContent?.includes("包含数据"),"corrupt data removed");empty=true;await click("清除空档案");check(!corrupt,"empty allocation not cleaned");results.push("corrupt records preserved, empty allocation explicitly cleaned");
  return results;
};
(window as any).showJoiningPanel=async()=>{reset();profiles.set("first",fixture("first","awaiting_root_confirmation"));await open();};
