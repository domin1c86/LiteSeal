import { StrictMode } from "react";
import { root } from "./device-harness-root";
import RootMessagingPanel from "../src/components/RootMessagingPanel";
import PanelDialog from "../src/components/PanelDialog";
import type { RootMessagingSnapshot,ActivationProgress } from "../../electron/contracts";
let view:RootMessagingSnapshot,delay=false,deferred:((value:ActivationProgress)=>void)|null=null;
const calls:{name:string;args:any}[]=[];
const api={
  get_root_messaging:async()=>structuredClone(view),
  check_root_messaging:async()=>{calls.push({name:"check",args:{}});view.admission="v3";return structuredClone(view);},
  prepare_root_messaging:async(args:any)=>{calls.push({name:"prepare",args});view.admission="switching";view.tasks.push({id:"original-root-switch",revision:1,kind:"enable",stage:"prepared",cancel_requested:false});return structuredClone(view.tasks[0]);},
  root_messaging_step:async(args:any)=>{calls.push({name:"step",args});if(delay)return new Promise<ActivationProgress>(resolve=>{deferred=resolve;});const job=view.tasks[0];job.stage=job.cancel_requested?"cancelled":"complete";view.admission=job.cancel_requested?"legacy":"v3";return {task:structuredClone(job),condition:job.cancel_requested?"cancelled" as const:"complete" as const,http_status:null};},
  cancel_root_messaging:async(args:any)=>{calls.push({name:"cancel",args});view.tasks[0].cancel_requested=true;view.tasks[0].stage="started";view.tasks[0].revision++;return structuredClone(view.tasks[0]);},
  forget_root_messaging:async(args:any)=>{calls.push({name:"forget",args});view.tasks=[];},
};
function reset(){view={root_fingerprint:"b".repeat(64),admission:"legacy",pending:{messages:0,uploads:0,scheduled:0,operations:0,reactions:0,receipts:0},tasks:[]};calls.length=0;delay=false;window.confirm=()=>true;window.desktop=new Proxy(api,{get(target,key:keyof typeof api){if(!(key in target))throw new Error("root switch attempted generic/session API "+String(key));return target[key];}}) as any;}
const sleep=()=>new Promise(resolve=>setTimeout(resolve,90));
const check=(value:unknown,message:string)=>{if(!value)throw new Error(message);};
const button=(text:string)=>[...document.querySelectorAll<HTMLButtonElement>("button")].find(b=>b.textContent?.trim()===text);
async function click(text:string){check(button(text),"missing root button "+text);button(text)!.click();await sleep();}
let generation=0;
const panel=()=>root.render(<StrictMode><PanelDialog key={++generation} label="原设备切换" wide onClose={()=>root.render(<div>closed</div>)}><RootMessagingPanel onClose={()=>root.render(<div>closed</div>)}/></PanelDialog></StrictMode>);
(window as any).runRootMessagingTests=async()=>{
  const results:string[]=[];reset();panel();await sleep();check(button("准备原设备协议切换")!.disabled,"cutover not explicitly confirmed");
  check(document.body.textContent!.includes("不能撤回")&&document.body.textContent!.includes("启用后单聊会暂停"),"impact absent");document.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click();await sleep();await click("准备原设备协议切换");
  check(calls.find(c=>c.name==="prepare")!.args.confirmedFingerprint===view.root_fingerprint,"confirmation not root-bound");check(!button("准备原设备协议切换")&&document.body.textContent!.includes("新的旧单聊任务已暂停"),"pending cutover offers replacement");results.push("explicit irreversible impact, root fingerprint and durable original request");
  await click("查询或继续原切换");check(calls.find(c=>c.name==="step")!.args.id==="original-root-switch","retry changed number");check(document.body.textContent!.includes("单聊 v3 已启用")&&!button("取消原切换申请")&&!button("准备原设备协议切换"),"enabled cutover can revert or repeat");results.push("original retry and one-way accepted state");
  reset();view.pending.messages=1;view.pending.uploads=1;view.pending.receipts=1;panel();await sleep();check(button("准备原设备协议切换")!.disabled&&document.body.textContent!.includes("先处理这些原任务"),"backlog ignored");results.push("visible scoped backlog and blocked preparation without deletion");
  reset();panel();await sleep();await click("查询远端启用状态");check(view.admission==="v3"&&!calls.some(c=>c.name==="prepare"),"remote observation re-signed enable");results.push("remote enabled observation without new root event");
  reset();view.admission="switching";view.tasks=[{id:"original-root-switch",revision:1,kind:"enable",stage:"started",cancel_requested:false}];panel();await sleep();delay=true;button("查询或继续原切换")!.click();await sleep();check(!button("取消原切换申请")!.disabled,"pending network prevents cancel");await click("取消原切换申请");deferred!({task:{...view.tasks[0],stage:"complete"},condition:"complete",http_status:null});await sleep();check(!document.body.textContent!.includes("单聊 v3 已启用"),"late accepted UI overwrote cancellation");delay=false;await click("确认原切换取消结果");await click("整理切换终态任务");check(!view.tasks.length&&!calls.some(c=>c.name==="prepare"),"cleanup automatically re-signed");results.push("concurrent cancel, late result refusal and explicit terminal cleanup");
  reset();view.admission="switching";view.tasks=[{id:"original-root-switch",revision:1,kind:"enable",stage:"started",cancel_requested:false}];panel();await sleep();delay=true;button("查询或继续原切换")!.click();await sleep();window.dispatchEvent(new Event("liteseal-device-paused"));deferred!({task:{...view.tasks[0],stage:"complete"},condition:"complete",http_status:null});await sleep();check(!document.body.textContent!.includes(view.root_fingerprint)&&!document.body.textContent!.includes("单聊 v3 已启用"),"pause exposed late configuration");results.push("pause removes confirmation and ignores late acceptance");
  return results;
};
(window as any).showRootMessagingPanel=async()=>{reset();view.pending.messages=2;panel();await sleep();};
