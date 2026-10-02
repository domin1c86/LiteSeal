import {StrictMode} from "react";
import {root} from "./device-harness-root";
import NormalProfilePanel from "../src/components/NormalProfilePanel";
import App from "../src/App";
import type {NormalProfileSnapshot,NormalProfileChoice} from "../../electron/contracts";
const choice=(join:boolean):NormalProfileChoice=>({target:join?{kind:"join",profileId:"joined-profile"}:{kind:"root"},scope_fingerprint:(join?"b":"a").repeat(64),origin:"https://synthetic.example",account:"synthetic-account",device:join?"joined-device":"root-device",device_name:join?"第二台 Windows 🦭":"原设备",protocol:join?"v3":"legacy",has_session:true,eligible:true,access_expired:false});
let view:NormalProfileSnapshot,delayed=false,deferred:((next:NormalProfileSnapshot)=>void)|null=null;
const calls:{name:string;args:any}[]=[];
const api={
  get_direct_chat:async()=>({identity:{account:"synthetic-account",origin:"https://synthetic.example",root_device:"synthetic-root",root_fingerprint:"a".repeat(64),encryption_fingerprint:"b".repeat(64),signing_fingerprint:"c".repeat(64)},device:"joined-device",peers:[],tasks:[],can_network:true}),
  get_direct_history:async()=>({messages:[],next_cursor:null}),
  get_normal_profile:async()=>structuredClone(view),
  select_normal_profile:async(args:any)=>{calls.push({name:"select",args});if(delayed)return new Promise<NormalProfileSnapshot>(r=>{deferred=r;});view.generation++;view.explicit=true;view.selected=structuredClone(view.profiles.find(p=>JSON.stringify(p.target)===JSON.stringify(args.target))!.profile);return structuredClone(view);},
  clear_normal_profile:async(args:any)=>{calls.push({name:"clear",args});view.generation++;view.explicit=true;view.selected=null;return structuredClone(view);},
};
function reset(){const root=choice(false),joined=choice(true);view={generation:0,explicit:false,selected:root,error:null,profiles:[{target:root.target,profile:root,error:null},{target:joined.target,profile:joined,error:null}]};delayed=false;calls.length=0;window.confirm=()=>true;window.desktop=new Proxy(api,{get(target,key:keyof typeof api){if(!(key in target))throw new Error("selected joining app used root/secret API "+String(key));return target[key];}}) as any;}
const sleep=()=>new Promise(r=>setTimeout(r,55));
const check=(v:unknown,message:string)=>{if(!v)throw new Error(message);};
const button=(text:string,index=0)=>[...document.querySelectorAll<HTMLButtonElement>("button")].filter(b=>b.textContent?.trim()===text)[index];
async function click(text:string,index=0){check(button(text,index),"missing profile button "+text);button(text,index)!.click();await sleep();}
let generation=0;const panel=()=>root.render(<StrictMode><NormalProfilePanel key={++generation} onClose={()=>root.render(<div>closed</div>)}/></StrictMode>);
(window as any).runNormalProfileTests=async()=>{
  const results:string[]=[];reset();panel();await sleep();check(!calls.length,"mount changes selection");window.confirm=()=>false;await click("使用这个档案",1);check(!calls.length,"denied confirmation selects");window.confirm=()=>true;await click("使用这个档案",1);check(calls[0].args.target.profileId==="joined-profile"&&calls[0].args.generation===0&&calls[0].args.scopeFingerprint==="b".repeat(64),"scope or CAS confirmation lost");results.push("explicit joining choice carries original target, generation and scope fingerprint");
  await click("停止使用当前档案");check(view.selected===null&&view.explicit&&calls[calls.length-1]!.args.generation===1,"clear falls back to root");results.push("stop selection is explicit and does not auto-select original root");
  reset();view.profiles[1].profile=null;view.profiles[1].error="损坏档案不可用";panel();await sleep();check([...document.querySelectorAll('button')].filter(b=>b.textContent==="使用这个档案").length===1&&document.body.textContent!.includes("损坏档案不可用"),"unavailable profile silently selected");results.push("damaged or incomplete profile has no choose action");
  reset();panel();await sleep();delayed=true;button("使用这个档案",1)!.click();await sleep();window.dispatchEvent(new Event("liteseal-device-paused"));deferred!({...view,generation:1,explicit:true,selected:choice(true)});await sleep();check(!document.body.textContent!.includes("synthetic-account")&&button("查询可用档案")!.disabled,"lock accepts late selection metadata");results.push("pause clears choices and rejects late selection result");
  reset();view.explicit=true;view.generation=1;view.selected=choice(true);root.render(<StrictMode><App key={++generation}/></StrictMode>);await sleep();check(document.body.textContent!.includes("joined-device")&&!document.body.textContent!.includes("root-device"),"restart opens original root app");results.push("joined restart mounts selected home and never calls legacy root APIs");
  view={...view,generation:2,selected:null};window.dispatchEvent(new Event("liteseal-normal-profile-changed"));await sleep();check(document.body.textContent!.includes("当前没有可用")&&!document.body.textContent!.includes("joined-device"),"selection event retains old home");results.push("selection event unmounts old scope and cleared restart has no fallback");
  view={...view,generation:3,error:"范围无法验证"};window.dispatchEvent(new Event("liteseal-normal-profile-changed"));await sleep();check(document.body.textContent!.includes("范围无法验证"),"corrupt bound choice falls back to root");results.push("invalid binding stays visible as an error without root fallback");return results;
};
(window as any).showNormalProfilePanel=async()=>{reset();panel();await sleep();};
(window as any).showNormalProfileHome=async()=>{reset();view.explicit=true;view.generation=1;view.selected=choice(true);root.render(<StrictMode><App key={++generation}/></StrictMode>);await sleep();};
