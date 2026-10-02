import {useEffect,useRef,useState} from "react";
import {getDesktopApi} from "../lib/desktopApi";
import type {DirectDraft} from "../../../electron/contracts";
type Local={peer:string;epoch:number;revision:number;text:string;version:number;dirty:boolean;ready:boolean;blocked:boolean;prepared:string|null};
export function useDirectDraft(){
  const local=useRef<Local>({peer:"",epoch:0,revision:0,text:"",version:0,dirty:false,ready:false,blocked:false,prepared:null});
  const live=useRef(false),queue=useRef<Promise<unknown>>(Promise.resolve());
  const [text,showText]=useState(""),[ready,setReady]=useState(false),[saving,setSaving]=useState(false),[dirty,setDirty]=useState(false),[error,setError]=useState("");
  const current=(epoch:number)=>live.current&&local.current.epoch===epoch;
  useEffect(()=>{live.current=true;return()=>{live.current=false;local.current.epoch++;};},[]);
  function pause(){local.current={peer:"",epoch:local.current.epoch+1,revision:0,text:"",version:0,dirty:false,ready:false,blocked:false,prepared:null};showText("");setReady(false);setDirty(false);setSaving(false);setError("");}
  async function load(peer:string){
    const epoch=++local.current.epoch;local.current={peer,epoch,revision:0,text:"",version:0,dirty:false,ready:false,blocked:false,prepared:null};showText("");setReady(false);setDirty(false);setError("");
    if(!peer)return;
    try{const draft=await getDesktopApi().get_direct_draft({account:peer});if(!current(epoch))return;local.current={...local.current,revision:draft.revision,text:draft.text,prepared:draft.prepared,ready:true};showText(draft.text);setReady(true);}
    catch(e){if(current(epoch)){local.current.blocked=true;setError(String(e));}}
  }
  function flush():Promise<DirectDraft&{version:number}>{
    const epoch=local.current.epoch;
    const work=queue.current.catch(()=>{}).then(async()=>{
      if(!current(epoch)||!local.current.ready)throw new Error("草稿范围尚未确认，请重新读取或保留当前正文");
      if(local.current.blocked){const observed=await getDesktopApi().get_direct_draft({account:local.current.peer});if(!current(epoch))throw new Error("草稿范围已失效");if(observed.revision!==local.current.revision)throw new Error("草稿已被其他操作修改，当前正文保留，请重新核对");local.current.blocked=false;}
      const peer=local.current.peer;setSaving(true);
      try{
        while(current(epoch)&&local.current.dirty){
          const {revision,text,version}=local.current;let saved:DirectDraft;
          try{saved=await getDesktopApi().save_direct_draft({account:peer,revision,text});}
          catch(failure){const observed=await getDesktopApi().get_direct_draft({account:peer});if(observed.revision===revision+1&&observed.text===text&&observed.prepared===null)saved=observed;else throw failure;}
          if(!current(epoch))throw new Error("草稿保存结果已失效");
          local.current.revision=saved.revision;local.current.prepared=saved.prepared;
          if(local.current.version===version){local.current.dirty=false;setDirty(false);}setError("");
        }
        if(!current(epoch))throw new Error("草稿范围已失效");
        return {peer,revision:local.current.revision,text:local.current.text,prepared:local.current.prepared,version:local.current.version};
      }catch(e){if(current(epoch)){local.current.blocked=true;setError(String(e));}throw e;}
      finally{if(current(epoch))setSaving(false);}
    });queue.current=work;return work;
  }
  function edit(value:string){if(!local.current.ready)return;local.current.text=value;local.current.version++;local.current.dirty=true;local.current.prepared=null;showText(value);setDirty(true);if(!local.current.blocked)void flush().catch(()=>{});}
  async function consumed(revision:number,version:number,id?:string){
    const {epoch,peer}=local.current;const next=await getDesktopApi().get_direct_draft({account:peer});
    if(!current(epoch))return;
    if(next.revision===revision+1&&next.prepared&&(!id||next.prepared===id)){local.current.revision=next.revision;if(local.current.version===version){local.current.text="";local.current.prepared=next.prepared;local.current.dirty=false;local.current.blocked=false;showText("");setDirty(false);setError("");}}
    else if(next.revision!==local.current.revision){local.current.blocked=true;setError("草稿已经变化，当前正文没有被清空；请重新核对");}
  }
  return {text,ready,saving,dirty,error,load,edit,flush,consumed,pause};
}
