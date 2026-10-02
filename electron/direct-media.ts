import {randomUUID,createHash} from "node:crypto";
import fs from "node:fs/promises";
import {linkSync} from "node:fs";
import path from "node:path";
import type {DesktopBridge} from "./bridge";
import type {DirectMediaInfo,DirectMediaTask} from "./contracts";
type Host={capture:()=>number;check:(epoch:number)=>void;temp:()=>string;open:()=>Promise<string|null>;save:(name:string)=>Promise<string|null>;clipboard:()=>Promise<Buffer>};
type Preview={scope:string;id:string;epoch:number;directory:string;file:string;digest:string;info:DirectMediaInfo;pending:boolean};
const limit=20*1024*1024;
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const directMediaCommands=new Set(["select_direct_media","stage_direct_file","stage_direct_voice","stage_direct_clipboard","export_direct_media","close_direct_media_preview"]);
/** Main-only paths and authenticated bytes, renderer-only opaque URLs. */
export class DirectMedia {
  private previews=new Map<string,Preview>();
  private cleanups=new Set<Promise<void>>();
  constructor(private bridge:Pick<DesktopBridge,"call">,private host:Host){}
  private cleanup(directory:string):Promise<void>{
    const work=fs.rm(directory,{recursive:true,force:true,maxRetries:3,retryDelay:100});this.cleanups.add(work);
    void work.finally(()=>this.cleanups.delete(work)).catch(()=>{});return work;
  }
  async settle():Promise<void>{await Promise.all([...this.cleanups]);}
  invalidate(id?:string):void{
    for(const [token,p] of this.previews){if(id&&p.id!==id)continue;this.previews.delete(token);void this.cleanup(p.directory).catch(()=>{});}
  }
  async close(url:string):Promise<void>{const token=this.token(url);const p=this.previews.get(token);if(p){this.previews.delete(token);await this.cleanup(p.directory);}else await this.settle();}
  private token(url:string):string{const parsed=new URL(url);if(parsed.protocol!=="liteseal-media:"||parsed.host!=="preview"||parsed.search||parsed.hash||!uuid.test(parsed.pathname.slice(1)))throw new Error("预览句柄无效");return parsed.pathname.slice(1);}
  private input(args:unknown,allowed:string[]):Record<string,unknown>{if(!args||typeof args!=="object"||Array.isArray(args)||Object.keys(args).some(k=>!allowed.includes(k)))throw new Error("媒体参数无效");return args as Record<string,unknown>;}
  private async current(epoch:number,scope:string):Promise<void>{this.host.check(epoch);const view=await this.bridge.call("get_direct_chat",{});this.host.check(epoch);if(view.notification_scope!==scope)throw new Error("媒体档案已变化");}
  private async info(scope:string,id:string,pending:boolean):Promise<DirectMediaInfo>{
    if(!pending)return this.bridge.call("get_direct_media_info",{scope,id});
    const row=(await this.bridge.call("get_direct_media_tasks",{scope})).find(t=>t.id===id&&!t.download&&["staged","uploaded"].includes(t.phase));if(!row)throw new Error("原暂存媒体不可用");return{...row,cache:row.phase};
  }
  private route(input:Record<string,unknown>):{scope:string;account:string}{if(typeof input.scope!=="string"||!/^[0-9a-f]{64}$/.test(input.scope)||typeof input.account!=="string"||!uuid.test(input.account))throw new Error("媒体范围或账号无效");return{scope:input.scope,account:input.account};}
  private async stage(scope:string,account:string,file:string,epoch:number,voice?:number):Promise<DirectMediaTask>{
    if(!path.isAbsolute(file)||file.length>32767)throw new Error("媒体路径无效");await this.current(epoch,scope);
    const result=await this.bridge.call("stage_direct_media",{scope,account,id:randomUUID(),path:file,kind:voice===undefined?"attachment":"voice",durationMs:voice});
    await this.current(epoch,scope);return result;
  }
  async run(name:string,args:unknown):Promise<DirectMediaTask|string|null|void>{
    if(name==="close_direct_media_preview"){const input=this.input(args,["url"]);if(typeof input.url!=="string")throw new Error("预览句柄无效");return this.close(input.url);}
    const epoch=this.host.capture();
    if(name==="export_direct_media"){
      const input=this.input(args,["scope","id","preview","pending"]);if(typeof input.scope!=="string"||!/^[0-9a-f]{64}$/.test(input.scope)||typeof input.id!=="string"||!uuid.test(input.id)||input.preview!==undefined&&typeof input.preview!=="boolean"||input.pending!==undefined&&typeof input.pending!=="boolean"||input.pending&&!input.preview)throw new Error("媒体导出参数无效");
      const scope=input.scope,id=input.id;await this.current(epoch,scope);
      const pending=input.pending===true;const info=await this.info(scope,id,pending);await this.current(epoch,scope);
      if(input.preview&&!['image/png','image/jpeg','image/webp','audio/webm'].includes(info.mime))throw new Error("此文件请另存为查看");
      const destination=input.preview?null:await this.host.save(info.name);await this.current(epoch,scope);if(!input.preview&&!destination)return null;
      const directory=await fs.mkdtemp(path.join(input.preview?this.host.temp():path.dirname(destination!),".liteseal-direct-media-"));const file=path.join(directory,"verified");let retained=false;
      try{
        const written=await this.bridge.call("write_direct_media",{scope,id,path:file,pending});await this.current(epoch,scope);
        const latest=await this.info(scope,id,pending);await this.current(epoch,scope);
        if(written.info.id!==id||written.info.mime!==latest.mime||written.info.size!==latest.size||!/^[0-9a-f]{64}$/.test(written.digest))throw new Error("媒体认证结果无法验证");
        if(input.preview){if(this.previews.size>=16)throw new Error("请先关闭部分媒体预览");const token=randomUUID();this.previews.set(token,{scope,id,epoch,directory,file,digest:written.digest,info:written.info,pending});retained=true;return `liteseal-media://preview/${token}`;}
        // No await between the final scope check and the exclusive commit.
        this.host.check(epoch);linkSync(file,destination!);return "已保存认证附件";
      }finally{if(!retained)await fs.rm(directory,{recursive:true,force:true});}
    }
    const allowed=name==="stage_direct_file"?["scope","account","path"]:name==="stage_direct_voice"?["scope","account","bytes","durationMs"]:["scope","account"];
    const input=this.input(args,allowed);const {scope,account}=this.route(input);await this.current(epoch,scope);
    if(name==="select_direct_media"){const selected=await this.host.open();await this.current(epoch,scope);return selected?this.stage(scope,account,selected,epoch):null;}
    if(name==="stage_direct_file"){if(typeof input.path!=="string")throw new Error("媒体路径无效");return this.stage(scope,account,input.path,epoch);}
    const voice=name==="stage_direct_voice";
    if(!voice&&name!=="stage_direct_clipboard")throw new Error("媒体命令无效");
    let bytes:Buffer;
    if(voice){if(!(input.bytes instanceof ArrayBuffer)||input.bytes.byteLength<1||input.bytes.byteLength>11*1024*1024||!Number.isInteger(input.durationMs)||Number(input.durationMs)<1||Number(input.durationMs)>60000)throw new Error("录音时长或大小无效");bytes=Buffer.from(input.bytes);}
    else{bytes=await this.host.clipboard();if(bytes.length>limit)throw new Error("剪贴板图片超过 20 MiB");}
    await this.current(epoch,scope);const directory=await fs.mkdtemp(path.join(this.host.temp(),".liteseal-direct-input-"));const file=path.join(directory,voice?"voice.webm":"clipboard.png");
    try{await fs.writeFile(file,bytes,{flag:"wx",mode:0o600});await this.current(epoch,scope);return await this.stage(scope,account,file,epoch,voice?Number(input.durationMs):undefined);}
    finally{bytes.fill(0);await fs.rm(directory,{recursive:true,force:true});}
  }
  async response(request:Request):Promise<Response>{
    let token:string;try{token=this.token(request.url);}catch{return new Response(null,{status:404});}
    const p=this.previews.get(token);if(!p||request.method!=="GET")return new Response(null,{status:404});
    try{
      await this.current(p.epoch,p.scope);const info=await this.info(p.scope,p.id,p.pending);await this.current(p.epoch,p.scope);
      if(this.previews.get(token)!==p||info.mime!==p.info.mime||info.size!==p.info.size)throw new Error("预览已失效");
      const stat=await fs.lstat(p.file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size!==info.size||stat.size>limit)throw new Error("媒体预览文件无效");
      const bytes=await fs.readFile(p.file);if(createHash("sha256").update(bytes).digest("hex")!==p.digest)throw new Error("媒体预览认证失败");
      await this.info(p.scope,p.id,p.pending);await this.current(p.epoch,p.scope);if(this.previews.get(token)!==p)throw new Error("预览已关闭");
      const headers={"Content-Type":info.mime,"Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Accept-Ranges":"bytes"};const range=request.headers.get("range");
      if(range){const m=/^bytes=(\d+)-(\d*)$/.exec(range);if(!m)return new Response(null,{status:416});const start=Number(m[1]),end=m[2]?Number(m[2]):bytes.length-1;if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start<0||start>end||end>=bytes.length)return new Response(null,{status:416});return new Response(bytes.subarray(start,end+1),{status:206,headers:{...headers,"Content-Range":`bytes ${start}-${end}/${bytes.length}`}});}
      return new Response(bytes,{headers});
    }catch{this.invalidate(p.id);return new Response(null,{status:403});}
  }
}
