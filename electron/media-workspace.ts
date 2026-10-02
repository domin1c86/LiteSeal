import fs from "node:fs/promises";
import path from "node:path";
import {randomUUID} from "node:crypto";
const domain="LiteSeal/media-workspace/v1";
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const same=(a:string,b:string)=>process.platform==="win32"?a.toLowerCase()===b.toLowerCase():a===b;
type Marker={domain:string;owner:string;id?:string};
async function readMarker(file:string):Promise<Marker>{
  const stat=await fs.lstat(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>256)throw new Error("媒体工作目录标记无法验证");
  const data=JSON.parse(await fs.readFile(file,"utf8")) as Marker;
  if(data.domain!==domain||!uuid.test(data.owner)||Object.keys(data).some(k=>!["domain","owner","id"].includes(k)))throw new Error("媒体工作目录标记无法验证");return data;
}
async function writeMarker(file:string,data:Marker):Promise<void>{
  const handle=await fs.open(file,"wx",0o600);try{await handle.writeFile(JSON.stringify(data));await handle.sync();}finally{await handle.close();}
}
/** One instance owns this fixed, app-private directory. Never scan OS temp or
 * trust a path from a marker. Recovery removes only fixed names in UUID leaves. */
export class MediaWorkspace {
  private constructor(readonly root:string,private owner:string){}
  static async open(base:string):Promise<MediaWorkspace>{
    if(!path.isAbsolute(base))throw new Error("媒体工作目录基础路径无效");await fs.mkdir(base,{recursive:true,mode:0o700});
    const parent=await fs.realpath(base);const root=path.join(parent,"media-work-v1");
    try{await fs.mkdir(root,{mode:0o700});}catch(e){if((e as NodeJS.ErrnoException).code!=="EEXIST")throw e;}
    const stat=await fs.lstat(root);if(!stat.isDirectory()||stat.isSymbolicLink()||!same(await fs.realpath(root),root))throw new Error("媒体工作目录不是自有普通目录");
    const marker=path.join(root,"owner.json");let data:Marker;
    try{data=await readMarker(marker);if(data.id!==undefined)throw new Error("媒体工作目录标记无效");}
    catch(e){if((e as NodeJS.ErrnoException).code!=="ENOENT")throw e;if((await fs.readdir(root)).length)throw new Error("未标记的媒体目录已有内容，已保留");data={domain,owner:randomUUID()};await writeMarker(marker,data);}
    const workspace=new MediaWorkspace(root,data.owner);await workspace.recover();return workspace;
  }
  private async verify():Promise<void>{
    const stat=await fs.lstat(this.root);if(!stat.isDirectory()||stat.isSymbolicLink()||!same(await fs.realpath(this.root),this.root))throw new Error("媒体工作目录已变化");
    const marker=await readMarker(path.join(this.root,"owner.json"));if(marker.owner!==this.owner||marker.id!==undefined)throw new Error("媒体工作目录所有权已变化");
  }
  async allocate():Promise<string>{
    await this.verify();const id=randomUUID();const directory=path.join(this.root,id);await fs.mkdir(directory,{mode:0o700});
    await writeMarker(path.join(directory,"owner.json"),{domain,owner:this.owner,id});return directory;
  }
  async remove(directory:string):Promise<void>{
    await this.verify();const absolute=path.resolve(directory),id=path.basename(absolute);
    if(!uuid.test(id)||!same(path.dirname(absolute),this.root))throw new Error("媒体工作条目范围无法验证");
    let stat;try{stat=await fs.lstat(absolute);}catch(e){if((e as NodeJS.ErrnoException).code==="ENOENT")return;throw e;}
    if(!stat.isDirectory()||stat.isSymbolicLink()||!same(await fs.realpath(absolute),absolute))throw new Error("媒体工作条目不是普通目录");
    const names=await fs.readdir(absolute);if(!names.length){await fs.rmdir(absolute);return;}
    const marker=await readMarker(path.join(absolute,"owner.json"));if(marker.owner!==this.owner||marker.id!==id)throw new Error("媒体工作条目所有权无法验证");
    const allowed=new Set(["owner.json","verified","voice.webm","clipboard.png"]);
    for(const name of names){if(!allowed.has(name))throw new Error("媒体工作条目含未知文件，已保留");const entry=await fs.lstat(path.join(absolute,name));if(!entry.isFile()||entry.isSymbolicLink())throw new Error("媒体工作条目含链接或目录，已保留");}
    // Never recurse: a new unexpected entry or link cannot expand deletion.
    for(const name of names.filter(n=>n!=="owner.json")){await fs.rm(path.join(absolute,name),{force:true,maxRetries:3,retryDelay:100});}
    await fs.unlink(path.join(absolute,"owner.json"));await fs.rmdir(absolute);
  }
  async recover():Promise<void>{
    await this.verify();const names=await fs.readdir(this.root);if(names.length>513)throw new Error("媒体遗留条目超过安全扫描上限，已保留");
    for(const name of names){if(name==="owner.json")continue;if(!uuid.test(name))throw new Error("媒体工作目录含未知条目，已保留");await this.remove(path.join(this.root,name));}
  }
}
