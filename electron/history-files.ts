import fs from "node:fs/promises";
import {constants} from "node:fs";
import path from "node:path";
import type {DesktopBridge} from "./bridge";
export const historyFileCommands=new Set(["export_direct_history_transfer","import_direct_history_transfer","export_transferred_media","export_backup_transferred_media"]);
type Dialogs={open:()=>Promise<string|null>;save:(history:boolean)=>Promise<string|null>};
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function string(value:unknown):value is string {return typeof value==="string"&&value.length>0&&value.length<=256;}
/** Paths come solely from native dialogs; keys and file bytes remain in Rust. */
export async function historyFileCommand(name:string,args:unknown,bridge:DesktopBridge,dialogs:Dialogs,check:()=>void):Promise<unknown>{
  if(!historyFileCommands.has(name)||!args||typeof args!=="object"||Array.isArray(args))throw new Error("无效历史文件操作");
  const input=args as Record<string,unknown>,archive=name==="export_backup_transferred_media",opening=name==="import_direct_history_transfer",history=name==="export_direct_history_transfer";
  const allowed=archive?["id","messageId"]:opening?["scope"]:history?["scope","id","revision"]:["scope","id"];
  if(Object.keys(input).some(key=>!allowed.includes(key))||(archive?(!string(input.id)||!uuid.test(input.id)||!string(input.messageId)||!uuid.test(input.messageId)):!string(input.scope)))throw new Error("无效历史文件参数");
  if(!opening&&!archive&&(!string(input.id)||!uuid.test(input.id)))throw new Error("无效历史编号");
  if(history&&(!Number.isSafeInteger(input.revision)||(input.revision as number)<1))throw new Error("无效历史修订");
  check();
  const selected=opening?await dialogs.open():await dialogs.save(history);check();
  if(!selected)return null;if(!path.isAbsolute(selected))throw new Error("文件选择结果无效");
  if(opening){const result=await bridge.call(name as never,{...input,path:selected} as never);check();return result;}
  const directory=await fs.mkdtemp(path.join(path.dirname(selected),".liteseal-history-export-"));const temporary=path.join(directory,"verified");
  let created:Awaited<ReturnType<typeof fs.stat>>|undefined;
  try {
    check();const result=await bridge.call(name as never,{...input,path:temporary} as never);check();
    const info=await fs.lstat(temporary);if(!info.isFile()||info.isSymbolicLink()||info.size>(history?129*1024*1024:20*1024*1024))throw new Error("历史文件输出无法验证");
    await fs.copyFile(temporary,selected,constants.COPYFILE_EXCL);created=await fs.stat(selected);check();return result;
  } catch(error) {
    if(created){const current=await fs.lstat(selected).catch(()=>null);if(current?.isFile()&&current.ino===created.ino&&current.size===created.size&&current.mtimeMs===created.mtimeMs)await fs.unlink(selected).catch(()=>{});}
    throw error;
  } finally {await fs.rm(directory,{recursive:true,force:true});}
}
