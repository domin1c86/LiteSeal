import { contextBridge, ipcRenderer, webUtils } from "electron";
import { commandNames, type DesktopApi } from "./contracts";

const api = Object.fromEntries(commandNames.map(name => [name, async (args: object) => {
  let input = args;
  if(name==="stage_direct_file") {const {scope,account,file}=args as {scope:string;account:string;file:File};const path=webUtils.getPathForFile(file);if(!path)throw new Error("所选文件没有本机路径");input={scope,account,path};}
  if(name==="stage_direct_voice") {const {scope,account,blob,durationMs}=args as {scope:string;account:string;blob:Blob;durationMs:number};if(!(blob instanceof Blob)||blob.size>11*1024*1024)throw new Error("录音大小无效");input={scope,account,durationMs,bytes:await blob.arrayBuffer()};}
  if(name==="stage_group_attachment_file") {const {groupId,file}=args as {groupId:string;file:File};const path=webUtils.getPathForFile(file);if(!path)throw new Error("文件没有本机路径，请选择文件或粘贴图片");input={groupId,path};}
  if (name === "stage_attachment_file") {
    const { peerId, file } = args as { peerId: string; file: File };
    const path = webUtils.getPathForFile(file);
    if (!path) throw new Error("剪贴板文件没有本机路径，请使用图片粘贴或选择文件");
    input = { peerId, path };
  }
  const response = await ipcRenderer.invoke(`liteseal:${name}`, input);
  if (!response.ok) throw new Error(response.error);
  return response.result;
}])) as DesktopApi;
contextBridge.exposeInMainWorld("desktop", Object.freeze(api));
// A fixed event only; no raw ipcRenderer or arbitrary channel subscription.
ipcRenderer.on("liteseal:locked", () => window.dispatchEvent(new Event("liteseal-app-locked")));
ipcRenderer.on("liteseal:device-paused", () => window.dispatchEvent(new Event("liteseal-device-paused")));
ipcRenderer.on("liteseal:scheduled-changed", () => window.dispatchEvent(new Event("liteseal-scheduled-changed")));
ipcRenderer.on("liteseal:groups-changed", () => window.dispatchEvent(new Event("liteseal-groups-changed")));
ipcRenderer.on("liteseal:session-refresh-changed", () => window.dispatchEvent(new Event("liteseal-session-refresh-changed")));
ipcRenderer.on("liteseal:normal-profile-changed", () => window.dispatchEvent(new Event("liteseal-normal-profile-changed")));
ipcRenderer.on("liteseal:direct-changed", () => window.dispatchEvent(new Event("liteseal-direct-changed")));
ipcRenderer.on("liteseal:direct-notification-target", () => window.dispatchEvent(new Event("liteseal-direct-notification-target")));
ipcRenderer.on("liteseal:direct-status", (_event,report) => window.dispatchEvent(new CustomEvent("liteseal-direct-status",{detail:report})));
