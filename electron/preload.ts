import { contextBridge, ipcRenderer, webUtils } from "electron";
import { commandNames, type DesktopApi } from "./contracts";

const api = Object.fromEntries(commandNames.map(name => [name, async (args: object) => {
  let input = args;
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
ipcRenderer.on("liteseal:scheduled-changed", () => window.dispatchEvent(new Event("liteseal-scheduled-changed")));
