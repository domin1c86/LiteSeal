import { contextBridge, ipcRenderer } from "electron";
import { commandNames, type DesktopApi } from "./contracts";

const api = Object.fromEntries(commandNames.map(name => [name, async (args: object) => {
  const response = await ipcRenderer.invoke(`liteseal:${name}`, args);
  if (!response.ok) throw new Error(response.error);
  return response.result;
}])) as DesktopApi;
contextBridge.exposeInMainWorld("desktop", Object.freeze(api));
