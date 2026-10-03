const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('voiceTrial',Object.freeze({request:value=>ipcRenderer.invoke('voice-trial:request',value)}));
