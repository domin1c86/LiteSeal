import { app, clipboard, BrowserWindow, dialog, ipcMain, Menu, nativeImage, net, powerMonitor, protocol, session, shell, Tray } from "electron";
import { ChatNotifications } from "./notifications";
import path from "node:path";
import fs from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { DesktopBridge } from "./bridge";
import { commandNames } from "./contracts";
import type {CommandMap} from "./contracts";
import { deviceCommands, DeviceControlGate } from "./device-control";
import {DirectMedia,directMediaCommands} from "./direct-media";
import {MediaWorkspace} from "./media-workspace";
import {historyFileCommands,historyFileCommand} from "./history-files";

protocol.registerSchemesAsPrivileged([{ scheme: "liteseal", privileges: { standard: true, secure: true, supportFetchAPI: true } },{scheme:"liteseal-media",privileges:{standard:true,secure:true,supportFetchAPI:true,stream:true}}]);
const devUrl = "http://127.0.0.1:1420";
const bridge = new DesktopBridge();
const deviceControl = new DeviceControlGate(bridge);
let directMedia:DirectMedia|undefined;
function suspendDevices() { directMedia?.invalidate(); deviceControl.suspend(); mainWindow?.webContents.send("liteseal:device-paused"); }
let screenLocked = false;
let systemSuspended = false;
let mainWindow: BrowserWindow | undefined;
let archiveWindow: BrowserWindow | undefined;
let archiveHandle: string | null = null;
let backupGeneration = 0;
const archiveCommands = new Set(["get_backup_archive_info", "get_backup_conversations", "get_backup_history", "get_backup_transferred_history", "export_backup_transferred_media", "export_backup_attachment", "close_backup_archive", "app_lock_state"]);
function invalidateBackups() {
  backupGeneration++;
  archiveHandle = null;
  const window = archiveWindow; archiveWindow = undefined;
  window?.destroy();
  void bridge.call("close_backup_archive", {}).catch(() => {});
}
let quitting = false;
let cleanedUp = false;
let exitRequested = false;
let tray: Tray | undefined;
let explainedTray = false;
const notifications = new ChatNotifications(() => mainWindow, bridge);
let locked = false;
let lockEnabled = false;
let lockGeneration = 0;
let directContextRequest = 0;
let unlockAfter = 0;
let unlockBusy = false;
let releaseUrl: string | null = null;
function lockApp() {
  invalidateBackups();
  if (!lockEnabled || locked) return;
  suspendDevices();
  locked = true; lockGeneration++;
  notifications.lock(true);
  // Unmount decrypted renderer state, including message and image previews.
  mainWindow?.webContents.send("liteseal:locked");
}

if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on("second-instance", () => {
    if (mainWindow?.isMinimized()) mainWindow.restore();
    mainWindow?.show();
    mainWindow?.focus();
  });
  app.on("window-all-closed", () => app.quit());
  app.on("before-quit", event => {
    invalidateBackups();
    suspendDevices();
    if (cleanedUp) return;
    exitRequested = true;
    event.preventDefault();
    // Let the renderer's pending-save guard run while the sidecar is still alive.
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.close();
      return;
    }
    if (quitting) return;
    quitting = true;
    notifications.clear();
    tray?.destroy();
    void bridge.stop().then(()=>directMedia?.settle()).catch(error=>dialog.showErrorBox("媒体临时文件整理失败",String(error))).finally(() => { cleanedUp = true; app.quit(); });
  });
  bridge.on("failure", (error: Error) => {
    if (!quitting && mainWindow) {
      dialog.showErrorBox("LiteSeal 桌面服务异常", error.message);
      app.quit();
    }
  });
  void app.whenReady().then(async () => {
    const mediaWorkspace=await MediaWorkspace.open(app.getPath("userData"));
    const root = app.getAppPath();
    const assetRoot = path.join(root, "ui", "dist");
    const executable = path.join(app.isPackaged ? process.resourcesPath : path.join(root, "target", "debug"),
      app.isPackaged ? "desktop" : "", `liteseal-desktop${process.platform === "win32" ? ".exe" : ""}`);
    await bridge.start(executable);
    let scheduledBusy = false;
    setInterval(() => {
      if (scheduledBusy || quitting || exitRequested) return;
      scheduledBusy = true;
      void bridge.call("process_scheduled_messages", {}).then(changes => {
        if (changes > 0 && !locked) mainWindow?.webContents.send("liteseal:scheduled-changed");
      }).catch(() => {}).finally(() => { scheduledBusy = false; });
    }, 1000).unref();
    let groupsBusy = false;
    setInterval(() => {
      if (groupsBusy || quitting || exitRequested) return;
      groupsBusy = true;
      const notificationGeneration = notifications.generation();
      const groupRevision = notifications.groupRevision();
      void bridge.call("process_groups", {}).then(report => {
        try { notifications.receiveGroups(report, notificationGeneration, groupRevision); } catch { /* OS notifications never fail delivery. */ }
        if (report.changed > 0 && !locked) mainWindow?.webContents.send("liteseal:groups-changed");
      }).catch(() => {}).finally(() => { groupsBusy = false; });
    }, 10000).unref();
    let refreshBusy=false;
    setInterval(()=>{
      if(refreshBusy||locked||screenLocked||systemSuspended||quitting||exitRequested)return;
      let epoch:number;try{epoch=deviceControl.capture();}catch{return;}
      refreshBusy=true;
      void bridge.call("process_session_refreshes",{}).then(changed=>{
        deviceControl.check(epoch);if(changed&&!locked&&!screenLocked&&!systemSuspended)mainWindow?.webContents.send("liteseal:session-refresh-changed");
      }).catch(()=>{}).finally(()=>{refreshBusy=false;});
    },30000).unref();
    let directBusy=false;
    let audioBusy = false;
    setInterval(() => {
      if (audioBusy || locked || screenLocked || systemSuspended || quitting || exitRequested) return;
      let epoch: number; try { epoch = deviceControl.capture(); } catch { return; }
      const generation = lockGeneration; audioBusy = true;
      void bridge.call("process_audio_calls", {}).then(report => {
        deviceControl.check(epoch); if (generation !== lockGeneration) return;
        mainWindow?.webContents.send("liteseal:audio-status", report);
      }).catch(() => {
        try {
          deviceControl.check(epoch);
          if (generation === lockGeneration) mainWindow?.webContents.send("liteseal:audio-status",
            {scope: null, call: null, handle: null, closed: null, unavailable: true});
        } catch { /* A suspended context already releases local audio. */ }
      }).finally(() => { audioBusy = false; });
    }, 2000).unref();
    setInterval(()=>{
      if(directBusy||locked||screenLocked||systemSuspended||quitting||exitRequested)return;
      let epoch:number;try{epoch=deviceControl.capture();}catch{return;}
      const generation=lockGeneration,notificationGeneration=notifications.directGeneration(),notificationRevision=notifications.directRevision();directBusy=true;
      void bridge.call("process_direct_chat",{}).then(report=>{
        deviceControl.check(epoch);if(generation!==lockGeneration)return;
        try{notifications.receiveDirect(report,notificationGeneration,notificationRevision);}catch{/* Toast failures never fail delivery or ACK. */}
        mainWindow?.webContents.send("liteseal:direct-status",report);
        if(report.changed)mainWindow?.webContents.send("liteseal:direct-changed");
      }).catch(()=>{}).finally(()=>{directBusy=false;});
    },2000).unref();
    let directMediaBusy=false;
    setInterval(()=>{
      if(directMediaBusy||locked||screenLocked||systemSuspended||quitting||exitRequested)return;
      let epoch:number;try{epoch=deviceControl.capture();}catch{return;}
      const generation=lockGeneration;directMediaBusy=true;
      void bridge.call("process_direct_media",{}).then(report=>{
        deviceControl.check(epoch);if(generation!==lockGeneration)return;
        mainWindow?.webContents.send("liteseal:direct-status",report);
        if(report.changed)mainWindow?.webContents.send("liteseal:direct-changed");
      }).catch(()=>{}).finally(()=>{directMediaBusy=false;});
    },2000).unref();
    let directOperationsBusy=false;
    setInterval(()=>{
      if(directOperationsBusy||locked||screenLocked||systemSuspended||quitting||exitRequested)return;
      let epoch:number;try{epoch=deviceControl.capture();}catch{return;}
      const generation=lockGeneration;directOperationsBusy=true;
      void bridge.call("process_direct_operations",{}).then(report=>{
        deviceControl.check(epoch);if(generation!==lockGeneration)return;
        mainWindow?.webContents.send("liteseal:direct-status",report);
        if((report.operation_poll?.received??0)>0||report.operation?.condition==="accepted"){
          directMedia?.invalidate();notifications.retireDirectOperations();
        }
        if(report.changed)mainWindow?.webContents.send("liteseal:direct-changed");
      }).catch(()=>{}).finally(()=>{directOperationsBusy=false;});
    },2000).unref();
    for(const receive of [false,true]) {
      let historyBusy=false;
      setInterval(()=>{
        if(historyBusy||locked||screenLocked||systemSuspended||quitting||exitRequested)return;
        let epoch:number;try{epoch=deviceControl.capture();}catch{return;}
        const generation=lockGeneration;historyBusy=true;
        void bridge.call("process_direct_history",{receive}).then(report=>{
          deviceControl.check(epoch);if(generation!==lockGeneration)return;
          mainWindow?.webContents.send("liteseal:direct-status",report);
          if(report.changed)mainWindow?.webContents.send("liteseal:direct-changed");
        }).catch(()=>{}).finally(()=>{historyBusy=false;});
      },2000).unref();
    }
    try {
      const configuration = JSON.parse(await fs.readFile(path.join(app.getPath("userData"), "app-lock.json"), "utf8"));
      if (typeof configuration.enabled !== "boolean") throw new Error("应用锁配置损坏");
      lockEnabled = configuration.enabled; locked = lockEnabled; notifications.lock(locked);
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    if (locked) suspendDevices();
    if (quitting) return;
    app.setAppUserModelId("com.liteseal.app");
    powerMonitor.on("lock-screen", () => { screenLocked = true; suspendDevices(); notifications.lock(true); lockApp(); });
    powerMonitor.on("suspend", () => { systemSuspended = true; suspendDevices(); invalidateBackups(); void bridge.call("suspend_scheduled_messages", {}).catch(() => {}); });
    powerMonitor.on("unlock-screen", () => { screenLocked = false; if (!locked) { notifications.lock(false); if (!systemSuspended) void deviceControl.resume().catch(() => {}); } });
    powerMonitor.on("resume", () => { systemSuspended = false; if (!locked && !screenLocked) void deviceControl.resume().catch(() => {}); });
    setInterval(() => { if (powerMonitor.getSystemIdleTime() >= 300) lockApp(); }, 1000).unref();
    directMedia=new DirectMedia(bridge,{
      capture:()=>{if(locked||screenLocked||systemSuspended)throw new Error("媒体已暂停");return deviceControl.capture();},
      check:epoch=>{if(locked||screenLocked||systemSuspended)throw new Error("媒体已暂停");deviceControl.check(epoch);},
      temp:()=>app.getPath("temp"),
      open:async()=>{const r=await dialog.showOpenDialog(mainWindow!,{title:"选择加密文件或图片（20 MiB）",properties:["openFile"]});return r.canceled?null:r.filePaths[0]??null;},
      save:async name=>{const r=await dialog.showSaveDialog(mainWindow!,{title:"认证附件另存为（新文件）",defaultPath:name});return r.canceled?null:r.filePath??null;},
      clipboard:async()=>{const items=await clipboard.read();const image=items.flatMap(item=>item.types.filter(type=>type.startsWith("image/")).map(type=>({item,type})))[0];if(!image)throw new Error("剪贴板没有图片");const blob=await image.item.getType(image.type);if(!(blob instanceof Blob)||blob.size>20*1024*1024)throw new Error("剪贴板图片过大或无效");const source=Buffer.from(await blob.arrayBuffer());if(image.type==="image/png")return source;const picture=nativeImage.createFromBuffer(source);if(picture.isEmpty())throw new Error("剪贴板图片损坏");return picture.toPNG();},
    },mediaWorkspace);
    protocol.handle("liteseal-media",request=>directMedia!.response(request));
    const csp = `default-src 'self'; script-src 'self'${app.isPackaged ? "" : " 'unsafe-inline'"}; style-src 'self' 'unsafe-inline'; img-src 'self' data: liteseal-media:; media-src 'self' data: blob: liteseal-media:; connect-src 'self'${app.isPackaged ? "" : " ws://127.0.0.1:1420"}; object-src 'none'; base-uri 'none'; frame-src 'none'`;
    protocol.handle("liteseal", async request => {
      const url = new URL(request.url);
      if (url.host !== "app" || request.method !== "GET") return new Response(null, { status: 403 });
      let file: string;
      try { file = path.resolve(assetRoot, `.${decodeURIComponent(url.pathname === "/" ? "/index.html" : url.pathname)}`); }
      catch { return new Response(null, { status: 400 }); }
      if (!file.startsWith(assetRoot + path.sep)) return new Response(null, { status: 403 });
      const response = await net.fetch(pathToFileURL(file).href);
      const headers = new Headers(response.headers);
      headers.set("Content-Security-Policy", csp);
      return new Response(response.body, { status: response.status, headers });
    });
    const trustedUrl = (value: string) => {
      try {
        const url = new URL(value);
        return app.isPackaged ? url.protocol === "liteseal:" && url.host === "app" : url.origin === devUrl;
      } catch { return false; }
    };
    session.defaultSession.setPermissionRequestHandler((contents, permission, callback, details) => {
      callback(permission === "media" && !locked && contents === mainWindow?.webContents
        && trustedUrl(details.requestingUrl) && "mediaTypes" in details
        && details.mediaTypes?.length === 1 && details.mediaTypes[0] === "audio");
    });
    session.defaultSession.setPermissionCheckHandler((contents, permission, origin, details) =>
      permission === "media" && !locked && contents === mainWindow?.webContents
      && details.isMainFrame && details.mediaType === "audio" && trustedUrl(details.requestingUrl ?? origin));
    session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
      callback({ responseHeaders: { ...details.responseHeaders,
        "Content-Security-Policy": [details.webContentsId === archiveWindow?.webContents.id ? csp.replace(/connect-src [^;]+/, "connect-src 'none'") : csp],
      } });
    });
    for (const name of commandNames) {
      ipcMain.handle(`liteseal:${name}`, async (event, args: object) => {
        const readingArchive = event.sender === archiveWindow?.webContents;
        const senderWindow = readingArchive ? archiveWindow : mainWindow;
        if (!senderWindow || event.sender !== senderWindow.webContents || event.senderFrame !== senderWindow.webContents.mainFrame || !trustedUrl(event.senderFrame.url) || readingArchive && !archiveCommands.has(name)) {
          return { ok: false, error: "不允许的桌面接口来源" };
        }
        try {
          if (name === "app_lock_state") return { ok: true, result: locked };
          if (name === "lock_app") { if (!lockEnabled) throw new Error("请在账号设置中先验证 Windows 密码并启用应用锁"); lockApp(); return { ok: true, result: null }; }
          if (name === "unlock_app") {
            if (!locked) return { ok: true, result: null };
            if (unlockBusy || Date.now() < unlockAfter) throw new Error("请稍后再试");
            const password = (args as { password: string }).password;
            if (typeof password !== "string" || password.length > 1024) throw new Error("无效密码");
            unlockBusy = true; unlockAfter = Date.now() + 5000;
            try { await bridge.call("unlock_app", { password }); locked = false; notifications.lock(screenLocked); if (!screenLocked && !systemSuspended) await deviceControl.resume(); }
            finally { unlockBusy = false; }
            return { ok: true, result: null };
          }
          if (locked) throw new Error("应用已锁定，请先验证 Windows 身份");
          const generation = lockGeneration;
          const deviceEpoch = deviceCommands.has(name) ? deviceControl.capture() : null;
          if(historyFileCommands.has(name)){
            const archiveEpoch=backupGeneration;
            const check=()=>{if(locked||generation!==lockGeneration)throw new Error("应用已锁定，历史文件结果失效");if(deviceEpoch!==null)deviceControl.check(deviceEpoch);if(readingArchive&&archiveEpoch!==backupGeneration)throw new Error("离线档案已关闭或变化");};
            const result=await historyFileCommand(name,args,bridge,{
              open:async()=>{const choice=await dialog.showOpenDialog(senderWindow,{title:"选择仅本设备可解密的授权历史文件",properties:["openFile"],filters:[{name:"LiteSeal 授权历史",extensions:["lhistory"]}]});return choice.canceled?null:choice.filePaths[0]??null;},
              save:async history=>{const choice=await dialog.showSaveDialog(senderWindow,{title:history?"保存选定历史授权（10 分钟内导入）":"保存认证后的迁移附件",defaultPath:history?"LiteSeal-selected-history.lhistory":"LiteSeal-history-attachment",...(history?{filters:[{name:"LiteSeal 授权历史",extensions:["lhistory"]}]}:{})});return choice.canceled?null:choice.filePath??null;},
            },check);
            if(name==="import_direct_history_transfer"&&result){directMedia?.invalidate();notifications.retireDirectOperations();mainWindow?.webContents.send("liteseal:direct-changed");}
            return{ok:true,result};
          }
          if(directMediaCommands.has(name)){const result=await directMedia!.run(name,args);if(deviceEpoch!==null)deviceControl.check(deviceEpoch);if(locked||generation!==lockGeneration)throw new Error("媒体结果已失效");return{ok:true,result};}
          if(["select_normal_profile","clear_normal_profile","sign_out","clear_keypair","logout_all_sessions","change_password","save_root_session"].includes(name))directMedia?.invalidate();
          if(name==="clear_direct_media_cache")directMedia?.invalidate();
          if(name==="hide_direct_message"||name==="hide_transferred_message"||name==="clear_direct_media"||name==="cancel_direct_media")directMedia?.invalidate((args as {id:string}).id);
          if(name==="direct_operation_step")directMedia?.invalidate();
          if(name==="stage_group_recorded_audio"){
            const input=args as {groupId:string;encoded:string;durationMs:number};if(Object.keys(args).some(k=>!["groupId","encoded","durationMs"].includes(k))||typeof input.groupId!=="string"||input.groupId.length>128||typeof input.encoded!=="string"||input.encoded.length>15*1024*1024||!Number.isInteger(input.durationMs)||input.durationMs<1||input.durationMs>60000)throw new Error("群语音长度、大小或参数无效");const bytes=Buffer.from(input.encoded,"base64");if(bytes.length>11*1024*1024||!bytes.subarray(0,4).equals(Buffer.from([0x1a,0x45,0xdf,0xa3])))throw new Error("群语音格式无效");const result=await bridge.call(name,input);if(locked||generation!==lockGeneration)throw new Error("应用已锁定");return{ok:true,result};
          }
          if(name==="select_group_attachment"||name==="stage_group_attachment_file"){
            const input=args as {groupId:string;path?:string};if(typeof input.groupId!=="string"||input.groupId.length>128||Object.keys(args).some(key=>!(name==="select_group_attachment"?["groupId"]:["groupId","path"]).includes(key)))throw new Error("无效群附件参数");
            let selected=input.path;if(name==="select_group_attachment"){const result=await dialog.showOpenDialog(mainWindow!,{title:"选择群文件（最大 20 MiB）",properties:["openFile"]});if(result.canceled)return{ok:true,result:null};selected=result.filePaths[0];}
            if(locked||generation!==lockGeneration)throw new Error("应用已锁定");if(typeof selected!=="string"||!path.isAbsolute(selected))throw new Error("无效文件路径");
            const result=await bridge.call("select_group_attachment",{groupId:input.groupId,path:selected} as never);if(locked||generation!==lockGeneration)throw new Error("应用已锁定");return{ok:true,result};
          }
          if(name==="stage_group_clipboard_image"){
            const {groupId}=args as {groupId:string};if(typeof groupId!=="string"||groupId.length>128||Object.keys(args).some(k=>k!=="groupId"))throw new Error("无效群编号");
            const items=await clipboard.read();const image=items.flatMap(item=>item.types.filter(type=>type.startsWith("image/")).map(type=>({item,type})))[0];if(!image)throw new Error("剪贴板没有图片");const clip=await image.item.getType(image.type);if(!(clip instanceof Blob))throw new Error("剪贴板图片格式无效");const source=Buffer.from(await clip.arrayBuffer());if(source.length>11*1024*1024)throw new Error("图片过大");const picture=image.type==="image/png"?null:nativeImage.createFromBuffer(source);if(picture?.isEmpty())throw new Error("剪贴板图片损坏");const bytes=picture?picture.toPNG():source;if(bytes.length>11*1024*1024)throw new Error("图片过大");
            const result=await bridge.call("stage_group_clipboard_image",{groupId,encoded:bytes.toString("base64")} as never);if(locked||generation!==lockGeneration)throw new Error("应用已锁定");return{ok:true,result};
          }
          if(name==="export_group_attachment"){
            const input=args as {groupId:string;id:string;preview?:boolean;media?:"image"|"audio"};if(typeof input.groupId!=="string"||typeof input.id!=="string"||input.groupId.length>128||input.id.length>128||Object.keys(args).some(k=>!["groupId","id","preview","media"].includes(k)))throw new Error("无效群附件导出参数");
            let destination:string|undefined;if(!input.preview){const result=await dialog.showSaveDialog(mainWindow!,{title:"保存认证后的群附件"});if(result.canceled)return{ok:true,result:null};destination=result.filePath;}
            if(locked||generation!==lockGeneration)throw new Error("应用已锁定");
            const directory=await fs.mkdtemp(path.join(input.preview?app.getPath("temp"):path.dirname(destination!),".liteseal-group-export-"));const temporary=path.join(directory,"verified");
            try{await bridge.call("export_group_attachment",{groupId:input.groupId,id:input.id,path:temporary} as never);if(locked||generation!==lockGeneration)throw new Error("应用已锁定");if(input.preview){const info=await fs.stat(temporary);if(info.size>20*1024*1024)throw new Error("群附件过大");const bytes=await fs.readFile(temporary);let mime=bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))?"image/png":bytes[0]===255&&bytes[1]===216&&bytes[2]===255?"image/jpeg":bytes.subarray(0,4).toString()==="RIFF"&&bytes.subarray(8,12).toString()==="WEBP"?"image/webp":null;if(input.media==="audio"){if(!bytes.subarray(0,4).equals(Buffer.from([0x1a,0x45,0xdf,0xa3]))||!bytes.subarray(0,4096).includes(Buffer.from("A_OPUS")))throw new Error("群语音格式无效");mime="audio/webm";}if(!mime)throw new Error("附件格式不能预览，请另存为");return{ok:true,result:`data:${mime};base64,${bytes.toString("base64")}`};}await fs.rename(temporary,destination!);return{ok:true,result:"已保存"};}finally{await fs.rm(directory,{recursive:true,force:true});}
          }
          const backupEpoch = backupGeneration;
          if (name === "start_backup_export" || name === "start_backup_restore") {
            const input = args as { password: string; includeAttachments?: boolean };
            const allowed = name === "start_backup_export" ? ["password", "includeAttachments"] : ["password"];
            if (Object.keys(args).some(key => !allowed.includes(key)) || typeof input.password !== "string" || Buffer.byteLength(input.password, "utf8") < 12 || Buffer.byteLength(input.password, "utf8") > 1024 || name === "start_backup_export" && typeof input.includeAttachments !== "boolean") throw new Error("备份口令须为 12–1024 字节，且只能传入备份选项");
            if (archiveWindow) throw new Error("请先关闭离线恢复档案");
            let selected: string | undefined;
            if (name === "start_backup_export") {
              const result = await dialog.showSaveDialog(mainWindow!, { title: "创建口令加密备份（新文件）", defaultPath: "LiteSeal-history.lseal", filters: [{ name: "LiteSeal 加密备份", extensions: ["lseal"] }] });
              if (!result.canceled) selected = result.filePath;
              if (selected) {
                try { await fs.lstat(selected); throw new Error("备份目标已存在，请选择新文件"); }
                catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
              }
            } else {
              const result = await dialog.showOpenDialog(mainWindow!, { title: "选择加密备份，隔离离线恢复", properties: ["openFile"], filters: [{ name: "LiteSeal 加密备份", extensions: ["lseal"] }] });
              if (!result.canceled) selected = result.filePaths[0];
            }
            if (!selected) return { ok: true, result: null };
            if (locked || generation !== lockGeneration || backupEpoch !== backupGeneration) throw new Error("应用锁定或恢复档案已关闭，操作已取消");
            const result = name === "start_backup_export"
              ? await bridge.call(name, { path: selected, password: input.password, includeAttachments: input.includeAttachments } as never)
              : await bridge.call(name, { path: selected, parent: path.join(app.getPath("userData"), "archive-work"), password: input.password } as never);
            if (locked || generation !== lockGeneration || backupEpoch !== backupGeneration) { invalidateBackups(); throw new Error("应用锁定或恢复档案已关闭，操作已取消"); }
            return { ok: true, result };
          }
          if (name === "open_backup_archive") {
            const id = (args as { id: string }).id;
            if (typeof id !== "string" || Object.keys(args).some(key => key !== "id")) throw new Error("恢复档案编号无效");
            const result = await bridge.call(name, { id });
            if (locked || generation !== lockGeneration || backupEpoch !== backupGeneration) { invalidateBackups(); throw new Error("应用锁定或恢复档案已关闭"); }
            if (archiveWindow) { if (archiveHandle !== id) throw new Error("请先关闭已打开的档案"); archiveWindow.focus(); return { ok: true, result }; }
            archiveHandle = id;
            const window = archiveWindow = new BrowserWindow({ width: 1050, height: 780, minWidth: 390, title: "LiteSeal · 离线恢复档案", show: false,
              webPreferences: { preload: path.join(root, "dist-electron", "preload.cjs"), contextIsolation: true, nodeIntegration: false, sandbox: true } });
            window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
            window.webContents.on("will-navigate", event => event.preventDefault());
            window.on("closed", () => { if (archiveWindow === window) { backupGeneration++; archiveWindow = undefined; archiveHandle = null; void bridge.call("close_backup_archive", {}).catch(() => {}); } });
            await window.loadURL(`${app.isPackaged ? "liteseal://app/index.html" : devUrl + "/"}#archive=${encodeURIComponent(id)}`);
            if (locked || generation !== lockGeneration || backupEpoch !== backupGeneration || archiveWindow !== window) throw new Error("恢复档案已关闭");
            window.show(); return { ok: true, result };
          }
          if (name === "close_backup_archive") { invalidateBackups(); return { ok: true, result: null }; }
          if (name === "export_backup_attachment") {
            const input = args as { id: string; messageId: string; groupId?:string; directV3?:boolean; preview?: boolean };
            if (typeof input.id !== "string" || typeof input.messageId !== "string" || Object.keys(args).some(key => !["id", "messageId", "groupId", "directV3", "preview"].includes(key)) || input.directV3 !== undefined && typeof input.directV3 !== "boolean" || input.directV3 && input.groupId !== undefined || input.preview !== undefined && typeof input.preview !== "boolean" || readingArchive && input.id !== archiveHandle) throw new Error("恢复附件参数无效");
            let destination: string | undefined;
            if (!input.preview) { const choice = await dialog.showSaveDialog(senderWindow, { title: "从离线档案保存附件（新文件）", defaultPath: "attachment" }); if (choice.canceled || !choice.filePath) return { ok: true, result: null }; destination = choice.filePath; }
            const directory = await fs.mkdtemp(path.join(destination ? path.dirname(destination) : app.getPath("temp"), ".liteseal-archive-media-"));
            try {
              const temporary = path.join(directory, "verified");
              const mime = await bridge.call(name, { id: input.id, messageId: input.messageId, groupId:input.groupId, directV3:input.directV3, path: temporary } as never);
              if (locked || generation !== lockGeneration || backupEpoch !== backupGeneration) throw new Error("应用锁定或恢复档案已关闭");
              await bridge.call("get_backup_archive_info", { id: input.id });
              if (locked || generation !== lockGeneration || backupEpoch !== backupGeneration) throw new Error("应用锁定或恢复档案已关闭");
              if (input.preview) {
                const bytes = await fs.readFile(temporary);
                if (locked || generation !== lockGeneration || backupEpoch !== backupGeneration) throw new Error("应用锁定或恢复档案已关闭");
                const safe = mime === "image/png" && bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))
                  || mime === "image/jpeg" && bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255
                  || mime === "image/webp" && bytes.subarray(0,4).toString() === "RIFF" && bytes.subarray(8,12).toString() === "WEBP"
                  || mime === "audio/webm" && bytes.subarray(0,4).equals(Buffer.from([0x1a,0x45,0xdf,0xa3]));
                if (!safe || bytes.length > 20 * 1024 * 1024) throw new Error("此附件不支持安全预览，请另存为查看");
                return { ok: true, result: `data:${mime};base64,${bytes.toString("base64")}` };
              }
              await fs.link(temporary, destination!); return { ok: true, result: "附件已保存" };
            } finally { await fs.rm(directory, { recursive: true, force: true }); }
          }
          if (readingArchive && (args as { id?: string }).id !== archiveHandle) throw new Error("恢复档案编号已失效");
          if (["sign_out", "logout_all_sessions", "change_password", "clear_keypair"].includes(name)) invalidateBackups();
          if (name === "configure_app_lock") {
            const input = args as { enabled: boolean; password: string };
            if (typeof input.enabled !== "boolean" || typeof input.password !== "string" || input.password.length > 1024) throw new Error("无效应用锁设置");
            if (unlockBusy || Date.now() < unlockAfter) throw new Error("请稍后再试");
            unlockBusy = true; unlockAfter = Date.now() + 5000;
            try { await bridge.call("unlock_app", { password: input.password }); }
            finally { unlockBusy = false; }
            if (locked || generation !== lockGeneration) throw new Error("应用已锁定，请解锁后修改设置");
            await fs.mkdir(app.getPath("userData"), { recursive: true });
            const settings = path.join(app.getPath("userData"), "app-lock.json");
            await fs.writeFile(settings + ".tmp", JSON.stringify({ enabled: input.enabled }), { mode: 0o600 });
            await fs.rename(settings + ".tmp", settings);
            lockEnabled = input.enabled;
            return { ok: true, result: null };
          }
          if (name === "check_app_update") {
            const response = await net.fetch("https://api.github.com/repos/domin1c86/LiteSeal/releases/latest", { headers: { Accept: "application/vnd.github+json" }, signal: AbortSignal.timeout(15000) });
            if (!response.ok) throw new Error(response.status === 404 ? "尚无正式发布版本" : `版本检查失败：${response.status}`);
            const release = await response.json();
            const tag = String(release.tag_name ?? "");
            if (!/^v?\d+\.\d+\.\d+$/.test(tag)) throw new Error("发布版本号格式不支持");
            const latest = tag.replace(/^v/, "");
            const compare = (a: string, b: string) => {
              const left = a.split(".").map(Number), right = b.split(".").map(Number);
              for (let i = 0; i < 3; i++) { if (left[i] !== right[i]) return left[i] > right[i]; }
              return false;
            };
            releaseUrl = `https://github.com/domin1c86/LiteSeal/releases/tag/${encodeURIComponent(tag)}`;
            return { ok: true, result: { current: app.getVersion(), latest, available: compare(latest, app.getVersion()) } };
          }
          if (name === "open_app_release") {
            if (!releaseUrl) throw new Error("请先检查版本");
            await shell.openExternal(releaseUrl);
            return { ok: true, result: null };
          }
          if (name === "select_attachment" || name === "stage_attachment_file") {
            const peerId = (args as { peerId: string }).peerId;
            if (typeof peerId !== "string" || peerId.length > 128) throw new Error("无效联系人");
            let filePath: string;
            if (name === "select_attachment") {
              const selected = await dialog.showOpenDialog(mainWindow!, { title: "选择文件（最大 20 MiB）", properties: ["openFile"] });
              if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
              if (selected.canceled || !selected.filePaths[0]) return { ok: true, result: null };
              filePath = selected.filePaths[0];
            } else {
              filePath = (args as { path: string }).path;
              if (typeof filePath !== "string" || !path.isAbsolute(filePath) || filePath.length > 32767) throw new Error("无效文件路径");
            }
            const result = await bridge.call("select_attachment", { peerId, path: filePath } as never);
            if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
            return { ok: true, result };
          }
          if (name === "stage_clipboard_image") {
            const peerId = (args as { peerId: string }).peerId;
            if (typeof peerId !== "string" || peerId.length > 128) throw new Error("无效联系人");
            const items = await clipboard.read();
            const image = items.flatMap(item => item.types.filter(type => type.startsWith("image/")).map(type => ({ item, type })))[0];
            if (!image) throw new Error("剪贴板中没有图片");
            const blob = await image.item.getType(image.type);
            if (!(blob instanceof Blob)) throw new Error("剪贴板图片格式无效");
            if (blob.size > 11 * 1024 * 1024) throw new Error("剪贴板图片过大，请保存为文件后选择发送");
            const source = Buffer.from(await blob.arrayBuffer());
            const picture = image.type === "image/png" ? null : nativeImage.createFromBuffer(source);
            if (picture?.isEmpty()) throw new Error("剪贴板图片损坏");
            const bytes = picture ? picture.toPNG() : source;
            if (bytes.length > 11 * 1024 * 1024) throw new Error("剪贴板图片过大，请保存为文件后选择发送");
            const result = await bridge.call("stage_clipboard_image", { peerId, encoded: bytes.toString("base64") } as never);
            if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
            return { ok: true, result };
          }
          if (name === "stage_recorded_audio") {
            const input = args as { peerId: string; encoded: string; durationMs: number };
            if (typeof input.peerId !== "string" || input.peerId.length > 128
              || typeof input.encoded !== "string" || input.encoded.length > 15 * 1024 * 1024
              || !Number.isInteger(input.durationMs) || input.durationMs < 1 || input.durationMs > 60_000) throw new Error("语音长度或大小无效");
            const bytes = Buffer.from(input.encoded, "base64");
            if (bytes.length > 11 * 1024 * 1024 || !bytes.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))) throw new Error("录音格式或大小无效");
            const result = await bridge.call("stage_recorded_audio", input as never);
            if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
            return { ok: true, result };
          }
          if (name === "choose_profile_avatar") {
            const selected = await dialog.showOpenDialog(mainWindow!, { title: "选择公开头像", properties: ["openFile"], filters: [{ name: "图片", extensions: ["png", "jpg", "jpeg", "webp"] }] });
            if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
            if (selected.canceled || !selected.filePaths[0]) return { ok: true, result: null };
            const filePath = selected.filePaths[0];
            if ((await fs.stat(filePath)).size > 20 * 1024 * 1024) throw new Error("头像源文件不能超过 20 MiB");
            const picture = nativeImage.createFromPath(filePath);
            if (picture.isEmpty()) throw new Error("头像图片损坏或格式不支持");
            const bytes = picture.resize({ width: 128, height: 128, quality: "best" }).toPNG();
            if (bytes.length > 64 * 1024) throw new Error("处理后头像仍超过 64 KiB，请选择更简单的图片");
            return { ok: true, result: bytes.toString("base64") };
          }
          if (name === "export_attachment" || name === "preview_attachment_task") {
            const pendingId = name === "preview_attachment_task" ? (args as { id: string }).id : undefined;
            const input = pendingId ? { messageId: "", preview: true, media: "image" as const } : args as { messageId: string; preview?: boolean; media?: "image" | "audio" };
            if (typeof input.messageId !== "string" || input.messageId.length > 128) throw new Error("无效附件消息");
            if (input.preview) {
              const metadata = pendingId ? (await bridge.call("list_attachment_tasks", {})).find(task => task.id === pendingId) : await bridge.call("begin_attachment_download", { messageId: input.messageId });
              if (!metadata || (!pendingId && metadata.offset !== metadata.total) || metadata.size > 20 * 1024 * 1024
                || (input.media === "audio" && (metadata.mime !== "audio/webm" || !metadata.duration_ms))) throw new Error("请先完成下载或重新选择文件");
              const chunks: Buffer[] = [];
              for (let offset = 0; offset < metadata.size; offset += 1024 * 1024) {
                const bytes = await bridge.call("export_attachment", { messageId: input.messageId, taskId: pendingId, offset } as never) as unknown as number[];
                if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
                chunks.push(Buffer.from(bytes));
              }
              const bytes = Buffer.concat(chunks);
              const mime = bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])) ? "image/png"
                : bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255 ? "image/jpeg"
                : bytes.subarray(0,4).toString() === "RIFF" && bytes.subarray(8,12).toString() === "WEBP" ? "image/webp" : null;
              if (input.media === "audio") {
                if (!bytes.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3])) || bytes.length > 11 * 1024 * 1024) throw new Error("语音格式或大小不支持");
                return { ok: true, result: `data:audio/webm;base64,${bytes.toString("base64")}` };
              }
              if (!mime) throw new Error("不支持此文件的图片预览");
              return { ok: true, result: `data:${mime};base64,${bytes.toString("base64")}` };
            }
            let destination: string | undefined;
            if (!input.preview) {
              const result = await dialog.showSaveDialog(mainWindow!, { title: "附件另存为", defaultPath: "attachment" });
              if (result.canceled || !result.filePath) return { ok: true, result: null };
              destination = result.filePath;
            }
            const directory = await fs.mkdtemp(path.join(path.dirname(destination!), ".liteseal-export-"));
            const temporary = path.join(directory, "verified");
            try {
              await bridge.call("export_attachment", { messageId: input.messageId, path: temporary } as never);
              if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
              await fs.rename(temporary, destination!); return { ok: true, result: "已保存" };
            } finally { await fs.rm(directory, { recursive: true, force: true }); }
          }
          if (name === "set_notification_context") {
            const input = args as { userId: string | null; activePeerId: string | null; activeGroupId?: string | null };
            const notificationGeneration = notifications.generation();
            let identity: import("./contracts").NotificationIdentity | null = null;
            if (input.userId !== null) {
              const saved = await bridge.call("load_identity", {});
              if (!saved.token || saved.user_id !== input.userId) throw new Error("通知账号不匹配");
              identity = saved;
            }
            if (input.activePeerId !== null && typeof input.activePeerId !== "string") throw new Error("无效会话");
            if (locked || generation !== lockGeneration || notificationGeneration !== notifications.generation()) throw new Error("通知上下文已失效");
            if (input.activeGroupId != null && typeof input.activeGroupId !== "string") throw new Error("无效群会话");
            notifications.context(input.userId, input.activePeerId, input.activeGroupId ?? null, identity);
            return { ok: true, result: null };
          }
          if (name === "take_notification_target") return { ok: true, result: notifications.takeTarget() };
          if(name==="set_direct_notification_context"||name==="take_direct_notification_target") {
            const input=args as {scope:string;activeAccount?:string|null};
            const contextRequest=name==="set_direct_notification_context"?++directContextRequest:directContextRequest;
            const current=await bridge.call("get_direct_chat",{});
            if(locked||generation!==lockGeneration||deviceEpoch===null)throw new Error("通知上下文已失效");
            deviceControl.check(deviceEpoch);
            if(typeof input.scope!=="string"||input.scope!==current.notification_scope||name==="set_direct_notification_context"&&contextRequest!==directContextRequest)throw new Error("通知档案已变化");
            if(name==="take_direct_notification_target")return {ok:true,result:notifications.takeDirect(input.scope)};
            if(input.activeAccount!==null&&!current.peers.some(p=>p.account===input.activeAccount))throw new Error("通知会话无效");
            notifications.directContext(input.scope,input.activeAccount??null);return {ok:true,result:null};
          }
          if (name === "copy_message_text") {
            const text = args && typeof args === "object" ? (args as Record<string, unknown>).text : undefined;
            if (typeof text !== "string" || text.length > 1024 * 1024) throw new Error("无效的复制文本或文本超过 1 MiB");
            clipboard.writeText(text);
            return { ok: true, result: null };
          }
          if (name === "save_session" || name === "sign_out" || name === "clear_keypair" || name === "logout_all_sessions" || name === "change_password") notifications.context(null, null);
          if (["save_session", "sign_out", "clear_keypair", "logout_all_sessions", "change_password"].includes(name)) deviceControl.invalidate();
          const result = await bridge.call(name, args as never);
          if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
          if(name==="direct_operation_step"&&(result as CommandMap["direct_operation_step"]["result"]).condition==="accepted"){
            notifications.retireDirectOperations();mainWindow?.webContents.send("liteseal:direct-changed");
          }
          if (deviceEpoch !== null) deviceControl.check(deviceEpoch);
          if(name==="receive_direct_history_relay"&&(result as CommandMap["receive_direct_history_relay"]["result"]).imported){directMedia?.invalidate();notifications.retireDirectOperations();mainWindow?.webContents.send("liteseal:direct-changed");}
          if (name === "save_root_session") { notifications.context(null, null); deviceControl.invalidate(); mainWindow?.webContents.send("liteseal:normal-profile-changed"); }
          if(name==="select_normal_profile"||name==="clear_normal_profile"){
            lockGeneration++;invalidateBackups();notifications.context(null,null);deviceControl.invalidate();
            mainWindow?.webContents.send("liteseal:normal-profile-changed");
          }
          if (name === "poll_messages") {
            // A failed notification must never consume or fail a persisted relay batch.
            await notifications.receive(result as import("../ui/src/types").PollMessagesResult).catch(() => {});
          }
          if(["save_root_session","select_normal_profile","clear_normal_profile","sign_out","clear_keypair","logout_all_sessions","change_password"].includes(name))notifications.directContext(null,null);
          if(name==="set_direct_muted"||name==="mark_direct_read"||name==="hide_direct_message") {
            if(name==="hide_direct_message")notifications.directContext(null,null);
            else notifications.dismissDirect((args as {account:string}).account);
          }
          if (name === "clear_group_history") { notifications.suppressGroup((args as { groupId: string }).groupId); mainWindow?.webContents.send("liteseal:groups-changed"); }
          if (name === "clear_direct_media_cache") mainWindow?.webContents.send("liteseal:direct-changed");
          if (name === "set_direct_media_transfer") mainWindow?.webContents.send("liteseal:direct-changed");
          if (name === "set_group_muted") notifications.suppressGroup((args as { groupId: string }).groupId);
          if (name === "set_conversation_muted") notifications.dismiss((args as { peerId: string }).peerId);
          if (name === "set_contact_policy") notifications.dismiss((args as { peerId: string }).peerId);
          if (name === "submit_message_operation" || (name === "sync_message_operations" && result)) notifications.clear();
          return { ok: true, result };
        }
        catch (error) { return { ok: false, error: error instanceof Error ? error.message : "桌面操作失败" }; }
      });
    }
    mainWindow = new BrowserWindow({
      title: "LiteSeal", width: 1024, height: 768, show: false,
      icon: path.join(root, "electron", "icons", "icon.png"),
      webPreferences: { preload: path.join(root, "dist-electron", "preload.cjs"),
        nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true },
    });
    mainWindow.setMenuBarVisibility(false);
    mainWindow.webContents.on("before-input-event", (event, input) => {
      if (input.type !== "keyDown" || !(input.control || input.meta)) return;
      if (["+", "=", "-", "0"].includes(input.key)) {
        event.preventDefault();
        const current = mainWindow!.webContents.getZoomFactor();
        const next = input.key === "0" ? 1 : current + (input.key === "-" ? -0.1 : 0.1);
        mainWindow!.webContents.setZoomFactor(Math.max(0.75, Math.min(2, next)));
      }
    });
    try {
      tray = new Tray(path.join(root, "electron", "icons", "icon.png"));
      tray.setToolTip("LiteSeal · 关闭窗口后继续接收消息");
      const show = () => { if (mainWindow?.isMinimized()) mainWindow.restore(); mainWindow?.show(); mainWindow?.focus(); };
      tray.setContextMenu(Menu.buildFromTemplate([
        { label: "打开 LiteSeal", click: show },
        { label: "退出 LiteSeal", click: () => app.quit() },
      ]));
      tray.on("double-click", show);
    } catch { tray = undefined; }
    mainWindow.on("close", event => {
      if (exitRequested || !tray) return;
      event.preventDefault();
      if (!explainedTray) {
        explainedTray = true;
        dialog.showMessageBoxSync(mainWindow!, { type: "info", title: "LiteSeal 继续运行", message: "关闭窗口会收起到托盘并继续接收消息。要完全退出，请使用托盘菜单中的“退出 LiteSeal”。" });
      }
      mainWindow?.hide();
    });
    mainWindow.on("closed", () => { mainWindow = undefined; });
    mainWindow.webContents.on("will-prevent-unload", () => { exitRequested = false; if (!locked && !screenLocked && !systemSuspended) void deviceControl.resume().catch(() => {}); });
    mainWindow.webContents.on("render-process-gone", () => {notifications.context(null, null);notifications.directContext(null,null);});
    mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
    mainWindow.webContents.on("will-navigate", event => event.preventDefault());
    mainWindow.webContents.on("will-attach-webview", event => event.preventDefault());
    mainWindow.once("ready-to-show", () => mainWindow?.show());
    await mainWindow.loadURL(app.isPackaged ? "liteseal://app/index.html" : devUrl);
  }).catch(async (error: unknown) => {
    dialog.showErrorBox("LiteSeal 启动失败", error instanceof Error ? error.message : "无法启动桌面应用");
    app.quit();
  });
}
