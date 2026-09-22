import { app, clipboard, BrowserWindow, dialog, ipcMain, Menu, net, powerMonitor, protocol, session, shell, Tray } from "electron";
import { ChatNotifications } from "./notifications";
import path from "node:path";
import fs from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { DesktopBridge } from "./bridge";
import { commandNames } from "./contracts";

protocol.registerSchemesAsPrivileged([{ scheme: "liteseal", privileges: { standard: true, secure: true, supportFetchAPI: true } }]);
const devUrl = "http://127.0.0.1:1420";
const bridge = new DesktopBridge();
let mainWindow: BrowserWindow | undefined;
let quitting = false;
let cleanedUp = false;
let exitRequested = false;
let tray: Tray | undefined;
let explainedTray = false;
const notifications = new ChatNotifications(() => mainWindow, bridge);
let locked = false;
let lockEnabled = false;
let lockGeneration = 0;
let unlockAfter = 0;
let unlockBusy = false;
let releaseUrl: string | null = null;
function lockApp() {
  if (!lockEnabled || locked) return;
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
    void bridge.stop().finally(() => { cleanedUp = true; app.quit(); });
  });
  bridge.on("failure", (error: Error) => {
    if (!quitting && mainWindow) {
      dialog.showErrorBox("LiteSeal 桌面服务异常", error.message);
      app.quit();
    }
  });
  void app.whenReady().then(async () => {
    const root = app.getAppPath();
    const assetRoot = path.join(root, "ui", "dist");
    const executable = path.join(app.isPackaged ? process.resourcesPath : path.join(root, "target", "debug"),
      app.isPackaged ? "desktop" : "", `liteseal-desktop${process.platform === "win32" ? ".exe" : ""}`);
    await bridge.start(executable);
    try { await bridge.call("load_identity", {}); lockEnabled = true; locked = true; notifications.lock(true); } catch { /* First run has no chat identity. */ }
    if (quitting) return;
    app.setAppUserModelId("com.liteseal.app");
    powerMonitor.on("lock-screen", lockApp);
    setInterval(() => { if (powerMonitor.getSystemIdleTime() >= 300) lockApp(); }, 1000).unref();
    const csp = `default-src 'self'; script-src 'self'${app.isPackaged ? "" : " 'unsafe-inline'"}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'${app.isPackaged ? "" : " ws://127.0.0.1:1420"}; object-src 'none'; base-uri 'none'; frame-src 'none'`;
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
    session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
      callback({ responseHeaders: { ...details.responseHeaders,
        "Content-Security-Policy": [csp],
      } });
    });
    for (const name of commandNames) {
      ipcMain.handle(`liteseal:${name}`, async (event, args: object) => {
        if (!mainWindow || event.sender !== mainWindow.webContents || event.senderFrame !== mainWindow.webContents.mainFrame || !trustedUrl(event.senderFrame.url)) {
          return { ok: false, error: "不允许的桌面接口来源" };
        }
        try {
          if (name === "app_lock_state") return { ok: true, result: locked };
          if (name === "lock_app") { lockApp(); return { ok: true, result: null }; }
          if (name === "unlock_app") {
            if (!locked) return { ok: true, result: null };
            if (unlockBusy || Date.now() < unlockAfter) throw new Error("请稍后再试");
            const password = (args as { password: string }).password;
            if (typeof password !== "string" || password.length > 1024) throw new Error("无效密码");
            unlockBusy = true; unlockAfter = Date.now() + 5000;
            try { await bridge.call("unlock_app", { password }); locked = false; notifications.lock(false); }
            finally { unlockBusy = false; }
            return { ok: true, result: null };
          }
          if (locked) throw new Error("应用已锁定，请先验证 Windows 身份");
          const generation = lockGeneration;
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
          if (name === "select_attachment") {
            const peerId = (args as { peerId: string }).peerId;
            if (typeof peerId !== "string" || peerId.length > 128) throw new Error("无效联系人");
            const selected = await dialog.showOpenDialog(mainWindow, { title: "选择文件（最大 20 MiB）", properties: ["openFile"] });
            if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
            if (selected.canceled || !selected.filePaths[0]) return { ok: true, result: null };
            const result = await bridge.call("select_attachment", { peerId, path: selected.filePaths[0] } as never);
            if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
            return { ok: true, result };
          }
          if (name === "export_attachment") {
            const input = args as { messageId: string; preview?: boolean };
            if (typeof input.messageId !== "string" || input.messageId.length > 128) throw new Error("无效附件消息");
            let destination: string | undefined;
            if (!input.preview) {
              const result = await dialog.showSaveDialog(mainWindow, { title: "附件另存为", defaultPath: "attachment" });
              if (result.canceled || !result.filePath) return { ok: true, result: null };
              destination = result.filePath;
            }
            const directory = await fs.mkdtemp(path.join(destination ? path.dirname(destination) : app.getPath("temp"), ".liteseal-export-"));
            const temporary = path.join(directory, "verified");
            try {
              await bridge.call("export_attachment", { messageId: input.messageId, path: temporary } as never);
              if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
              if (destination) { await fs.rename(temporary, destination); return { ok: true, result: "已保存" }; }
              const bytes = await fs.readFile(temporary);
              if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
              const mime = bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])) ? "image/png"
                : bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255 ? "image/jpeg"
                : bytes.subarray(0,4).toString() === "RIFF" && bytes.subarray(8,12).toString() === "WEBP" ? "image/webp" : null;
              if (!mime) throw new Error("不支持此文件的图片预览");
              return { ok: true, result: `data:${mime};base64,${bytes.toString("base64")}` };
            } finally { await fs.rm(directory, { recursive: true, force: true }); }
          }
          if (name === "set_notification_context") {
            const input = args as { userId: string | null; activePeerId: string | null };
            if (input.userId !== null) {
              const identity = await bridge.call("load_identity", {});
              if (!identity.token || identity.user_id !== input.userId) throw new Error("通知账号不匹配");
            }
            if (input.activePeerId !== null && typeof input.activePeerId !== "string") throw new Error("无效会话");
            notifications.context(input.userId, input.activePeerId);
            return { ok: true, result: null };
          }
          if (name === "take_notification_target") return { ok: true, result: notifications.takeTarget() };
          if (name === "copy_message_text") {
            const text = args && typeof args === "object" ? (args as Record<string, unknown>).text : undefined;
            if (typeof text !== "string" || text.length > 1024 * 1024) throw new Error("无效的复制文本或文本超过 1 MiB");
            clipboard.writeText(text);
            return { ok: true, result: null };
          }
          if (name === "sign_out" || name === "clear_keypair" || name === "logout_all_sessions") notifications.context(null, null);
          const result = await bridge.call(name, args as never);
          if (name === "save_session") lockEnabled = true;
          if (locked || generation !== lockGeneration) throw new Error("应用已锁定");
          if (name === "poll_messages") {
            // A failed notification must never consume or fail a persisted relay batch.
            await notifications.receive(result as import("../ui/src/types").PollMessagesResult).catch(() => {});
          }
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
    mainWindow.webContents.on("will-prevent-unload", () => { exitRequested = false; });
    mainWindow.webContents.on("render-process-gone", () => notifications.context(null, null));
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
