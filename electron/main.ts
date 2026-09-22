import { app, clipboard, BrowserWindow, dialog, ipcMain, Menu, net, powerMonitor, protocol, session, Tray } from "electron";
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
    if (quitting) return;
    app.setAppUserModelId("com.liteseal.app");
    powerMonitor.on("lock-screen", () => notifications.lock(true));
    powerMonitor.on("unlock-screen", () => notifications.lock(false));
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
          if (name === "select_attachment") {
            const peerId = (args as { peerId: string }).peerId;
            if (typeof peerId !== "string" || peerId.length > 128) throw new Error("无效联系人");
            const selected = await dialog.showOpenDialog(mainWindow, { title: "选择文件（最大 20 MiB）", properties: ["openFile"] });
            if (selected.canceled || !selected.filePaths[0]) return { ok: true, result: null };
            return { ok: true, result: await bridge.call("select_attachment", { peerId, path: selected.filePaths[0] } as never) };
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
              if (destination) { await fs.rename(temporary, destination); return { ok: true, result: "已保存" }; }
              const bytes = await fs.readFile(temporary);
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
