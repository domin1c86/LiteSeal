import { app, BrowserWindow, dialog, ipcMain, net, protocol, session } from "electron";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { DesktopBridge } from "./bridge";
import { commandNames } from "./contracts";

protocol.registerSchemesAsPrivileged([{ scheme: "liteseal", privileges: { standard: true, secure: true, supportFetchAPI: true } }]);
const devUrl = "http://127.0.0.1:1420";
const bridge = new DesktopBridge();
let mainWindow: BrowserWindow | undefined;
let quitting = false;
let cleanedUp = false;

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
    event.preventDefault();
    // Let the renderer's pending-save guard run while the sidecar is still alive.
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.close();
      return;
    }
    if (quitting) return;
    quitting = true;
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
        try { return { ok: true, result: await bridge.call(name, args as never) }; }
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
