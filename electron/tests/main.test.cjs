const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const fs = require('node:fs/promises');
const vm = require('node:vm');

test('main process restricts IPC origins, navigation and packaged assets without opening a GUI', { timeout: 10000 }, async t => {
  const handlers = new Map();
  let protocolHandler, window, preferences, startupError;
  let loaded;
  const load = new Promise(resolve => { loaded = resolve; });
  const child = new EventEmitter();
  child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  child.kill = () => { child.emit('exit', 0); child.emit('close', 0); };
  child.stdin.on('finish', child.kill);
  child.stdin.on('data', frame => {
    const request = JSON.parse(frame.toString());
    child.stdout.write(JSON.stringify({ id: request.id, result: [] }) + '\n');
  });
  const app = Object.assign(new EventEmitter(), {
    isPackaged: true, requestSingleInstanceLock: () => true,
    whenReady: async () => {}, getAppPath: () => process.cwd(), quit: () => {},
  });
  t.after(() => app.emit('before-quit', { preventDefault() {} }));
  const electron = {
    app,
    BrowserWindow: class extends EventEmitter {
      constructor(options) {
        super(); window = this; preferences = options.webPreferences;
        this.webContents = Object.assign(new EventEmitter(), {
          mainFrame: { url: 'liteseal://app/index.html' },
          setWindowOpenHandler(handler) { this.openHandler = handler; },
        });
      }
      setMenuBarVisibility() {}
      async loadURL(url) { assert.equal(url, 'liteseal://app/index.html'); loaded(); }
    },
    dialog: { showErrorBox(_title, error) { startupError = error; loaded(); } },
    ipcMain: { handle(name, handler) { handlers.set(name, handler); } },
    protocol: { registerSchemesAsPrivileged() {}, handle(scheme, handler) { assert.equal(scheme, 'liteseal'); protocolHandler = handler; } },
    net: { async fetch() { return new Response('<html></html>', { headers: { 'content-type': 'text/html' } }); } },
    session: { defaultSession: { setPermissionRequestHandler() {}, setPermissionCheckHandler() {}, webRequest: { onHeadersReceived() {} } } },
  };
  vm.runInNewContext(await fs.readFile('dist-electron/main.cjs', 'utf8'), {
    Buffer, URL, Headers, Response, console, setTimeout, clearTimeout,
    process: { platform: process.platform, resourcesPath: '/installed/resources' },
    require(name) {
      if (name === 'electron') return electron;
      if (name === 'node:child_process') return { spawn(executable, args, options) {
        assert.match(executable.replaceAll('\\', '/'), /resources\/desktop\/liteseal-desktop/);
        assert.equal(options.shell, false);
        setTimeout(() => child.stdout.write('{"ready":true,"version":1}\n'), 0);
        return child;
      } };
      return require(name);
    },
  });
  await load;
  assert.equal(startupError, undefined);
  assert.equal(preferences.contextIsolation, true);
  assert.equal(preferences.sandbox, true);
  assert.equal(preferences.nodeIntegration, false);
  assert.equal(window.webContents.openHandler().action, 'deny');
  let blocked = false;
  window.webContents.emit('will-navigate', { preventDefault() { blocked = true; } });
  assert.equal(blocked, true);
  const handler = handlers.get('liteseal:get_contacts');
  const valid = { sender: window.webContents, senderFrame: window.webContents.mainFrame };
  assert.equal((await handler(valid, {})).ok, true);
  assert.equal((await handler({ ...valid, sender: {} }, {})).ok, false);
  assert.equal((await handler({ ...valid, senderFrame: { url: 'liteseal://app/index.html' } }, {})).ok, false);
  window.webContents.mainFrame.url = 'https://untrusted.example';
  assert.equal((await handler(valid, {})).ok, false);
  const response = await protocolHandler({ url: 'liteseal://app/index.html', method: 'GET' });
  assert.match(response.headers.get('Content-Security-Policy'), /script-src 'self';/);
  assert.equal((await protocolHandler({ url: 'liteseal://other/index.html', method: 'GET' })).status, 403);
  assert.equal((await protocolHandler({ url: 'liteseal://app/%2e%2e%2fsecret', method: 'GET' })).status, 403);
  assert.equal((await protocolHandler({ url: 'liteseal://app/index.html', method: 'POST' })).status, 403);
});
