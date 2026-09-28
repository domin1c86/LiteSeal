const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');

test('main process restricts IPC origins, navigation and packaged assets without opening a GUI', { timeout: 10000 }, async t => {
  const handlers = new Map();
  const intervals = [], commands = [], rendererEvents = [];
  const userData = await fs.mkdtemp(path.join(os.tmpdir(), 'liteseal-main-test-'));
  const avatarPath = path.join(userData, 'avatar.png');
  await fs.writeFile(avatarPath, Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  t.after(() => fs.rm(userData, { recursive: true, force: true }));
  let protocolHandler, window, preferences, startupError, permissionRequest, permissionCheck;
  let loaded;
  const load = new Promise(resolve => { loaded = resolve; });
  const child = new EventEmitter();
  child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  child.kill = () => { child.emit('exit', 0); child.emit('close', 0); };
  child.stdin.on('finish', child.kill);
  child.stdin.on('data', frame => {
    const request = JSON.parse(frame.toString());
    commands.push(request.command.name);
    child.stdout.write(JSON.stringify({ id: request.id, result: request.command.name === 'process_scheduled_messages' ? 1 : request.command.name === 'process_groups' ? { changed: 1, errors: [] } : [] }) + '\n');
  });
  const app = Object.assign(new EventEmitter(), {
    isPackaged: true, requestSingleInstanceLock: () => true,
    whenReady: async () => {}, getAppPath: () => process.cwd(), getPath: () => userData,
    setAppUserModelId() {}, quit: () => {},
  });
  t.after(() => app.emit('before-quit', { preventDefault() {} }));
  const electron = {
    app,
    BrowserWindow: class extends EventEmitter {
      constructor(options) {
        super(); window = this; preferences = options.webPreferences;
        this.webContents = Object.assign(new EventEmitter(), {
          mainFrame: { url: 'liteseal://app/index.html' },
          send(...args) { rendererEvents.push(args); },
          setWindowOpenHandler(handler) { this.openHandler = handler; },
        });
      }
      setMenuBarVisibility() {}
      isDestroyed() { return false; }
      close() { this.emit('closed'); }
      async loadURL(url) { assert.equal(url, 'liteseal://app/index.html'); loaded(); }
    },
    dialog: { showErrorBox(_title, error) { startupError = error; loaded(); }, async showOpenDialog() { return { canceled: false, filePaths: [avatarPath] }; } },
    nativeImage: { createFromPath() { return { isEmpty: () => false, resize() { return { toPNG: () => Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]) }; } }; } },
    ipcMain: { handle(name, handler) { handlers.set(name, handler); } },
    protocol: { registerSchemesAsPrivileged() {}, handle(scheme, handler) { assert.equal(scheme, 'liteseal'); protocolHandler = handler; } },
    net: { async fetch() { return new Response('<html></html>', { headers: { 'content-type': 'text/html' } }); } },
    clipboard: { async read() { return [{ types: ['image/png'], async getType() { return new Blob([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])]); } }]; } },
    session: { defaultSession: { setPermissionRequestHandler(handler) { permissionRequest = handler; }, setPermissionCheckHandler(handler) { permissionCheck = handler; }, webRequest: { onHeadersReceived() {} } } },
    powerMonitor: Object.assign(new EventEmitter(), { getSystemIdleTime: () => 0 }),
  };
  vm.runInNewContext(await fs.readFile('dist-electron/main.cjs', 'utf8'), {
    Blob, Buffer, URL, Headers, Response, console, setTimeout, clearTimeout,
    setInterval: callback => { intervals.push(callback); return { unref() {} }; },
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
  intervals[0](); await new Promise(resolve => setTimeout(resolve, 0));
  assert.ok(rendererEvents.some(args => args[0] === 'liteseal:scheduled-changed' && args.length === 1));
  intervals[1](); await new Promise(resolve => setTimeout(resolve, 0));
  assert.ok(rendererEvents.some(args => args[0] === 'liteseal:groups-changed' && args.length === 1));
  const permission = (kind, details, contents = window.webContents) => new Promise(resolve => permissionRequest(contents, kind, resolve, details));
  assert.equal(await permission('media', { requestingUrl: 'liteseal://app/index.html', mediaTypes: ['audio'] }), true);
  assert.equal(await permission('media', { requestingUrl: 'liteseal://app/index.html', mediaTypes: ['video'] }), false);
  assert.equal(await permission('media', { requestingUrl: 'https://untrusted.example', mediaTypes: ['audio'] }), false);
  assert.equal(await permission('media', { requestingUrl: 'liteseal://app/index.html', mediaTypes: ['audio'] }, {}), false);
  assert.equal(permissionCheck(window.webContents, 'media', 'liteseal://app', { isMainFrame: true, mediaType: 'audio', requestingUrl: 'liteseal://app/index.html' }), true);
  assert.equal(permissionCheck(window.webContents, 'media', 'liteseal://app', { isMainFrame: false, mediaType: 'audio', requestingUrl: 'liteseal://app/index.html' }), false);
  assert.equal(permissionCheck(window.webContents, 'media', 'liteseal://app', { isMainFrame: true, mediaType: 'video', requestingUrl: 'liteseal://app/index.html' }), false);
  assert.equal((await handlers.get('liteseal:stage_recorded_audio')(valid, { peerId: 'bob', encoded: '', durationMs: 1000 })).ok, false);
  assert.equal((await handlers.get('liteseal:stage_recorded_audio')(valid, { peerId: 'bob', encoded: Buffer.from([0x1a, 0x45, 0xdf, 0xa3]).toString('base64'), durationMs: 60_001 })).ok, false);
  assert.equal((await handlers.get('liteseal:stage_recorded_audio')(valid, { peerId: 'bob', encoded: Buffer.from([0x1a, 0x45, 0xdf, 0xa3]).toString('base64'), durationMs: 1000 })).ok, true);
  assert.equal((await handlers.get('liteseal:choose_profile_avatar')(valid, {})).result, Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).toString('base64'));
  assert.equal((await handlers.get('liteseal:stage_clipboard_image')(valid, { peerId: 'bob' })).ok, true);
  const lock = handlers.get('liteseal:lock_app');
  const configure = handlers.get('liteseal:configure_app_lock');
  const unlock = handlers.get('liteseal:unlock_app');
  const lockState = handlers.get('liteseal:app_lock_state');
  assert.equal((await configure(valid, { enabled: true, password: 'test-password' })).ok, true);
  assert.equal((await lock(valid, {})).ok, true);
  assert.equal((await lockState(valid, {})).result, true);
  const previousCalls = commands.filter(name => name === 'process_scheduled_messages').length;
  const previousEvents = rendererEvents.length;
  intervals[0](); await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(commands.filter(name => name === 'process_scheduled_messages').length, previousCalls + 1);
  assert.equal(rendererEvents.length, previousEvents);
  assert.equal((await handlers.get('liteseal:list_scheduled_messages')(valid, {})).ok, false);
  const previousGroupCalls=commands.filter(name=>name==='process_groups').length;
  intervals[1](); await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(commands.filter(name=>name==='process_groups').length,previousGroupCalls+1);
  assert.equal(rendererEvents.length,previousEvents);
  for(const name of ['get_sent_group_invites','revoke_group_invite','set_group_muted','get_groups','get_group_history','group_draft','send_group_text','accept_group_invite','change_group_membership','process_groups']) {
    assert.equal((await handlers.get(`liteseal:${name}`)(valid,{})).ok,false,name);
  }
  assert.equal(await permission('media', { requestingUrl: 'liteseal://app/index.html', mediaTypes: ['audio'] }), false);
  assert.equal(permissionCheck(window.webContents, 'media', 'liteseal://app', { isMainFrame: true, mediaType: 'audio', requestingUrl: 'liteseal://app/index.html' }), false);
  assert.equal((await handler(valid, {})).ok, false);
  assert.equal((await unlock(valid, { password: 'test-password' })).ok, false);
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
