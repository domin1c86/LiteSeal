const { app, BrowserWindow, nativeTheme } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const directory = process.argv[2];
app.setPath('userData', path.join(directory, 'profile'));
app.commandLine.appendSwitch('force-device-scale-factor', '1');
app.disableHardwareAcceleration();
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let window;
const report = { status: 'failed', scope: 'real Chromium with synthetic data and mocked desktop APIs; no real user storage or server', screens: [], checks: [], errors: [] };
app.whenReady().then(async () => {
  window = new BrowserWindow({ width: 1360, height: 1000, useContentSize: true, show: false, webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, backgroundThrottling: false } });
  window.webContents.on('console-message', (_event, level, message) => { if (level >= 3) report.errors.push(message); });
  window.webContents.on('render-process-gone', () => report.errors.push('renderer terminated'));
  for (const theme of ['light', 'dark']) for (const [width, height] of [[1360, 1000], [390, 844]]) {
    nativeTheme.themeSource = theme;
    window.setContentSize(width, height);
    await window.loadFile(path.join(directory, 'app.html'));
    const checks = await window.webContents.executeJavaScript('window.checkStyleInteractions()');
    report.checks.push({ theme, width, checks });
    for (const screen of ['login', 'register', 'chat', 'contacts', 'account', 'organizer', 'storage', 'lock', 'edit', 'search', 'scheduled', 'attachments', 'emoji', 'group', 'group-storage']) {
      if (screen === 'group') {
        await window.loadFile(path.join(directory, 'groups.html'));
        await window.webContents.executeJavaScript('window.showCollaboration()');
      } else if (screen === 'group-storage') await window.webContents.executeJavaScript('window.showStorage()');
      else await window.webContents.executeJavaScript(`window.tour(${JSON.stringify(screen)})`);
      await pause(100);
      window.setContentSize(width + 1, height); await pause(60);
      window.setContentSize(width, height); await pause(120);
      const layout = await window.webContents.executeJavaScript(`({ overflow: document.documentElement.scrollWidth > innerWidth, dialogs: [...document.querySelectorAll('[role=dialog]')].filter(e => e.checkVisibility()).map(e => { const r=e.getBoundingClientRect();return {label:e.getAttribute('aria-label'),visible:r.left>=0 && r.right<=innerWidth && r.top>=0 && r.bottom<=innerHeight}; }) })`);
      if (layout.overflow || layout.dialogs.some(d => !d.visible)) throw new Error(`${screen} ${theme} ${width}: viewport overflow`);
      const file = `${screen}-${theme}-${width}.png`;
      await fs.writeFile(path.join(directory, file), (await window.webContents.capturePage()).toPNG());
      report.screens.push({ screen, theme, width, file, ...layout });
    }
  }
  if (report.errors.length) throw new Error('renderer console errors');
  report.status = 'passed';
}).catch(error => report.errors.push(String(error))).finally(async () => {
  await fs.writeFile(path.join(directory, 'result.json'), JSON.stringify(report, null, 2));
  const cards = report.screens.map(s => `<article><h2>${s.screen} · ${s.theme} · ${s.width}px</h2><a href="${s.file}"><img loading="lazy" src="${s.file}" alt="${s.screen}"></a></article>`).join('');
  await fs.writeFile(path.join(directory, 'index.html'), `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>LiteSeal UI · da66ac0 风格对齐</title><style>body{margin:32px;background:#161616;color:#ececec;font:14px system-ui}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:24px}article{border:1px solid #363636;border-radius:12px;padding:16px}h2{font-size:14px}img{width:100%;max-height:600px;object-fit:contain;object-position:top}p{color:#aaa}</style><h1>LiteSeal · UI 风格对齐</h1><p>以 da66ac0 的灰阶、字标、侧栏和气泡为基准。以下为真实组件搭配模拟接口及虚构数据的截图，不代表真实系统验收。</p><main>${cards}</main></html>`);
  window?.destroy(); app.exit(report.status === 'passed' ? 0 : 1);
});
