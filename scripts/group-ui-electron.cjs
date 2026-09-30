const { app, BrowserWindow,nativeTheme } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const directory = process.argv[2];
app.setPath('userData', path.join(directory, 'profile'));
app.disableHardwareAcceleration();
let window;
const report = { status: 'failed', scope: 'real Electron Chromium, mocked desktop business API', tests: [], errors: [] };
app.whenReady().then(async () => {
  window = new BrowserWindow({ width: 1280, height: 900, useContentSize: true, show: false, webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, backgroundThrottling: false } });
  window.webContents.on('console-message', (_event, level, message) => { if (level >= 3) report.errors.push(message); });
  window.webContents.on('render-process-gone', () => { report.errors.push('renderer terminated'); });
  await window.loadFile(path.join(directory, 'index.html'));
  report.tests = await window.webContents.executeJavaScript('window.runGroupTests()');
  await window.webContents.executeJavaScript('window.showCollaboration()');
  window.setContentSize(1281, 900);
  await new Promise(resolve => setTimeout(resolve, 100));
  window.setContentSize(1280, 900);
  await new Promise(resolve => setTimeout(resolve, 300));
  await fs.writeFile(path.join(directory, 'wide.png'), (await window.webContents.capturePage()).toPNG());
  window.setContentSize(390, 844);
  report.narrowTests = await window.webContents.executeJavaScript('window.runGroupTests()');
  await window.webContents.executeJavaScript('window.showCollaboration()');
  window.setContentSize(391, 844);
  await new Promise(resolve => setTimeout(resolve, 100));
  window.setContentSize(390, 844);
  await new Promise(resolve => setTimeout(resolve, 300));
  const overflow = await window.webContents.executeJavaScript('document.documentElement.scrollWidth > window.innerWidth');
  if (overflow) throw new Error('narrow viewport horizontal overflow');
  await fs.writeFile(path.join(directory, 'narrow.png'), (await window.webContents.capturePage()).toPNG());
  for(const theme of ['light','dark']){
    nativeTheme.themeSource=theme;
    for(const [label,width,height] of [['wide',1280,900],['narrow',390,844]]){
      window.setContentSize(width,height);await window.webContents.executeJavaScript('window.showExtensions()');
      if(!await window.webContents.executeJavaScript('document.querySelector(".group-activity")?.textContent.includes("周末讨论活动")'))throw new Error('extension card missing at capture');
      window.setContentSize(width+1,height);await new Promise(resolve=>setTimeout(resolve,100));window.setContentSize(width,height);await new Promise(resolve=>setTimeout(resolve,300));
      if(await window.webContents.executeJavaScript('document.documentElement.scrollWidth > window.innerWidth'))throw new Error('extension viewport horizontal overflow');
      await fs.writeFile(path.join(directory,`extensions-${theme}-${label}.png`),(await window.webContents.capturePage()).toPNG());
    }
  }
  if (report.errors.length) throw new Error('renderer console errors');
  report.status = 'passed';
}).catch(error => { report.errors.push(String(error)); }).finally(async () => {
  await fs.writeFile(path.join(directory, 'result.json'), JSON.stringify(report, null, 2));
  window?.destroy(); app.exit(report.status === 'passed' ? 0 : 1);
});
