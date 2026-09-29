const { app, BrowserWindow } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const directory = process.argv[2];
app.setPath('userData', path.join(directory, 'profile')); app.disableHardwareAcceleration();
let window;
const report = { status: 'failed', scope: 'real Electron Chromium, simulated backup API, no network', wide: [], narrow: [], errors: [] };
app.whenReady().then(async () => {
  window = new BrowserWindow({ width: 1280, height: 900, useContentSize: true, show: false, webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, backgroundThrottling: false } });
  window.webContents.on('console-message', (_event, level, message) => { if (level >= 3) report.errors.push(message); });
  window.webContents.on('render-process-gone', () => report.errors.push('renderer terminated'));
  await window.loadFile(path.join(directory, 'index.html'));
  for (const [name, width, height] of [['wide',1280,900],['narrow',390,844]]) {
    window.setContentSize(width,height);
    report[name] = await window.webContents.executeJavaScript('window.runBackupTests()');
    await window.webContents.executeJavaScript('window.showBackupArchive()');
    await new Promise(resolve => setTimeout(resolve,300));
    if (await window.webContents.executeJavaScript('document.documentElement.scrollWidth > window.innerWidth')) throw new Error('horizontal overflow');
    await fs.writeFile(path.join(directory,name+'.png'),(await window.webContents.capturePage()).toPNG());
  }
  if (report.errors.length) throw new Error('renderer errors'); report.status='passed';
}).catch(error=>report.errors.push(String(error))).finally(async()=>{await fs.writeFile(path.join(directory,'result.json'),JSON.stringify(report,null,2));window?.destroy();app.exit(report.status==='passed'?0:1);});
