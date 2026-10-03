const {app,BrowserWindow,ipcMain}=require('electron');
const {spawn}=require('node:child_process');const fs=require('node:fs/promises');const path=require('node:path');
const directory=process.argv[2];const root=path.resolve(__dirname,'..');
app.setPath('userData',path.join(directory,'profile'));app.disableHardwareAcceleration();
app.commandLine.appendSwitch('use-fake-device-for-media-stream');app.commandLine.appendSwitch('use-fake-ui-for-media-stream');app.commandLine.appendSwitch('mute-audio');
let window;let child;let waiting;let stdout='';let queue=Promise.resolve();
const report={status:'failed',scope:'same-host real Chromium WebRTC and isolated Rust synthetic identities; fake audio, no real microphone, profiles, external STUN/TURN or production signalling',cases:[],quality:[],errors:[]};
function request(value){
  const job=queue.then(()=>new Promise((resolve,reject)=>{
    const encoded=JSON.stringify(value);if(encoded.length>300000){reject(new Error('trial input limit'));return;}
    waiting={resolve,reject};child.stdin.write(encoded+'\n',error=>{if(error){waiting=null;reject(new Error('native write failed'));}});
  }));queue=job.catch(()=>{});return job;
}
app.whenReady().then(async()=>{
  child=spawn(path.join(root,'target/debug/examples/voice_call_trial.exe'),[],{cwd:root,stdio:['pipe','pipe','ignore'],windowsHide:true});
  child.once('error',()=>waiting?.reject(new Error('native trial unavailable')));
  child.once('exit',()=>waiting?.reject(new Error('native trial exited')));
  child.stdout.setEncoding('utf8');child.stdout.on('data',chunk=>{stdout+=chunk;if(stdout.length>300000){waiting?.reject(new Error('native response limit'));child.kill();return;}let end;while((end=stdout.indexOf('\n'))>=0){const line=stdout.slice(0,end);stdout=stdout.slice(end+1);const current=waiting;waiting=null;try{const response=JSON.parse(line);if(response.ok)current?.resolve(response.value);else current?.reject(new Error('voice trial request rejected'));}catch{current?.reject(new Error('invalid native response'));}}});
  window=new BrowserWindow({width:900,height:600,show:false,webPreferences:{preload:path.join(__dirname,'voice-call-trial-preload.cjs'),sandbox:true,contextIsolation:true,nodeIntegration:false,backgroundThrottling:false}});
  ipcMain.handle('voice-trial:request',(event,value)=>{if(event.sender!==window.webContents)throw new Error('unknown trial window');return request(value);});
  window.webContents.on('console-message',(_event,level)=>{if(level>=3)report.errors.push('renderer error');});
  await window.loadFile(path.join(directory,'index.html'));
  const result=await window.webContents.executeJavaScript('window.runVoiceCallTests()');
  report.cases=result.cases;report.quality=result.quality;
  if(report.errors.length)throw new Error('trial renderer errors');report.status='passed';
}).catch(error=>{report.errors.push(String(error.message));}).finally(async()=>{
  ipcMain.removeHandler('voice-trial:request');window?.destroy();child?.stdin.end();
  if(child&&!child.exitCode)child.kill();
  await fs.writeFile(path.join(directory,'result.json'),JSON.stringify(report,null,2));app.exit(report.status==='passed'?0:1);
});
