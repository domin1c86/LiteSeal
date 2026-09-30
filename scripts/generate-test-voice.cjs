// Synthetic oscillator, no microphone permission or external network.
const { app, BrowserWindow } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const output = path.resolve(process.argv[2]);
app.setPath('userData', path.join(path.dirname(output), 'voice-profile'));
app.disableHardwareAcceleration();
let window;
app.whenReady().then(async () => {
  window = new BrowserWindow({ show: false, webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, backgroundThrottling: false } });
  await window.loadURL('data:text/html,<meta charset="utf-8"><title>Isolated synthetic voice fixture</title>');
  const bytes = await window.webContents.executeJavaScript(`(async()=>{
    const context=new AudioContext(), destination=context.createMediaStreamDestination(), tone=context.createOscillator();
    await context.resume();tone.connect(destination);const recorder=new MediaRecorder(destination.stream,{mimeType:'audio/webm;codecs=opus'}),chunks=[];
    const ended=new Promise(resolve=>recorder.onstop=resolve);recorder.ondataavailable=e=>chunks.push(e.data);tone.start();recorder.start();
    await new Promise(resolve=>setTimeout(resolve,1000));recorder.stop();await ended;tone.stop();destination.stream.getTracks().forEach(t=>t.stop());
    const bytes=await new Blob(chunks,{type:'audio/webm'}).arrayBuffer();const decoded=await context.decodeAudioData(bytes.slice(0));
    if(decoded.duration<0.5||decoded.duration>2)throw new Error('synthetic voice duration invalid');await context.close();return Array.from(new Uint8Array(bytes));
  })()`,true);
  await fs.writeFile(output,Buffer.from(bytes),{flag:'wx'});
}).then(()=>{window?.destroy();app.exit(0);}).catch(()=>{window?.destroy();app.exit(1);});
