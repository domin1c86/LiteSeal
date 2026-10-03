import {useLayoutEffect, useRef, useState} from 'react';
import {getDesktopApi} from '../lib/desktopApi';
import {VoiceCallTrial, type VoiceCallState, type VoiceQuality} from '../lib/voiceCallTrial';
import {VoiceCallPlayback} from '../lib/voiceCallPlayback';
import type {AudioReport, AudioTarget, AudioView} from '../../../electron/contracts';

const labels: Record<VoiceCallState, string> = {idle:'未通话',calling:'正在呼叫',ringing:'收到音频呼叫',connecting:'正在连接',connected:'通话中',ended:'通话已结束',failed:'呼叫未完成'};
export function AudioCallPanel({scope, peer, online, paused}: {scope:string;peer:string;online:boolean;paused:boolean}) {
  const [state,setState] = useState<VoiceCallState>('idle'), [error,setError] = useState('');
  const [view,setView] = useState<AudioView|null>(null), [targets,setTargets] = useState<AudioTarget[]>([]);
  const [device,setDevice] = useState(''), [input,setInput] = useState(''), [output,setOutput] = useState('');
  const [inputs,setInputs] = useState<MediaDeviceInfo[]>([]), [outputs,setOutputs] = useState<MediaDeviceInfo[]>([]);
  const [blocked,setBlocked] = useState(false), [quality,setQuality] = useState<VoiceQuality|null>(null);
  const engine = useRef<VoiceCallTrial|null>(null), playback = useRef<VoiceCallPlayback|null>(null), epoch = useRef(0);
  const selected = useRef({peer,device}); selected.current = {peer,device};
  const active = !['idle','ended','failed'].includes(state);
  useLayoutEffect(() => {
    const n = ++epoch.current; const current = () => epoch.current === n;
    setState('idle');setView(null);setError('');setBlocked(false);setQuality(null);setInput('');setOutput('');setInputs([]);setOutputs([]);
    if (paused || !online) return;
    const api = getDesktopApi(); const sink = new VoiceCallPlayback(); playback.current = sink;
    const call = new VoiceCallTrial({endWithRetire:true, playback:sink,
      native:{
        begin:async () => { const choice=selected.current;
          if (!choice.peer || !choice.device) throw new Error('choose target');
          const result=await api.begin_audio_call({scope,peer:choice.peer,device:choice.device});
          if (!current()) { await api.retire_audio_call({scope,id:result.id}).catch(()=>{}); throw new Error('retired'); }
          setView(result);return result.id;
        },
        seal:signal => api.prepare_audio_signal({scope,...signal}),
        open:wire => {
          if (typeof wire !== 'string') throw new Error('invalid handle');
          return api.open_audio_signal({scope,handle:wire});
        },
        retire:id => api.retire_audio_call({scope,id}),
      },
      send:async handle => { if(typeof handle!=='string')throw new Error('invalid handle');await api.publish_audio_signal({scope,handle}); },
      onState:next => { if(current()){setState(next);if(['ended','failed'].includes(next)){setView(null);setQuality(null);}} },
      onPlaybackBlocked:() => {if(current())setBlocked(true);},
    }); engine.current=call;
    const seen=new Set<string>();let receiving=false;
    const report=(event:Event) => {
      const value=(event as CustomEvent<AudioReport>).detail;
      if(!current()||!value)return;
      if(value.unavailable){call.pause();setError('音频信令暂不可用，请重新发起呼叫');return;}
      if(value.scope!==scope)return;
      if(document.visibilityState==='hidden') {
        call.pause();
        if(value.call)void api.retire_audio_call({scope,id:value.call.id}).catch(()=>{});
        return;
      }
      if(value.closed){call.pause();return;}
      if(value.call)setView(value.call);
      if(!value.handle||seen.has(value.handle)||receiving)return;
      const handle=value.handle;receiving=true;seen.add(handle);
      void call.receive(handle).catch(()=>{if(current()){call.pause();setError('音频信令验证或连接失败');}}).finally(()=>{receiving=false;});
    };
    const stop=()=>{if(current()){call.pause();setView(null);setQuality(null);}};
    const hidden=()=>{if(document.visibilityState==='hidden')stop();};
    window.addEventListener('liteseal-audio-status',report);
    for(const event of ['liteseal-app-locked','liteseal-device-paused','liteseal-normal-profile-changed','pagehide'])window.addEventListener(event,stop);
    document.addEventListener('visibilitychange',hidden);
    const timer=setInterval(()=>{if(call.state==='connected')void call.quality().then(value=>{if(current())setQuality(value);}).catch(()=>{});},2000);
    return()=>{++epoch.current;call.pause();sink.pause();engine.current=null;playback.current=null;clearInterval(timer);
      window.removeEventListener('liteseal-audio-status',report);
      for(const event of ['liteseal-app-locked','liteseal-device-paused','liteseal-normal-profile-changed','pagehide'])window.removeEventListener(event,stop);
      document.removeEventListener('visibilitychange',hidden);
    };
  },[scope,online,paused]);
  useLayoutEffect(()=>{setTargets([]);setDevice('');engine.current?.pause();setView(null);setError('');},[peer]);
  async function run(work:()=>Promise<unknown>){const n=epoch.current;setError('');try{await work();}catch{if(epoch.current===n)setError('音频操作未完成，请检查设备权限和对方状态');}}
  async function devices(){const n=epoch.current;const call=engine.current,sink=playback.current;if(!call||!sink)return;
    const [ins,outs]=await Promise.all([call.inputDevices(),sink.outputDevices()]);if(n===epoch.current){setInputs(ins);setOutputs(outs);}}
  async function loadTargets(){const n=epoch.current,account=peer;const values=await getDesktopApi().get_audio_targets({scope,peer:account});
    if(n===epoch.current&&selected.current.peer===account){setTargets(values);setDevice('');}}
  return <section aria-label="音频呼叫"><h3>音频呼叫</h3>
    <p role="status">{labels[state]}{view?` · ${view.peer} · 设备 ${view.target.device}`:''}</p>
    <p>对方须在线并在双方已接受联系的设备上接听。当前支持直接网络连接。</p>
    <button disabled={paused||!online||!peer||active} onClick={()=>void run(loadTargets)}>查看对方可呼叫设备</button>
    <label>呼叫设备<select aria-label="呼叫设备" disabled={paused||active} value={device} onChange={e=>setDevice(e.target.value)}><option value="">请选择设备</option>{targets.map(item=><option key={item.device} value={item.device}>{item.device}</option>)}</select></label>
    {targets.filter(item=>item.device===device).map(item=><details key={item.device}><summary>此设备公钥指纹</summary><p>{item.encryption_fingerprint}</p><p>{item.signing_fingerprint}</p></details>)}
    <button disabled={paused||!online||!device||active} onClick={()=>void run(async()=>{await engine.current?.call(input||undefined);await devices();})}>发起音频呼叫</button>
    {state==='ringing'&&<><button disabled={paused} onClick={()=>void run(async()=>{await engine.current?.accept(input||undefined);await devices();})}>接听</button><button onClick={()=>void run(()=>engine.current?.reject()??Promise.resolve())}>拒绝</button></>}
    {active&&<button onClick={()=>void run(()=>engine.current?.hangup()??Promise.resolve())}>结束通话</button>}
    <button disabled={paused||!online} onClick={()=>void run(devices)}>刷新音频设备</button>
    <label>麦克风<select aria-label="通话麦克风" value={input} disabled={active&&state!=='ringing'} onChange={e=>setInput(e.target.value)}><option value="">系统默认</option>{inputs.map((item,i)=><option key={item.deviceId} value={item.deviceId}>{item.label||`麦克风 ${i+1}`}</option>)}</select></label>
    <label>扬声器<select aria-label="通话扬声器" value={output} disabled={!active} onChange={e=>{const id=e.target.value;setOutput(id);void run(()=>playback.current?.selectOutput(id)??Promise.resolve());}}><option value="">系统默认</option>{outputs.map((item,i)=><option key={item.deviceId} value={item.deviceId}>{item.label||`扬声器 ${i+1}`}</option>)}</select></label>
    {blocked&&<button onClick={()=>void run(async()=>{await playback.current?.retry();setBlocked(false);})}>播放对方音频</button>}
    {state==='connected'&&<button onClick={()=>void run(()=>engine.current?.restart()??Promise.resolve())}>重连通话</button>}
    {quality&&<p>发送 {quality.packetsSent} 包 · 接收 {quality.packetsReceived} 包 · 丢包 {quality.packetsLost} · 往返 {Math.round(quality.roundTripSeconds*1000)} 毫秒</p>}
    {error&&<p role="alert">{error}</p>}
  </section>;
}
