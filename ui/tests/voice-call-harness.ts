import { VoiceCallTrial, type VoiceNativeTransport, type VoiceQuality, type VoiceSignal } from '../src/lib/voiceCallTrial';
import {VoiceCallPlayback} from '../src/lib/voiceCallPlayback';
declare global {
  interface Window {
    voiceTrial: { request(value: unknown): Promise<unknown> };
    runVoiceCallTests(): Promise<{ cases: string[]; quality: VoiceQuality[] }>;
  }
}
function assert(value: unknown, message: string): void { if (!value) throw new Error(message); }
async function until(test: () => boolean, message: string) {
  const deadline = performance.now() + 12_000;
  while (!test()) { if (performance.now() > deadline) throw new Error(message); await new Promise(resolve => setTimeout(resolve, 50)); }
}
function native(actor: string): VoiceNativeTransport {
  return {
    begin: async () => await window.voiceTrial.request({ op: 'begin', actor }) as string,
    seal: async signal => window.voiceTrial.request({ op: 'seal', actor, signal }),
    open: async wire => await window.voiceTrial.request({ op: 'open', actor, wire }) as VoiceSignal | null,
    retire: async id => { await window.voiceTrial.request({ op: 'retire', actor, id }); },
  };
}
function pair(overrides?: { capture?: (constraints: MediaStreamConstraints) => Promise<MediaStream>; denyBegin?: boolean; deferred?: boolean }) {
  const streams: MediaStream[] = []; const connections: RTCPeerConnection[] = [];
  const audio: HTMLAudioElement[] = [];
  const createOutput = () => { const element = new Audio(); element.muted = true; audio.push(element); return element; };
  const alicePlayback = new VoiceCallPlayback(createOutput);
  const bobPlayback = new VoiceCallPlayback(createOutput);
  let selected: MediaStreamConstraints | undefined; let offer: unknown;
  const aliceNative = native('alice'); const bobNative = native('bob');
  const capture = async (constraints: MediaStreamConstraints) => {
    selected = constraints;
    const stream = await (overrides?.capture ?? (constraints => navigator.mediaDevices.getUserMedia(constraints)))(constraints);
    streams.push(stream); return stream;
  };
  const createConnection = () => { const pc = new RTCPeerConnection({ iceServers: [] }); connections.push(pc); return pc; };
  const alice = new VoiceCallTrial({ native: overrides?.denyBegin ? { ...aliceNative, begin: async () => { throw new Error('synthetic admission failure'); } } : aliceNative,
    playback: alicePlayback, capture, createConnection, send: async wire => { offer = wire; if (!overrides?.deferred) await bob.receive(wire); } });
  const bob = new VoiceCallTrial({ native: bobNative, playback: bobPlayback, capture, createConnection, send: async wire => alice.receive(wire) });
  return { alice, bob, streams, connections, audio, alicePlayback, bobPlayback, get selected() { return selected; }, get offer() { return offer; } };
}
window.runVoiceCallTests = async () => {
  const cases: string[] = []; const quality: VoiceQuality[] = [];
  const terminal = (p: ReturnType<typeof pair>) => {
    assert(p.streams.every(stream => stream.getTracks().every(track => track.readyState === 'ended')), 'audio track leaked');
    assert(p.connections.every(pc => pc.connectionState === 'closed'), 'peer connection leaked');
    assert(p.audio.every(element => element.paused && element.srcObject === null), 'output element leaked');
  };
  {
    const p=pair({ denyBegin:true }); await p.alice.call().catch(() => {});
    assert(p.alice.state === 'failed' && !p.streams.length && !p.connections.length, 'authentication acquired audio');
    cases.push('native admission failure acquires no input or peer connection');
  }
  {
    const p=pair({ deferred:true }); await p.alice.call();
    const wire=structuredClone(p.offer) as { ciphertext: number[] }; wire.ciphertext[40]^=1;
    await p.bob.receive(wire).then(() => { throw new Error('tampered signal accepted'); }, () => {});
    assert(p.bob.state === 'idle' && p.streams.length === 1 && p.connections.length === 1, 'unauthenticated offer acquired callee devices');
    await p.bob.receive(p.offer); assert(p.bob.state === 'ringing', 'valid offer not admitted');
    await p.bob.receive(p.offer); assert(p.bob.state === 'ringing', 'duplicate changed ringing');
    await p.bob.reject(); assert(p.alice.state === 'ended' && p.bob.state === 'ended', 'rejection state'); terminal(p);
    cases.push('native tamper rejection precedes callee allocation, exact replay is idempotent and reject releases caller audio');
  }
  {
    const p=pair(); const devices=await p.alice.inputDevices(); assert(devices.length > 0, 'synthetic audio input missing');
    const chosen=devices.find(device => !['default','communications'].includes(device.deviceId))?.deviceId ?? devices[0].deviceId;
    await p.alice.call(chosen); assert(p.bob.state === 'ringing' && p.streams.length === 1, 'callee captured before consent');
    await p.bob.accept(chosen); await until(() => p.alice.state === 'connected' && p.bob.state === 'connected','actual DTLS peers did not connect');
    const constraints=p.selected?.audio as MediaTrackConstraints;
    assert((constraints.deviceId as ConstrainDOMStringParameters)?.exact === chosen,'device selection did not reach capture');
    await new Promise(resolve => setTimeout(resolve, 1_500));
    const values=await Promise.all([p.alice.quality(),p.bob.quality()]);
    for(const value of values) assert(value.bytesSent > 0 && value.bytesReceived > 0 && value.packetsReceived > 0 && value.dtlsState === 'connected' && value.codec.toLowerCase() === 'audio/opus','actual encrypted Opus media missing');
    quality.push(...values); cases.push('selected synthetic inputs establish bidirectional authenticated DTLS-SRTP/Opus and bounded public quality stats');
    await until(() => p.alicePlayback.state === 'playing' && p.bobPlayback.state === 'playing', 'muted remote audio playback missing');
    await p.alicePlayback.selectOutput('');
    await p.alicePlayback.selectOutput('synthetic-nonexistent-output').then(() => { throw new Error('missing output accepted'); }, () => {});
    assert(p.alicePlayback.state === 'playing', 'output refusal interrupted admitted stream');
    cases.push('authenticated remote audio plays in muted elements; default output works and unavailable output fails visibly');
    const tracks=p.streams.map(stream => stream.getAudioTracks()[0].id);
    const previousIce=p.connections[0].localDescription?.sdp.match(/a=ice-ufrag:([^\r\n]+)/)?.[1];
    await p.alice.restart();
    await until(() => p.alice.state === 'connected' && p.bob.state === 'connected','ICE restart failed');
    assert(p.streams.length === 2 && tracks.every((id,index) => p.streams[index].getAudioTracks()[0].id === id),'restart reacquired devices');
    assert(previousIce && previousIce !== p.connections[0].localDescription?.sdp.match(/a=ice-ufrag:([^\r\n]+)/)?.[1], 'ICE restart reused old credentials');
    await new Promise(resolve => setTimeout(resolve,500));
    assert((await p.bob.quality()).bytesReceived > values[1].bytesReceived, 'media did not resume after ICE restart');
    cases.push('signed ICE restart preserves admitted call identity and existing audio inputs');
    await p.alice.hangup(); assert(p.bob.state === 'ended','hangup not received'); terminal(p);
    await p.bob.receive(p.offer).then(() => { throw new Error('retired offer accepted'); },() => {}); terminal(p);
    cases.push('hangup releases both peers and a retired offer cannot reopen audio');
  }
  {
    const p=pair({ capture: async () => { throw new DOMException('synthetic permission denial','NotAllowedError'); } });
    await p.alice.call().catch(() => {}); assert(p.alice.state === 'failed','permission refusal did not fail safely'); terminal(p);
    cases.push('permission refusal retains no live device or connection');
  }
  {
    const p=pair({ capture: async () => { throw new DOMException('synthetic absent input','NotFoundError'); } });
    await p.alice.call().catch(() => {}); assert(p.alice.state === 'failed','missing input did not fail safely'); terminal(p);
    cases.push('missing audio input fails safely without a live peer');
  }
  {
    let captures=0;
    const p=pair({ capture: async constraints => {
      if (++captures === 2) throw new DOMException('synthetic callee refusal','NotAllowedError');
      return navigator.mediaDevices.getUserMedia(constraints);
    } });
    await p.alice.call(); await p.bob.accept().catch(() => {});
    assert(p.bob.state === 'failed' && p.alice.state === 'ended','callee refusal left caller recording'); terminal(p);
    cases.push('callee capture failure sends authenticated termination and releases caller input');
  }
  {
    let resolveCapture: ((stream: MediaStream) => void) | undefined;
    const p=pair({ capture: () => new Promise(resolve => { resolveCapture=resolve; }) });
    const calling=p.alice.call().catch(() => {}); await until(() => !!resolveCapture,'capture did not start');
    p.alice.pause(); const stream=await navigator.mediaDevices.getUserMedia({ audio:true,video:false }); resolveCapture!(stream); await calling;
    assert(p.alice.state === 'ended' && stream.getTracks().every(track => track.readyState === 'ended') && !p.connections.length,'late capture escaped pause');
    p.bob.pause(); cases.push('lock or profile pause retires late capture and never creates a late connection');
  }
  {
    const stream = await navigator.mediaDevices.getUserMedia({audio:true,video:false});
    const elements: HTMLAudioElement[] = [];
    const output = new VoiceCallPlayback(() => {
      const element = new Audio(); element.muted = true; elements.push(element); return element;
    });
    await output.attach(stream);
    let settle!: () => void;
    const old = elements[0]; const originalSetSink = old.setSinkId.bind(old);
    old.setSinkId = async device => {
      await new Promise<void>(resolve => { settle = resolve; });
      await originalSetSink(device);
    };
    const changing = output.selectOutput('').then(() => false, () => true);
    output.pause(); await output.attach(stream); settle();
    assert(await changing, 'retired output change was accepted');
    assert(old.paused && old.srcObject === null && elements[1].srcObject === stream && output.state === 'playing', 'late output change affected the new stream');
    output.pause(); stream.getTracks().forEach(track => track.stop());
    cases.push('late output change remains on a retired element and cannot alter the next admitted stream');
  }
  {
    const stream = await navigator.mediaDevices.getUserMedia({audio:true,video:false});
    const element = new Audio(); element.muted = true;
    const nativePlay = element.play.bind(element);
    element.play = async () => { throw new DOMException('synthetic autoplay refusal','NotAllowedError'); };
    const output = new VoiceCallPlayback(() => element);
    await output.attach(stream).catch(() => {});
    assert(output.state === 'blocked', 'output permission refusal was hidden');
    element.play = nativePlay; await output.retry();
    assert(output.state === 'playing', 'explicit output playback retry failed');
    output.pause(); assert(element.paused && element.srcObject === null, 'output retry leaked media');
    stream.getTracks().forEach(track => track.stop());
    cases.push('output playback refusal remains visible and explicit retry plays only the admitted stream');
  }
  document.body.textContent='T24 隔离语音验证通过：'+cases.length+' 项；合成音频，无真实麦克风或账号。';
  return { cases, quality };
};
