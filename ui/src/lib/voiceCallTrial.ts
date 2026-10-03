/** T24 runnable engine. Production needs an authenticated native transport and
 * current-profile lifecycle wiring before this can be offered in the app. */
export type VoiceCallState = 'idle' | 'calling' | 'ringing' | 'connecting' | 'connected' | 'ended' | 'failed';
import type {VoiceCallPlayback} from './voiceCallPlayback';
export type VoiceSignalKind = 'offer' | 'answer' | 'restart' | 'reject' | 'hangup';
export interface VoiceSignal { id: string; kind: VoiceSignalKind; sdp?: string }
export interface VoiceNativeTransport {
  begin(): Promise<string>;
  seal(signal: VoiceSignal): Promise<unknown>;
  open(wire: unknown): Promise<VoiceSignal | null>;
  retire(id: string): Promise<void>;
}
export interface VoiceQuality {
  state: VoiceCallState; bytesSent: number; bytesReceived: number;
  packetsSent: number; packetsReceived: number; packetsLost: number;
  jitterSeconds: number; roundTripSeconds: number; dtlsState: string;
  localCandidateType: string; remoteCandidateType: string; codec: string;
}
export interface VoiceCallOptions {
  native: VoiceNativeTransport;
  send(wire: unknown): Promise<void>;
  onState?(state: VoiceCallState): void;
  onRemoteAudio?(stream: MediaStream | null): void;
  playback?: VoiceCallPlayback;
  onPlaybackBlocked?(): void;
  capture?(constraints: MediaStreamConstraints): Promise<MediaStream>;
  createConnection?(): RTCPeerConnection;
  timeoutMs?: number;
  /** Production transport closes with an independent presigned stop proof. */
  endWithRetire?: boolean;
}

export class VoiceCallTrial {
  state: VoiceCallState = 'idle';
  private id: string | null = null;
  private pending: VoiceSignal | null = null;
  private pc: RTCPeerConnection | null = null;
  private stream: MediaStream | null = null;
  private epoch = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  constructor(private readonly options: VoiceCallOptions) {}
  private setState(state: VoiceCallState) { this.state = state; this.options.onState?.(state); }
  private current(epoch: number) { if (epoch !== this.epoch) throw new Error('call retired'); }
  private arm() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => { void this.hangup().catch(() => {}); }, this.options.timeoutMs ?? 30_000);
  }
  private release(state: VoiceCallState) {
    ++this.epoch;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const pc = this.pc; this.pc = null;
    if (pc) { pc.ontrack = null; pc.onconnectionstatechange = null; pc.close(); }
    this.stream?.getTracks().forEach(track => track.stop()); this.stream = null;
    this.options.playback?.pause();
    this.options.onRemoteAudio?.(null); this.pending = null;
    const id = this.id; this.id = null; this.setState(state);
    if (id) void this.options.native.retire(id).catch(() => {});
  }
  /** Lock, sign-out, device switch, unload and sleep must call pause. */
  pause() { this.release('ended'); }
  async inputDevices(): Promise<MediaDeviceInfo[]> {
    return (await navigator.mediaDevices.enumerateDevices()).filter(device => device.kind === 'audioinput');
  }
  private async connection(epoch: number, deviceId?: string) {
    const stream = await (this.options.capture ?? (constraints => navigator.mediaDevices.getUserMedia(constraints)))({
      audio: deviceId ? { deviceId: { exact: deviceId }, echoCancellation: true } : { echoCancellation: true }, video: false,
    });
    if (epoch !== this.epoch) { stream.getTracks().forEach(track => track.stop()); this.current(epoch); }
    if (stream.getVideoTracks().length || stream.getAudioTracks().length !== 1) {
      stream.getTracks().forEach(track => track.stop()); throw new Error('one audio input required');
    }
    this.stream = stream;
    const pc = this.options.createConnection?.() ?? new RTCPeerConnection({ iceServers: [] });
    this.pc = pc;
    pc.ontrack = event => {
      if (epoch !== this.epoch || event.track.kind !== 'audio') return;
      const remote = event.streams[0] ?? new MediaStream([event.track]);
      this.options.onRemoteAudio?.(remote);
      if (this.options.playback) void this.options.playback.attach(remote).catch(() => {
        if (epoch === this.epoch && this.options.playback?.state === 'blocked') this.options.onPlaybackBlocked?.();
      });
    };
    pc.onconnectionstatechange = () => {
      if (epoch !== this.epoch) return;
      if (pc.connectionState === 'connected') { if (this.timer) clearTimeout(this.timer); this.timer = null; this.setState('connected'); }
      if (pc.connectionState === 'failed') this.release('failed');
      if (pc.connectionState === 'disconnected') this.arm();
    };
    const sender = pc.addTrack(stream.getAudioTracks()[0], stream);
    const parameters = sender.getParameters();
    if (parameters.encodings.length) { parameters.encodings[0].maxBitrate = 24_000; await sender.setParameters(parameters); }
    this.current(epoch);
    return pc;
  }
  private async localDescription(pc: RTCPeerConnection, description: RTCSessionDescriptionInit, epoch: number) {
    await pc.setLocalDescription(description); this.current(epoch);
    if (pc.iceGatheringState !== 'complete') await new Promise<void>((resolve, reject) => {
      const done = () => { clearTimeout(timer); pc.removeEventListener('icegatheringstatechange', changed); };
      const changed = () => { if (pc.iceGatheringState === 'complete') { done(); resolve(); } };
      const timer = setTimeout(() => { done(); reject(new Error('ICE gathering timeout')); }, 8_000);
      pc.addEventListener('icegatheringstatechange', changed); changed();
    });
    this.current(epoch);
    const sdp = pc.localDescription?.sdp;
    if (!sdp || sdp.length > 32_768) throw new Error('bounded audio SDP required');
    return sdp;
  }
  private async send(kind: VoiceSignalKind, epoch: number, sdp?: string) {
    this.current(epoch); if (!this.id) throw new Error('no active call');
    const wire = await this.options.native.seal({ id: this.id, kind, ...(sdp ? { sdp } : {}) });
    this.current(epoch); await this.options.send(wire); this.current(epoch);
  }
  async call(deviceId?: string) {
    if (this.id) throw new Error('call already active');
    const epoch = ++this.epoch;
    try {
      const id = await this.options.native.begin();
      if (epoch !== this.epoch) { await this.options.native.retire(id); this.current(epoch); }
      this.id = id; this.setState('calling'); this.arm();
      const pc = await this.connection(epoch, deviceId);
      const sdp = await this.localDescription(pc, await pc.createOffer(), epoch);
      await this.send('offer', epoch, sdp);
    } catch { if (epoch === this.epoch) this.release('failed'); throw new Error('voice call could not start'); }
  }
  async receive(wire: unknown) {
    const epoch = this.epoch;
    let signal: VoiceSignal | null;
    try { signal = await this.options.native.open(wire); } catch { throw new Error('voice signal authentication failed'); }
    this.current(epoch); if (!signal) return;
    if (!this.id) {
      if (signal.kind !== 'offer' || !signal.sdp) throw new Error('unexpected voice signal');
      this.id = signal.id; this.pending = signal; this.setState('ringing'); this.arm(); return;
    }
    if (signal.id !== this.id) throw new Error('another call is active');
    if (signal.kind === 'reject' || signal.kind === 'hangup') { this.release('ended'); return; }
    if (signal.kind === 'answer' && this.pc && signal.sdp && this.pc.signalingState === 'have-local-offer') {
      try { await this.pc.setRemoteDescription({ type: 'answer', sdp: signal.sdp }); this.current(epoch); this.setState(this.pc.connectionState === 'connected' ? 'connected' : 'connecting'); }
      catch { if (epoch === this.epoch) this.release('failed'); throw new Error('voice answer failed'); }
      return;
    }
    if (signal.kind === 'restart' && this.pc && signal.sdp && this.state === 'connected') {
      try {
        await this.pc.setRemoteDescription({ type: 'offer', sdp: signal.sdp }); this.current(epoch);
        const sdp = await this.localDescription(this.pc, await this.pc.createAnswer(), epoch);
        await this.send('answer', epoch, sdp);
      } catch { if (epoch === this.epoch) this.release('failed'); throw new Error('voice reconnect failed'); }
      return;
    }
    throw new Error('unexpected voice signal');
  }
  async accept(deviceId?: string) {
    if (!this.pending?.sdp || this.state !== 'ringing') throw new Error('no incoming call');
    const epoch = this.epoch; const sdp = this.pending.sdp; this.pending = null;
    try {
      this.setState('connecting'); const pc = await this.connection(epoch, deviceId);
      await pc.setRemoteDescription({ type: 'offer', sdp }); this.current(epoch);
      const answer = await this.localDescription(pc, await pc.createAnswer(), epoch);
      await this.send('answer', epoch, answer);
    } catch {
      if (epoch === this.epoch) await this.end('hangup', 'failed').catch(() => {});
      throw new Error('voice call could not be accepted');
    }
  }
  async restart() {
    if (this.state !== 'connected' || !this.pc) throw new Error('no connected call');
    const epoch = this.epoch;
    try { this.pc.restartIce(); const sdp = await this.localDescription(this.pc, await this.pc.createOffer(), epoch); await this.send('restart', epoch, sdp); }
    catch { if (epoch === this.epoch) this.release('failed'); throw new Error('voice reconnect failed'); }
  }
  async reject() {
    if (this.state !== 'ringing') throw new Error('no incoming call');
    await this.end('reject');
  }
  async hangup() { await this.end('hangup'); }
  private async end(kind: 'reject' | 'hangup', state: VoiceCallState = 'ended') {
    if (this.options.endWithRetire) { this.release(state); return; }
    const id = this.id;
    // Release hardware immediately, including when native/network operations fail.
    const native = id ? this.options.native.seal({ id, kind }) : null;
    this.release(state);
    if (native) { const wire = await native; await this.options.send(wire); }
  }
  async quality(): Promise<VoiceQuality> {
    const quality: VoiceQuality = { state: this.state, bytesSent: 0, bytesReceived: 0, packetsSent: 0, packetsReceived: 0, packetsLost: 0, jitterSeconds: 0, roundTripSeconds: 0, dtlsState: '', localCandidateType: '', remoteCandidateType: '', codec: '' };
    const pc = this.pc; const epoch = this.epoch; if (!pc) return quality;
    const stats = await pc.getStats(); this.current(epoch);
    stats.forEach(stat => {
      if (stat.type === 'outbound-rtp' && stat.kind === 'audio') { quality.bytesSent += stat.bytesSent ?? 0; quality.packetsSent += stat.packetsSent ?? 0; const codec = stats.get(stat.codecId); quality.codec = codec?.mimeType ?? ''; }
      if (stat.type === 'inbound-rtp' && stat.kind === 'audio') { quality.bytesReceived += stat.bytesReceived ?? 0; quality.packetsReceived += stat.packetsReceived ?? 0; quality.packetsLost += stat.packetsLost ?? 0; quality.jitterSeconds = stat.jitter ?? 0; }
      if (stat.type === 'transport') quality.dtlsState = stat.dtlsState ?? '';
      if (stat.type === 'candidate-pair' && stat.state === 'succeeded' && stat.nominated) { quality.roundTripSeconds = stat.currentRoundTripTime ?? 0; quality.localCandidateType = stats.get(stat.localCandidateId)?.candidateType ?? ''; quality.remoteCandidateType = stats.get(stat.remoteCandidateId)?.candidateType ?? ''; }
    });
    return quality;
  }
}
