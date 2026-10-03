/** A separate media element per admitted stream prevents a late output-device
 * change from affecting another call. No device identifiers are persisted. */
export type VoicePlaybackState = 'idle' | 'playing' | 'blocked';
export class VoiceCallPlayback {
  state: VoicePlaybackState = 'idle';
  private element: HTMLAudioElement | null = null;
  private epoch = 0;
  constructor(private readonly createElement: () => HTMLAudioElement = () => new Audio()) {}
  pause() {
    ++this.epoch;
    const element = this.element;
    this.element = null;
    if (element) { element.pause(); element.srcObject = null; }
    this.state = 'idle';
  }
  async attach(stream: MediaStream) {
    this.pause();
    if (stream.getVideoTracks().length || stream.getAudioTracks().length !== 1) {
      throw new Error('one admitted audio stream required');
    }
    const epoch = this.epoch;
    const element = this.createElement();
    this.element = element;
    element.srcObject = stream;
    try {
      await element.play();
      if (epoch !== this.epoch || this.element !== element) {
        element.pause(); element.srcObject = null;
        throw new Error('audio playback retired');
      }
      this.state = 'playing';
    } catch {
      if (epoch === this.epoch && this.element === element) this.state = 'blocked';
      throw new Error('audio playback unavailable; choose an output or retry');
    }
  }
  async outputDevices(): Promise<MediaDeviceInfo[]> {
    const epoch = this.epoch;
    const devices = await navigator.mediaDevices.enumerateDevices();
    if (epoch !== this.epoch) throw new Error('audio playback retired');
    return devices.filter(device => device.kind === 'audiooutput');
  }
  async selectOutput(deviceId: string) {
    const element = this.element;
    const epoch = this.epoch;
    if (!element || typeof element.setSinkId !== 'function') throw new Error('output selection unavailable');
    try { await element.setSinkId(deviceId); }
    catch { throw new Error('output device unavailable or permission refused'); }
    if (epoch !== this.epoch || this.element !== element) throw new Error('audio playback retired');
  }
  async retry() {
    const element = this.element;
    const epoch = this.epoch;
    if (!element?.srcObject) throw new Error('no admitted audio stream');
    try { await element.play(); }
    catch { throw new Error('audio playback unavailable'); }
    if (epoch !== this.epoch || this.element !== element) {
      element.pause(); element.srcObject = null;
      throw new Error('audio playback retired');
    }
    this.state = 'playing';
  }
}
