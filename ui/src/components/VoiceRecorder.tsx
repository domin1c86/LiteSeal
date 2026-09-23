import { useEffect, useRef, useState } from "react";
import { getDesktopApi } from "../lib/desktopApi";

const MAX_BYTES = 11 * 1024 * 1024;

function encode(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("无法读取录音"));
    reader.onload = () => resolve(String(reader.result).split(",", 2)[1] ?? "");
    reader.readAsDataURL(blob);
  });
}

export function VoiceRecorder({ peerId, onStaged }: { peerId: string; onStaged: () => Promise<void> }) {
  const [recording, setRecording] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [clip, setClip] = useState<{ blob: Blob; url: string; durationMs: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const recorder = useRef<MediaRecorder | null>(null);
  const stream = useRef<MediaStream | null>(null);
  const started = useRef(0);
  const mounted = useRef(true);
  const busyRef = useRef(false);
  const discard = useRef(false);
  const clipUrl = useRef<string | null>(null);
  const stop = () => { if (recorder.current?.state === "recording") recorder.current.stop(); };
  const clearClip = () => {
    if (clipUrl.current) URL.revokeObjectURL(clipUrl.current);
    clipUrl.current = null;
    setClip(null);
  };
  useEffect(() => {
    mounted.current = true;
    const suspend = () => { if (document.hidden || !document.hasFocus()) stop(); };
    const locked = () => { discard.current = true; stop(); clearClip(); };
    document.addEventListener("visibilitychange", suspend);
    window.addEventListener("blur", suspend);
    window.addEventListener("liteseal-app-locked", locked);
    return () => {
      mounted.current = false;
      discard.current = true;
      stop();
      stream.current?.getTracks().forEach(track => track.stop());
      if (clipUrl.current) URL.revokeObjectURL(clipUrl.current);
      document.removeEventListener("visibilitychange", suspend);
      window.removeEventListener("blur", suspend);
      window.removeEventListener("liteseal-app-locked", locked);
    };
  }, []);
  useEffect(() => {
    if (!recording) return;
    const timer = window.setInterval(() => {
      const duration = Date.now() - started.current;
      setElapsed(Math.min(60, Math.floor(duration / 1000)));
      if (duration >= 60_000) stop();
    }, 200);
    return () => window.clearInterval(timer);
  }, [recording]);
  async function start() {
    if (busyRef.current || recording) return;
    setError(""); clearClip(); discard.current = false;
    if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder
      || !MediaRecorder.isTypeSupported("audio/webm;codecs=opus")) {
      setError("当前环境不支持 WebM/Opus 录音"); return;
    }
    busyRef.current = true; setBusy(true);
    try {
      const microphone = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
      if (!mounted.current || discard.current) { microphone.getTracks().forEach(track => track.stop()); return; }
      stream.current = microphone;
      const chunks: Blob[] = [];
      let totalBytes = 0;
      const current = new MediaRecorder(microphone, { mimeType: "audio/webm;codecs=opus" });
      recorder.current = current;
      current.ondataavailable = event => {
        if (!event.data.size) return;
        totalBytes += event.data.size;
        if (totalBytes > MAX_BYTES) { discard.current = true; setError("录音超过 11 MiB，请缩短录音"); stop(); return; }
        chunks.push(event.data);
      };
      current.onstop = () => {
        microphone.getTracks().forEach(track => track.stop());
        stream.current = null; recorder.current = null;
        if (!mounted.current) return;
        setRecording(false);
        const durationMs = Math.min(60_000, Math.max(0, Date.now() - started.current));
        const blob = new Blob(chunks, { type: "audio/webm" });
        if (discard.current) return;
        if (durationMs < 500 || !blob.size) { setError("录音过短，请重试"); return; }
        if (blob.size > MAX_BYTES) { setError("录音超过 11 MiB，请缩短录音"); return; }
        const url = URL.createObjectURL(blob);
        clipUrl.current = url;
        setClip({ blob, url, durationMs });
      };
      current.onerror = () => { discard.current = true; if (mounted.current) setError("录音设备出错，请重试"); stop(); };
      current.start(1000);
      started.current = Date.now(); setElapsed(0); setRecording(true);
    } catch (failure) {
      stream.current?.getTracks().forEach(track => track.stop()); stream.current = null;
      if (mounted.current) setError(`无法使用麦克风：${String(failure)}`);
    } finally { busyRef.current = false; if (mounted.current) setBusy(false); }
  }
  async function stage() {
    if (!clip || busyRef.current) return;
    busyRef.current = true;
    setBusy(true); setError("");
    try {
      const encoded = await encode(clip.blob);
      if (!mounted.current) return;
      await getDesktopApi().stage_recorded_audio({ peerId, encoded, durationMs: clip.durationMs });
      if (mounted.current) clearClip();
      await onStaged();
    } catch (failure) { if (mounted.current) setError(String(failure)); }
    finally { busyRef.current = false; if (mounted.current) setBusy(false); }
  }
  return <div aria-label="语音消息">
    {!recording && !clip && <button disabled={busy} onClick={() => void start()}>录制语音（最多 60 秒）</button>}
    {recording && <><span role="status">录音中 {elapsed} / 60 秒</span><button onClick={stop}>停止录音</button><button onClick={() => { discard.current = true; stop(); }}>取消录音</button></>}
    {clip && <><audio controls src={clip.url} aria-label="发送前试听语音" /><span>{Math.ceil(clip.durationMs / 1000)} 秒</span><button disabled={busy} onClick={() => void stage()}>加入待发附件</button><button disabled={busy} onClick={clearClip}>丢弃录音</button></>}
    {error && <p role="alert">{error}</p>}
  </div>;
}
