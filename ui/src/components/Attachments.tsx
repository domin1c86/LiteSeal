import { useEffect, useRef, useState } from "react";
import type { AttachmentTask } from "../../../electron/contracts";
import { VoiceRecorder } from "./VoiceRecorder";
import { attachmentApi,type AttachmentTarget } from "../lib/attachmentTarget";

export function AttachmentComposer({ peerId="", target:chosen, online, onSent }: { peerId?: string; target?:AttachmentTarget; online: boolean; onSent: () => void }) {
  const target:AttachmentTarget=chosen??{kind:"direct",id:peerId};const api=attachmentApi(target);
  const [tasks, setTasks] = useState<AttachmentTask[]>([]);
  const [preview, setPreview] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const cancelled = useRef(false);
  const alive = useRef(true);
  const reload = () => api.tasks().then(rows => { if (alive.current) setTasks(rows); });
  useEffect(() => { alive.current = true; void reload().catch(failure => setError(String(failure))); return () => { alive.current = false; cancelled.current = true; }; }, [target.kind,target.id]);
  async function stageFile(file: File, pasted = false) {
    if (busy) return;
    setBusy(true); setError("");
    try {
      if (pasted && file.type.startsWith("image/")) {
        try { await api.paste(); }
        catch { await api.stage(file); }
      } else {
        await api.stage(file);
      }
      if (alive.current) await reload();
    } catch (failure) { if (alive.current) setError(String(failure)); }
    finally { if (alive.current) setBusy(false); }
  }
  useEffect(() => {
    const paste = (event: ClipboardEvent) => {
      if (event.target instanceof Element && event.target.closest('[role="dialog"]')) return;
      const file = event.clipboardData?.files[0];
      if (!file) return;
      event.preventDefault();
      void stageFile(file, true);
    };
    window.addEventListener("paste", paste);
    return () => window.removeEventListener("paste", paste);
  }, [target.kind,target.id, busy]);
  async function send(task: AttachmentTask) {
    if (busy) return;
    cancelled.current = false; setBusy(true); setError("");
    try {
      let current = task;
      while (current.offset < current.total && !cancelled.current) {
        current = await api.step(current.id);
        if (alive.current) setTasks(rows => rows.map(row => row.id === current.id ? current : row));
      }
      if (cancelled.current) return;
      await api.publish(current.id);
      // The signed outbox now owns retries. Retain the task until publish succeeds.
      await api.finish(current.id);
      if (alive.current) { await reload(); onSent(); }
    } catch (failure) { if (alive.current) { setError(String(failure)); await reload().catch(() => {}); } }
    finally { if (alive.current) setBusy(false); }
  }
  return <section className="attachment-composer" aria-label="发送加密附件" style={{ padding: "6px 24px" }} onDragOver={event => {
    if (event.dataTransfer.types.includes("Files")) event.preventDefault();
  }} onDrop={event => {
    if (!event.dataTransfer.files.length) return;
    event.preventDefault();
    void stageFile(event.dataTransfer.files[0]);
  }}>
    <p className="attachment-hint">可拖入一个文件，或按 Ctrl+V 粘贴图片及已复制的文件。</p>
    <button disabled={busy} onClick={async () => {
      setBusy(true); setError("");
      try { await api.select(); await reload(); } catch (failure) { if (alive.current) setError(String(failure)); }
      finally { if (alive.current) setBusy(false); }
    }}>选择文件或图片（20 MiB）</button>
    <VoiceRecorder key={target.kind+target.id} target={target} onStaged={reload} />
    {tasks.map(task => <div key={task.id}>
      <span>{task.name} · {(task.size / 1024).toFixed(1)} KiB</span>
      {task.mime.startsWith("image/") && <button disabled={busy} onClick={async () => {
        setBusy(true); try { const result = await api.preview(task.id); if (alive.current) setPreview(result); } catch (failure) { setError(String(failure)); } finally { if (alive.current) setBusy(false); }
      }}>发送前预览</button>}
      <progress value={task.offset} max={task.total} aria-label="加密附件上传进度" />
      <button disabled={busy || !online} onClick={() => void send(task)}>确认发送 / 继续原任务</button>
      <button disabled={busy} onClick={async () => {
        try { await api.cancel(task.id); await reload(); } catch (failure) { setError(String(failure)); }
      }}>取消任务</button>
    </div>)}
    {busy && <button onClick={() => { cancelled.current = true; }}>停止传输（保留任务）</button>}
    {preview && <div><img src={preview} alt="待发图片预览" decoding="async" style={{ maxWidth: 200, maxHeight: 150 }} onError={() => { setPreview(null); setError("图片损坏，无法预览"); }} /><button onClick={() => setPreview(null)}>关闭预览</button></div>}
    {error && <p role="alert">{error}；失败后可继续原任务。已提交的消息不会因取消任务而撤回。</p>}
  </section>;
}

export function AttachmentCard({ messageId, target={kind:"direct",id:""}, name, image, audio }: { messageId: string;target?:AttachmentTarget; name: string; image: boolean; audio: boolean }) {
  const api=attachmentApi(target);
  const [progress, setProgress] = useState<AttachmentTask | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [preview, setPreview] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);
  const cancelled = useRef(false), alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; cancelled.current = true; }; }, []);
  async function download(show: false | "image" | "audio") {
    if (busy) return;
    setBusy(true); setError(""); cancelled.current = false;
    try {
      let task = await api.begin(messageId);
      while (task.offset < task.total && !cancelled.current) {
        task = await api.step(task.id);
        if (alive.current) setProgress(task);
      }
      if (cancelled.current) return;
      const result = await api.export(messageId,task.id,show);
      if (alive.current && show) setPreview(result);
    } catch (failure) { if (alive.current) setError(String(failure)); }
    finally { if (alive.current) setBusy(false); }
  }
  return <div>
    <button disabled={busy} onClick={() => void download(false)}>下载并另存为</button>
    {image && <button disabled={busy} onClick={() => void download("image")}>验证并预览图片</button>}
    {audio && <button disabled={busy} onClick={() => void download("audio")}>验证并播放语音</button>}
    {busy && <><progress value={progress?.offset ?? 0} max={progress?.total ?? 1} /><button onClick={() => { cancelled.current = true; }}>取消下载</button></>}
    {preview && audio && <audio controls src={preview} aria-label={name} onError={() => { setPreview(null); setError("语音损坏或格式不支持"); }} />}
    {preview && image && <button aria-label="查看大图" onClick={() => setExpanded(value => !value)}><img src={preview} alt={name} decoding="async" style={{ maxWidth: expanded ? "min(70vw, 100%)" : 180, maxHeight: expanded ? "60vh" : 140 }} onError={() => { setPreview(null); setError("图片损坏或格式不支持"); }} onLoad={event => {
      if (event.currentTarget.naturalWidth * event.currentTarget.naturalHeight > 40_000_000) { setPreview(null); setError("图片尺寸过大，请另存为后查看"); }
    }} /></button>}
    {preview && <button onClick={() => setPreview(null)}>关闭预览</button>}
    {error && <p role="alert">{error}</p>}
  </div>;
}
