import { useEffect, useRef, useState } from "react";
import PanelDialog from "./PanelDialog";
import { getDesktopApi } from "../lib/desktopApi";
import type { BackupJob } from "../../../electron/contracts";
import "./backup.css";

export default function BackupPanel({ onClose, canExport = true }: { onClose: () => void; canExport?: boolean }) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [includeAttachments, setIncludeAttachments] = useState(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [job, setJob] = useState<BackupJob | null>(null);
  const mounted = useRef(false), jobId = useRef<string | null>(null), handedOff = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; if (jobId.current && !handedOff.current) void getDesktopApi().cancel_backup_job({ id: jobId.current }).catch(() => {}); };
  }, []);
  useEffect(() => {
    if (!job || job.state !== "running") return;
    let active = true;
    const poll = async () => { try { const next = await getDesktopApi().get_backup_job({ id: job.id }); if (active) { setJob(next); if (next.error) setError(next.error); } } catch (failure) { if (active) setError(String(failure)); } };
    void poll(); const timer = setInterval(() => void poll(), 400);
    return () => { active = false; clearInterval(timer); };
  }, [job?.id, job?.state]);
  const valid = new TextEncoder().encode(password).length >= 12 && new TextEncoder().encode(password).length <= 1024;
  const running = job?.state === "running";
  async function start(exporting: boolean) {
    if (!valid || exporting && password !== confirmation) return;
    const secret = password; setPassword(""); setConfirmation(""); setBusy(true); setError(""); setJob(null);
    try {
      const id = exporting ? await getDesktopApi().start_backup_export({ password: secret, includeAttachments }) : await getDesktopApi().start_backup_restore({ password: secret });
      if (!mounted.current) { if (id) await getDesktopApi().cancel_backup_job({ id }); return; }
      if (id) { jobId.current = id; const view = await getDesktopApi().get_backup_job({ id }); if (mounted.current) { setJob(view); if (view.error) setError(view.error); } }
    } catch (failure) { if (mounted.current) setError(String(failure)); } finally { if (mounted.current) setBusy(false); }
  }
  return <PanelDialog label="备份与隔离恢复" wide busy={busy || !!running} onClose={onClose}>
    <p>使用独立口令保护身份密钥、联系人、历史和本机设置。忘记备份口令无法恢复。</p>
    <p>不包含登录令牌、待发送任务或定时任务。恢复只打开离线档案，不替换当前数据，也不接管原设备。</p>
    <div className="backup-fields">
      <label>独立备份口令（至少 12 字节）<input type="password" autoComplete="off" aria-label="独立备份口令" value={password} disabled={busy || running} onChange={e => setPassword(e.target.value)} /></label>
      {canExport && <><label>确认备份口令<input type="password" autoComplete="off" aria-label="确认备份口令" value={confirmation} disabled={busy || running} onChange={e => setConfirmation(e.target.value)} /></label>
      <label><input type="checkbox" checked={includeAttachments} disabled={busy || running} onChange={e => setIncludeAttachments(e.target.checked)} />包含已完整下载并验证的附件</label></>}
    </div>
    <p>未包含或未完整下载的附件不会自动补下载；远端过期后可能无法取回。密钥派生需要 256 MiB 可用内存。</p>
    <div className="backup-actions">
      {canExport && <button disabled={busy || running || !valid || password !== confirmation} onClick={() => void start(true)}>创建加密备份</button>}
      <button disabled={busy || running || !valid} onClick={() => void start(false)}>选择备份并隔离恢复</button>
      {running && <button onClick={async () => { try { await getDesktopApi().cancel_backup_job({ id: job!.id }); setJob(await getDesktopApi().get_backup_job({ id: job!.id })); } catch (failure) { setError(String(failure)); } }}>取消任务</button>}
    </div>
    {job && <div role="status" className="backup-status">
      <p>{({ running: "正在处理", completed: "处理完成", failed: "处理失败", cancelled: "任务已取消" })[job.state]}</p>
      {running && <progress max={job.total || 1} value={job.completed} />}
      {job.summary && <p>{job.summary.messages} 条单聊历史 · {job.summary.groups} 个群 · {job.summary.attachments} 个附件；{job.summary.missing_attachments} 个附件未包含，{job.summary.skipped_attachments} 个缓存或任务跳过。</p>}
      {job.restorable && <button disabled={busy} onClick={async () => { setBusy(true); setError(""); try { await getDesktopApi().open_backup_archive({ id: job.id }); handedOff.current = true; onClose(); } catch (failure) { setError(String(failure)); } finally { if (mounted.current) setBusy(false); } }}>打开离线只读档案</button>}
    </div>}
    {error && <p role="alert">{error}</p>}
  </PanelDialog>;
}
