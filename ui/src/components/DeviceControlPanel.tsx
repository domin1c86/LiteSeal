import { useEffect, useRef, useState } from "react";
import PanelDialog from "./PanelDialog";
import RootMessagingPanel from "./RootMessagingPanel";
import { getDesktopApi } from "../lib/desktopApi";
import type { DeviceControlSnapshot, DeviceRequest, DeviceTask, DeviceTaskPhase, DeviceProgress } from "../../../electron/contracts";

const phases: Record<DeviceTaskPhase, string> = {
  draft: "待提交", awaiting_root_confirmation: "待核对原设备", awaiting_challenge: "等待原设备验证",
  awaiting_authorization: "等待授权", prepared: "待发送", cancelling: "正在确认取消", conflict: "版本冲突",
  complete: "已完成", cancelled: "已取消", expired: "已过期", revoked: "已撤销",
};
const kinds: Record<DeviceTask["kind"], string> = { join: "加入", challenge: "验证新设备", grant: "授权", revoke: "撤销授权" };
const conditions: Record<DeviceProgress["condition"], string> = {
  advanced: "任务已推进", waiting: "等待另一台设备完成验证，请稍后刷新", needs_password: "请在加入设备完成账号验证",
  needs_confirmation: "请在加入设备核对原设备指纹", syncing: "正在校验设备目录，请继续查询",
  retry: "连接未完成，可继续原任务重试", session_required: "登录会话已失效，请在原设备重新登录",
  unsupported: "服务器尚未启用设备授权", conflict: "设备目录已变化，请取消原任务后重新核对",
  terminal: "任务状态已确认",
  unsigned_abandoned: "未签署的本机申请已结束；未确认远端删除，可能需要等待原申请过期",
};
const terminal = (task: DeviceTask) => ["complete", "cancelled", "expired", "revoked"].includes(task.phase);

export default function DeviceControlPanel({ onClose }: { onClose: () => void }) {
  const [showMessaging,setShowMessaging]=useState(false);
  const [snapshot, setSnapshot] = useState<DeviceControlSnapshot | null>(null);
  const [selected, setSelected] = useState<DeviceRequest | null>(null);
  const [confirmed, setConfirmed] = useState(false), [revokeConfirmed, setRevokeConfirmed] = useState(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [status, setStatus] = useState("");
  const live = useRef(false), inFlight = useRef(false), epoch = useRef(0);
  const paused = useRef(false), authorizedFingerprint = useRef<string | null>(null);

  async function run(action?: () => Promise<string | void>) {
    if (!live.current || inFlight.current || paused.current) return;
    inFlight.current = true; const generation = epoch.current; setBusy(true); setError("");
    const current = () => live.current && generation === epoch.current;
    try {
      const message = await action?.();
      if (!current()) return;
      if (message) setStatus(message);
      const view = await getDesktopApi().get_device_control({});
      if (!current()) return;
      setSnapshot(view);
      const fingerprint = view.authorized?.combined_fingerprint ?? null;
      if (fingerprint !== authorizedFingerprint.current) { authorizedFingerprint.current = fingerprint; setRevokeConfirmed(false); }
      setSelected(previous => {
        const next = previous && view.requests.find(row => row.request_id === previous.request_id);
        // A changed target or stage always needs another explicit confirmation.
        if (!next || next.combined_fingerprint !== previous!.combined_fingerprint || next.phase !== previous!.phase) {
          setConfirmed(false); return null;
        }
        return previous;
      });
    } catch (failure) { if (current()) setError(String(failure)); }
    finally { inFlight.current = false; if (current()) setBusy(false); }
  }
  useEffect(() => {
    live.current = true;
    const locked = () => { epoch.current++; paused.current = true; setSnapshot(null); setSelected(null); setConfirmed(false); setRevokeConfirmed(false); setStatus(""); setBusy(false); setError("设备授权已暂停，请解锁后重新打开"); };
    window.addEventListener("liteseal-app-locked", locked);
    window.addEventListener("liteseal-device-paused", locked);
    void run();
    const timer = setInterval(() => void run(), 5000);
    return () => { live.current = false; epoch.current++; clearInterval(timer); window.removeEventListener("liteseal-app-locked", locked); window.removeEventListener("liteseal-device-paused", locked); };
  }, []);

  async function inspect(requestId: string) {
    await run(async () => {
      const generation = epoch.current;
      const view = await getDesktopApi().inspect_device_request({ requestId });
      if (live.current && generation === epoch.current) { setSelected(view); setConfirmed(false); }
    });
  }
  async function prepare(grant: boolean) {
    if (!selected || !confirmed) return;
    const request = selected; setConfirmed(false);
    await run(async () => {
      const args = { requestId: request.request_id, confirmedFingerprint: request.combined_fingerprint };
      const task = grant ? await getDesktopApi().prepare_device_grant(args) : await getDesktopApi().prepare_device_challenge(args);
      return task ? "已保存任务，请在任务列表继续发送" : "设备目录仍在校验，请刷新后重新核对";
    });
  }
  const pending = snapshot?.tasks.some(task => !terminal(task));
  return <PanelDialog label="可信设备授权" wide busy={busy} onClose={onClose}>
    <p>在原设备核对另一台 Windows 的指纹后批准授权。当前仅管理授权记录，第二台设备的聊天激活尚未开放。</p>
    <button disabled={busy} onClick={() => void run()}>刷新设备状态</button>
    {snapshot && <>
      <h3>原设备指纹</h3><code>{snapshot.root_fingerprint}</code>
      <p>请在加入设备核对完整指纹。设备名称只供识别，不能替代指纹验证。</p>
      {!snapshot.supported ? <p role="status">服务器尚未启用设备授权</p> : <>
        {snapshot.syncing && <p role="status">正在校验设备目录，请刷新后继续</p>}
        <h3>加入请求</h3>
        {snapshot.requests.filter(row => !["authorized", "cancelled", "expired", "revoked"].includes(row.phase)).map(request => <div key={request.request_id}>
          <span>{request.device_name} · {request.device_id}</span>
          <button disabled={busy || snapshot.syncing} onClick={() => void inspect(request.request_id)}>核对设备</button>
        </div>)}
        {!snapshot.requests.some(row => !["authorized", "cancelled", "expired", "revoked"].includes(row.phase)) && <p>没有待处理的加入请求</p>}
        {selected && <section aria-label="设备指纹确认">
          <h3>{selected.device_name}</h3>
          <p>加密密钥指纹</p><code>{selected.encryption_fingerprint}</code>
          <p>签名密钥指纹</p><code>{selected.signing_fingerprint}</code>
          <label><input type="checkbox" disabled={busy} checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />我已在另一台设备核对这两个完整指纹</label>
          {selected.phase === "ready" && <button disabled={busy || !confirmed || pending || snapshot.syncing} onClick={() => void prepare(false)}>验证新设备</button>}
          {selected.phase === "proved" && <button disabled={busy || !confirmed || pending || snapshot.syncing} onClick={() => void prepare(true)}>批准设备授权</button>}
          {!["ready", "proved"].includes(selected.phase) && <p>等待加入设备完成验证后刷新</p>}
        </section>}
        <h3>已授权设备</h3>
        {snapshot.authorized ? <section>
          <p>{snapshot.authorized.device_id} · 已授权，聊天激活尚未开放</p>
          <p>加密密钥指纹</p><code>{snapshot.authorized.encryption_fingerprint}</code>
          <p>签名密钥指纹</p><code>{snapshot.authorized.signing_fingerprint}</code>
          <label><input type="checkbox" checked={revokeConfirmed} disabled={busy} onChange={event => setRevokeConfirmed(event.target.checked)} />确认撤销此设备的授权</label>
          <button disabled={busy || !revokeConfirmed || pending || snapshot.syncing} onClick={() => {
            const confirmedFingerprint = snapshot.authorized!.combined_fingerprint;
            setRevokeConfirmed(false); void run(async () => { const task = await getDesktopApi().prepare_device_revoke({ confirmedFingerprint }); return task ? "已保存撤销任务，请继续发送" : "请等待设备目录校验后重试"; });
          }}>准备撤销授权</button>
        </section> : <p>{snapshot.syncing ? "设备目录校验中" : "没有已授权的第二台设备"}</p>}
      </>}
      <h3>设备任务</h3>
      {snapshot.tasks.map(task => <div key={task.id}>
        <span>{kinds[task.kind]} · {phases[task.phase]}</span>
        {!terminal(task) && <>
          <button disabled={busy || task.phase === "conflict" || !snapshot.supported} onClick={() => void run(async () => conditions[(await getDesktopApi().device_task_step({ id: task.id })).condition])}>{task.phase === "cancelling" ? "确认取消结果" : "继续原任务"}</button>
          <button disabled={busy || task.phase === "cancelling"} onClick={() => void run(async () => { await getDesktopApi().cancel_device_task({ id: task.id }); return "取消请求已保存，请继续确认取消结果"; })}>取消设备任务</button>
        </>}
        {terminal(task) && <button disabled={busy} onClick={() => void run(() => getDesktopApi().discard_device_task({ id: task.id }))}>清除已结束任务</button>}
      </div>)}
      {!snapshot.tasks.length && <p>没有本机设备任务</p>}
      {snapshot.supported&&!snapshot.syncing&&(!showMessaging?<button disabled={paused.current} onClick={()=>setShowMessaging(true)}>管理原设备协议切换</button>:<RootMessagingPanel onClose={()=>setShowMessaging(false)}/>)}
    </>}
    {status && <p role="status">{status}</p>}
    {error && <p role="alert">{error}</p>}
  </PanelDialog>;
}
