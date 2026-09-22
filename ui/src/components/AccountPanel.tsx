import { useEffect, useState } from "react";
import type { Contact } from "../types";
import type { CommandMap } from "../../../electron/contracts";

export default function AccountPanel({ contacts, onClose, onContactsChanged, onLogout }: {
  contacts: Contact[]; onClose: () => void; onContactsChanged: () => void; onLogout: () => void;
}) {
  const [requests, setRequests] = useState<CommandMap["list_contact_requests"]["result"]>([]);
  const [sessions, setSessions] = useState<CommandMap["list_account_sessions"]["result"]>([]);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [update, setUpdate] = useState<CommandMap["check_app_update"]["result"] | null>(null);
  const [windowsPassword, setWindowsPassword] = useState("");
  const [lockStatus, setLockStatus] = useState("");
  async function refresh() {
    const [policies, active] = await Promise.all([window.desktop.list_contact_requests({}), window.desktop.list_account_sessions({})]);
    setRequests(policies); setSessions(active);
  }
  useEffect(() => { void refresh().catch(failure => setError(String(failure))); }, []);
  async function policy(peerId: string, status: CommandMap["set_contact_policy"]["args"]["status"]) {
    setBusy(true); setError("");
    try { await window.desktop.set_contact_policy({ peerId, status }); await refresh(); onContactsChanged(); }
    catch (failure) { setError(String(failure)); } finally { setBusy(false); }
  }
  const peers = [...requests, ...contacts.filter(peer => !requests.some(row => row.peer_id === peer.user_id)).map(peer => ({ peer_id: peer.user_id, username: peer.username, status: "未设置" }))];
  return <section role="dialog" aria-modal="true" aria-label="账号与消息请求" style={{ position: "fixed", inset: "8%", zIndex: 25, background: "var(--surface)", color: "var(--text)", padding: 24, overflow: "auto" }}>
    <button onClick={onClose} disabled={busy}>关闭</button><button disabled={busy} onClick={() => void refresh().catch(failure => setError(String(failure)))}>刷新</button>
    <h2>消息请求与拉黑</h2>
    <p>接受前只保存请求身份，消息正文留在发送方，不进入正常通知和未读。已有联系人升级后也需要允许接收。请核对指纹。</p>
    {peers.map(peer => <div key={peer.peer_id}><span>{peer.username} · {peer.peer_id.slice(0, 8)} · {peer.status}</span>
      <button disabled={busy || peer.status === "accepted"} onClick={() => void policy(peer.peer_id, "accepted")}>接受 / 允许接收</button>
      <button disabled={busy || peer.status === "rejected"} onClick={() => void policy(peer.peer_id, "rejected")}>拒绝</button>
      <button disabled={busy} onClick={() => void policy(peer.peer_id, peer.status === "blocked" ? "pending" : "blocked")}>{peer.status === "blocked" ? "解除拉黑（待接受）" : "拉黑"}</button>
    </div>)}
    <p>拒绝或拉黑后停止新消息投递。此前已进入离线队列的密文暂时隔离以保留消息链，重新接受后才恢复；解除拉黑本身不会恢复投递。请求上限为 100 个，拒绝后移出待处理计数。</p>
    <h2>账号会话</h2>
    {sessions.map(session => <p key={session.id}>{session.current ? "当前会话 · " : ""}{session.name} · 设备 {session.device_id} · {session.revoked ? "已撤销" : `访问令牌到期 ${session.expires_at}`}</p>)}
    <button disabled={busy} onClick={async () => {
      if (!window.confirm("退出此账号的全部会话？本机密钥与历史会保留。")) return;
      setBusy(true); setError("");
      try { await window.desktop.logout_all_sessions({}); onLogout(); }
      catch (failure) { setError(String(failure)); setBusy(false); }
    }}>退出全部会话</button>
    <h2>应用锁</h2>
    <p>先验证当前 Windows 账号密码再启用；Windows Hello PIN 不适用于此验证。启用后锁屏、空闲 5 分钟和重启均需解锁。</p>
    <input type="password" autoComplete="off" aria-label="设置应用锁的 Windows 账号密码" value={windowsPassword} onChange={event => setWindowsPassword(event.target.value)} />
    {[true, false].map(enabled => <button key={String(enabled)} disabled={busy || !windowsPassword} onClick={async () => {
      setBusy(true); setError(""); const password = windowsPassword; setWindowsPassword("");
      try { await window.desktop.configure_app_lock({ enabled, password }); setLockStatus(enabled ? "应用锁已启用" : "应用锁已关闭"); }
      catch (failure) { setError(String(failure)); } finally { setBusy(false); }
    }}>{enabled ? "验证并启用应用锁" : "验证并关闭应用锁"}</button>)}
    <p role="status">{lockStatus}</p>
    <h2>版本与升级</h2>
    <button disabled={busy} onClick={async () => {
      setBusy(true); setError(""); try { setUpdate(await window.desktop.check_app_update({})); } catch (failure) { setError(String(failure)); } finally { setBusy(false); }
    }}>检查正式版本</button>
    {update && <p>当前 {update.current} · 最新 {update.latest} · {update.available ? "有可用更新" : "无需更新"} <button onClick={() => { void window.desktop.open_app_release({}).catch(failure => setError(String(failure))); }}>打开此版本发布页</button></p>}
    <p>升级前完全退出应用并备份本机身份和数据库，核对安装包签名。安装不自动执行；升级失败可按升级指南恢复原版本和对应数据快照。</p>
    {error && <p role="alert">{error}</p>}
  </section>;
}
