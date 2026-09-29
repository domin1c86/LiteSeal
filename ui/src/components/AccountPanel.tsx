import PanelDialog from "./PanelDialog";
import BackupPanel from "./BackupPanel";
import { getDesktopApi } from "../lib/desktopApi";
import { useEffect, useState } from "react";
import type { Contact } from "../types";
import type { CommandMap } from "../../../electron/contracts";

export default function AccountPanel({ userId, contacts, typingEnabled, onTypingEnabledChange, onClose, onContactsChanged, onLogout }: {
  userId: string; contacts: Contact[]; typingEnabled: boolean; onTypingEnabledChange: (enabled: boolean) => void; onClose: () => void; onContactsChanged: () => void; onLogout: () => void;
}) {
  const [requests, setRequests] = useState<CommandMap["list_contact_requests"]["result"]>([]);
  const [showBackup, setShowBackup] = useState(false);
  const [sessions, setSessions] = useState<CommandMap["list_account_sessions"]["result"]>([]);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [update, setUpdate] = useState<CommandMap["check_app_update"]["result"] | null>(null);
  const [profileName, setProfileName] = useState("");
  const [profileAvatar, setProfileAvatar] = useState<string | null>(null);
  const [accountName, setAccountName] = useState("");
  const [windowsPassword, setWindowsPassword] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [lockStatus, setLockStatus] = useState("");
  const [readReceiptsEnabled, setReadReceiptsEnabled] = useState(false);
  async function refresh() {
    setReadReceiptsEnabled(await getDesktopApi().get_read_receipt_enabled({}));
    onTypingEnabledChange(await getDesktopApi().get_typing_enabled({}));
    const [policies, active, profile] = await Promise.all([getDesktopApi().list_contact_requests({}), getDesktopApi().list_account_sessions({}), getDesktopApi().get_public_profile({ userId })]);
    setRequests(policies); setSessions(active);
    setProfileName(profile.display_name); setProfileAvatar(profile.avatar_png); setAccountName(profile.username);
  }
  useEffect(() => { void refresh().catch(failure => setError(String(failure))); }, []);
  async function policy(peerId: string, status: CommandMap["set_contact_policy"]["args"]["status"]) {
    setBusy(true); setError("");
    try { await getDesktopApi().set_contact_policy({ peerId, status }); await refresh(); onContactsChanged(); }
    catch (failure) { setError(String(failure)); } finally { setBusy(false); }
  }
  const peers = [...requests, ...contacts.filter(peer => !requests.some(row => row.peer_id === peer.user_id)).map(peer => ({ peer_id: peer.user_id, username: peer.username, status: "未设置" }))];
  return <PanelDialog label="账号与消息请求" wide busy={busy} onClose={onClose}>
    <h2>备份与恢复</h2>
    <button disabled={busy} onClick={() => setShowBackup(true)}>备份与隔离恢复</button>
    {showBackup && <BackupPanel onClose={() => setShowBackup(false)} />}
    <button onClick={onClose} disabled={busy}>关闭</button><button disabled={busy} onClick={() => void refresh().catch(failure => setError(String(failure)))}>刷新</button>
    <h2>公开资料</h2>
    <p>账号名 {accountName || "读取中…"} 和身份密钥保持不变。公开昵称与头像可被其他已登录用户看到，不作为验签依据。</p>
    <label>公开昵称 <input maxLength={40} value={profileName} disabled={busy} onChange={event => setProfileName(event.target.value)} /></label>
    {profileAvatar && <img src={`data:image/png;base64,${profileAvatar}`} alt="当前公开头像" style={{ display: "block", width: 64, height: 64, objectFit: "cover" }} />}
    <button disabled={busy} onClick={async () => {
      setBusy(true); setError(""); try { const avatar = await getDesktopApi().choose_profile_avatar({}); if (avatar) setProfileAvatar(avatar); }
      catch (failure) { setError(String(failure)); } finally { setBusy(false); }
    }}>选择头像</button>
    <button disabled={busy || !profileAvatar} onClick={() => setProfileAvatar(null)}>移除头像</button>
    <button disabled={busy} onClick={async () => {
      setBusy(true); setError("");
      try { const profile = await getDesktopApi().update_public_profile({ displayName: profileName.trim(), avatarPng: profileAvatar }); setProfileName(profile.display_name); setProfileAvatar(profile.avatar_png); }
      catch (failure) { setError(String(failure)); } finally { setBusy(false); }
    }}>保存公开资料</button>
    <h2>消息请求与拉黑</h2>
    <p>接受前只保存请求身份，消息正文留在发送方，不进入正常通知和未读。已有联系人升级后也需要允许接收。请核对指纹。</p>
    {peers.map(peer => <div key={peer.peer_id}><span>{peer.username} · {peer.peer_id.slice(0, 8)} · {peer.status}</span>
      <button disabled={busy || peer.status === "accepted"} onClick={() => void policy(peer.peer_id, "accepted")}>接受 / 允许接收</button>
      <button disabled={busy || peer.status === "rejected"} onClick={() => void policy(peer.peer_id, "rejected")}>拒绝</button>
      <button disabled={busy} onClick={() => void policy(peer.peer_id, peer.status === "blocked" ? "pending" : "blocked")}>{peer.status === "blocked" ? "解除拉黑（待接受）" : "拉黑"}</button>
    </div>)}
    <p>拒绝或拉黑后停止新消息投递。此前已进入离线队列的密文暂时隔离以保留消息链，重新接受后才恢复；解除拉黑本身不会恢复投递。请求上限为 100 个，拒绝后移出待处理计数。</p>
    <h2>账号会话</h2>
    <h3>阅读回执</h3>
    <p>默认关闭。启用后，当前窗口前台实际显示且首次标记已读的单聊消息会向发送者提交签名回执。关闭期间已读的消息不会在重新启用后补发；已经发出的回执无法撤回。设备接收确认仍独立于阅读回执。</p>
    <label><input type="checkbox" checked={readReceiptsEnabled} disabled={busy} onChange={async event => {
      const enabled = event.target.checked;
      setBusy(true); setError("");
      try { await getDesktopApi().set_read_receipt_enabled({ enabled }); setReadReceiptsEnabled(enabled); }
      catch (failure) { setError(String(failure)); }
      finally { setBusy(false); }
    }} /> 向联系人发送阅读回执</label>
    <h3>正在输入提示</h3>
    <p>默认关闭。启用后，仅在当前单聊实际输入时发送短暂状态；停止、失焦或断线后对方提示会消失，不写入聊天历史。</p>
    <label><input type="checkbox" checked={typingEnabled} disabled={busy} onChange={async event => {
      const enabled = event.target.checked;
      setBusy(true); setError("");
      try { await getDesktopApi().set_typing_enabled({ enabled }); onTypingEnabledChange(enabled); }
      catch (failure) { setError(String(failure)); }
      finally { setBusy(false); }
    }} /> 向联系人显示我正在输入</label>
    {sessions.map(session => <p key={session.id}>{session.current ? "当前会话 · " : ""}{session.name} · 设备 {session.device_id} · {session.revoked ? "已撤销" : `访问令牌到期 ${session.expires_at}`}</p>)}
    <button disabled={busy} onClick={async () => {
      if (!window.confirm("退出此账号的全部会话？本机密钥与历史会保留。")) return;
      setBusy(true); setError("");
      try { await getDesktopApi().logout_all_sessions({}); onLogout(); }
      catch (failure) { setError(String(failure)); setBusy(false); }
    }}>退出全部会话</button>
    <h3>修改账号密码</h3>
    <p>需要当前密码；成功后全部会话立即失效，本机会保留身份密钥和历史并返回登录。密码无法恢复丢失的设备密钥。</p>
    <input type="password" autoComplete="current-password" placeholder="当前账号密码" aria-label="当前账号密码" value={currentPassword} disabled={busy} onChange={event => setCurrentPassword(event.target.value)} />
    <input type="password" autoComplete="new-password" placeholder="新账号密码" aria-label="新账号密码" value={newPassword} disabled={busy} onChange={event => setNewPassword(event.target.value)} />
    <input type="password" autoComplete="new-password" placeholder="确认新账号密码" aria-label="确认新账号密码" value={confirmPassword} disabled={busy} onChange={event => setConfirmPassword(event.target.value)} />
    <button disabled={busy || !currentPassword || newPassword.length < 8 || newPassword !== confirmPassword} onClick={async () => {
      setBusy(true); setError("");
      try {
        await getDesktopApi().change_password({ currentPassword, newPassword });
        setCurrentPassword(""); setNewPassword(""); setConfirmPassword("");
        onLogout();
      } catch (failure) { setError(String(failure)); }
      finally { setBusy(false); }
    }}>验证并修改密码</button>
    <h2>应用锁</h2>
    <p>先验证当前 Windows 账号密码再启用；Windows Hello PIN 不适用于此验证。启用后锁屏、空闲 5 分钟和重启均需解锁。</p>
    <input type="password" autoComplete="off" placeholder="设置应用锁的 Windows 账号密码" aria-label="设置应用锁的 Windows 账号密码" value={windowsPassword} onChange={event => setWindowsPassword(event.target.value)} />
    {[true, false].map(enabled => <button key={String(enabled)} disabled={busy || !windowsPassword} onClick={async () => {
      setBusy(true); setError(""); const password = windowsPassword; setWindowsPassword("");
      try { await getDesktopApi().configure_app_lock({ enabled, password }); setLockStatus(enabled ? "应用锁已启用" : "应用锁已关闭"); }
      catch (failure) { setError(String(failure)); } finally { setBusy(false); }
    }}>{enabled ? "验证并启用应用锁" : "验证并关闭应用锁"}</button>)}
    <p role="status">{lockStatus}</p>
    <h2>版本与升级</h2>
    <button disabled={busy} onClick={async () => {
      setBusy(true); setError(""); try { setUpdate(await getDesktopApi().check_app_update({})); } catch (failure) { setError(String(failure)); } finally { setBusy(false); }
    }}>检查正式版本</button>
    {update && <p>当前 {update.current} · 最新 {update.latest} · {update.available ? "有可用更新" : "无需更新"} <button onClick={() => { void getDesktopApi().open_app_release({}).catch(failure => setError(String(failure))); }}>打开此版本发布页</button></p>}
    <p>升级前完全退出应用并备份本机身份和数据库，核对安装包签名。安装不自动执行；升级失败可按升级指南恢复原版本和对应数据快照。</p>
    {error && <p role="alert">{error}</p>}
  </PanelDialog>;
}
