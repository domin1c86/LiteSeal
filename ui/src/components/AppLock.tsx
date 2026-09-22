import { useEffect, useState } from "react";
export default function AppLock({ children }: { children: React.ReactNode }) {
  const [locked, setLocked] = useState(true);
  const [loading, setLoading] = useState(true);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    const lock = () => { setPassword(""); setLocked(true); };
    const refresh = () => { void window.desktop.app_lock_state({}).then(value => { if (active) { setLocked(value); setLoading(false); } }).catch(failure => { if (active) setError(String(failure)); }); };
    refresh(); const timer = setInterval(refresh, 500);
    window.addEventListener("liteseal-app-locked", lock);
    return () => { active = false; clearInterval(timer); window.removeEventListener("liteseal-app-locked", lock); };
  }, []);
  if (loading) return <p role="status">正在读取应用锁…{error}</p>;
  if (!locked) return <>{children}</>;
  return <main style={{ maxWidth: 440, margin: "15vh auto", padding: 24 }}>
    <h1>LiteSeal 已锁定</h1><p>请输入当前 Windows 账号密码（不是 Windows Hello PIN）。锁屏、空闲 5 分钟或重启后需要再次验证。</p>
    <form onSubmit={async event => {
      event.preventDefault(); if (busy) return; setBusy(true); setError("");
      const secret = password; setPassword("");
      try { await window.desktop.unlock_app({ password: secret }); setLocked(false); }
      catch (failure) { setError(String(failure)); } finally { setBusy(false); }
    }}><input type="password" aria-label="Windows 账号密码" autoComplete="off" value={password} disabled={busy} onChange={event => setPassword(event.target.value)} autoFocus />
    <button disabled={busy || !password}>解锁</button></form>
    <p>应用锁保护聊天界面；不等于整个 SQLite 数据库加密。</p>
    {error && <p role="alert">{error}</p>}
  </main>;
}
