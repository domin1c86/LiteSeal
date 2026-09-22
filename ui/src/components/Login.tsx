import { useEffect, useState } from "react";
import { useDesktop, validateInvite } from "../hooks/useDesktop";
import type { Identity, RegisterResult } from "../types";

interface LoginProps {
  onLogin: (result: RegisterResult & { serverUrl: string; publicKey: number[]; ed25519Pk: number[] }) => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [inviteCode, setInviteCode] = useState("");
  const [inviteCheck, setInviteCheck] = useState<{ key: string; valid: boolean; error?: string } | null>(null);
  const [inviteRetry, setInviteRetry] = useState(0);
  const [mode, setMode] = useState<"login" | "register">("login");
  const [serverUrl, setServerUrl] = useState("http://localhost:3000");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { register, login, prepareIdentity, saveSession } = useDesktop();

  const registering = mode === "register";
  const validUrl = isServerUrl(serverUrl);
  const validPassword = Array.from(password).length >= 8;
  const inviteKey = JSON.stringify([serverUrl.trim(), inviteCode.trim()]);
  const currentInvite = inviteCheck?.key === inviteKey ? inviteCheck : null;
  const inviteState: FieldState = !inviteCode.trim() ? "empty"
    : !validUrl ? "invalid"
    : !currentInvite ? "checking"
    : currentInvite.valid ? "valid" : "invalid";
  const canSubmit = validUrl && !!username.trim() && (registering
    ? validPassword && confirmPassword === password && inviteState === "valid"
    : password.length > 0);

  useEffect(() => {
    if (!registering || !validUrl || !inviteCode.trim()) return;
    let active = true;
    const timer = setTimeout(() => {
      validateInvite(serverUrl.trim(), inviteCode.trim()).then(
        (valid) => { if (active) setInviteCheck({ key: inviteKey, valid }); },
        (err) => { if (active) setInviteCheck({ key: inviteKey, valid: false, error: String(err) }); }
      );
    }, 400);
    return () => { active = false; clearTimeout(timer); };
  }, [registering, validUrl, serverUrl, inviteCode, inviteKey, inviteRetry]);

  function switchMode(next: "login" | "register") {
    if (next === mode) return;
    setMode(next);
    setError(null);
    setConfirmPassword("");
    setInviteCheck(null);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (loading || !canSubmit) return;

    setLoading(true);
    setError(null);

    try {
      // Reuse the saved keypair + device on login so contacts keep a stable
      // public key for us; fresh keys only for register or first login here.
      // Rust holds the secret halves; only public keys reach this page.
      let identity: Identity;
      try { identity = await prepareIdentity(); }
      catch (error) { throw new Error(`无法读取原有密钥，请先恢复密钥文件，避免覆盖历史：${String(error)}`); }
      let savedDeviceId: string | undefined;
      if (identity.saved) {
        if (mode === "register") throw new Error("本机已有聊天身份，请登录原账号；注册其他账号请使用独立 Windows 用户环境。");
        if ((identity.server_url || "http://localhost:3000").replace(/\/+$/, "") !== serverUrl.trim().replace(/\/+$/, "")) {
          throw new Error("当前密钥属于另一服务器，请使用原服务器地址登录。");
        }
        savedDeviceId = identity.device_id || undefined;
      }

      let result: RegisterResult;
      if (mode === "register") {
        result = await register(username.trim(), password, serverUrl, identity.public_key, identity.ed25519_pk, inviteCode.trim());
      } else {
        try {
          result = await login(username.trim(), password, serverUrl, identity.public_key, identity.ed25519_pk, savedDeviceId);
        } catch (err) {
          if (savedDeviceId && String(err).includes("403")) {
            throw new Error("原设备已被撤销或账号不匹配。已保留原密钥，请确认账号或恢复设备；不会自动覆盖旧身份。");
          }
          throw err;
        }
      }

      if (identity.saved && result.user_id !== identity.user_id) throw new Error("账号与本机历史不匹配，原密钥未修改。");
      const token = result.access_token ?? result.token;
      const deviceId = result.device_id ?? "";
      await saveSession({
        userId: result.user_id,
        token,
        refreshToken: result.refresh_token ?? "",
        deviceId,
        serverUrl,
      });
      onLogin({
        ...result,
        token,
        serverUrl,
        publicKey: identity.public_key,
        ed25519Pk: identity.ed25519_pk,
      });
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>
          liteseal<span style={styles.titleCursor}>▌</span>
        </h1>
        <p style={styles.subtitle}>end-to-end encrypted messaging</p>
        <p style={{ color: "var(--text-muted)", fontSize: 12 }}>普通退出保留本机密钥。同账号登录可继续读取历史；丢失密钥后，仅凭账号密码无法恢复旧消息。</p>
        <div style={styles.segmented}>
          <button
            type="button"
            style={{ ...styles.segment, ...(mode === "login" ? styles.segmentActive : {}) }}
            disabled={loading}
            onClick={() => switchMode("login")}
          >
            Login
          </button>
          <button
            type="button"
            style={{ ...styles.segment, ...(mode === "register" ? styles.segmentActive : {}) }}
            disabled={loading}
            onClick={() => switchMode("register")}
          >
            Register
          </button>
        </div>
        <form onSubmit={handleSubmit} style={styles.form}>
          <ValidationField label="Server URL" value={serverUrl} onChange={(value) => { setServerUrl(value); setInviteCheck(null); }}
            disabled={loading} showStatus={registering}
            state={fieldState(serverUrl, validUrl)}
            hint={validUrl ? "地址格式有效（不代表已连接）" : "请输入 http:// 或 https:// 开头的服务器地址"} />
          <ValidationField label="Username" value={username} onChange={setUsername}
            disabled={loading} showStatus={registering} autoComplete="username"
            state={fieldState(username, !!username.trim())}
            hint={username.trim() ? "格式有效，注册时检查用户名是否已占用" : "请输入非空用户名"} />
          {registering && <ValidationField label="Invite code" value={inviteCode} onChange={(value) => { setInviteCode(value); setInviteCheck(null); }}
            disabled={loading} showStatus state={inviteState}
            hint={inviteState === "valid" ? "邀请码有效"
              : inviteState === "checking" ? "正在向服务器验证…"
              : currentInvite?.error ?? (inviteState === "invalid"
                ? validUrl ? "邀请码无效，请检查后重试" : "请先填写有效的服务器地址"
                : "请输入管理员提供的邀请码（区分大小写）")} />}
          {registering && currentInvite?.error && <button type="button" disabled={loading}
            style={styles.segment} onClick={() => { setInviteCheck(null); setInviteRetry((n) => n + 1); }}>
            重新验证邀请码
          </button>}
          <ValidationField label="Password" type="password" value={password} onChange={setPassword}
            disabled={loading} showStatus={registering}
            autoComplete={registering ? "new-password" : "current-password"}
            state={fieldState(password, validPassword)}
            hint={validPassword ? "密码符合要求：至少 8 个字符" : "密码至少需要 8 个字符"} />
          {registering && <ValidationField label="Confirm password" type="password"
            value={confirmPassword} onChange={setConfirmPassword} disabled={loading} showStatus
            autoComplete="new-password"
            state={fieldState(confirmPassword, validPassword && confirmPassword === password)}
            hint={!confirmPassword ? "请再次输入密码"
              : confirmPassword !== password ? "两次输入的密码不一致"
              : !validPassword ? "请先让密码满足至少 8 个字符的要求" : "两次输入的密码一致"} />}
          <button
            className="primary-button"
            type="submit"
            disabled={loading || !canSubmit}
            style={styles.button}
          >
            {loading ? "Connecting..." : mode === "register" ? "Register & Connect" : "Login"}
          </button>
          {error && <p role="alert" style={styles.error}>{error}</p>}
        </form>
      </div>
    </div>
  );
}

type FieldState = "empty" | "checking" | "valid" | "invalid";

function fieldState(value: string, valid: boolean): FieldState {
  return !value ? "empty" : valid ? "valid" : "invalid";
}

function isServerUrl(value: string): boolean {
  try {
    const url = new URL(value.trim());
    return ["http:", "https:"].includes(url.protocol) && !!url.hostname;
  } catch { return false; }
}

function ValidationField({ label, value, onChange, state, hint, showStatus, disabled,
  type = "text", autoComplete }: {
  label: string; value: string; onChange: (value: string) => void;
  state: FieldState; hint: string; showStatus: boolean; disabled: boolean;
  type?: string; autoComplete?: string;
}) {
  const id = `auth-${label.toLowerCase().replace(/ /g, "-")}`;
  const color = state === "valid" ? "var(--ok)" : state === "invalid"
    ? "var(--danger)" : state === "checking" ? "var(--warn)" : "var(--text-subtle)";
  return <div style={{ textAlign: "left" }}>
    <label htmlFor={id} style={styles.label}>{label}</label>
    <div style={styles.fieldRow}>
      <input id={id} className="form-input" type={type} placeholder={label} value={value}
        onChange={(e) => onChange(e.target.value)} disabled={disabled} autoComplete={autoComplete}
        aria-invalid={showStatus && state === "invalid"}
        aria-describedby={showStatus ? `${id}-hint` : undefined}
        style={{ ...styles.input, width: "100%", minWidth: 0 }} />
      {showStatus && <span data-status={state} aria-hidden="true" style={{
        ...styles.lamp, backgroundColor: color,
      }} />}
    </div>
    {showStatus && <p id={`${id}-hint`} aria-live="polite" style={{ ...styles.hint, color }}>
      {state === "valid" ? "✓ " : state === "invalid" ? "! " : ""}{hint}
    </p>}
  </div>;
}

const styles: Record<string, React.CSSProperties> = {
  label: { display: "block", fontSize: "12px", color: "var(--text-muted)", marginBottom: "6px" },
  fieldRow: { display: "flex", alignItems: "center", gap: "10px" },
  lamp: { width: "9px", height: "9px", borderRadius: "50%", flexShrink: 0 },
  hint: { fontSize: "11px", lineHeight: 1.5, margin: "5px 0 0", overflowWrap: "anywhere" },
  container: {
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "center",
    minHeight: "100vh",
    padding: "24px",
    backgroundColor: "var(--workspace-bg)",
  },
  card: {
    margin: "auto 0",
    padding: "36px",
    borderRadius: "var(--radius-lg)",
    backgroundColor: "var(--sidebar-bg)",
    border: "1px solid var(--border)",
    boxShadow: "var(--shadow-modal)",
    width: "min(440px, 100%)",
    textAlign: "center",
  },
  title: {
    margin: 0,
    fontFamily: "var(--font-mono)",
    fontSize: "22px",
    fontWeight: 600,
    letterSpacing: "-0.01em",
    color: "var(--text)",
  },
  titleCursor: {
    color: "var(--text-subtle)",
    fontWeight: 400,
  },
  subtitle: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    marginTop: "8px",
    marginBottom: "28px",
    fontSize: "12px",
  },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: "12px",
  },
  segmented: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: "6px",
    padding: "4px",
    borderRadius: "var(--radius-md)",
    border: "1px solid var(--border)",
    backgroundColor: "var(--surface-muted)",
    marginBottom: "18px",
  },
  segment: {
    border: "1px solid transparent",
    borderRadius: "var(--radius-sm)",
    padding: "8px 10px",
    backgroundColor: "transparent",
    color: "var(--text-muted)",
    cursor: "pointer",
    fontSize: "13px",
    fontWeight: 600,
  },
  segmentActive: {
    backgroundColor: "var(--surface-active)",
    color: "var(--text)",
  },
  input: {
    padding: "11px 13px",
    borderRadius: "var(--radius-md)",
    border: "1px solid var(--border-strong)",
    backgroundColor: "var(--surface-muted)",
    color: "var(--text)",
    fontSize: "14px",
    outline: "none",
  },
  button: {
    padding: "11px",
    borderRadius: "var(--radius-md)",
    border: "none",
    backgroundColor: "var(--accent)",
    color: "var(--accent-contrast)",
    fontSize: "14px",
    cursor: "pointer",
    fontWeight: 600,
  },
  error: {
    fontFamily: "var(--font-mono)",
    color: "var(--danger)",
    fontSize: "12px",
    margin: 0,
  },
};
