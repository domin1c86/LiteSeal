import { useState } from "react";
import { useTauri } from "../hooks/useTauri";
import type { SessionView } from "../types";

interface LoginProps {
  onLogin: (session: SessionView) => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<"login" | "register">("login");
  const [inviteCode, setInviteCode] = useState("");
  const [replacementRequired, setReplacementRequired] = useState(false);
  const [serverUrl, setServerUrl] = useState("http://localhost:3000");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { register, login } = useTauri();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!username.trim() || password.length < 8) return;

    setLoading(true);
    setError(null);

    try {
      if (mode === "register") {
        const session = await register(username.trim(), password, inviteCode.trim(), serverUrl);
        onLogin(session);
      } else {
        const outcome = await login(username.trim(), password, serverUrl, replacementRequired);
        if (outcome.outcome === "device_replacement_required") {
          setReplacementRequired(true);
          setError("This account already has an active device. Confirm replacement to continue.");
          return;
        }
        onLogin(outcome.session);
      }
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
        <div style={styles.segmented}>
          <button
            type="button"
            style={{ ...styles.segment, ...(mode === "login" ? styles.segmentActive : {}) }}
            onClick={() => {
              setMode("login");
              setReplacementRequired(false);
              setError(null);
            }}
          >
            Login
          </button>
          <button
            type="button"
            style={{ ...styles.segment, ...(mode === "register" ? styles.segmentActive : {}) }}
            onClick={() => {
              setMode("register");
              setReplacementRequired(false);
              setError(null);
            }}
          >
            Register
          </button>
        </div>
        <form onSubmit={handleSubmit} style={styles.form}>
          <input
            className="form-input"
            type="text"
            placeholder="Server URL"
            value={serverUrl}
            onChange={(e) => setServerUrl(e.target.value)}
            style={styles.input}
          />
          {mode === "register" && (
            <input
              className="form-input"
              type="password"
              placeholder="Single-use invite code"
              value={inviteCode}
              onChange={(e) => setInviteCode(e.target.value)}
              style={styles.input}
            />
          )}
          <input
            className="form-input"
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            style={styles.input}
            autoFocus
          />
          <input
            className="form-input"
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={styles.input}
          />
          <button
            className="primary-button"
            type="submit"
            disabled={
              loading ||
              !username.trim() ||
              password.length < 8 ||
              (mode === "register" && !inviteCode.trim())
            }
            style={styles.button}
          >
            {loading
              ? "Connecting..."
              : mode === "register"
                ? "Register & Connect"
                : replacementRequired
                  ? "Replace old device & login"
                  : "Login"}
          </button>
          {error && <p style={styles.error}>{error}</p>}
        </form>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    height: "100vh",
    padding: "24px",
    backgroundColor: "var(--workspace-bg)",
  },
  card: {
    padding: "36px",
    borderRadius: "var(--radius-lg)",
    backgroundColor: "var(--sidebar-bg)",
    border: "1px solid var(--border)",
    boxShadow: "var(--shadow-modal)",
    width: "min(380px, 100%)",
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
