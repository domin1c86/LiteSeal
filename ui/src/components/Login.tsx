import { useState } from "react";
import { useTauri } from "../hooks/useTauri";
import type { RegisterResult } from "../types";

interface LoginProps {
  onLogin: (result: RegisterResult & { serverUrl: string; publicKey: number[]; secretKey: number[]; ed25519Pk: number[]; ed25519Sk: number[] }) => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<"login" | "register">("login");
  const [serverUrl, setServerUrl] = useState("http://localhost:3000");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { register, login, connectRelay, generateKeypair, saveKeypair } = useTauri();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!username.trim() || password.length < 8) return;

    setLoading(true);
    setError(null);

    try {
      const [publicKey, secretKey, ed25519Pk, ed25519Sk] = await generateKeypair();
      const result =
        mode === "register"
          ? await register(username.trim(), password, serverUrl, publicKey, ed25519Pk)
          : await login(username.trim(), password, serverUrl, publicKey, ed25519Pk);
      const token = result.access_token ?? result.token;
      await connectRelay(serverUrl, result.user_id, token, result.device_id);
      await saveKeypair(result.user_id, token, publicKey, secretKey, ed25519Pk, ed25519Sk);
      onLogin({ ...result, token, serverUrl, publicKey, secretKey, ed25519Pk, ed25519Sk });
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>LiteSeal</h1>
        <p style={styles.subtitle}>Secure Messaging</p>
        <div style={styles.segmented}>
          <button
            type="button"
            style={{ ...styles.segment, ...(mode === "login" ? styles.segmentActive : {}) }}
            onClick={() => setMode("login")}
          >
            Login
          </button>
          <button
            type="button"
            style={{ ...styles.segment, ...(mode === "register" ? styles.segmentActive : {}) }}
            onClick={() => setMode("register")}
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
            disabled={loading || !username.trim() || password.length < 8}
            style={styles.button}
          >
            {loading ? "Connecting..." : mode === "register" ? "Register & Connect" : "Login"}
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
    backgroundColor: "var(--surface)",
    border: "1px solid var(--border)",
    boxShadow: "var(--shadow-modal)",
    width: "min(380px, 100%)",
    textAlign: "center",
  },
  title: {
    margin: 0,
    fontSize: "24px",
    fontWeight: 600,
    color: "var(--text)",
  },
  subtitle: {
    color: "var(--text-muted)",
    marginTop: "4px",
    marginBottom: "28px",
    fontSize: "14px",
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
    backgroundColor: "var(--surface-muted)",
    marginBottom: "18px",
  },
  segment: {
    border: "none",
    borderRadius: "var(--radius-sm)",
    padding: "8px 10px",
    backgroundColor: "transparent",
    color: "var(--text-muted)",
    cursor: "pointer",
    fontWeight: 600,
  },
  segmentActive: {
    backgroundColor: "var(--surface)",
    color: "var(--text)",
    border: "1px solid var(--border)",
  },
  input: {
    padding: "11px 13px",
    borderRadius: "var(--radius-md)",
    border: "1px solid var(--border-strong)",
    backgroundColor: "var(--surface)",
    color: "var(--text)",
    fontSize: "14px",
    outline: "none",
  },
  button: {
    padding: "11px",
    borderRadius: "var(--radius-md)",
    border: "none",
    backgroundColor: "var(--accent)",
    color: "white",
    fontSize: "14px",
    cursor: "pointer",
    fontWeight: 600,
  },
  error: {
    color: "var(--danger)",
    fontSize: "13px",
    margin: 0,
  },
};
