import { useState } from "react";
import { useTauri } from "../hooks/useTauri";
import type { RegisterResult } from "../types";

interface LoginProps {
  onLogin: (result: RegisterResult & { serverUrl: string; secretKey: number[] }) => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState("");
  const [serverUrl, setServerUrl] = useState("http://localhost:3000");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { register, connectRelay, generateKeypair } = useTauri();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!username.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const [publicKey, secretKey, ed25519Pk] = await generateKeypair();
      const result = await register(username.trim(), serverUrl, publicKey, ed25519Pk);
      await connectRelay(serverUrl, result.user_id, result.token);
      onLogin({ ...result, serverUrl, secretKey });
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
        <form onSubmit={handleSubmit} style={styles.form}>
          <input
            type="text"
            placeholder="Server URL"
            value={serverUrl}
            onChange={(e) => setServerUrl(e.target.value)}
            style={styles.input}
          />
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            style={styles.input}
            autoFocus
          />
          <button type="submit" disabled={loading || !username.trim()} style={styles.button}>
            {loading ? "Connecting..." : "Register & Connect"}
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
    backgroundColor: "#1a1a2e",
  },
  card: {
    padding: "40px",
    borderRadius: "12px",
    backgroundColor: "#16213e",
    boxShadow: "0 4px 20px rgba(0,0,0,0.3)",
    width: "360px",
    textAlign: "center",
  },
  title: {
    margin: 0,
    fontSize: "28px",
    color: "#e94560",
  },
  subtitle: {
    color: "#a0a0b0",
    marginTop: "4px",
    marginBottom: "24px",
  },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: "12px",
  },
  input: {
    padding: "10px 14px",
    borderRadius: "6px",
    border: "1px solid #333",
    backgroundColor: "#0f3460",
    color: "#fff",
    fontSize: "14px",
    outline: "none",
  },
  button: {
    padding: "10px",
    borderRadius: "6px",
    border: "none",
    backgroundColor: "#e94560",
    color: "#fff",
    fontSize: "14px",
    cursor: "pointer",
    fontWeight: "bold",
  },
  error: {
    color: "#e94560",
    fontSize: "13px",
    margin: 0,
  },
};
