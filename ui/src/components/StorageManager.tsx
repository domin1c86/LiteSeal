import { useState, useEffect } from "react";
import { useTauri } from "../hooks/useTauri";
import type { StorageStats } from "../types";

interface StorageManagerProps {
  onClose: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

export default function StorageManager({ onClose }: StorageManagerProps) {
  const [stats, setStats] = useState<StorageStats | null>(null);
  const [clearing, setClearing] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const { getStorageStats, clearExpiredMessages, clearDownloadedAttachments } =
    useTauri();

  useEffect(() => {
    getStorageStats()
      .then(setStats)
      .catch((err) => console.error("Failed to load storage stats:", err));
  }, []);

  async function handleClearExpired() {
    setClearing(true);
    setResult(null);
    try {
      const count = await clearExpiredMessages();
      setResult(`Cleared ${count} expired messages`);
      const updated = await getStorageStats();
      setStats(updated);
    } catch (err) {
      setResult(`Error: ${err}`);
    } finally {
      setClearing(false);
    }
  }

  async function handleClearAttachments() {
    setClearing(true);
    setResult(null);
    try {
      const count = await clearDownloadedAttachments();
      setResult(`Cleared ${count} attachments`);
      const updated = await getStorageStats();
      setStats(updated);
    } catch (err) {
      setResult(`Error: ${err}`);
    } finally {
      setClearing(false);
    }
  }

  return (
    <div style={styles.overlay}>
      <div style={styles.modal}>
        <div style={styles.header}>
          <h3 style={styles.title}>Storage Manager</h3>
          <button style={styles.closeBtn} onClick={onClose}>
            ×
          </button>
        </div>

        {stats ? (
          <div style={styles.body}>
            <div style={styles.statsGrid}>
              <StatCard
                label="Messages"
                value={stats.message_count.toString()}
                sub={formatBytes(stats.ciphertext_bytes)}
              />
              <StatCard
                label="Attachments"
                value={stats.attachment_count.toString()}
                sub={formatBytes(stats.attachment_bytes)}
              />
              <StatCard
                label="Conversations"
                value={stats.conversation_count.toString()}
                sub=""
              />
              <StatCard
                label="Total"
                value={formatBytes(stats.total_bytes)}
                sub=""
                highlight
              />
            </div>

            <div style={styles.actions}>
              <button
                style={styles.actionBtn}
                onClick={handleClearExpired}
                disabled={clearing}
              >
                {clearing ? "Clearing..." : "Clear Expired Messages"}
              </button>
              <button
                style={styles.actionBtn}
                onClick={handleClearAttachments}
                disabled={clearing}
              >
                {clearing ? "Clearing..." : "Clear Unpinned Attachments"}
              </button>
            </div>

            {result && <p style={styles.result}>{result}</p>}
          </div>
        ) : (
          <p style={styles.loading}>Loading...</p>
        )}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  sub,
  highlight,
}: {
  label: string;
  value: string;
  sub: string;
  highlight?: boolean;
}) {
  return (
    <div style={{ ...styles.statCard, ...(highlight ? styles.statHighlight : {}) }}>
      <span style={styles.statLabel}>{label}</span>
      <span style={styles.statValue}>{value}</span>
      {sub && <span style={styles.statSub}>{sub}</span>}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  overlay: {
    position: "fixed",
    inset: 0,
    backgroundColor: "rgba(0,0,0,0.6)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 1000,
  },
  modal: {
    backgroundColor: "#1a1a2e",
    borderRadius: "12px",
    width: "420px",
    maxHeight: "80vh",
    overflow: "auto",
    border: "1px solid #0f3460",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "16px 20px",
    borderBottom: "1px solid #0f3460",
  },
  title: {
    margin: 0,
    color: "#e0e0e0",
    fontSize: "16px",
  },
  closeBtn: {
    background: "none",
    border: "none",
    color: "#888",
    fontSize: "22px",
    cursor: "pointer",
    padding: "0 4px",
  },
  body: {
    padding: "20px",
  },
  statsGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: "12px",
    marginBottom: "20px",
  },
  statCard: {
    backgroundColor: "#16213e",
    borderRadius: "8px",
    padding: "12px",
    display: "flex",
    flexDirection: "column",
    gap: "4px",
  },
  statHighlight: {
    border: "1px solid #e94560",
  },
  statLabel: {
    color: "#888",
    fontSize: "12px",
    textTransform: "uppercase" as const,
    letterSpacing: "0.5px",
  },
  statValue: {
    color: "#e0e0e0",
    fontSize: "20px",
    fontWeight: "bold",
  },
  statSub: {
    color: "#666",
    fontSize: "12px",
  },
  actions: {
    display: "flex",
    flexDirection: "column" as const,
    gap: "10px",
  },
  actionBtn: {
    backgroundColor: "#0f3460",
    color: "#e0e0e0",
    border: "none",
    borderRadius: "6px",
    padding: "10px 16px",
    cursor: "pointer",
    fontSize: "14px",
    transition: "background-color 0.15s",
  },
  result: {
    color: "#e94560",
    fontSize: "13px",
    marginTop: "12px",
    textAlign: "center" as const,
  },
  loading: {
    color: "#888",
    textAlign: "center" as const,
    padding: "40px 0",
  },
};
