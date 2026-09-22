import { useState, useEffect } from "react";
import { useDesktop } from "../hooks/useDesktop";
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
  const [cache, setCache] = useState<{ cache_bytes: number; database_allocated: number; database_reusable: number; disk_bytes: number; limit: number } | null>(null);
  const [peerId, setPeerId] = useState("");
  const [peers, setPeers] = useState<{user_id: string; username: string}[]>([]);
  const [stats, setStats] = useState<StorageStats | null>(null);
  const [clearing, setClearing] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const { getStorageStats, clearExpiredMessages, clearDownloadedAttachments } =
    useDesktop();

  useEffect(() => {
    void window.desktop.attachment_cache_stats({}).then(setCache).catch(error => setResult(String(error)));
    void window.desktop.get_contacts({}).then(setPeers).catch(error => setResult(String(error)));
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
            {cache && <section><p>附件密文缓存：{formatBytes(cache.cache_bytes)} / {formatBytes(cache.limit)}。数据库已分配：{formatBytes(cache.database_allocated)}；内部可复用：{formatBytes(cache.database_reusable)}；数据库和日志文件合计：{formatBytes(cache.disk_bytes)}。</p>
              <select aria-label="附件清理会话" value={peerId} onChange={event => setPeerId(event.target.value)}><option value="">所有会话</option>{peers.map(peer => <option key={peer.user_id} value={peer.user_id}>{peer.username}</option>)}</select>
              <button disabled={clearing} onClick={async () => {
                setClearing(true);
                try { const before = cache.cache_bytes; await window.desktop.clear_attachment_cache({ peerId: peerId || undefined }); const after = await window.desktop.attachment_cache_stats({}); setCache(after); setResult(`已移除 ${formatBytes(before - after.cache_bytes)} 密文缓存，文件大小减少 ${formatBytes(Math.max(0, cache.disk_bytes - after.disk_bytes))}。SQLite 空间可复用，文件未必缩小；没有删除正文、链或待发任务。`); }
                catch (failure) { setResult(String(failure)); } finally { setClearing(false); }
              }}>清理已下载附件缓存</button>
              <p>远端附件保留 30 天，期限内可重新下载；已过期或无权限会明确报错。待发附件不会被此操作清除。</p>
            </section>}
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
                className="outline-button"
                style={styles.actionBtn}
                onClick={handleClearExpired}
                disabled={clearing}
              >
                {clearing ? "Clearing..." : "Clear Expired Messages"}
              </button>
              <button
                className="outline-button"
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
    backgroundColor: "var(--overlay)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "16px",
    zIndex: 1000,
  },
  modal: {
    backgroundColor: "var(--sidebar-bg)",
    borderRadius: "var(--radius-lg)",
    width: "min(440px, 100%)",
    maxHeight: "min(80vh, calc(100vh - 32px))",
    overflow: "auto",
    border: "1px solid var(--border-strong)",
    boxShadow: "var(--shadow-modal)",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "14px 20px",
    borderBottom: "1px solid var(--border)",
  },
  title: {
    margin: 0,
    color: "var(--text)",
    fontSize: "14px",
    fontWeight: 600,
  },
  closeBtn: {
    background: "none",
    border: "none",
    color: "var(--text-muted)",
    fontSize: "18px",
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
    backgroundColor: "var(--surface-muted)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-md)",
    padding: "12px",
    display: "flex",
    flexDirection: "column",
    gap: "4px",
  },
  statHighlight: {
    border: "1px solid var(--border-strong)",
    backgroundColor: "var(--accent-soft)",
  },
  statLabel: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    fontSize: "10.5px",
    textTransform: "uppercase" as const,
    letterSpacing: "0.05em",
  },
  statValue: {
    fontFamily: "var(--font-mono)",
    color: "var(--text)",
    fontSize: "20px",
    fontWeight: 600,
  },
  statSub: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    fontSize: "11px",
  },
  actions: {
    display: "flex",
    flexDirection: "column" as const,
    gap: "10px",
  },
  actionBtn: {
    backgroundColor: "transparent",
    color: "var(--text-muted)",
    border: "1px solid var(--border-strong)",
    borderRadius: "var(--radius-md)",
    padding: "10px 16px",
    cursor: "pointer",
    fontSize: "13px",
    transition: "background-color 0.15s",
  },
  result: {
    fontFamily: "var(--font-mono)",
    color: "var(--ok)",
    fontSize: "12px",
    marginTop: "12px",
    textAlign: "center" as const,
  },
  loading: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    fontSize: "12px",
    textAlign: "center" as const,
    padding: "40px 0",
  },
};
