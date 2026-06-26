import { useState } from "react";
import { useTauri } from "../hooks/useTauri";
import type { UserSearchResult } from "../types";

interface AddContactProps {
  serverUrl: string;
  onClose: () => void;
  onAdded: () => void;
}

export default function AddContact({
  serverUrl,
  onClose,
  onAdded,
}: AddContactProps) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<UserSearchResult[]>([]);
  const [searching, setSearching] = useState(false);
  const [adding, setAdding] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { searchUsers, addContact } = useTauri();

  async function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    if (!query.trim()) return;

    setSearching(true);
    setError(null);
    try {
      const res = await searchUsers(query.trim(), serverUrl);
      setResults(res);
    } catch (err) {
      setError(String(err));
    } finally {
      setSearching(false);
    }
  }

  async function handleAdd(user: UserSearchResult) {
    setAdding(user.user_id);
    setError(null);
    try {
      await addContact(user.user_id, user.username, user.public_key);
      onAdded();
    } catch (err) {
      setError(String(err));
    } finally {
      setAdding(null);
    }
  }

  return (
    <div style={styles.overlay} onClick={onClose}>
      <div style={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div style={styles.header}>
          <h3 style={styles.title}>Add Contact</h3>
          <button style={styles.closeBtn} onClick={onClose}>
            ✕
          </button>
        </div>

        <form onSubmit={handleSearch} style={styles.searchRow}>
          <input
            type="text"
            placeholder="Search by username..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={styles.input}
            autoFocus
          />
          <button
            type="submit"
            disabled={searching || !query.trim()}
            style={styles.searchBtn}
          >
            {searching ? "..." : "Search"}
          </button>
        </form>

        {error && <p style={styles.error}>{error}</p>}

        <div style={styles.results}>
          {results.length === 0 && !searching && (
            <p style={styles.empty}>No results</p>
          )}
          {results.map((user) => (
            <div key={user.user_id} style={styles.resultItem}>
              <div style={styles.avatar}>
                {user.username.charAt(0).toUpperCase()}
              </div>
              <div style={styles.info}>
                <span style={styles.name}>{user.username}</span>
                <span style={styles.userId}>{user.user_id}</span>
              </div>
              <button
                style={styles.addBtn}
                disabled={adding === user.user_id}
                onClick={() => handleAdd(user)}
              >
                {adding === user.user_id ? "..." : "Add"}
              </button>
            </div>
          ))}
        </div>
      </div>
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
    backgroundColor: "#16213e",
    borderRadius: "12px",
    width: "400px",
    maxHeight: "500px",
    display: "flex",
    flexDirection: "column",
    boxShadow: "0 4px 20px rgba(0,0,0,0.4)",
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
    color: "#a0a0b0",
    fontSize: "18px",
    cursor: "pointer",
    padding: "4px",
  },
  searchRow: {
    display: "flex",
    padding: "12px 20px",
    gap: "8px",
    borderBottom: "1px solid #0f3460",
  },
  input: {
    flex: 1,
    padding: "8px 12px",
    borderRadius: "6px",
    border: "1px solid #333",
    backgroundColor: "#0f3460",
    color: "#fff",
    fontSize: "14px",
    outline: "none",
  },
  searchBtn: {
    padding: "8px 16px",
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
    margin: "0 20px",
    padding: "8px 0",
  },
  results: {
    flex: 1,
    overflowY: "auto",
    padding: "8px 0",
  },
  empty: {
    color: "#555",
    fontSize: "13px",
    textAlign: "center",
    padding: "20px",
  },
  resultItem: {
    display: "flex",
    alignItems: "center",
    padding: "10px 20px",
    gap: "10px",
  },
  avatar: {
    width: "36px",
    height: "36px",
    borderRadius: "50%",
    backgroundColor: "#e94560",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: "#fff",
    fontWeight: "bold",
    fontSize: "14px",
    flexShrink: 0,
  },
  info: {
    flex: 1,
    overflow: "hidden",
    display: "flex",
    flexDirection: "column",
  },
  name: {
    color: "#e0e0e0",
    fontSize: "14px",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  },
  userId: {
    color: "#666",
    fontSize: "11px",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  },
  addBtn: {
    padding: "6px 14px",
    borderRadius: "6px",
    border: "none",
    backgroundColor: "#0f3460",
    color: "#e0e0e0",
    fontSize: "13px",
    cursor: "pointer",
    flexShrink: 0,
  },
};
