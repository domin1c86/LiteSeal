import { useState } from "react";
import { useTauri } from "../hooks/useTauri";
import type { Contact, UserSearchResult } from "../types";

interface AddContactProps {
  userId: string;
  contacts: Contact[];
  onClose: () => void;
  onAdded: () => void;
}

export default function AddContact({
  userId,
  contacts,
  onClose,
  onAdded,
}: AddContactProps) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<UserSearchResult[]>([]);
  const [searching, setSearching] = useState(false);
  const [searched, setSearched] = useState(false);
  const [adding, setAdding] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { searchUsers, addContact } = useTauri();

  async function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    if (!query.trim()) return;

    setSearching(true);
    setError(null);
    try {
      const res = await searchUsers(query.trim());
      setResults(res);
      setSearched(true);
    } catch (err) {
      setError(String(err));
    } finally {
      setSearching(false);
    }
  }

  async function handleAdd(user: UserSearchResult) {
    const disabledReason = getDisabledReason(user);
    if (disabledReason) return;

    setAdding(user.user_id);
    setError(null);
    try {
      await addContact(user.user_id, user.username, user.public_key, user.ed25519_pk);
      onAdded();
    } catch (err) {
      setError(String(err));
    } finally {
      setAdding(null);
    }
  }

  function getDisabledReason(user: UserSearchResult): string | null {
    if (user.user_id === userId) return "You";
    if (contacts.some((contact) => contact.user_id === user.user_id)) {
      return "Already added";
    }
    if (!user.public_key || user.public_key.length !== 32) return "Missing key";
    return null;
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
            className="form-input"
            type="text"
            placeholder="Search by username..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={styles.input}
            autoFocus
          />
          <button
            className="primary-button"
            type="submit"
            disabled={searching || !query.trim()}
            style={styles.searchBtn}
          >
            {searching ? "..." : "Search"}
          </button>
        </form>

        {error && <p style={styles.error}>{error}</p>}

        <div style={styles.results}>
          {searched && results.length === 0 && !searching && (
            <p style={styles.empty}>No results</p>
          )}
          {results.map((user) => {
            const disabledReason = getDisabledReason(user);
            return (
              <div key={user.user_id} style={styles.resultItem}>
                <div style={styles.avatar}>
                  {user.username.charAt(0).toUpperCase()}
                </div>
                <div style={styles.info}>
                  <span style={styles.name}>{user.username}</span>
                  <span style={styles.userId}>{user.user_id}</span>
                </div>
                <button
                  className="outline-button"
                  style={styles.addBtn}
                  disabled={adding === user.user_id || disabledReason !== null}
                  onClick={() => handleAdd(user)}
                >
                  {adding === user.user_id ? "..." : disabledReason ?? "Add"}
                </button>
              </div>
            );
          })}
        </div>
      </div>
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
    border: "1px solid var(--border-strong)",
    width: "min(420px, 100%)",
    maxHeight: "min(520px, calc(100vh - 32px))",
    display: "flex",
    flexDirection: "column",
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
    fontSize: "15px",
    cursor: "pointer",
    padding: "4px",
  },
  searchRow: {
    display: "flex",
    padding: "12px 20px",
    gap: "8px",
    borderBottom: "1px solid var(--border)",
  },
  input: {
    flex: 1,
    padding: "9px 12px",
    borderRadius: "var(--radius-md)",
    border: "1px solid var(--border-strong)",
    backgroundColor: "var(--surface-muted)",
    color: "var(--text)",
    fontSize: "14px",
    outline: "none",
    minWidth: 0,
  },
  searchBtn: {
    padding: "9px 16px",
    borderRadius: "var(--radius-md)",
    border: "none",
    backgroundColor: "var(--accent)",
    color: "var(--accent-contrast)",
    fontSize: "13px",
    cursor: "pointer",
    fontWeight: 600,
  },
  error: {
    fontFamily: "var(--font-mono)",
    color: "var(--danger)",
    fontSize: "12px",
    margin: "0 20px",
    padding: "8px 0",
  },
  results: {
    flex: 1,
    overflowY: "auto",
    padding: "8px 0",
  },
  empty: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    fontSize: "12px",
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
    width: "34px",
    height: "34px",
    borderRadius: "var(--radius-md)",
    backgroundColor: "var(--accent-soft)",
    border: "1px solid var(--border)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: "var(--text-muted)",
    fontFamily: "var(--font-mono)",
    fontWeight: 600,
    fontSize: "13px",
    flexShrink: 0,
  },
  info: {
    flex: 1,
    overflow: "hidden",
    display: "flex",
    flexDirection: "column",
    gap: "2px",
  },
  name: {
    color: "var(--text)",
    fontSize: "14px",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  },
  userId: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    fontSize: "10.5px",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  },
  addBtn: {
    padding: "6px 14px",
    borderRadius: "var(--radius-md)",
    border: "1px solid var(--border-strong)",
    backgroundColor: "transparent",
    color: "var(--text-muted)",
    fontSize: "13px",
    cursor: "pointer",
    flexShrink: 0,
  },
};
