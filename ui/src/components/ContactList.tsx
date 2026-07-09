import type { Contact } from "../types";

interface ContactListProps {
  contacts: Contact[];
  activeConversation: string | null;
  onSelect: (contactId: string) => void;
  onAddClick: () => void;
  onStorageClick: () => void;
  onLogout: () => void;
}

export function trustLabel(contact: Contact): { text: string; color: string } {
  if (contact.trust_state === "verified") {
    return { text: "✓ verified", color: "var(--ok)" };
  }
  if (contact.trust_state === "key_changed" || contact.key_changed) {
    return { text: "⚠ key changed", color: "var(--warn)" };
  }
  return { text: "unverified", color: "var(--text-subtle)" };
}

export default function ContactList({
  contacts,
  activeConversation,
  onSelect,
  onAddClick,
  onStorageClick,
  onLogout,
}: ContactListProps) {
  return (
    <div className="contact-sidebar" style={styles.container}>
      <div style={styles.header}>
        <span className="contact-sidebar-title" style={styles.wordmark}>
          liteseal<span style={styles.wordmarkCursor}>▌</span>
        </span>
        <div style={styles.headerBtns}>
          <button className="icon-button" style={styles.iconBtn} onClick={onStorageClick} title="Storage">
            ⚙
          </button>
          <button className="primary-button" style={styles.addBtn} onClick={onAddClick} title="Add contact">
            +
          </button>
          <button className="icon-button" style={styles.iconBtn} onClick={onLogout} title="Logout">
            ⏻
          </button>
        </div>
      </div>
      {contacts.length === 0 && (
        <p style={styles.empty}>no contacts yet</p>
      )}
      {contacts.map((contact) => {
        const isActive = contact.user_id === activeConversation;
        const trust = trustLabel(contact);
        return (
          <div
            className="contact-row"
            key={contact.user_id}
            style={{
              ...styles.item,
              ...(isActive ? styles.itemActive : {}),
            }}
            onClick={() => onSelect(contact.user_id)}
          >
            <div style={{ ...styles.avatar, ...(isActive ? styles.avatarActive : {}) }}>
              {contact.username.charAt(0).toUpperCase()}
            </div>
            <div style={styles.info}>
              <span className="contact-name" style={styles.name}>{contact.username}</span>
              <span style={{ ...styles.trust, color: trust.color }}>{trust.text}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    width: "280px",
    backgroundColor: "var(--sidebar-bg)",
    borderRight: "1px solid var(--border)",
    overflowY: "auto",
    display: "flex",
    flexDirection: "column",
    flexShrink: 0,
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    minHeight: "58px",
    padding: "0 14px 0 18px",
    borderBottom: "1px solid var(--border)",
    flexShrink: 0,
  },
  wordmark: {
    fontFamily: "var(--font-mono)",
    fontSize: "15px",
    fontWeight: 600,
    letterSpacing: "-0.01em",
    color: "var(--text)",
  },
  wordmarkCursor: {
    color: "var(--text-subtle)",
    fontWeight: 400,
  },
  headerBtns: {
    display: "flex",
    gap: "6px",
  },
  iconBtn: {
    width: "26px",
    height: "26px",
    borderRadius: "var(--radius-sm)",
    border: "none",
    backgroundColor: "transparent",
    color: "var(--text-muted)",
    fontSize: "13px",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    lineHeight: 1,
    padding: 0,
  },
  addBtn: {
    width: "26px",
    height: "26px",
    borderRadius: "var(--radius-sm)",
    border: "none",
    backgroundColor: "var(--accent)",
    color: "var(--accent-contrast)",
    fontSize: "15px",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    lineHeight: 1,
    padding: 0,
  },
  empty: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    fontSize: "12px",
    textAlign: "center",
    marginTop: "20px",
  },
  item: {
    display: "flex",
    alignItems: "center",
    padding: "9px 12px",
    margin: "6px 8px 0",
    borderRadius: "var(--radius-md)",
    borderLeft: "2px solid transparent",
    cursor: "pointer",
    gap: "10px",
    transition: "background-color 0.15s",
  },
  itemActive: {
    backgroundColor: "var(--surface-active)",
    borderLeftColor: "var(--text)",
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
  avatarActive: {
    color: "var(--text)",
    borderColor: "var(--border-strong)",
  },
  info: {
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
  trust: {
    fontFamily: "var(--font-mono)",
    fontSize: "10.5px",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  },
};
