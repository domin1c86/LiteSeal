import type { Contact } from "../types";

interface ContactListProps {
  contacts: Contact[];
  activeConversation: string | null;
  onSelect: (contactId: string) => void;
  onAddClick: () => void;
  onStorageClick: () => void;
  onLogout: () => void;
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
        <h3 className="contact-sidebar-title" style={styles.heading}>Contacts</h3>
        <div style={styles.headerBtns}>
          <button className="icon-button" style={styles.iconBtn} onClick={onStorageClick} title="Storage">
            ⚙
          </button>
          <button className="primary-button" style={styles.addBtn} onClick={onAddClick}>
            +
          </button>
          <button className="icon-button" style={styles.iconBtn} onClick={onLogout} title="Logout">
            ⏻
          </button>
        </div>
      </div>
      {contacts.length === 0 && (
        <p style={styles.empty}>No contacts yet</p>
      )}
      {contacts.map((contact) => {
        const isActive = contact.user_id === activeConversation;
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
            <div style={styles.avatar}>
              {contact.username.charAt(0).toUpperCase()}
            </div>
            <div style={styles.info}>
              <span className="contact-name" style={styles.name}>{contact.username}</span>
              <span style={styles.trust}>
                {contact.trust_state === "verified"
                  ? "Verified"
                  : contact.trust_state === "key_changed" || contact.key_changed
                    ? "Key changed"
                    : "Unverified"}
              </span>
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
  },
  heading: {
    margin: 0,
    color: "var(--text-muted)",
    fontSize: "14px",
    fontWeight: 600,
    letterSpacing: 0,
  },
  headerBtns: {
    display: "flex",
    gap: "8px",
  },
  iconBtn: {
    width: "24px",
    height: "24px",
    borderRadius: "50%",
    border: "1px solid var(--border)",
    backgroundColor: "var(--surface-muted)",
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
    width: "24px",
    height: "24px",
    borderRadius: "50%",
    border: "none",
    backgroundColor: "var(--accent)",
    color: "white",
    fontSize: "16px",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    lineHeight: 1,
    padding: 0,
  },
  empty: {
    color: "var(--text-subtle)",
    fontSize: "13px",
    textAlign: "center",
    marginTop: "20px",
  },
  item: {
    display: "flex",
    alignItems: "center",
    padding: "9px 12px",
    margin: "6px 8px 0",
    borderRadius: "var(--radius-md)",
    cursor: "pointer",
    gap: "10px",
    transition: "background-color 0.15s",
  },
  itemActive: {
    backgroundColor: "var(--surface-active)",
  },
  avatar: {
    width: "36px",
    height: "36px",
    borderRadius: "50%",
    backgroundColor: "var(--accent-soft)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: "var(--accent)",
    fontWeight: 600,
    fontSize: "14px",
    flexShrink: 0,
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
    color: "var(--text-subtle)",
    fontSize: "11px",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  },
};
