import type { Contact } from "../types";

interface ContactListProps {
  contacts: Contact[];
  activeConversation: string | null;
  onSelect: (contactId: string) => void;
  onAddClick: () => void;
  onStorageClick: () => void;
}

export default function ContactList({
  contacts,
  activeConversation,
  onSelect,
  onAddClick,
  onStorageClick,
}: ContactListProps) {
  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h3 style={styles.heading}>Contacts</h3>
        <div style={styles.headerBtns}>
          <button style={styles.iconBtn} onClick={onStorageClick} title="Storage">
            ⚙
          </button>
          <button style={styles.addBtn} onClick={onAddClick}>
            +
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
              <span style={styles.name}>{contact.username}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    width: "240px",
    backgroundColor: "#16213e",
    borderRight: "1px solid #0f3460",
    overflowY: "auto",
    display: "flex",
    flexDirection: "column",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "0 16px",
    marginTop: "16px",
  },
  heading: {
    margin: 0,
    color: "#a0a0b0",
    fontSize: "13px",
    textTransform: "uppercase",
    letterSpacing: "1px",
  },
  headerBtns: {
    display: "flex",
    gap: "8px",
  },
  iconBtn: {
    width: "24px",
    height: "24px",
    borderRadius: "50%",
    border: "none",
    backgroundColor: "#0f3460",
    color: "#a0a0b0",
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
    backgroundColor: "#e94560",
    color: "#fff",
    fontSize: "16px",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    lineHeight: 1,
    padding: 0,
  },
  empty: {
    color: "#555",
    fontSize: "13px",
    textAlign: "center",
    marginTop: "20px",
  },
  item: {
    display: "flex",
    alignItems: "center",
    padding: "10px 16px",
    cursor: "pointer",
    gap: "10px",
    transition: "background-color 0.15s",
  },
  itemActive: {
    backgroundColor: "#0f3460",
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
    overflow: "hidden",
  },
  name: {
    color: "#e0e0e0",
    fontSize: "14px",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  },
};
