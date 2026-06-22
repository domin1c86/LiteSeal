import type { User, Conversation } from "../types";

interface ContactListProps {
  contacts: User[];
  conversations: Conversation[];
  activeConversation: string | null;
  onSelect: (conversationId: string) => void;
}

export default function ContactList({
  contacts,
  conversations,
  activeConversation,
  onSelect,
}: ContactListProps) {
  return (
    <div style={styles.container}>
      <h3 style={styles.heading}>Contacts</h3>
      {contacts.length === 0 && (
        <p style={styles.empty}>No contacts yet</p>
      )}
      {contacts.map((contact) => {
        const conv = conversations.find(
          (c) => c.conversation_type === "direct"
        );
        const isActive = conv && conv.id === activeConversation;
        return (
          <div
            key={contact.id}
            style={{
              ...styles.item,
              ...(isActive ? styles.itemActive : {}),
            }}
            onClick={() => conv && onSelect(conv.id)}
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
  heading: {
    margin: "16px",
    color: "#a0a0b0",
    fontSize: "13px",
    textTransform: "uppercase",
    letterSpacing: "1px",
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
