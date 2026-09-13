import { useState } from "react";
import { useConversationSummaries } from "../hooks/useConversationSummaries";
import type { Contact, Draft } from "../types";

export type SidebarTab = "chats" | "contacts";

interface ContactListProps {
  userId: string;
  secretKey: number[];
  signingPublicKey: number[];
  contacts: Contact[];
  flags: Record<string, { pinned: boolean; archived: boolean }>;
  drafts: Record<string, Draft>;
  preferencesReady: boolean;
  onFlagsChange: (id: string, flags: { pinned: boolean; archived: boolean }) => void;
  activeConversation: string | null;
  tab: SidebarTab;
  onTabChange: (tab: SidebarTab) => void;
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
  contacts, userId, secretKey, signingPublicKey, flags, drafts, preferencesReady, onFlagsChange,
  activeConversation,
  tab,
  onTabChange,
  onSelect,
  onAddClick,
  onStorageClick,
  onLogout,
}: ContactListProps) {
  const { previews, error } = useConversationSummaries(userId, secretKey, signingPublicKey, contacts);
  const [showArchived, setShowArchived] = useState(false);
  const archiveCount = contacts.filter(contact => flags[contact.user_id]?.archived).length;
  const ordered = tab === "chats" ? contacts.filter(contact => !!flags[contact.user_id]?.archived === showArchived).sort((a, b) =>
    Number(!!flags[b.user_id]?.pinned) - Number(!!flags[a.user_id]?.pinned)
    || (previews[b.user_id]?.timestamp ?? 0) - (previews[a.user_id]?.timestamp ?? 0) || a.username.localeCompare(b.username)) : contacts;
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
      <div style={styles.tabs}>
        <button
          className="sidebar-tab"
          style={{ ...styles.tab, ...(tab === "chats" ? styles.tabActive : {}) }}
          onClick={() => onTabChange("chats")}
        >
          chats
        </button>
        <button
          className="sidebar-tab"
          style={{ ...styles.tab, ...(tab === "contacts" ? styles.tabActive : {}) }}
          onClick={() => onTabChange("contacts")}
        >
          contacts
        </button>
      </div>
      {tab === "chats" && <button onClick={() => setShowArchived(value => !value)}>
        {showArchived ? "返回聊天" : `已归档 (${archiveCount})`}
      </button>}
      {ordered.length === 0 && (
        <p style={styles.empty}>{showArchived && tab === "chats" ? "暂无归档会话" : "暂无会话"}</p>
      )}
      {error && <p role="alert" style={styles.empty}>{error}</p>}
      {ordered.map((contact) => {
        const isActive = contact.user_id === activeConversation;
        const trust = trustLabel(contact);
        const preview = previews[contact.user_id];
        const preference = flags[contact.user_id] ?? { pinned: false, archived: false };
        const summary = drafts[contact.user_id]?.text ? `[草稿] ${drafts[contact.user_id].text}` : preview?.text ?? "加载中…";
        return (
          <div
            role="button"
            tabIndex={0}
            onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(contact.user_id); } }}
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
              <span className="contact-name" style={styles.name}>{tab === "chats" && preference.pinned ? "📌 " : ""}{contact.username}</span>
              {tab === "chats" ? <span style={styles.trust} title={summary}>{summary}</span>
                : <span style={{ ...styles.trust, color: trust.color }}>{trust.text}</span>}
            </div>
            {tab === "chats" && <div style={{ display: "flex", flexDirection: "column", gap: 4 }} onClick={event => event.stopPropagation()} onKeyDown={event => event.stopPropagation()}>
              <button disabled={!preferencesReady} aria-label={`${preference.pinned ? "取消置顶" : "置顶"} ${contact.username}`} onClick={() => onFlagsChange(contact.user_id, { ...preference, pinned: !preference.pinned })}>{preference.pinned ? "取消置顶" : "置顶"}</button>
              <button disabled={!preferencesReady} aria-label={`${preference.archived ? "取消归档" : "归档"} ${contact.username}`} onClick={() => onFlagsChange(contact.user_id, { ...preference, archived: !preference.archived })}>{preference.archived ? "移回聊天" : "归档"}</button>
            </div>}
            {tab === "chats" && preview && <div style={{ marginLeft: "auto", textAlign: "right", flexShrink: 0, fontSize: 11 }}>
              {preview.timestamp > 0 && <time dateTime={new Date(preview.timestamp).toISOString()} title={new Date(preview.timestamp).toLocaleString()}>
                {new Date(preview.timestamp).toLocaleDateString() === new Date().toLocaleDateString()
                  ? new Date(preview.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
                  : new Date(preview.timestamp).toLocaleDateString()}
              </time>}
              {preview.unread > 0 && <div aria-label={`${preview.unread} 条未读消息`} style={{ color: "var(--accent)", fontWeight: 700 }}>{preview.unread > 99 ? "99+" : preview.unread}</div>}
            </div>}
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
  tabs: {
    display: "flex",
    gap: "4px",
    padding: "8px 10px",
    borderBottom: "1px solid var(--border)",
    flexShrink: 0,
  },
  tab: {
    flex: 1,
    fontFamily: "var(--font-mono)",
    fontSize: "11.5px",
    padding: "6px 0",
    border: "none",
    borderRadius: "var(--radius-sm)",
    backgroundColor: "transparent",
    color: "var(--text-subtle)",
    cursor: "pointer",
    textTransform: "lowercase",
  },
  tabActive: {
    backgroundColor: "var(--surface-active)",
    color: "var(--text)",
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
