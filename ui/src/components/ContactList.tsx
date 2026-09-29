import ActionMenu from "./ActionMenu";
import { useState } from "react";
import { useConversationSummaries } from "../hooks/useConversationSummaries";
import type { Contact, Draft, PublicProfile } from "../types";

export type SidebarTab = "chats" | "contacts";

interface ContactListProps {
  userId: string;
  signingPublicKey: number[];
  contacts: Contact[];
  profiles: Record<string, PublicProfile>;
  flags: Record<string, { pinned: boolean; archived: boolean }>;
  muted: Record<string, boolean>;
  onMutedChange: (id: string, muted: boolean) => void;
  aliases: Record<string, string>;
  lists: { id: string; name: string; peers: string[] }[];
  onOrganizer: () => void;
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
  contacts, profiles, userId, signingPublicKey, flags, muted, onMutedChange, aliases, lists, onOrganizer, drafts, preferencesReady, onFlagsChange,
  activeConversation,
  tab,
  onTabChange,
  onSelect,
  onAddClick,
  onStorageClick,
  onLogout,
}: ContactListProps) {
  const { previews, error } = useConversationSummaries(userId, signingPublicKey, contacts);
  const [showArchived, setShowArchived] = useState(false);
  const [filter, setFilter] = useState("all");
  const archiveCount = contacts.filter(contact => flags[contact.user_id]?.archived).length;
  const ordered = tab === "chats" ? contacts.filter(contact => !!flags[contact.user_id]?.archived === showArchived
    && (filter === "all" || (filter === "unread" ? (previews[contact.user_id]?.unread ?? 0) > 0 : lists.find(list => list.id === filter)?.peers.includes(contact.user_id)))).sort((a, b) =>
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
      <div className="sidebar-filters">{tab === "chats" && <button onClick={() => setShowArchived(value => !value)}>
        {showArchived ? "返回聊天" : `已归档 (${archiveCount})`}
      </button>}
      {tab === "chats" && <select aria-label="筛选会话" value={filter} onChange={event => setFilter(event.target.value)}>
        <option value="all">全部</option><option value="unread">未读</option>
        {lists.map(list => <option key={list.id} value={list.id}>{list.name}</option>)}
      </select>}
      <button className="sidebar-organizer" onClick={onOrganizer}>本机列表、收藏和便笺</button></div>
      {ordered.length === 0 && (
        <p style={styles.empty}>{showArchived && tab === "chats" ? "暂无归档会话" : "暂无会话"}</p>
      )}
      {error && <p role="alert" style={styles.empty}>{error}</p>}
      {ordered.map((contact) => {
        const isActive = contact.user_id === activeConversation;
        const trust = trustLabel(contact);
        const preview = previews[contact.user_id];
        const preference = flags[contact.user_id] ?? { pinned: false, archived: false };
        const summary = drafts[contact.user_id]?.text || drafts[contact.user_id]?.reply || drafts[contact.user_id]?.forwarded ? `[草稿] ${drafts[contact.user_id].text || "引用回复"}` : preview?.text ?? "加载中…";
        return (
          <div
            role="button"
            tabIndex={0}
            onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(contact.user_id); } }}
            className="contact-row inset-indicator"
            data-indicator-active={isActive}
            aria-current={isActive ? "true" : undefined}
            key={contact.user_id}
            style={{
              ...styles.item,
              ...(isActive ? styles.itemActive : {}),
            }}
            onClick={() => onSelect(contact.user_id)}
          >
            <div style={{ ...styles.avatar, ...(isActive ? styles.avatarActive : {}) }}>
              {profiles[contact.user_id]?.avatar_png
                ? <img src={`data:image/png;base64,${profiles[contact.user_id].avatar_png}`} alt="" style={{ width: "100%", height: "100%", objectFit: "cover", borderRadius: "inherit" }} />
                : contact.username.charAt(0).toUpperCase()}
            </div>
            <div className="contact-info" style={styles.info}>
              <span className="contact-name" style={styles.name} title={`${contact.username} · ${contact.user_id}`}>{tab === "chats" && preference.pinned ? "📌 " : ""}{aliases[contact.user_id] || profiles[contact.user_id]?.display_name || contact.username}</span>
              {tab === "chats" ? <span style={styles.trust} title={summary}>{summary}</span>
                : <span style={{ ...styles.trust, color: trust.color }}>{trust.text}</span>}
            </div>
            {tab === "chats" && <div className="contact-actions" onClick={event => event.stopPropagation()} onKeyDown={event => event.stopPropagation()}><ActionMenu label={`管理会话 ${contact.username}`}>
              <button disabled={!preferencesReady} aria-label={`${preference.pinned ? "取消置顶" : "置顶"} ${contact.username}`} onClick={() => onFlagsChange(contact.user_id, { ...preference, pinned: !preference.pinned })}>{preference.pinned ? "取消置顶" : "置顶"}</button>
              <button disabled={!preferencesReady} aria-label={`${preference.archived ? "取消归档" : "归档"} ${contact.username}`} onClick={() => onFlagsChange(contact.user_id, { ...preference, archived: !preference.archived })}>{preference.archived ? "移回聊天" : "归档"}</button>
              <button disabled={!preferencesReady} aria-pressed={!!muted[contact.user_id]} onClick={() => onMutedChange(contact.user_id, !muted[contact.user_id])}>{muted[contact.user_id] ? "取消静音" : "静音"}</button>
            </ActionMenu></div>}
            {tab === "chats" && preview && <div className="contact-meta" style={{ marginLeft: "auto", textAlign: "right", flexShrink: 0, fontSize: 11 }}>
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
    width: "34px",
    height: "34px",
    borderRadius: "var(--radius-md)",
    backgroundColor: "var(--accent-soft)",
    borderWidth: "1px",
    borderStyle: "solid",
    borderColor: "var(--border)",
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
