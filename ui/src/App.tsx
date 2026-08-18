import { useState, useEffect, useCallback } from "react";
import Login from "./components/Login";
import Chat from "./components/Chat";
import ContactList from "./components/ContactList";
import ContactDetail from "./components/ContactDetail";
import AddContact from "./components/AddContact";
import StorageManager from "./components/StorageManager";
import { useTauri } from "./hooks/useTauri";
import type { SidebarTab } from "./components/ContactList";
import type { Contact, DisplayMessage, RelayEvent, SessionView } from "./types";

export interface RelayBatch {
  seq: number;
  messages: DisplayMessage[];
  events: RelayEvent[];
}

export default function App() {
  const [session, setSession] = useState<SessionView | null>(null);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [activeConversation, setActiveConversation] = useState<string | null>(
    null
  );
  const [sidebarTab, setSidebarTab] = useState<SidebarTab>("chats");
  const [selectedContact, setSelectedContact] = useState<string | null>(null);
  const [showAddContact, setShowAddContact] = useState(false);
  const [showStorage, setShowStorage] = useState(false);
  const { getContacts, bootstrap, logout, pollEvents } = useTauri();
  const [loading, setLoading] = useState(true);
  const [relayBatch, setRelayBatch] = useState<RelayBatch | null>(null);

  // Poll at the app level so incoming messages are acked and persisted even
  // when no conversation is open; Chat consumes batches for its conversation.
  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    let seq = 0;
    let timeout: number | undefined;
    const poll = async () => {
      try {
        const result = await pollEvents();
        if (result.messages.length > 0 || result.events.length > 0) {
          seq += 1;
          setRelayBatch({ seq, messages: result.messages, events: result.events });
        }
      } catch {
        // Offline sessions keep local history readable.
      }
      if (!cancelled) timeout = window.setTimeout(poll, 2000);
    };
    void poll();
    return () => {
      cancelled = true;
      if (timeout !== undefined) window.clearTimeout(timeout);
    };
  }, [session, pollEvents]);

  function handleLogin(activeSession: SessionView) {
    setSession(activeSession);
  }

  useEffect(() => {
    bootstrap()
      .then((state) => setSession(state.session))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [bootstrap]);

  async function handleLogout() {
    try {
      await logout();
    } catch {}
    setSession(null);
    setContacts([]);
    setActiveConversation(null);
    setSelectedContact(null);
    setSidebarTab("chats");
  }

  const refreshContacts = useCallback(() => {
    getContacts()
      .then(setContacts)
      .catch((err) => console.error("Failed to load contacts:", err));
  }, [getContacts]);

  useEffect(() => {
    if (!session) return;
    refreshContacts();
  }, [session, refreshContacts]);

  function handleContactAdded() {
    getContacts()
      .then(setContacts)
      .catch(console.error);
    setShowAddContact(false);
  }

  if (loading) {
    return (
      <div style={styles.loading}>
        <span style={styles.loadingWordmark}>
          liteseal<span style={styles.loadingCursor}>▌</span>
        </span>
      </div>
    );
  }

  if (!session) {
    return <Login onLogin={handleLogin} />;
  }

  const detailContact = contacts.find((c) => c.user_id === selectedContact) ?? null;

  return (
    <div className="app-shell" style={styles.layout}>
      {!session.connected && (
        <div style={styles.offlineBanner}>offline mode · sending and sync are paused</div>
      )}
      <ContactList
        contacts={contacts}
        activeConversation={sidebarTab === "chats" ? activeConversation : selectedContact}
        tab={sidebarTab}
        onTabChange={setSidebarTab}
        onSelect={(id) =>
          sidebarTab === "chats" ? setActiveConversation(id) : setSelectedContact(id)
        }
        onAddClick={() => setShowAddContact(true)}
        onStorageClick={() => setShowStorage(true)}
        onLogout={handleLogout}
      />
      {sidebarTab === "contacts" ? (
        detailContact ? (
          <ContactDetail
            contact={detailContact}
            onMessage={() => {
              setActiveConversation(detailContact.user_id);
              setSidebarTab("chats");
            }}
            onContactsChanged={refreshContacts}
          />
        ) : (
          <div style={styles.contactsEmpty}>
            <p style={styles.contactsEmptyText}>no contact selected</p>
          </div>
        )
      ) : (
        <Chat
          conversationId={activeConversation}
          userId={session.user_id}
          contacts={contacts}
          relayBatch={relayBatch}
          onContactsChanged={refreshContacts}
        />
      )}
      {showAddContact && (
        <AddContact
          userId={session.user_id}
          contacts={contacts}
          onClose={() => setShowAddContact(false)}
          onAdded={handleContactAdded}
        />
      )}
      {showStorage && (
        <StorageManager onClose={() => setShowStorage(false)} />
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  loading: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    height: "100vh",
    backgroundColor: "var(--workspace-bg)",
  },
  loadingWordmark: {
    fontFamily: "var(--font-mono)",
    fontSize: "18px",
    fontWeight: 600,
    letterSpacing: "-0.01em",
    color: "var(--text-muted)",
  },
  loadingCursor: {
    color: "var(--text-subtle)",
    fontWeight: 400,
  },
  layout: {
    display: "flex",
    height: "100vh",
    overflow: "hidden",
    backgroundColor: "var(--workspace-bg)",
    color: "var(--text)",
  },
  contactsEmpty: {
    flex: 1,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "var(--workspace-bg)",
  },
  contactsEmptyText: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    fontSize: "13px",
  },
  offlineBanner: {
    position: "fixed",
    top: "10px",
    left: "50%",
    transform: "translateX(-50%)",
    zIndex: 20,
    padding: "6px 10px",
    borderRadius: "var(--radius-md)",
    backgroundColor: "var(--surface)",
    border: "1px solid var(--border-strong)",
    color: "var(--text-muted)",
    fontFamily: "var(--font-mono)",
    fontSize: "11px",
  },
};
