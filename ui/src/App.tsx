import { useState, useEffect } from "react";
import Login from "./components/Login";
import Chat from "./components/Chat";
import ContactList from "./components/ContactList";
import AddContact from "./components/AddContact";
import StorageManager from "./components/StorageManager";
import { useTauri } from "./hooks/useTauri";
import type { RegisterResult, Contact, IncomingMessage, RelayEvent } from "./types";

export interface RelayBatch {
  seq: number;
  messages: IncomingMessage[];
  events: RelayEvent[];
}

interface Session {
  user_id: string;
  token: string;
  refreshToken: string;
  deviceId: string;
  serverUrl: string;
  publicKey: number[];
  secretKey: number[];
  ed25519Pk: number[];
  ed25519Sk: number[];
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [activeConversation, setActiveConversation] = useState<string | null>(
    null
  );
  const [showAddContact, setShowAddContact] = useState(false);
  const [showStorage, setShowStorage] = useState(false);
  const { getContacts, loadKeypair, saveKeypair, refreshSession, connectRelay, clearKeypair, disconnect, pollMessages } = useTauri();
  const [loading, setLoading] = useState(true);
  const [relayBatch, setRelayBatch] = useState<RelayBatch | null>(null);

  // Poll at the app level so incoming messages are acked and persisted even
  // when no conversation is open; Chat consumes batches for its conversation.
  useEffect(() => {
    if (!session) return;
    let seq = 0;
    const interval = setInterval(async () => {
      try {
        const result = await pollMessages();
        if (result.messages.length > 0 || result.events.length > 0) {
          seq += 1;
          setRelayBatch({ seq, messages: result.messages, events: result.events });
        }
      } catch {
        // not connected; ignore
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [session]);

  function handleLogin(result: RegisterResult & { serverUrl: string; publicKey: number[]; secretKey: number[]; ed25519Pk: number[]; ed25519Sk: number[] }) {
    setSession({
      user_id: result.user_id,
      token: result.access_token ?? result.token,
      refreshToken: result.refresh_token ?? "",
      deviceId: result.device_id ?? "",
      serverUrl: result.serverUrl,
      publicKey: result.publicKey,
      secretKey: result.secretKey,
      ed25519Pk: result.ed25519Pk,
      ed25519Sk: result.ed25519Sk,
    });
  }

  useEffect(() => {
    loadKeypair()
      .then(async (saved) => {
        const serverUrl = saved.server_url || "http://localhost:3000";
        const base: Session = {
          user_id: saved.user_id,
          token: saved.token,
          refreshToken: saved.refresh_token,
          deviceId: saved.device_id,
          serverUrl,
          publicKey: saved.public_key,
          secretKey: saved.secret_key,
          ed25519Pk: saved.ed25519_pk,
          ed25519Sk: saved.ed25519_sk,
        };
        if (!saved.token || !saved.device_id) {
          // Legacy keystore without a device binding cannot reconnect; force login.
          return;
        }
        try {
          await connectRelay(serverUrl, saved.user_id, saved.token, saved.device_id);
          setSession(base);
        } catch {
          // Access token likely expired (30 min TTL): rotate via refresh token.
          try {
            const r = await refreshSession(serverUrl, saved.refresh_token);
            const token = r.access_token ?? r.token;
            const refreshed = {
              ...saved,
              token,
              refresh_token: r.refresh_token ?? saved.refresh_token,
            };
            await saveKeypair(refreshed);
            await connectRelay(serverUrl, r.user_id, token, saved.device_id);
            setSession({ ...base, token, refreshToken: refreshed.refresh_token });
          } catch {
            // Server unreachable or refresh token stale: offline session so
            // local history stays readable; sending will surface errors.
            setSession(base);
          }
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  async function handleLogout() {
    try {
      await disconnect();
    } catch {}
    try {
      await clearKeypair();
    } catch {}
    setSession(null);
    setContacts([]);
    setActiveConversation(null);
  }

  function refreshContacts() {
    getContacts()
      .then(setContacts)
      .catch((err) => console.error("Failed to load contacts:", err));
  }

  useEffect(() => {
    if (!session) return;
    refreshContacts();
  }, [session]);

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

  return (
    <div className="app-shell" style={styles.layout}>
      <ContactList
        contacts={contacts}
        activeConversation={activeConversation}
        onSelect={setActiveConversation}
        onAddClick={() => setShowAddContact(true)}
        onStorageClick={() => setShowStorage(true)}
        onLogout={handleLogout}
      />
      <Chat
        conversationId={activeConversation}
        userId={session.user_id}
        deviceId={session.deviceId}
        token={session.token}
        serverUrl={session.serverUrl}
        secretKey={session.secretKey}
        signingKey={session.ed25519Sk}
        contacts={contacts}
        relayBatch={relayBatch}
        onContactsChanged={refreshContacts}
      />
      {showAddContact && (
        <AddContact
          serverUrl={session.serverUrl}
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
};
