import { useState, useEffect } from "react";
import Login from "./components/Login";
import Chat from "./components/Chat";
import ContactList from "./components/ContactList";
import AddContact from "./components/AddContact";
import StorageManager from "./components/StorageManager";
import { useTauri } from "./hooks/useTauri";
import type { RegisterResult, Contact } from "./types";

interface Session {
  user_id: string;
  token: string;
  deviceId?: string;
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
  const { getContacts, loadKeypair, connectRelay, clearKeypair, disconnect } = useTauri();
  const [loading, setLoading] = useState(true);

  function handleLogin(result: RegisterResult & { serverUrl: string; publicKey: number[]; secretKey: number[]; ed25519Pk: number[]; ed25519Sk: number[] }) {
    setSession({
      user_id: result.user_id,
      token: result.access_token ?? result.token,
      deviceId: result.device_id,
      serverUrl: result.serverUrl,
      publicKey: result.publicKey,
      secretKey: result.secretKey,
      ed25519Pk: result.ed25519Pk,
      ed25519Sk: result.ed25519Sk,
    });
  }

  useEffect(() => {
    loadKeypair()
      .then(async ([userId, token, publicKey, secretKey, ed25519Pk, ed25519Sk]) => {
        const serverUrl = "http://localhost:3000";
        if (!token) {
          setSession({ user_id: userId, token, serverUrl, publicKey, secretKey, ed25519Pk, ed25519Sk });
          return;
        }
        try {
          const connectResult = await connectRelay(serverUrl, userId, token);
          if (connectResult.connected) {
            setSession({ user_id: userId, token, serverUrl, publicKey, secretKey, ed25519Pk, ed25519Sk });
          }
        } catch {
          setSession({ user_id: userId, token, serverUrl, publicKey, secretKey, ed25519Pk, ed25519Sk });
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
        Loading...
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
        token={session.token}
        serverUrl={session.serverUrl}
        secretKey={session.secretKey}
        contacts={contacts}
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
    color: "var(--text-muted)",
  },
  layout: {
    display: "flex",
    height: "100vh",
    overflow: "hidden",
    backgroundColor: "var(--workspace-bg)",
    color: "var(--text)",
  },
};
