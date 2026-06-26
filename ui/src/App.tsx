import { useState, useEffect } from "react";
import Login from "./components/Login";
import Chat from "./components/Chat";
import ContactList from "./components/ContactList";
import AddContact from "./components/AddContact";
import { useTauri } from "./hooks/useTauri";
import type { RegisterResult, Contact } from "./types";

interface Session {
  user_id: string;
  token: string;
  serverUrl: string;
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [activeConversation, setActiveConversation] = useState<string | null>(
    null
  );
  const [showAddContact, setShowAddContact] = useState(false);
  const { getContacts } = useTauri();

  function handleLogin(result: RegisterResult & { serverUrl: string }) {
    setSession({
      user_id: result.user_id,
      token: result.token,
      serverUrl: result.serverUrl,
    });
  }

  useEffect(() => {
    if (!session) return;
    getContacts()
      .then(setContacts)
      .catch((err) => console.error("Failed to load contacts:", err));
  }, [session]);

  function handleContactAdded() {
    getContacts()
      .then(setContacts)
      .catch(console.error);
    setShowAddContact(false);
  }

  if (!session) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div style={styles.layout}>
      <ContactList
        contacts={contacts}
        activeConversation={activeConversation}
        onSelect={setActiveConversation}
        onAddClick={() => setShowAddContact(true)}
      />
      <Chat
        conversationId={activeConversation}
        userId={session.user_id}
        token={session.token}
        serverUrl={session.serverUrl}
      />
      {showAddContact && (
        <AddContact
          serverUrl={session.serverUrl}
          onClose={() => setShowAddContact(false)}
          onAdded={handleContactAdded}
        />
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  layout: {
    display: "flex",
    height: "100vh",
    overflow: "hidden",
  },
};
