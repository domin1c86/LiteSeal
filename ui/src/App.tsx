import { useState } from "react";
import Login from "./components/Login";
import Chat from "./components/Chat";
import ContactList from "./components/ContactList";
import type { RegisterResult, User, Conversation } from "./types";

interface Session {
  user_id: string;
  token: string;
  serverUrl: string;
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [contacts] = useState<User[]>([]);
  const [conversations] = useState<Conversation[]>([]);
  const [activeConversation, setActiveConversation] = useState<string | null>(
    null
  );

  function handleLogin(result: RegisterResult & { serverUrl: string }) {
    setSession({
      user_id: result.user_id,
      token: result.token,
      serverUrl: result.serverUrl,
    });
  }

  if (!session) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div style={styles.layout}>
      <ContactList
        contacts={contacts}
        conversations={conversations}
        activeConversation={activeConversation}
        onSelect={setActiveConversation}
      />
      <Chat
        conversationId={activeConversation}
        userId={session.user_id}
        token={session.token}
        serverUrl={session.serverUrl}
      />
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
