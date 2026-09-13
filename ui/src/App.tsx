import { useState, useEffect, useRef } from "react";
import { useConversationPreferences } from "./hooks/useConversationPreferences";
import Login from "./components/Login";
import Chat from "./components/Chat";
import ContactList from "./components/ContactList";
import ContactDetail from "./components/ContactDetail";
import AddContact from "./components/AddContact";
import StorageManager from "./components/StorageManager";
import { useDesktop } from "./hooks/useDesktop";
import type { SidebarTab } from "./components/ContactList";
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
  const preferences = useConversationPreferences(session);
  const { drafts } = preferences;
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [activeConversation, setActiveConversation] = useState<string | null>(
    null
  );
  const [sidebarTab, setSidebarTab] = useState<SidebarTab>("chats");
  const [selectedContact, setSelectedContact] = useState<string | null>(null);
  const [showAddContact, setShowAddContact] = useState(false);
  const [showStorage, setShowStorage] = useState(false);
  const { getContacts, loadKeypair, saveKeypair, refreshSession, connectRelay, signOut, disconnect, pollMessages, syncMessageOperations } = useDesktop();
  const [loading, setLoading] = useState(true);
  const [connection, setConnection] = useState("connecting");
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [startupError, setStartupError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const connectionWork = useRef<Promise<void>>(Promise.resolve());
  const [relayBatch, setRelayBatch] = useState<RelayBatch | null>(null);

  // One serialized pump owns reconnect and polling; renders never overlap requests.
  useEffect(() => {
    if (!session) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    let current = session;
    let failures = 0;
    let seq = 0;
    let needsConnect = true;
    const schedule = (delay: number) => { if (active) timer = setTimeout(tick, delay); };
    async function pump() {
      if (!active) return;
      try {
        if (needsConnect) {
          setConnection(failures ? "reconnecting" : "connecting");
          try {
            await connectRelay(current.serverUrl, current.user_id, current.token, current.deviceId);
          } catch (error) {
            if (!active) return;
            if (!String(error).includes("Authentication failed")) throw error;
            if (!current.refreshToken) { setConnection("auth_required"); setConnectionError("登录已失效，请重新登录；本地历史仍可查看。"); return; }
            let refreshed: RegisterResult;
            try { refreshed = await refreshSession(current.serverUrl, current.refreshToken); }
            catch (refreshError) {
              if (!active) return;
              if (/401|403/.test(String(refreshError))) {
                setConnection("auth_required"); setConnectionError("登录已失效或设备已撤销，请重新登录。"); return;
              }
              throw refreshError;
            }
            if (!active) return;
            current = { ...current, token: refreshed.access_token ?? refreshed.token,
              refreshToken: refreshed.refresh_token ?? current.refreshToken };
            await saveKeypair({ user_id: current.user_id, token: current.token,
              refresh_token: current.refreshToken, device_id: current.deviceId, server_url: current.serverUrl,
              public_key: current.publicKey, secret_key: current.secretKey,
              ed25519_pk: current.ed25519Pk, ed25519_sk: current.ed25519Sk });
            if (!active) return;
            setSession(previous => previous?.user_id === current.user_id ? current : previous);
            await connectRelay(current.serverUrl, current.user_id, current.token, current.deviceId);
          }
          if (!active) return;
          needsConnect = false;
        }
        const result = await pollMessages();
        if (!active) return;
        // Deliver the persisted message batch even when operation sync later fails.
        if (result.messages.length || result.events.length) setRelayBatch({ seq: ++seq, ...result });
        const operationChanges = await syncMessageOperations();
        if (!active) return;
        setConnection("online"); setConnectionError(null); failures = 0;
        if (operationChanges) setRelayBatch({ seq: ++seq, ...result });
        schedule(1000);
      } catch (error) {
        if (!active) return;
        needsConnect = true;
        failures += 1;
        const delay = Math.min(30000, 1000 * 2 ** Math.min(failures - 1, 5));
        setConnection("offline");
        setConnectionError(`连接暂不可用，${delay / 1000} 秒后重试。${String(error)}`);
        schedule(delay);
      }
    }
    function tick() {
      connectionWork.current = connectionWork.current.catch(() => {}).then(pump);
    }
    tick();
    return () => { active = false; clearTimeout(timer); };
  }, [session?.user_id, session?.deviceId, session?.serverUrl, retry]);

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
        setSession(base);
      })
      .catch((error) => {
        if (!String(error).includes("No saved keypair")) setStartupError(`无法读取保存的会话：${String(error)}`);
      })
      .finally(() => setLoading(false));
  }, []);

  async function handleLogout() {
    setLoading(true);
    try { await preferences.flush(); }
    catch { setLoading(false); return; }
    setSession(null);
    await connectionWork.current.catch(() => {});
    try {
      await disconnect();
    } catch {}
    try {
      const warning = await signOut();
      setStartupError(warning);
    } catch (error) { setStartupError(`退出处理未完成：${String(error)}。请勿删除密钥文件。`); }
    setSession(null);
    setContacts([]);
    setActiveConversation(null);
    setSelectedContact(null);
    setSidebarTab("chats");
    setLoading(false);
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
    return <><div role="alert">{startupError}</div><Login onLogin={handleLogin} /></>;
  }

  const detailContact = contacts.find((c) => c.user_id === selectedContact) ?? null;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh" }}>
      <div role="status" style={{ padding: "6px 12px", background: "var(--surface)", color: "var(--text-muted)", fontSize: 12 }}>
        {{ online: "已连接", connecting: "正在连接…", reconnecting: "正在重连…", offline: "离线", auth_required: "需要重新登录" }[connection]}
        {connectionError && <span> · {connectionError}</span>}
        {connection === "auth_required"
          ? <button onClick={() => { void preferences.flush().then(() => setSession(null)).catch(() => {}); }}>重新登录</button>
          : connection !== "online" && <button onClick={() => setRetry(value => value + 1)}>立即重连</button>}
      </div>
      {preferences.ready && <div role="status" style={{ padding: "2px 12px", fontSize: 12 }}>{preferences.saving ? "会话更改保存中，请稍候再关闭窗口" : "会话更改已保存到本机"}</div>}
      {preferences.error && <div role="alert">{preferences.error} <button onClick={() => { void preferences.retry().catch(() => {}); }}>重试</button></div>}
    <div className="app-shell" style={{ ...styles.layout, flex: 1, minHeight: 0 }}>
      <ContactList
        key={session.user_id}
        userId={session.user_id}
        secretKey={session.secretKey}
        signingPublicKey={session.ed25519Pk}
        contacts={contacts}
        flags={preferences.flags}
        drafts={drafts}
        preferencesReady={preferences.ready}
        onFlagsChange={(id, flags) => { void preferences.saveFlags(id, flags).catch(() => {}); }}
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
      ) : !preferences.ready ? <div role="status">正在恢复会话设置和草稿…</div> : (
        <Chat
          key={`${session.user_id}:${activeConversation}`}
          draft={drafts[activeConversation ?? ""] ?? { text: "" }}
          onForward={async (peerId, draft) => {
            const previous = drafts[peerId];
            if (previous && (previous.text || previous.messageId || previous.reply || previous.forwarded)) throw new Error("目标会话已有草稿，请先发送或清空，转发不会覆盖它。");
            await preferences.saveDraft(peerId, draft);
            setActiveConversation(peerId);
            setSidebarTab("chats");
          }}
          onDraftChange={(draft) => activeConversation ? preferences.saveDraft(activeConversation, draft) : Promise.resolve()}
          online={connection === "online"}
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
      )}
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
};
