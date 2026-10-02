import { getDesktopApi } from "./lib/desktopApi";
import { useState, useEffect, useRef } from "react";
import { useConversationPreferences } from "./hooks/useConversationPreferences";
import { useOrganizer } from "./hooks/useOrganizer";
import OrganizerPanel from "./components/OrganizerPanel";
import AccountPanel from "./components/AccountPanel";
import GroupPanel from "./components/GroupPanel";
import Login from "./components/Login";
import Chat from "./components/Chat";
import ContactList from "./components/ContactList";
import ContactDetail from "./components/ContactDetail";
import AddContact from "./components/AddContact";
import StorageManager from "./components/StorageManager";
import NormalProfileHome from "./components/NormalProfileHome";
import NormalProfilePanel from "./components/NormalProfilePanel";
import type {NormalProfileSnapshot} from "../../electron/contracts";
import { useDesktop } from "./hooks/useDesktop";
import type { SidebarTab } from "./components/ContactList";
import type { RegisterResult, Contact, IncomingMessage, RelayEvent, PublicProfile } from "./types";

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
  ed25519Pk: number[];
}

export default function App(){
  const [view,setView]=useState<NormalProfileSnapshot|null>(null),[error,setError]=useState(""),[showProfiles,setShowProfiles]=useState(false);
  const refresh=useRef<()=>void>(()=>{});
  useEffect(()=>{let live=true,generation=0;const read=()=>{const n=++generation;setView(null);setError("");void getDesktopApi().get_normal_profile({}).then(next=>{if(live&&generation===n)setView(next);},failure=>{if(live&&generation===n)setError(String(failure));});};refresh.current=read;read();window.addEventListener("liteseal-normal-profile-changed",read);return()=>{live=false;generation++;window.removeEventListener("liteseal-normal-profile-changed",read);};},[]);
  if(error)return <main style={{padding:"24px",maxWidth:"840px",margin:"0 auto",overflowWrap:"anywhere"}}><section><p role="alert">无法恢复选中档案：{error}</p><button onClick={()=>refresh.current()}>重新查询档案</button><button onClick={()=>setShowProfiles(true)}>选择正常档案</button>{showProfiles&&<NormalProfilePanel onClose={()=>setShowProfiles(false)}/>}</section></main>;
  if(!view)return <div role="status">正在核对本机选中档案…</div>;
  if(view.error||view.selected?.target.kind==="join"||view.explicit&&!view.selected)return <NormalProfileHome key={`${view.generation}:${view.selected?.scope_fingerprint??"none"}`} view={view}/>;
  return <LegacyApp key={`${view.generation}:${view.selected?.scope_fingerprint??"unbound"}`}/>;
}

function LegacyApp() {
  const [session, setSession] = useState<Session | null>(null);
  const preferences = useConversationPreferences(session);
  const organizer = useOrganizer(session?.user_id);
  const [showOrganizer, setShowOrganizer] = useState(false);
  const [showAccount, setShowAccount] = useState(false);
  const [showGroups, setShowGroups] = useState(false);
  const [groupTarget, setGroupTarget] = useState<{ id: string; nonce: number } | null>(null);
  const [activeGroup, setActiveGroup] = useState<string | null>(null);
  const [groupBusy, setGroupBusy] = useState(false);
  const [groupAttention, setGroupAttention] = useState(0);
  const { drafts } = preferences;
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [profiles, setProfiles] = useState<Record<string, PublicProfile>>({});
  const [activeConversation, setActiveConversation] = useState<string | null>(
    null
  );
  const [sidebarTab, setSidebarTab] = useState<SidebarTab>("chats");
  const [selectedContact, setSelectedContact] = useState<string | null>(null);
  const [showAddContact, setShowAddContact] = useState(false);
  const [showStorage, setShowStorage] = useState(false);
  const { getContacts, loadIdentity, saveSession, refreshSession, connectRelay, signOut, disconnect, pollMessages, syncMessageOperations } = useDesktop();
  const [loading, setLoading] = useState(true);
  const [connection, setConnection] = useState("connecting");
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [startupError, setStartupError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const connectionWork = useRef<Promise<void>>(Promise.resolve());
  const [relayBatch, setRelayBatch] = useState<RelayBatch | null>(null);
  const [typingEnabled, setTypingEnabled] = useState(false);
  const [scheduledRevision, setScheduledRevision] = useState(0);
  const [scheduledError, setScheduledError] = useState<string | null>(null);
  const [scheduledAttention, setScheduledAttention] = useState<string[]>([]);
  useEffect(() => { setGroupTarget(null); setActiveGroup(null); }, [session?.user_id, session?.deviceId, session?.serverUrl]);
  useEffect(() => {
    if (!session) { setGroupAttention(0); return; }
    let active = true;
    const refresh = () => { void getDesktopApi().get_groups({}).then(snapshot => { if (active) setGroupAttention(snapshot.invitations.length + snapshot.groups.reduce((sum, group) => sum + group.unread, 0)); }).catch(() => {}); };
    refresh(); window.addEventListener("liteseal-groups-changed",refresh); const timer=setInterval(refresh,10000);
    return () => {active=false;clearInterval(timer);window.removeEventListener("liteseal-groups-changed",refresh);};
  }, [session?.user_id,session?.deviceId,session?.serverUrl]);

  useEffect(() => {
    if (!session) return;
    let active = true;
    async function refresh() {
      try {
        const tasks = await getDesktopApi().list_scheduled_messages({});
        if (active) { setScheduledAttention([...new Set(tasks.filter(task=>["missed","failed","needs_retry"].includes(task.state)).map(task=>task.peer_id))]); setScheduledError(null); }
      } catch (error) { if (active) setScheduledError(String(error)); }
    }
    const changed=()=>{setScheduledRevision(value=>value+1);void refresh();};
    void refresh();const timer=setInterval(refresh,10000);
    window.addEventListener("liteseal-scheduled-changed",changed);
    return () => { active=false;clearInterval(timer);window.removeEventListener("liteseal-scheduled-changed",changed); };
  }, [session?.user_id, session?.deviceId]);

  useEffect(() => {
    setScheduledAttention([]); setScheduledError(null);
    if (!session?.user_id) { setTypingEnabled(false); return; }
    let active = true;
    void getDesktopApi().get_typing_enabled({}).then(value => { if (active) setTypingEnabled(value); })
      .catch(() => { if (active) setTypingEnabled(false); });
    return () => { active = false; };
  }, [session?.user_id]);

  useEffect(() => {
    if (!window.desktop) return;
    let active = true;
    const takeTarget = async () => {
      try {
        const target = await getDesktopApi().take_notification_target({});
        if (active && target && target.userId === session?.user_id) {
          if (target.deviceId !== session?.deviceId || new URL(target.serverUrl).toString().replace(/\/+$/, "") !== new URL(session.serverUrl).toString().replace(/\/+$/, "")) return;
          if (target.kind === "group") { setGroupTarget({ id: target.groupId, nonce: Date.now() }); setShowGroups(true); }
          else if (!groupBusy) { setShowGroups(false); setActiveConversation(target.peerId); setSidebarTab("chats"); }
        }
      } catch { /* Notification routing never interrupts the message pump. */ }
    };
    void getDesktopApi().set_notification_context({ userId: session?.user_id ?? null,
      activePeerId: !showGroups && sidebarTab === "chats" ? activeConversation : null, activeGroupId: showGroups ? activeGroup : null }).catch(() => {});
    const timer = setInterval(takeTarget, 500);
    window.addEventListener("focus", takeTarget);
    return () => { active = false; clearInterval(timer); window.removeEventListener("focus", takeTarget); };
  }, [session?.user_id, session?.serverUrl, session?.deviceId, activeConversation, sidebarTab, showGroups, activeGroup, groupBusy]);

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
            await saveSession({ userId: current.user_id, token: current.token,
              refreshToken: current.refreshToken, deviceId: current.deviceId, serverUrl: current.serverUrl });
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
        const auxiliary = await Promise.allSettled([
          syncMessageOperations(), getDesktopApi().sync_reactions({}), getDesktopApi().sync_read_receipts({}),
        ]);
        if (!active) return;
        const auxiliaryError = auxiliary.filter(item => item.status === "rejected")
          .map(item => String(item.reason)).join("；");
        setConnection("online"); setConnectionError(auxiliaryError ? `附加消息状态同步失败：${auxiliaryError}` : null); failures = 0;
        if (auxiliary.some(item => item.status === "fulfilled" && item.value > 0)) setRelayBatch({ seq: ++seq, ...result });
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

  function handleLogin(result: RegisterResult & { serverUrl: string; publicKey: number[]; ed25519Pk: number[] }) {
    setSession({
      user_id: result.user_id,
      token: result.access_token ?? result.token,
      refreshToken: result.refresh_token ?? "",
      deviceId: result.device_id ?? "",
      serverUrl: result.serverUrl,
      publicKey: result.publicKey,
      ed25519Pk: result.ed25519Pk,
    });
  }

  useEffect(() => {
    loadIdentity()
      .then(async (saved) => {
        const serverUrl = saved.server_url || "http://localhost:3000";
        const base: Session = {
          user_id: saved.user_id,
          token: saved.token,
          refreshToken: saved.refresh_token,
          deviceId: saved.device_id,
          serverUrl,
          publicKey: saved.public_key,
          ed25519Pk: saved.ed25519_pk,
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
    if (organizer.busy || groupBusy) return;
    setLoading(true);
    try { await preferences.flush(); }
    catch { setLoading(false); return; }
    setSession(null);
    setShowGroups(false);
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

  useEffect(() => {
    let active = true;
    if (!session || !contacts.length) { setProfiles({}); return; }
    void Promise.allSettled(contacts.map(contact => getDesktopApi().get_public_profile({ userId: contact.user_id }))).then(results => {
      if (!active) return;
      const next: Record<string, PublicProfile> = {};
      results.forEach((result, index) => { if (result.status === "fulfilled") next[contacts[index].user_id] = result.value; });
      setProfiles(next);
    });
    return () => { active = false; };
  }, [session?.user_id, contacts]);

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
    <div className="app-frame">
      <div className="app-toolbar">
        <button onClick={() => setShowAccount(true)}>账号与消息请求</button>
        <button disabled={groupBusy} onClick={() => { void preferences.flush().then(() => setShowGroups(true)).catch(error => setConnectionError(String(error))); }}>群聊{groupAttention > 0 ? ` (${groupAttention})` : ""}</button>
        <button disabled={groupBusy} onClick={() => { void preferences.flush().then(() => getDesktopApi().lock_app({})).catch(error => setConnectionError(String(error))); }}>锁定</button>
        <span role="status" className="connection-state" data-state={connection}>{{ online: "已连接", connecting: "正在连接…", reconnecting: "正在重连…", offline: "离线", auth_required: "需要重新登录" }[connection]}</span>
        {connectionError && <span> · {connectionError}</span>}
        {scheduledError && <span role="alert"> · 定时任务检查失败：{scheduledError}</span>}
        {!!scheduledAttention.length && <span role="status"> · 定时任务待处理：{scheduledAttention.map(peer=><button key={peer} onClick={()=>{setActiveConversation(peer);setSidebarTab("chats");}}>{contacts.find(contact=>contact.user_id===peer)?.username ?? peer.slice(0,8)}</button>)}</span>}
        {connection === "auth_required"
          ? <button onClick={() => { void preferences.flush().then(() => setSession(null)).catch(() => {}); }}>重新登录</button>
          : connection !== "online" && <button onClick={() => setRetry(value => value + 1)}>立即重连</button>}
      </div>
      {preferences.ready && <div className="save-status" role="status">{preferences.saving ? "会话更改保存中，请稍候再关闭窗口" : "会话更改已保存到本机"}</div>}
      {preferences.error && <div role="alert">{preferences.error} <button onClick={() => { void preferences.retry().catch(() => {}); }}>重试</button></div>}
    <div className="app-shell" style={{ ...styles.layout, flex: 1, minHeight: 0 }}>
      {showGroups ? <GroupPanel key={`${session.user_id}:${session.deviceId}:${session.serverUrl}`} userId={session.user_id} target={groupTarget} onActiveChange={setActiveGroup} contacts={contacts} obscured={showAccount || showStorage || showOrganizer || showAddContact} onBusyChange={setGroupBusy} onClose={() => { setShowGroups(false); setGroupTarget(null); }} /> : <>
      <ContactList
        key={session.user_id}
        userId={session.user_id}
        signingPublicKey={session.ed25519Pk}
        contacts={contacts}
        profiles={profiles}
        flags={preferences.flags}
        aliases={organizer.value.aliases}
        lists={organizer.value.lists}
        onOrganizer={() => { if (organizer.ready) setShowOrganizer(true); }}
        muted={preferences.muted}
        onMutedChange={(id, value) => { void preferences.saveMuted(id, value).catch(() => {}); }}
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
            key={detailContact.user_id}
            contact={detailContact}
            profile={profiles[detailContact.user_id]}
            alias={organizer.value.aliases[detailContact.user_id] ?? ""}
            onAlias={alias => organizer.update(value => ({ ...value, aliases: { ...value.aliases, [detailContact.user_id]: alias } }))}
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
          onFavorite={messageId => organizer.update(value => ({ ...value, favorites: value.favorites.some(item => item.messageId === messageId) ? value.favorites : [...value.favorites, { messageId, peerId: activeConversation! }] }))}
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
          typingEnabled={typingEnabled}
          scheduledRevision={scheduledRevision}
          obscured={showAddContact || showStorage || showOrganizer || showAccount}
          conversationId={activeConversation}
          userId={session.user_id}
          deviceId={session.deviceId}
          token={session.token}
          serverUrl={session.serverUrl}
          contacts={contacts}
          relayBatch={relayBatch}
          onContactsChanged={refreshContacts}
        />
      )}
      </>}
      {showAddContact && (
        <AddContact
          serverUrl={session.serverUrl}
          token={session.token}
          userId={session.user_id}
          contacts={contacts}
          onClose={() => setShowAddContact(false)}
          onAdded={handleContactAdded}
        />
      )}
      {showStorage && (
        <StorageManager onClose={() => setShowStorage(false)} />
      )}
      {organizer.error && <p role="alert">本机整理数据不可用：{organizer.error}</p>}
      {showOrganizer && organizer.ready && <OrganizerPanel organizer={organizer} userId={session.user_id} contacts={contacts}
        onClose={() => setShowOrganizer(false)} onOpen={peerId => { setActiveConversation(peerId); setSidebarTab("chats"); }} />}
      {showAccount && <AccountPanel userId={session.user_id} contacts={contacts} typingEnabled={typingEnabled} onTypingEnabledChange={setTypingEnabled} onClose={() => setShowAccount(false)} onContactsChanged={refreshContacts} onLogout={() => { setShowAccount(false); void handleLogout(); }} />}
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
