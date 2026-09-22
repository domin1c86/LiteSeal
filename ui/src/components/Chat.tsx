import { latestOperations } from "../lib/messageOperations";
import { deliveryStatusLabel } from "../lib/deliveryStatus";
import { decodeContent, encodeContent } from "../lib/messageContent";
import { useState, useEffect, useRef, useLayoutEffect } from "react";
import { useDesktop } from "../hooks/useDesktop";
import { dmConversationId } from "../lib/conversation";
import { trustLabel } from "./ContactList";
import type { RelayBatch } from "../App";
import type { Draft, MessageOperation, Message, IncomingMessage, Contact, RelayEvent } from "../types";

interface ChatProps {
  draft: Draft;
  onForward: (peerId: string, draft: Draft) => Promise<void>;
  onDraftChange: (draft: Draft) => Promise<void>;
  online: boolean;
  conversationId: string | null;
  userId: string;
  deviceId: string;
  token: string;
  serverUrl: string;
  contacts: Contact[];
  relayBatch: RelayBatch | null;
  onContactsChanged: () => void;
}

export default function Chat({ draft, onDraftChange, onForward, online, conversationId, userId, deviceId, token, serverUrl, contacts, relayBatch, onContactsChanged }: ChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const input = draft.text;
  const [operationsLoaded, setOperationsLoaded] = useState(false);
  const [operations, setOperations] = useState<MessageOperation[]>([]);
  const [operationError, setOperationError] = useState<string | null>(null);
  const [operationRefresh, setOperationRefresh] = useState(0);
  const [operationBusy, setOperationBusy] = useState(false);
  const [operationDialog, setOperationDialog] = useState<{ targetId: string; kind: "edit" | "revoke"; content: ReturnType<typeof decodeContent>; revision: number } | null>(null);
  const [editedText, setEditedText] = useState("");
  const { getMessageOperations, submitMessageOperation, syncMessageOperations } = useDesktop();
  const latest = latestOperations(operations);
  const deletedIds = useRef(new Set<string>());
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const { deleteMessageLocally, getLocallyDeletedIds } = useDesktop();
  const { copyMessageText } = useDesktop();
  const [actionStatus, setActionStatus] = useState<string | null>(null);
  const [forwardDraft, setForwardDraft] = useState<Draft | null>(null);
  const [forwardTarget, setForwardTarget] = useState("");
  const [forwarding, setForwarding] = useState(false);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const [hasOlder, setHasOlder] = useState(false);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const cursor = useRef<{ timestamp: number; id: string } | null>(null);
  const historyGeneration = useRef(0);
  const scrollArea = useRef<HTMLDivElement>(null);
  const scrollRestore = useRef<{ height: number; top: number } | null>(null);
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { retryMessage, sendMessage, getUserDevices, getLocalMessagePage, encryptMessage, decryptMessage, signMessage, setContactTrust } = useDesktop();
  const activeContact = contacts.find((c) => c.user_id === conversationId);
  // conversationId prop is the peer's user id; storage/relay use the canonical DM id.
  const storageConversationId = conversationId ? dmConversationId(userId, conversationId) : null;

  const { markMessagesRead } = useDesktop();
  const [readError, setReadError] = useState<string | null>(null);
  useEffect(() => {
    if (!operationsLoaded) return;
    let active = true;
    let busy = false;
    const mark = async () => {
      if (busy || !document.hasFocus() || document.visibilityState !== "visible") return;
      busy = true;
      try {
        const ids = messages.filter(message => message.sender_id !== userId).map(message => message.id);
        for (let offset = 0; offset < ids.length && active; offset += 1000) {
          await markMessagesRead(userId, ids.slice(offset, offset + 1000));
        }
        if (active) setReadError(null);
      } catch (error) { if (active) setReadError(`未读状态保存失败：${String(error)}`); }
      finally { busy = false; }
    };
    void mark();
    window.addEventListener("focus", mark);
    document.addEventListener("visibilitychange", mark);
    return () => { active = false; window.removeEventListener("focus", mark); document.removeEventListener("visibilitychange", mark); };
  }, [messages, userId, operationsLoaded]);

  useEffect(() => {
    if (!storageConversationId) return;
    let active = true;
    getMessageOperations(storageConversationId).then(result => {
      if (active) { setOperations(result); setOperationError(null); setOperationsLoaded(true); }
    }).catch(error => { if (active) { setOperationError(String(error)); setOperationsLoaded(false); } });
    return () => { active = false; };
  }, [storageConversationId, relayBatch, contacts, operationRefresh, messages.length]);

  function incomingToMessage(m: IncomingMessage, ciphertext: number[]): Message {
    return {
      id: m.message_id,
      conversation_id: m.conversation_id,
      sender_id: m.from,
      sender_device_id: m.sender_device_id,
      sender_seq: m.sender_seq,
      timestamp: m.timestamp,
      message_type: "text",
      ciphertext,
      signature: m.signature,
      prev_hash: m.prev_hash ?? [],
      local_state: m.local_state ?? "received",
    };
  }

  async function decodeHistory(items: Message[]) {
    return Promise.all(items.map(async (message) => {
      const peer = contacts.find(contact => contact.user_id === (message.sender_id === userId ? conversationId : message.sender_id));
      if (!peer) return { ...message, ciphertext: Array.from(new TextEncoder().encode("[sender not in contacts]")) };
      try {
        const plaintext = await decryptMessage(message.ciphertext, peer.public_key);
        return { ...message, ciphertext: plaintext };
      } catch { return { ...message, ciphertext: Array.from(new TextEncoder().encode("[encrypted]")) }; }
    }));
  }

  useEffect(() => {
    if (!storageConversationId) return;
    let active = true;
    historyGeneration.current += 1;
    setLoadingOlder(false);
    setLoading(true); setHistoryError(null); cursor.current = null;
    Promise.all([getLocalMessagePage(storageConversationId, 51, undefined, undefined, userId), getLocallyDeletedIds(userId, storageConversationId)]).then(async ([rows, removed]) => {
      if (!active) return;
      for (const id of removed) deletedIds.current.add(id);
      const page = rows.slice(0, 50);
      const decoded = await decodeHistory([...page].reverse());
      if (!active) return;
      cursor.current = page.length ? page[page.length - 1] : null;
      setHasOlder(rows.length > 50);
      setMessages(previous => {
        const known = new Set(decoded.map(item => item.id));
        return [...decoded, ...previous.filter(item => !known.has(item.id))].filter(item => !deletedIds.current.has(item.id)).sort((a, b) => a.timestamp - b.timestamp || a.id.localeCompare(b.id));
      });
    }).catch(error => { if (active) setHistoryError(String(error)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [storageConversationId, userId, contacts]);

  async function loadOlder() {
    if (!storageConversationId || !cursor.current || loadingOlder || loading) return;
    const generation = historyGeneration.current;
    setLoadingOlder(true); setHistoryError(null);
    try {
      const rows = await getLocalMessagePage(storageConversationId, 51, cursor.current.timestamp, cursor.current.id, userId);
      const page = rows.slice(0, 50);
      const decoded = await decodeHistory([...page].reverse());
      if (!alive.current || generation !== historyGeneration.current) return;
      cursor.current = page.length ? page[page.length - 1] : cursor.current;
      setHasOlder(rows.length > 50);
      const area = scrollArea.current;
      if (area) scrollRestore.current = { height: area.scrollHeight, top: area.scrollTop };
      setMessages(previous => {
        const known = new Set(previous.map(item => item.id));
        return [...decoded.filter(item => !known.has(item.id)), ...previous].filter(item => !deletedIds.current.has(item.id));
      });
    } catch (error) { if (alive.current && generation === historyGeneration.current) setHistoryError(String(error)); }
    finally { if (alive.current && generation === historyGeneration.current) setLoadingOlder(false); }
  }

  useEffect(() => {
    if (!conversationId || !relayBatch) return;
    (async () => {
      try {
        applyRelayEvents(relayBatch.events);
        const incoming: IncomingMessage[] = relayBatch.messages;
        if (incoming.length > 0 && storageConversationId) {
          const removed = await getLocallyDeletedIds(userId, storageConversationId);
          if (!alive.current) return;
          for (const id of removed) deletedIds.current.add(id);
          const decoded = await Promise.all(
            incoming
              .filter((m) => m.conversation_id === storageConversationId && !deletedIds.current.has(m.message_id))
              .map(async (m) => {
                const sender = contacts.find((c) => c.user_id === m.from);
                if (!sender) {
                  return incomingToMessage(
                    m,
                    Array.from(new TextEncoder().encode("[sender not in contacts]"))
                  );
                }

                // Rust verified the signed envelope before storing and relaying it here.
                if (m.local_state === "integrity_failed") {
                  return incomingToMessage(
                    m,
                    Array.from(new TextEncoder().encode("[integrity check failed]"))
                  );
                }

                try {
                  const plaintext = await decryptMessage(m.ciphertext, sender.public_key);
                  return incomingToMessage(m, plaintext);
                } catch {
                  return incomingToMessage(
                    m,
                    Array.from(new TextEncoder().encode("[decryption failed]"))
                  );
                }
              })
          );
          setMessages((prev) => {
            const seen = new Set(prev.map((msg) => msg.id));
            const updates = new Map(decoded.map((msg) => [msg.id, msg]));
            return [...prev.map((msg) => updates.get(msg.id) ?? msg), ...decoded.filter((msg) => !seen.has(msg.id))].filter(msg => !deletedIds.current.has(msg.id));
          });
        }
      } catch {
        // ignore batch processing errors
      }
    })();
  }, [relayBatch]);

  function applyRelayEvents(events: RelayEvent[]) {
    if (events.length === 0) return;

    const stateByMessage = new Map<string, Message["local_state"]>();
    for (const event of events) {
      if (event.type === "delivered") {
        stateByMessage.set(event.message_id, "delivered");
      } else if (event.type === "offline") {
        stateByMessage.set(event.message_id, "offline");
      } else if (event.type === "delivery_update") {
        stateByMessage.set(event.message_id, event.status);
      } else if (event.type === "error") {
        setSendError(event.message);
      }
    }

    if (stateByMessage.size > 0) {
      setMessages((prev) =>
        prev.map((msg) =>
          stateByMessage.has(msg.id)
            ? { ...msg, local_state: stateByMessage.get(msg.id) }
            : msg
        )
      );
    }
  }

  useLayoutEffect(() => {
    const area = scrollArea.current;
    if (area && scrollRestore.current) {
      area.scrollTop = scrollRestore.current.top + area.scrollHeight - scrollRestore.current.height;
      scrollRestore.current = null;
    } else { messagesEndRef.current?.scrollIntoView({ behavior: "smooth" }); }
  }, [messages]);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    if (!online || sending || !input.trim() || !conversationId) return;

    const text = input.trim();
    const messageId = draft.messageId ?? crypto.randomUUID();
    setSendError(null);
    setSending(true);

    try {
      await onDraftChange({ ...draft, text: input, messageId });
      const contact = contacts.find((c) => c.user_id === conversationId);
      if (!contact) throw new Error("Recipient not found in contacts");

      const devices = (await getUserDevices(serverUrl, conversationId, token)).filter(
        (d) => !d.revoked && d.public_key.length === 32
      );
      if (devices.length === 0) throw new Error("Recipient has no active devices");

      const encoder = new TextEncoder();
      const plaintext = Array.from(encoder.encode(encodeContent({ text, reply: draft.reply, forwarded: draft.forwarded })));

      // Local copy encrypted to the contact's stored key so history stays readable.
      const ciphertext = await encryptMessage(plaintext, contact.public_key);
      const signature = await signMessage(ciphertext);

      const payloads = [];
      for (const device of devices) {
        const deviceCiphertext = await encryptMessage(plaintext, device.public_key);
        const deviceSignature = await signMessage(deviceCiphertext);
        payloads.push({
          recipient_user_id: conversationId,
          recipient_device_id: device.id,
          ciphertext: deviceCiphertext,
          signature: deviceSignature,
        });
      }

      const result = await sendMessage(
        userId,
        ciphertext,
        signature,
        deviceId,
        payloads,
        messageId
      );

      await onDraftChange({ text: "" });
      if (!alive.current) return;
      setMessages((prev) => [
        ...prev.filter(message => message.id !== result.message_id),
        {
          id: result.message_id,
          conversation_id: storageConversationId ?? conversationId,
          sender_id: userId,
          sender_device_id: deviceId,
          sender_seq: 0,
          timestamp: Date.now(),
          message_type: "text",
          local_state: "pending",
          ciphertext: plaintext,
          signature: [],
          prev_hash: [],
        },
      ]);
    } catch (err) {
      console.error("Send failed:", err);
      setSendError(String(err));
    } finally {
      setSending(false);
    }
  }

  if (!conversationId) {
    return (
      <div style={styles.empty}>
        <p style={styles.emptyText}>no conversation selected</p>
        <p style={styles.emptyHint}>messages are end-to-end encrypted</p>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div className="chat-header" style={styles.header}>
        <div style={styles.headerInner}>
          <div style={styles.headerText}>
            <span style={styles.headerTitle}>{activeContact?.username ?? "Conversation"}</span>
            <span
              style={{
                ...styles.headerMeta,
                color: activeContact ? trustLabel(activeContact).color : "var(--text-subtle)",
              }}
            >
              {activeContact
                ? `${trustLabel(activeContact).text}${activeContact.fingerprint ? ` · ${activeContact.fingerprint.match(/.{1,4}/g)?.join(" ")}` : ""}`
                : "end-to-end encrypted"}
            </span>
          </div>
          {activeContact && (
            <button
              className="outline-button"
              style={styles.verifyBtn}
              onClick={async () => {
                await setContactTrust(
                  activeContact.user_id,
                  activeContact.trust_state === "verified" ? "unverified" : "verified"
                );
                onContactsChanged();
              }}
            >
              {activeContact.trust_state === "verified" ? "Unverify" : "Verify"}
            </button>
          )}
        </div>
      </div>
      <div ref={scrollArea} className="chat-messages" style={styles.messages}>
        {hasOlder && <button disabled={loadingOlder || loading} onClick={loadOlder}>{loadingOlder ? "正在加载…" : "加载更早消息"}</button>}
        {historyError && <div role="alert">历史加载失败：{historyError}</div>}
        {loading && <p style={styles.loadingText}>loading…</p>}
        {!operationsLoaded && <p role="status">正在读取本机消息变更…</p>}
        {operationsLoaded && messages.map((msg) => {
          const isMine = msg.sender_id === userId;
          let text = "";
          try {
            text = new TextDecoder().decode(new Uint8Array(msg.ciphertext));
          } catch {
            text = "[encrypted]";
          }
          const operation = latest.get(msg.id);
          const revoked = operation?.kind === "revoke";
          const content = decodeContent(operation?.kind === "edit" && operation.content !== null ? operation.content : text);
          const pending = operations.some(item => item.target_id === msg.id && item.status === "pending");
          const notices = operations.filter(item => item.target_id === msg.id && item.status !== "accepted" && item.revision >= (operation?.revision ?? 0));
          const canModify = isMine && msg.sender_device_id === deviceId && Date.now() - msg.timestamp <= 48 * 60 * 60 * 1000
            && !revoked && !pending && online && !operationBusy && !sending && !["pending", "failed"].includes(msg.local_state ?? "");
          const sender = isMine ? userId : contacts.find(contact => contact.user_id === msg.sender_id)?.username ?? msg.sender_id;
          const reference = { messageId: msg.id, sender: sender.slice(0, 256), text: content.text.slice(0, 500) };
          return (
            <div
              id={`message-${msg.id}`}
              key={msg.id}
              style={{
                ...styles.messageRow,
                justifyContent: isMine ? "flex-end" : "flex-start",
              }}
            >
              <div
                style={{
                  ...styles.bubble,
                  ...(isMine ? styles.bubbleMine : styles.bubbleTheirs),
                }}
              >
                {!revoked && content.reply && <button style={{ display: "block", maxWidth: "100%", textAlign: "left", whiteSpace: "pre-wrap" }} onClick={() => {
                  const target = document.getElementById(`message-${content.reply!.messageId}`);
                  if (target) target.scrollIntoView({ block: "center", behavior: "smooth" });
                  else setActionStatus("原消息未加载，请先加载更早消息；引用快照仍可查看。");
                }}>回复 {content.reply.sender}：{content.reply.text}</button>}
                {!revoked && content.forwarded && <div style={{ fontSize: 12 }}>转发内容（来源由转发者提供）：{content.forwarded.sender}</div>}
                <span style={styles.messageText}>{revoked ? "此消息已被发送者撤回" : content.text}</span>
                {operation?.kind === "edit" && <span style={styles.timestamp}>已编辑 · 版本 {operation.revision}</span>}
                {notices.map(item => <div key={item.id} role="status">{item.status === "pending" ? "变更等待服务端确认，将自动重试" : item.error ?? "变更未通过校验"}</div>)}
                <div style={{ display: "flex", gap: 6 }}>
                  {!revoked && <button onClick={() => { void copyMessageText(content.text).then(() => setActionStatus("已复制消息正文")).catch(error => setActionStatus(String(error))); }}>复制</button>}
                  {!revoked && <button disabled={sending || !!draft.messageId} onClick={() => { void onDraftChange({ ...draft, reply: reference }).catch(error => setActionStatus(String(error))); }}>回复</button>}
                  <button disabled={sending || deleting || draft.messageId === msg.id} onClick={() => setDeleteTarget(msg.id)}>从本机删除</button>
                  {!revoked && <button onClick={() => { setForwardDraft({ text: content.text, forwarded: reference }); setForwardTarget(""); }}>转发</button>}
                  {isMine && !revoked && <>
                    <button disabled={!canModify} title="原发送设备可在服务器首次接收后的 48 小时内编辑" onClick={() => { setOperationDialog({ targetId: msg.id, kind: "edit", content, revision: operation?.revision ?? 0 }); setEditedText(content.text); }}>编辑</button>
                    <button disabled={!canModify} title="原发送设备可在服务器首次接收后的 48 小时内撤回" onClick={() => setOperationDialog({ targetId: msg.id, kind: "revoke", content, revision: operation?.revision ?? 0 })}>撤回</button>
                  </>}
                </div>
                {msg.local_state === "integrity_failed" && <span role="alert">消息顺序或完整性链异常，请核对来源</span>}
                <span style={styles.timestamp}>
                  {new Date(msg.timestamp).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                  {isMine && msg.local_state ? ` · ${deliveryStatusLabel(msg.local_state)}` : ""}
                  {isMine && ["failed", "pending"].includes(msg.local_state ?? "") && (
                    <button disabled={!online || sending} onClick={async () => {
                      setSending(true);
                      try { await retryMessage(msg.id); setSendError(null); }
                      catch (error) { setSendError(String(error)); }
                      finally { setSending(false); }
                    }}>重试原消息</button>
                  )}
                </span>
              </div>
            </div>
          );
        })}
        <div ref={messagesEndRef} />
      </div>
      {operationError && <div role="alert">消息变更更新失败：{operationError} <button onClick={() => setOperationRefresh(value => value + 1)}>重新读取</button></div>}
      {operations.some(item => item.status === "pending") && <button disabled={operationBusy || !online} onClick={async () => {
        setOperationBusy(true);
        try { await syncMessageOperations(); }
        catch (error) { setActionStatus(String(error)); }
        finally { if (alive.current) { setOperationBusy(false); setOperationRefresh(value => value + 1); } }
      }}>立即重试待确认变更</button>}
      {operationDialog && <div role="dialog" aria-modal="true" aria-label={operationDialog.kind === "edit" ? "编辑消息" : "撤回消息"}>
        <p>{operationDialog.kind === "edit" ? "保存后同步更新双方正文，保留已编辑标记。" : "确认后同步显示撤回提示，不能恢复编辑；对方此前已查看、复制或转发的内容不会被擦除。"}仅原发送设备可在服务器首次接收后的 48 小时内操作。</p>
        {operationDialog.kind === "edit" && <textarea aria-label="编辑后的正文" disabled={operationBusy} value={editedText} onChange={event => setEditedText(event.target.value)} />}
        <button disabled={operationBusy || !online || (operationDialog.kind === "edit" && !editedText.trim()) || operations.some(item => item.target_id === operationDialog.targetId && item.status === "pending")} onClick={async () => {
          setOperationBusy(true);
          try {
            await submitMessageOperation(operationDialog.targetId, operationDialog.kind,
              operationDialog.kind === "edit" ? encodeContent({ ...operationDialog.content, text: editedText.trim() }) : "", operationDialog.revision);
            if (alive.current) { setOperationsLoaded(false); setOperationDialog(null); setActionStatus("服务端已保存变更；对方离线时将在重新连接后补收。"); }
          } catch (error) { if (alive.current) setActionStatus(String(error)); }
          finally { if (alive.current) { setOperationBusy(false); setOperationRefresh(value => value + 1); } }
        }}>{operationBusy ? "正在提交…" : operationDialog.kind === "edit" ? "保存编辑" : "确认撤回"}</button>
        <button disabled={operationBusy} onClick={() => setOperationDialog(null)}>关闭</button>
      </div>}
      {deleteTarget && <div role="dialog" aria-modal="true" aria-label="从本机删除消息">
        <p>从本机聊天、摘要和未读计数中移除此消息。为保持消息链校验，加密记录仍保留；对方的消息、已经生成的引用/转发和正在进行的投递不受影响。这不是撤回或彻底擦除。</p>
        <button disabled={deleting} onClick={async () => {
          if (!storageConversationId) return;
          const id = deleteTarget;
          setDeleting(true);
          try {
            await deleteMessageLocally(userId, storageConversationId, id);
            deletedIds.current.add(id);
            if (!alive.current) return;
            setMessages(previous => previous.filter(message => message.id !== id));
            setDeleteTarget(null);
            setActionStatus("已从本机聊天中删除；未撤回对方消息。");
          } catch (error) { if (alive.current) setActionStatus(String(error)); }
          finally { if (alive.current) setDeleting(false); }
        }}>确认从本机删除</button>
        <button disabled={deleting} onClick={() => setDeleteTarget(null)}>取消</button>
      </div>}
      {actionStatus && <div role="status">{actionStatus}</div>}
      {forwardDraft && <div role="dialog" aria-label="转发消息">
        <label>目标联系人 <select value={forwardTarget} disabled={forwarding} onChange={event => setForwardTarget(event.target.value)}>
          <option value="">请选择</option>{contacts.map(contact => <option key={contact.user_id} value={contact.user_id}>{contact.username}</option>)}
        </select></label>
        <button disabled={!forwardTarget || forwarding} onClick={async () => {
          setForwarding(true);
          try { await onForward(forwardTarget, forwardDraft); if (alive.current) setForwardDraft(null); }
          catch (error) { if (alive.current) setActionStatus(String(error)); }
          finally { if (alive.current) setForwarding(false); }
        }}>生成转发草稿</button>
        <button disabled={forwarding} onClick={() => setForwardDraft(null)}>取消</button>
      </div>}
      {(draft.reply || draft.forwarded) && <div>
        {draft.reply && <div>回复 {draft.reply.sender}：{draft.reply.text}</div>}
        {draft.forwarded && <div>转发：{draft.forwarded.sender}</div>}
        <button disabled={sending || !!draft.messageId} onClick={() => { void onDraftChange({ ...draft, reply: undefined, forwarded: undefined }).catch(error => setActionStatus(String(error))); }}>移除引用/转发标记</button>
      </div>}
      {readError && <p role="alert">{readError}</p>}
      {sendError && <div style={styles.sendError}>{sendError}</div>}
      {draft.messageId && <div style={styles.sendError}>原消息内容已保留，重试沿用同一编号。
        <button disabled={sending} onClick={() => { void onDraftChange({ text: "" }).catch(() => {}); }}>保留已提交消息，另写一条</button>
      </div>}
      <form className="chat-composer" onSubmit={handleSend} style={styles.inputBar}>
        <span style={styles.prompt}>›</span>
        <input
          className="composer-input"
          type="text"
          placeholder="type a message…"
          value={input}
          disabled={sending || !!draft.messageId}
          onChange={(e) => { void onDraftChange({ ...draft, text: e.target.value }).catch(() => {}); }}
          style={styles.input}
        />
        <button
          className="composer-send"
          type="submit"
          disabled={!online || sending || !input.trim()}
          style={styles.sendBtn}
        >
          {sending ? "Sending..." : draft.messageId ? "重试原消息" : "Send"}
        </button>
      </form>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    flex: 1,
    display: "flex",
    flexDirection: "column",
    minWidth: 0,
    backgroundColor: "var(--workspace-bg)",
  },
  empty: {
    flex: 1,
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    gap: "0px",
    backgroundColor: "var(--workspace-bg)",
  },
  emptyText: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-muted)",
    fontSize: "15px",
    margin: 0,
  },
  emptyHint: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    fontSize: "12px",
    margin: "8px 0 0",
  },
  header: {
    minHeight: "58px",
    borderBottom: "1px solid var(--border)",
    display: "flex",
    alignItems: "center",
    padding: "0 24px",
    backgroundColor: "var(--workspace-bg)",
  },
  headerInner: {
    width: "100%",
    maxWidth: "840px",
    margin: "0 auto",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "12px",
  },
  headerText: {
    minWidth: 0,
    display: "flex",
    flexDirection: "column",
    gap: "2px",
  },
  headerTitle: {
    color: "var(--text)",
    fontSize: "15px",
    fontWeight: 600,
  },
  headerMeta: {
    fontFamily: "var(--font-mono)",
    fontSize: "11.5px",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  verifyBtn: {
    flexShrink: 0,
    border: "1px solid var(--border-strong)",
    backgroundColor: "transparent",
    color: "var(--text-muted)",
    borderRadius: "var(--radius-md)",
    padding: "6px 12px",
    cursor: "pointer",
    fontSize: "12px",
  },
  messages: {
    flex: 1,
    overflowY: "auto",
    width: "100%",
    maxWidth: "840px",
    margin: "0 auto",
    padding: "24px 24px 18px",
    display: "flex",
    flexDirection: "column",
    gap: "12px",
  },
  loadingText: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    fontSize: "12px",
    textAlign: "center",
  },
  messageRow: {
    display: "flex",
  },
  bubble: {
    maxWidth: "72%",
    padding: "10px 13px",
    borderRadius: "12px",
    display: "flex",
    flexDirection: "column",
    gap: "4px",
    border: "1px solid transparent",
  },
  bubbleMine: {
    backgroundColor: "var(--accent)",
    color: "var(--accent-contrast)",
    borderBottomRightRadius: "4px",
  },
  bubbleTheirs: {
    backgroundColor: "var(--surface)",
    color: "var(--text)",
    borderColor: "var(--border)",
    borderBottomLeftRadius: "4px",
  },
  messageText: {
    fontSize: "14px",
    wordBreak: "break-word",
  },
  timestamp: {
    fontFamily: "var(--font-mono)",
    fontSize: "10px",
    opacity: 0.7,
    alignSelf: "flex-end",
  },
  sendError: {
    width: "calc(100% - 48px)",
    maxWidth: "840px",
    margin: "0 auto 8px",
    fontFamily: "var(--font-mono)",
    color: "var(--danger)",
    fontSize: "12px",
  },
  inputBar: {
    display: "flex",
    alignItems: "center",
    width: "calc(100% - 48px)",
    maxWidth: "840px",
    margin: "0 auto 20px",
    padding: "8px 8px 8px 14px",
    border: "1px solid var(--border-strong)",
    borderRadius: "var(--composer-radius)",
    gap: "10px",
    backgroundColor: "var(--surface)",
    boxShadow: "var(--shadow-composer)",
  },
  prompt: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    fontSize: "14px",
    flexShrink: 0,
  },
  input: {
    flex: 1,
    padding: "8px 0",
    border: "none",
    backgroundColor: "transparent",
    color: "var(--text)",
    fontSize: "14px",
    outline: "none",
    minWidth: 0,
  },
  sendBtn: {
    padding: "8px 16px",
    borderRadius: "var(--radius-md)",
    border: "none",
    backgroundColor: "var(--accent)",
    color: "var(--accent-contrast)",
    fontSize: "13px",
    cursor: "pointer",
    fontWeight: 600,
    flexShrink: 0,
  },
};
