import { useState, useEffect, useRef, useCallback } from "react";
import { useTauri } from "../hooks/useTauri";
import { trustLabel } from "./ContactList";
import type { RelayBatch } from "../App";
import type { DisplayMessage, Contact, RelayEvent } from "../types";

interface ChatProps {
  conversationId: string | null;
  userId: string;
  contacts: Contact[];
  relayBatch: RelayBatch | null;
  onContactsChanged: () => void;
}

export default function Chat({ conversationId, userId, contacts, relayBatch, onContactsChanged }: ChatProps) {
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { sendText, getMessages, setContactTrust } = useTauri();
  const activeContact = contacts.find((c) => c.user_id === conversationId);

  useEffect(() => {
    if (!conversationId) return;
    setLoading(true);
    setSendError(null);
    getMessages(conversationId, 50, 0)
      .then(setMessages)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [conversationId, getMessages]);

  const applyRelayEvents = useCallback((events: RelayEvent[]) => {
    if (events.length === 0) return;

    const stateByMessage = new Map<string, string>();
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
            ? { ...msg, local_state: stateByMessage.get(msg.id) ?? msg.local_state }
            : msg
        )
      );
    }
  }, []);

  useEffect(() => {
    if (!conversationId || !relayBatch) return;
    applyRelayEvents(relayBatch.events);
    const incoming = relayBatch.messages.filter(
      (message) => message.sender_id === conversationId
    );
    setMessages((previous) => {
      const seen = new Set(previous.map((message) => message.id));
      return [...previous, ...incoming.filter((message) => !seen.has(message.id))];
    });
  }, [relayBatch, conversationId, applyRelayEvents]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim() || !conversationId) return;

    const text = input.trim();
    setInput("");
    setSendError(null);
    setSending(true);

    try {
      const result = await sendText(conversationId, text);

      setMessages((prev) => [
        ...prev,
        {
          id: result.message_id,
          conversation_id: conversationId,
          sender_id: userId,
          sender_device_id: "local",
          sender_seq: 0,
          timestamp: Date.now(),
          plaintext: text,
          local_state: "pending_v2",
          protocol_version: 2,
          verification_state: "authored_v2",
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
      <div className="chat-messages" style={styles.messages}>
        {loading && <p style={styles.loadingText}>loading…</p>}
        {messages.map((msg) => {
          const isMine = msg.sender_id === userId;
          return (
            <div
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
                <span style={styles.messageText}>{msg.plaintext}</span>
                {msg.protocol_version === 1 && (
                  <span style={styles.protocolLabel}>legacy v1 · ciphertext signature only</span>
                )}
                {msg.verification_state.includes("invalid") && (
                  <span style={styles.protocolLabel}>{msg.verification_state}</span>
                )}
                <span style={styles.timestamp}>
                  {new Date(msg.timestamp).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                  {isMine && msg.local_state ? ` · ${msg.local_state}` : ""}
                </span>
              </div>
            </div>
          );
        })}
        <div ref={messagesEndRef} />
      </div>
      {sendError && <div style={styles.sendError}>{sendError}</div>}
      <form className="chat-composer" onSubmit={handleSend} style={styles.inputBar}>
        <span style={styles.prompt}>›</span>
        <input
          className="composer-input"
          type="text"
          placeholder="type a message…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          style={styles.input}
        />
        <button
          className="composer-send"
          type="submit"
          disabled={sending || !input.trim()}
          style={styles.sendBtn}
        >
          {sending ? "Sending..." : "Send"}
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
  protocolLabel: {
    fontFamily: "var(--font-mono)",
    fontSize: "9px",
    opacity: 0.75,
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
