import { useState, useEffect, useRef } from "react";
import { useTauri } from "../hooks/useTauri";
import { dmConversationId } from "../lib/conversation";
import type { Message, IncomingMessage, Contact, RelayEvent } from "../types";

interface ChatProps {
  conversationId: string | null;
  userId: string;
  deviceId: string;
  token: string;
  serverUrl: string;
  secretKey: number[];
  signingKey: number[];
  contacts: Contact[];
  onContactsChanged: () => void;
}

export default function Chat({ conversationId, userId, deviceId, serverUrl, secretKey, signingKey, contacts, onContactsChanged }: ChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { sendMessage, getUserDevices, pollMessages, getLocalMessages, encryptMessage, decryptMessage, signMessage, verifyMessage, setContactTrust } = useTauri();
  const activeContact = contacts.find((c) => c.user_id === conversationId);
  // conversationId prop is the peer's user id; storage/relay use the canonical DM id.
  const storageConversationId = conversationId ? dmConversationId(userId, conversationId) : null;

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

  useEffect(() => {
    if (!conversationId || !storageConversationId) return;
    setLoading(true);
    setSendError(null);
    getLocalMessages(storageConversationId, 50, 0)
      .then(async (msgs) => {
        const decrypted = await Promise.all(
          msgs.map(async (msg) => {
            const peer = contacts.find((c) =>
              msg.sender_id === userId
                ? c.user_id === conversationId
                : c.user_id === msg.sender_id
            );
            if (!peer) return msg;
            try {
              const plaintext = await decryptMessage(msg.ciphertext, peer.public_key, secretKey);
              return { ...msg, ciphertext: plaintext };
            } catch {
              return { ...msg, ciphertext: Array.from(new TextEncoder().encode("[encrypted]")) };
            }
          })
        );
        setMessages(decrypted);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [conversationId, contacts, secretKey, userId]);

  useEffect(() => {
    if (!conversationId) return;
    const interval = setInterval(async () => {
      try {
        const result = await pollMessages();
        applyRelayEvents(result.events);
        const incoming: IncomingMessage[] = result.messages;
        if (incoming.length > 0) {
          const decoded = await Promise.all(
            incoming
              .filter((m) => m.conversation_id === storageConversationId)
              .map(async (m) => {
                const sender = contacts.find((c) => c.user_id === m.from);
                if (!sender) {
                  return incomingToMessage(
                    m,
                    Array.from(new TextEncoder().encode("[sender not in contacts]"))
                  );
                }

                try {
                  if (!sender.ed25519_pk || sender.ed25519_pk.length === 0) {
                    return incomingToMessage(
                      m,
                      Array.from(new TextEncoder().encode("[no ed25519 key, verification skipped]"))
                    );
                  }
                  const valid = await verifyMessage(m.ciphertext, m.signature, sender.ed25519_pk);
                  if (!valid) {
                    return incomingToMessage(
                      m,
                      Array.from(new TextEncoder().encode("[signature invalid]"))
                    );
                  }
                } catch {
                  // verification itself failed — treat as invalid
                  return incomingToMessage(
                    m,
                    Array.from(new TextEncoder().encode("[signature invalid]"))
                  );
                }

                try {
                  const plaintext = await decryptMessage(m.ciphertext, sender.public_key, secretKey);
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
            return [...prev, ...decoded.filter((msg) => !seen.has(msg.id))];
          });
        }
      } catch {
        // ignore poll errors
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [conversationId, contacts, secretKey]);

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
      const contact = contacts.find((c) => c.user_id === conversationId);
      if (!contact) throw new Error("Recipient not found in contacts");

      const devices = (await getUserDevices(serverUrl, conversationId)).filter(
        (d) => !d.revoked && d.public_key.length === 32
      );
      if (devices.length === 0) throw new Error("Recipient has no active devices");

      const encoder = new TextEncoder();
      const plaintext = Array.from(encoder.encode(text));

      // Local copy encrypted to the contact's stored key so history stays readable.
      const ciphertext = await encryptMessage(plaintext, contact.public_key, secretKey);
      const signature = await signMessage(ciphertext, signingKey);

      const payloads = [];
      for (const device of devices) {
        const deviceCiphertext = await encryptMessage(plaintext, device.public_key, secretKey);
        const deviceSignature = await signMessage(deviceCiphertext, signingKey);
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
        payloads
      );

      setMessages((prev) => [
        ...prev,
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
        <p style={styles.emptyText}>Select a conversation</p>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div className="chat-header" style={styles.header}>
        <div style={styles.headerInner}>
          <div style={styles.headerText}>
            <span style={styles.headerTitle}>{activeContact?.username ?? "Conversation"}</span>
            <span style={styles.headerMeta}>
              {activeContact
                ? `${activeContact.trust_state === "verified" ? "Verified" : activeContact.key_changed ? "Key changed" : "Unverified"}${activeContact.fingerprint ? ` · ${activeContact.fingerprint.match(/.{1,4}/g)?.join(" ")}` : ""}`
                : "End-to-end encrypted"}
            </span>
          </div>
          {activeContact && (
            <button
              className="secondary-button"
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
        {loading && <p style={styles.loadingText}>Loading...</p>}
        {messages.map((msg) => {
          const isMine = msg.sender_id === userId;
          let text = "";
          try {
            text = new TextDecoder().decode(new Uint8Array(msg.ciphertext));
          } catch {
            text = "[encrypted]";
          }
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
                <span style={styles.messageText}>{text}</span>
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
        <input
          className="composer-input"
          type="text"
          placeholder="Type a message..."
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
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "var(--workspace-bg)",
  },
  emptyText: {
    color: "var(--text-subtle)",
    fontSize: "16px",
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
    color: "var(--accent)",
    fontSize: "12px",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  verifyBtn: {
    flexShrink: 0,
    border: "1px solid var(--border)",
    backgroundColor: "var(--surface-muted)",
    color: "var(--text)",
    borderRadius: "8px",
    padding: "6px 10px",
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
    color: "var(--text-muted)",
    textAlign: "center",
  },
  messageRow: {
    display: "flex",
  },
  bubble: {
    maxWidth: "72%",
    padding: "10px 13px",
    borderRadius: "16px",
    display: "flex",
    flexDirection: "column",
    gap: "4px",
    border: "1px solid transparent",
  },
  bubbleMine: {
    backgroundColor: "var(--accent)",
    color: "white",
    borderBottomRightRadius: "6px",
  },
  bubbleTheirs: {
    backgroundColor: "var(--surface-muted)",
    color: "var(--text)",
    borderColor: "var(--border)",
    borderBottomLeftRadius: "6px",
  },
  messageText: {
    fontSize: "14px",
    wordBreak: "break-word",
  },
  timestamp: {
    fontSize: "10px",
    opacity: 0.7,
    alignSelf: "flex-end",
  },
  sendError: {
    width: "calc(100% - 48px)",
    maxWidth: "840px",
    margin: "0 auto 8px",
    color: "var(--danger)",
    fontSize: "13px",
  },
  inputBar: {
    display: "flex",
    alignItems: "center",
    width: "calc(100% - 48px)",
    maxWidth: "840px",
    margin: "0 auto 20px",
    padding: "8px 8px 8px 16px",
    border: "1px solid var(--border-strong)",
    borderRadius: "var(--composer-radius)",
    gap: "10px",
    backgroundColor: "var(--surface)",
    boxShadow: "var(--shadow-composer)",
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
    padding: "9px 16px",
    borderRadius: "18px",
    border: "none",
    backgroundColor: "var(--accent)",
    color: "white",
    fontSize: "14px",
    cursor: "pointer",
    fontWeight: 600,
    flexShrink: 0,
  },
};
