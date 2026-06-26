import { useState, useEffect, useRef } from "react";
import { useTauri } from "../hooks/useTauri";
import type { Message, IncomingMessage, Contact } from "../types";

interface ChatProps {
  conversationId: string | null;
  userId: string;
  token: string;
  serverUrl: string;
  secretKey: number[];
  contacts: Contact[];
}

export default function Chat({ conversationId, userId, secretKey, contacts }: ChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { sendMessage, pollMessages, getLocalMessages, encryptMessage, decryptMessage, signMessage } = useTauri();

  useEffect(() => {
    if (!conversationId) return;
    setLoading(true);
    getLocalMessages(conversationId, 50, 0)
      .then(setMessages)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [conversationId]);

  useEffect(() => {
    if (!conversationId) return;
    const interval = setInterval(async () => {
      try {
        const incoming: IncomingMessage[] = await pollMessages();
        if (incoming.length > 0) {
          const decrypted = await Promise.all(
            incoming
              .filter((m) => m.conversation_id === conversationId)
              .map(async (m) => {
                let plaintext: number[];
                try {
                  const sender = contacts.find((c) => c.user_id === m.from);
                  if (!sender) throw new Error("Sender not in contacts");
                  plaintext = await decryptMessage(m.ciphertext, sender.public_key, secretKey);
                } catch {
                  plaintext = m.ciphertext;
                }
                return {
                  id: m.message_id,
                  conversation_id: m.conversation_id,
                  sender_id: m.from,
                  sender_device_id: m.sender_device_id,
                  sender_seq: m.sender_seq,
                  timestamp: m.timestamp,
                  message_type: "text",
                  ciphertext: plaintext,
                  signature: m.signature,
                  prev_hash: [],
                };
              })
          );
          setMessages((prev) => [...prev, ...decrypted]);
        }
      } catch {
        // ignore poll errors
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [conversationId, contacts, secretKey]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim() || !conversationId) return;

    const text = input.trim();
    setInput("");

    try {
      const contact = contacts.find((c) => c.user_id === conversationId);
      if (!contact) throw new Error("Recipient not found in contacts");

      const encoder = new TextEncoder();
      const plaintext = Array.from(encoder.encode(text));
      const ciphertext = await encryptMessage(plaintext, contact.public_key, secretKey);
      const signature = await signMessage(ciphertext, secretKey);

      await sendMessage(
        conversationId,
        conversationId,
        ciphertext,
        signature,
        "device-1",
        messages.length
      );

      setMessages((prev) => [
        ...prev,
        {
          id: crypto.randomUUID(),
          conversation_id: conversationId,
          sender_id: userId,
          sender_device_id: "device-1",
          sender_seq: prev.length,
          timestamp: Date.now(),
          message_type: "text",
          ciphertext: plaintext,
          signature: [],
          prev_hash: [],
        },
      ]);
    } catch (err) {
      console.error("Send failed:", err);
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
      <div style={styles.messages}>
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
                </span>
              </div>
            </div>
          );
        })}
        <div ref={messagesEndRef} />
      </div>
      <form onSubmit={handleSend} style={styles.inputBar}>
        <input
          type="text"
          placeholder="Type a message..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          style={styles.input}
        />
        <button type="submit" style={styles.sendBtn}>
          Send
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
    backgroundColor: "#1a1a2e",
  },
  empty: {
    flex: 1,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "#1a1a2e",
  },
  emptyText: {
    color: "#555",
    fontSize: "16px",
  },
  messages: {
    flex: 1,
    overflowY: "auto",
    padding: "16px",
    display: "flex",
    flexDirection: "column",
    gap: "8px",
  },
  loadingText: {
    color: "#a0a0b0",
    textAlign: "center",
  },
  messageRow: {
    display: "flex",
  },
  bubble: {
    maxWidth: "65%",
    padding: "8px 12px",
    borderRadius: "12px",
    display: "flex",
    flexDirection: "column",
    gap: "4px",
  },
  bubbleMine: {
    backgroundColor: "#e94560",
    color: "#fff",
    borderBottomRightRadius: "4px",
  },
  bubbleTheirs: {
    backgroundColor: "#0f3460",
    color: "#e0e0e0",
    borderBottomLeftRadius: "4px",
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
  inputBar: {
    display: "flex",
    padding: "12px 16px",
    borderTop: "1px solid #0f3460",
    gap: "8px",
    backgroundColor: "#16213e",
  },
  input: {
    flex: 1,
    padding: "10px 14px",
    borderRadius: "6px",
    border: "1px solid #333",
    backgroundColor: "#0f3460",
    color: "#fff",
    fontSize: "14px",
    outline: "none",
  },
  sendBtn: {
    padding: "10px 20px",
    borderRadius: "6px",
    border: "none",
    backgroundColor: "#e94560",
    color: "#fff",
    fontSize: "14px",
    cursor: "pointer",
    fontWeight: "bold",
  },
};
