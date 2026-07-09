import { useState } from "react";
import { useTauri } from "../hooks/useTauri";
import { trustLabel } from "./ContactList";
import type { Contact } from "../types";

interface ContactDetailProps {
  contact: Contact;
  onMessage: () => void;
  onContactsChanged: () => void;
}

export default function ContactDetail({ contact, onMessage, onContactsChanged }: ContactDetailProps) {
  const { setContactTrust } = useTauri();
  const [busy, setBusy] = useState(false);
  const trust = trustLabel(contact);
  const verified = contact.trust_state === "verified";

  async function toggleTrust() {
    setBusy(true);
    try {
      await setContactTrust(contact.user_id, verified ? "unverified" : "verified");
      onContactsChanged();
    } catch (err) {
      console.error("Failed to update trust:", err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.avatar}>{contact.username.charAt(0).toUpperCase()}</div>
        <div style={styles.name}>{contact.username}</div>
        <div style={styles.fingerprint}>
          {contact.fingerprint
            ? contact.fingerprint.match(/.{1,4}/g)?.join(" ")
            : "no fingerprint"}
        </div>
        <div style={{ ...styles.trust, color: trust.color }}>{trust.text}</div>
        <div style={styles.actions}>
          <button className="primary-button" style={styles.messageBtn} onClick={onMessage}>
            Message
          </button>
          <button
            className="outline-button"
            style={styles.trustBtn}
            onClick={toggleTrust}
            disabled={busy}
          >
            {verified ? "Unverify" : "Verify"}
          </button>
        </div>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    flex: 1,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "24px",
    backgroundColor: "var(--workspace-bg)",
  },
  card: {
    width: "min(360px, 100%)",
    padding: "28px",
    textAlign: "center",
    backgroundColor: "var(--sidebar-bg)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-lg)",
  },
  avatar: {
    width: "52px",
    height: "52px",
    margin: "0 auto 12px",
    borderRadius: "var(--radius-md)",
    backgroundColor: "var(--accent-soft)",
    border: "1px solid var(--border-strong)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: "var(--text)",
    fontFamily: "var(--font-mono)",
    fontWeight: 600,
    fontSize: "18px",
  },
  name: {
    color: "var(--text)",
    fontSize: "16px",
    fontWeight: 600,
  },
  fingerprint: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-subtle)",
    fontSize: "11.5px",
    margin: "8px 0 4px",
    wordBreak: "break-all",
  },
  trust: {
    fontFamily: "var(--font-mono)",
    fontSize: "11.5px",
  },
  actions: {
    display: "flex",
    gap: "10px",
    justifyContent: "center",
    marginTop: "20px",
  },
  messageBtn: {
    padding: "8px 18px",
    borderRadius: "var(--radius-md)",
    border: "none",
    backgroundColor: "var(--accent)",
    color: "var(--accent-contrast)",
    fontSize: "13px",
    fontWeight: 600,
    cursor: "pointer",
  },
  trustBtn: {
    padding: "8px 14px",
    borderRadius: "var(--radius-md)",
    border: "1px solid var(--border-strong)",
    backgroundColor: "transparent",
    color: "var(--text-muted)",
    fontSize: "13px",
    cursor: "pointer",
  },
};
