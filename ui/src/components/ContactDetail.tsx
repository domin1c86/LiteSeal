import { useState } from "react";
import { useDesktop } from "../hooks/useDesktop";
import { trustLabel } from "./ContactList";
import type { Contact } from "../types";

interface ContactDetailProps {
  contact: Contact;
  onMessage: () => void;
  onContactsChanged: () => void;
  alias: string;
  onAlias: (value: string) => Promise<void>;
}

export default function ContactDetail({ contact, alias, onAlias, onMessage, onContactsChanged }: ContactDetailProps) {
  const { setContactTrust, removeContact } = useDesktop();
  const [remark, setRemark] = useState(alias);
  const [error, setError] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
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
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.avatar}>{contact.username.charAt(0).toUpperCase()}</div>
        <div style={styles.name}>{contact.username}</div>
        <p style={{ overflowWrap: "anywhere" }}>身份：{contact.user_id}</p>
        <label>本机备注 <input maxLength={80} value={remark} disabled={busy} onChange={event => setRemark(event.target.value)} /></label>
        <button disabled={busy || remark === alias} onClick={async () => {
          setBusy(true); try { await onAlias(remark.trim()); setError(""); } catch (failure) { setError(String(failure)); } finally { setBusy(false); }
        }}>保存备注</button>
        <p>备注仅用于本机显示，不修改账号、密钥或验签身份。</p>
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
        <button disabled={busy} onClick={() => setConfirmDelete(true)}>删除联系人</button>
        {confirmDelete && <div role="alertdialog" aria-label="删除联系人确认">
          <p>删除联系人保留加密历史和消息链。恢复同一身份与公钥后可再次读取；这不是撤回或拉黑，不能阻止对方发消息。</p>
          <button disabled={busy} onClick={async () => {
            setBusy(true); try { await removeContact(contact.user_id); onContactsChanged(); } catch (failure) { setError(String(failure)); } finally { setBusy(false); }
          }}>确认删除联系人</button>
          <button disabled={busy} onClick={() => setConfirmDelete(false)}>取消</button>
        </div>}
        {error && <p role="alert">{error}</p>}
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
