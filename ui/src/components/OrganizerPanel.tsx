import { useEffect, useState } from "react";
import type { useOrganizer } from "../hooks/useOrganizer";
import type { Contact } from "../types";
import { dmConversationId } from "../lib/conversation";
import { latestOperations } from "../lib/messageOperations";
import { projectMessage } from "../lib/messageProjection";

export default function OrganizerPanel({ organizer, userId, contacts, onClose, onOpen }: {
  organizer: ReturnType<typeof useOrganizer>; userId: string; contacts: Contact[];
  onClose: () => void; onOpen: (peerId: string) => void;
}) {
  const [notes, setNotes] = useState(organizer.value.notes);
  const [name, setName] = useState("");
  const [previews, setPreviews] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const apply = (change: Parameters<typeof organizer.update>[0]) => { void organizer.update(change).catch(failure => setError(String(failure))); };
  useEffect(() => {
    let active = true, busy = false;
    const refresh = async () => {
      if (busy) return; busy = true;
      const next: Record<string, string> = {};
      for (const favorite of organizer.value.favorites) {
        try {
          const peer = contacts.find(contact => contact.user_id === favorite.peerId);
          if (!peer) throw new Error("缺少联系人");
          const conversationId = dmConversationId(userId, favorite.peerId);
          const [rows, operations] = await Promise.all([
            window.desktop.get_message_context({ userId, conversationId, messageId: favorite.messageId }),
            window.desktop.get_message_operations({ conversationId }),
          ]);
          const row = rows.find(item => item.id === favorite.messageId);
          if (!row || row.local_state === "integrity_failed") throw new Error("原文不可用");
          const operation = latestOperations(operations).get(row.id);
          if (operation?.kind === "revoke") throw new Error("原文已撤回");
          const bytes = await window.desktop.decrypt_message({ ciphertext: row.ciphertext, senderPublicKey: peer.public_key });
          next[favorite.messageId] = projectMessage(new TextDecoder().decode(new Uint8Array(bytes)), operation).content.text.slice(0, 200);
        } catch { next[favorite.messageId] = "原文不可用（已删除、撤回或无法解密）"; }
        if (!active) return;
      }
      if (active) setPreviews(next);
      busy = false;
    };
    void refresh(); const timer = setInterval(refresh, 2000);
    return () => { active = false; clearInterval(timer); };
  }, [userId, contacts, organizer.value.favorites]);

  return <section role="dialog" aria-modal="true" aria-label="本机列表、收藏和便笺" style={{ position: "fixed", inset: "8%", zIndex: 20, background: "var(--surface)", color: "var(--text)", padding: 24, overflow: "auto", border: "1px solid var(--border)" }}>
    <button disabled={organizer.busy} onClick={() => { if (notes === organizer.value.notes || window.confirm("便笺尚未保存，放弃这些修改？")) onClose(); }}>关闭</button>
    <h2>本机列表</h2>
    <input aria-label="新列表名称" maxLength={40} value={name} onChange={event => setName(event.target.value)} />
    <button disabled={organizer.busy || !name.trim()} onClick={() => { apply(value => ({ ...value, lists: [...value.lists, { id: crypto.randomUUID(), name: name.trim(), peers: [] }] })); setName(""); }}>创建列表</button>
    {organizer.value.lists.map(list => <fieldset key={list.id}><legend>{list.name}</legend>
      {contacts.map(peer => <label key={peer.user_id} style={{ display: "block" }}><input type="checkbox" disabled={organizer.busy} checked={list.peers.includes(peer.user_id)} onChange={event => apply(value => ({ ...value, lists: value.lists.map(item => item.id === list.id ? { ...item, peers: event.target.checked ? [...item.peers, peer.user_id] : item.peers.filter(id => id !== peer.user_id) } : item) }))} />{organizer.value.aliases[peer.user_id] || peer.username} · {peer.user_id.slice(0, 8)}</label>)}
      <button disabled={organizer.busy} onClick={() => apply(value => ({ ...value, lists: value.lists.filter(item => item.id !== list.id) }))}>删除列表（保留聊天）</button>
    </fieldset>)}
    <h2>收藏引用</h2><p>仅保存消息编号，原文删除或撤回后不保留正文副本；不进行云同步。</p>
    {organizer.value.favorites.map(item => <div key={item.messageId}><span>{previews[item.messageId] ?? "读取中…"}</span>
      <button onClick={() => { onOpen(item.peerId); onClose(); }}>打开会话</button>
      <button disabled={organizer.busy} onClick={() => apply(value => ({ ...value, favorites: value.favorites.filter(row => row.messageId !== item.messageId) }))}>取消收藏</button>
    </div>)}
    <h2>加密便笺</h2><p>便笺只保存在本机，不向联系人发送。</p>
    <textarea aria-label="本机便笺" value={notes} onChange={event => setNotes(event.target.value)} rows={8} style={{ width: "100%" }} />
    <button disabled={organizer.busy || notes === organizer.value.notes} onClick={() => apply(value => ({ ...value, notes }))}>保存便笺</button>
    {(error || organizer.error) && <p role="alert">{error || organizer.error}</p>}
  </section>;
}
