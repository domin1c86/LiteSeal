import { useEffect, useRef, useState } from "react";
import { useDesktop } from "./useDesktop";
import type { Draft } from "../types";

type Identity = { user_id: string; publicKey: number[] };
type Flags = { pinned: boolean; archived: boolean };

export function useConversationPreferences(session: Identity | null) {
  const [drafts, setDrafts] = useState<Record<string, Draft>>({});
  const [flags, setFlags] = useState<Record<string, Flags>>({});
  const [muted, setMuted] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const draftVersions = useRef(new Map<string, Draft>());
  const queue = useRef<Promise<void>>(Promise.resolve());
  const pending = useRef(new Map<string, () => Promise<void>>());
  const { getConversationPreferences, saveConversationPreference, encryptMessage, decryptMessage } = useDesktop();

  useEffect(() => {
    let active = true;
    setReady(false); setDrafts({}); setFlags({}); setMuted({}); setError(null);
    if (!session) return;
    const identity = session;
    (async () => {
      try {
        const rows = await getConversationPreferences(identity.user_id);
        const decoded = await Promise.all(rows.map(async row => {
          let draft: Draft = { text: "" };
          if (row.draft.length) {
            const bytes = await decryptMessage(row.draft, identity.publicKey);
            const saved = JSON.parse(new TextDecoder().decode(new Uint8Array(bytes)));
            if (saved.version !== 1 || saved.peerId !== row.peer_id || typeof saved.text !== "string"
                || (saved.messageId !== undefined && typeof saved.messageId !== "string")) throw new Error("草稿格式不正确");
            const validReference = (value: unknown) => {
              if (!value || typeof value !== "object") return false;
              const item = value as Record<string, unknown>;
              return typeof item.messageId === "string" && item.messageId.length <= 128 && typeof item.sender === "string" && item.sender.length <= 256 && typeof item.text === "string" && item.text.length <= 500;
            };
            if ((saved.reply && !validReference(saved.reply)) || (saved.forwarded && !validReference(saved.forwarded))) throw new Error("草稿引用格式不正确");
            draft = { text: saved.text, messageId: saved.messageId, reply: saved.reply, forwarded: saved.forwarded };
          }
          return { row, draft };
        }));
        if (!active) return;
        setDrafts(Object.fromEntries(decoded.map(({ row, draft }) => [row.peer_id, draft])));
        setFlags(Object.fromEntries(rows.map(row => [row.peer_id, { pinned: row.pinned, archived: row.archived }])));
        setMuted(Object.fromEntries(rows.map(row => [row.peer_id, row.muted])));
        setReady(true);
      } catch (failure) { if (active) setError(`无法恢复会话设置和草稿：${String(failure)}。已保留原数据。`); }
    })();
    return () => { active = false; };
  }, [session?.user_id, revision]);

  useEffect(() => {
    const guard = (event: BeforeUnloadEvent) => {
      if (pending.current.size) { event.preventDefault(); event.returnValue = ""; }
    };
    window.addEventListener("beforeunload", guard);
    return () => window.removeEventListener("beforeunload", guard);
  }, []);

  function enqueue(key: string, work: () => Promise<void>): Promise<void> {
    pending.current.set(key, work);
    setSaving(true);
    const job = queue.current.catch(() => {}).then(work).then(() => {
      if (pending.current.get(key) === work) pending.current.delete(key);
      if (!pending.current.size) { setError(null); setSaving(false); }
    }).catch(failure => {
      setError(`会话更改尚未保存：${String(failure)}。请重试保存后再退出。`);
      throw failure;
    });
    queue.current = job;
    return job;
  }

  function saveDraft(peerId: string, draft: Draft) {
    if (!session || !ready) return Promise.reject(new Error("草稿尚未恢复"));
    const identity = session;
    draftVersions.current.set(peerId, draft);
    if (draft.text || draft.messageId || draft.reply || draft.forwarded) setDrafts(previous => ({ ...previous, [peerId]: draft }));
    return enqueue(`draft:${peerId}`, async () => {
      const encrypted = draft.text || draft.messageId || draft.reply || draft.forwarded
        ? await encryptMessage(Array.from(new TextEncoder().encode(JSON.stringify({ version: 1, peerId, ...draft }))), identity.publicKey)
        : [];
      await saveConversationPreference({ userId: identity.user_id, peerId, draft: encrypted });
      if (draftVersions.current.get(peerId) === draft) setDrafts(previous => ({ ...previous, [peerId]: draft }));
    });
  }

  function saveFlags(peerId: string, value: Flags) {
    if (!session || !ready) return Promise.reject(new Error("会话设置尚未恢复"));
    const userId = session.user_id;
    setFlags(previous => ({ ...previous, [peerId]: value }));
    return enqueue(`flags:${peerId}`, () => saveConversationPreference({ userId, peerId, ...value }));
  }

  async function flush() {
    await queue.current.catch(() => {});
    for (const [key, work] of [...pending.current]) await enqueue(key, work);
  }

  function saveMuted(peerId: string, value: boolean) {
    if (!session || !ready) return Promise.reject(new Error("会话设置尚未恢复"));
    const userId = session.user_id;
    return enqueue(`muted:${peerId}`, async () => {
      await window.desktop.set_conversation_muted({ userId, peerId, muted: value });
      setMuted(previous => ({ ...previous, [peerId]: value }));
    });
  }

  return { drafts, flags, muted, saveMuted, ready, error, saving, saveDraft, saveFlags, flush,
    retry: () => ready ? flush() : Promise.resolve(setRevision(value => value + 1)) };
}
