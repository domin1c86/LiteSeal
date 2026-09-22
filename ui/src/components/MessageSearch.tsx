import { useEffect, useRef, useState } from "react";
import { latestOperations } from "../lib/messageOperations";
import { projectMessage } from "../lib/messageProjection";
import type { Message, MessageOperation } from "../types";

interface Props {
  userId: string;
  conversationId: string;
  peerKey: number[];
  operations: MessageOperation[];
  revision: number;
  onSelect: (id: string) => Promise<void>;
  onClose: () => void;
}
type Hit = { id: string; excerpt: string; timestamp: number };

export default function MessageSearch({ userId, conversationId, peerKey, operations, revision, onSelect, onClose }: Props) {
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<Hit[]>([]);
  const [progress, setProgress] = useState({ scanned: 0, skipped: 0, matched: 0, busy: false });
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(-1);
  const [searchRevision, setSearchRevision] = useState(0);
  const generation = useRef(0);
  const input = useRef<HTMLInputElement>(null);
  const operationKey = JSON.stringify(operations);
  const keyFingerprint = peerKey.join(",");
  useEffect(() => { input.current?.focus(); }, []);

  useEffect(() => {
    const run = ++generation.current;
    setHits([]); setSelected(-1); setError("");
    setProgress({ scanned: 0, skipped: 0, matched: 0, busy: !!query.trim() });
    const timer = setTimeout(async () => {
      const needle = query.trim().toLocaleLowerCase();
      if (!needle) return;
      const latest = latestOperations(operations);
      const found: Hit[] = [];
      let scanned = 0, skipped = 0, matched = 0;
      let cursor: Message | undefined;
      try {
        while (run === generation.current) {
          const rows = await window.desktop.get_local_message_page({ userId, conversationId, limit: 100,
            beforeTimestamp: cursor?.timestamp, beforeId: cursor?.id });
          if (run !== generation.current) return;
          // Bound both plaintext lifetime and outstanding IPC requests.
          for (const row of rows) {
            if (run !== generation.current) return;
            scanned++;
            if (row.local_state === "integrity_failed") { skipped++; continue; }
            const operation = latest.get(row.id);
            if (operation?.kind === "revoke") continue;
            try {
              const bytes = await window.desktop.decrypt_message({ ciphertext: row.ciphertext, senderPublicKey: peerKey });
              if (run !== generation.current) return;
              const { content } = projectMessage(new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes)), operation);
              const text = [content.text, content.reply?.text, content.forwarded?.text].filter(Boolean).join("\n");
              const index = text.toLocaleLowerCase().indexOf(needle);
              if (index >= 0) {
                matched++;
                if (found.length < 500) found.push({ id: row.id, timestamp: row.timestamp,
                  excerpt: text.slice(Math.max(0, index - 40), index + needle.length + 80) });
              }
            } catch { skipped++; }
          }
          if (run !== generation.current) return;
          setHits([...found]); setProgress({ scanned, skipped, matched, busy: rows.length === 100 });
          if (rows.length < 100) break;
          cursor = rows[rows.length - 1];
          await new Promise(resolve => setTimeout(resolve, 0));
        }
      } catch (failure) { if (run === generation.current) setError(String(failure)); }
      finally { if (run === generation.current) setProgress({ scanned, skipped, matched, busy: false }); }
    }, 250);
    return () => { clearTimeout(timer); generation.current++; };
  }, [query, userId, conversationId, operationKey, keyFingerprint, revision, searchRevision]);

  async function select(index: number) {
    if (index < 0 || index >= hits.length) return;
    setSelected(index);
    try { await onSelect(hits[index].id); } catch (failure) { setError(String(failure)); }
  }
  return <section aria-label="搜索本机会话历史" onKeyDown={event => {
    if (event.key === "Escape") { event.stopPropagation(); onClose(); }
    if (event.key === "Enter" && event.target === input.current && !event.nativeEvent.isComposing) {
      event.preventDefault(); void select(Math.min(hits.length - 1, selected + 1));
    }
  }} style={{ padding: 12, borderBottom: "1px solid var(--border)", maxHeight: "35vh", overflow: "auto" }}>
    <input ref={input} aria-label="搜索关键词" value={query} onChange={event => setQuery(event.target.value)} placeholder="搜索本机会话历史（Ctrl+F）" />
    <button onClick={() => void select(selected - 1)} disabled={selected <= 0}>上一条</button>
    <button onClick={() => void select(selected + 1)} disabled={selected + 1 >= hits.length}>下一条</button>
    <button onClick={() => { generation.current++; setProgress(value => ({ ...value, busy: false })); }} disabled={!progress.busy}>取消搜索</button>
    <button onClick={() => setSearchRevision(value => value + 1)}>重新搜索</button>
    <button onClick={onClose}>关闭搜索</button>
    <p role="status">{progress.busy ? "搜索中" : "本轮扫描已停止"} · 已扫描本机 {progress.scanned} 条 · 匹配 {progress.matched} 条 · 无法解密或校验异常 {progress.skipped} 条。仅检索本机已保存历史；最多展示前 500 条结果。</p>
    {error && <p role="alert">搜索或定位失败：{error}</p>}
    {!progress.busy && query.trim() && !hits.length && <p>没有匹配结果。</p>}
    {hits.map((hit, index) => <button key={hit.id} aria-pressed={selected === index} onClick={() => void select(index)} style={{ display: "block", textAlign: "left", width: "100%" }}>
      {new Date(hit.timestamp).toLocaleString()} · {hit.excerpt}
    </button>)}
  </section>;
}
