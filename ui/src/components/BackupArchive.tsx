import { useEffect, useRef, useState } from "react";
import { getDesktopApi } from "../lib/desktopApi";
import { decodeContent } from "../lib/messageContent";
import type { BackupArchiveInfo, BackupConversation, BackupHistory } from "../../../electron/contracts";
import "./backup.css";

export default function BackupArchive({ id }: { id: string }) {
  const [info, setInfo] = useState<BackupArchiveInfo | null>(null);
  const [conversations, setConversations] = useState<BackupConversation[]>([]), [next, setNext] = useState<string | null>(null);
  const [selected, setSelected] = useState<BackupConversation | null>(null), [page, setPage] = useState<BackupHistory | null>(null);
  const [error, setError] = useState(""), [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<{ url: string; audio: boolean } | null>(null);
  const generation = useRef(0), alive = useRef(false);
  useEffect(() => {
    alive.current = true;
    const run = async () => { try { const [identity, list] = await Promise.all([getDesktopApi().get_backup_archive_info({ id }), getDesktopApi().get_backup_conversations({ id })]); if (alive.current) { setInfo(identity); setConversations(list.items); setNext(list.next); } } catch (failure) { if (alive.current) setError(String(failure)); } };
    void run(); return () => { alive.current = false; generation.current++; };
  }, [id]);
  async function history(conversation: BackupConversation, earlier = false) {
    const token = ++generation.current; setBusy(true); setError(""); setPreview(null);
    if (!earlier) { setSelected(conversation); setPage(null); }
    try {
      const result = await getDesktopApi().get_backup_history({ id, kind: conversation.kind, conversationId: conversation.id,
        ...(earlier && page?.next ? { beforeTime: page.next.time, beforeId: page.next.id } : {}), ...(earlier && page?.next_group ? { beforeGroup: page.next_group } : {}) });
      if (alive.current && token === generation.current) setPage(previous => earlier && previous ? { ...result, messages: [...result.messages, ...previous.messages], collaboration: result.collaboration ? { ...result.collaboration, polls: [...result.collaboration.polls, ...(previous.collaboration?.polls ?? []).filter(p => !result.collaboration!.polls.some(next => next.id === p.id))] } : undefined } : result);
    } catch (failure) { if (alive.current && token === generation.current) setError(String(failure)); } finally { if (alive.current && token === generation.current) setBusy(false); }
  }
  return <main className="backup-archive">
    <header className="backup-archive-header"><h1>离线恢复档案</h1><button onClick={() => void getDesktopApi().close_backup_archive({}).catch(failure => setError(String(failure)))}>关闭档案</button></header>
    <p>只读 · 不连接服务器 · 不发送消息 · 不激活原设备</p>
    {info && <details><summary>恢复身份与备份范围</summary><p>账号 {info.user_id} · 设备 {info.device_id}</p><p>{info.server_url}</p><p>加密指纹 {info.fingerprint}</p><p>签名指纹 {info.signing_fingerprint}</p><p>{info.summary.messages} 条单聊历史 · {info.summary.groups} 个群 · {info.summary.attachments} 个附件，{info.summary.missing_attachments} 个未包含。</p></details>}
    {error && <p role="alert">{error}</p>}
    <div className="backup-archive-layout"><nav aria-label="恢复会话"><ul>{conversations.map(item => <li key={`${item.kind}:${item.id}`}><button aria-current={selected?.id === item.id ? "true" : undefined} onClick={() => void history(item)}>{item.kind === "group" ? "群 · " : ""}{item.name}</button></li>)}</ul>
      {next && <button onClick={async () => { try { const result = await getDesktopApi().get_backup_conversations({ id, after: next }); if (alive.current) { setConversations(previous => [...previous, ...result.items]); setNext(result.next); } } catch (failure) { if (alive.current) setError(String(failure)); } }}>更多会话</button>}
    </nav><section aria-label="恢复历史"><h2>{selected?.name ?? "选择会话查看历史"}</h2>
      {busy && <p role="status">读取历史…</p>}
      {(page?.next || page?.next_group) && <button disabled={busy} onClick={() => selected && void history(selected, true)}>加载更早历史</button>}
      {page?.draft && <details><summary>备份中的草稿</summary><pre>{page.draft}</pre></details>}
      {page?.collaboration && <p>置顶：{page.collaboration.pin_unavailable ? "原消息不可用" : page.collaboration.pin ?? "无"}</p>}
      <ol className="backup-history">{page?.messages.map(message => { const content = decodeContent(message.text), attachment = content.attachment; return <li key={message.id}><div><small>{message.sender} · {new Date(message.timestamp).toLocaleString()}</small></div>
        {content.reply && <blockquote>{content.reply.sender}：{content.reply.text}</blockquote>}
        {content.forwarded && <p>转发自 {content.forwarded.sender}</p>}
        <p>{content.text}</p>
        {page.reactions?.filter(r => r.target_id === message.id).map(r => <span key={r.actor} title={r.actor}>{r.emoji} </span>)}
        {attachment && <div className="backup-actions"><button onClick={async () => { setError(""); try { const result = await getDesktopApi().export_backup_attachment({ id, messageId: message.id }); if (alive.current && result) setError(""); } catch (failure) { if (alive.current) setError(`附件未包含、原文不可用或保存失败：${String(failure)}`); } }}>保存已包含附件</button>
          {(attachment.mime.startsWith("image/") || attachment.mime === "audio/webm") && <button onClick={async () => { const token = generation.current; setError(""); try { const url = await getDesktopApi().export_backup_attachment({ id, messageId: message.id, preview: true }); if (alive.current && token === generation.current && url) setPreview({ url, audio: attachment.mime === "audio/webm" }); } catch (failure) { if (alive.current && token === generation.current) setError(String(failure)); } }}>查看已包含附件</button>}</div>}
        {page.collaboration?.polls.filter(p => p.id === message.id).map(poll => <div key={poll.id} className="backup-poll"><h3>{poll.question}</h3><p>{poll.closed ? "已关闭" : "备份时未关闭"} · 实名单选投票</p><ul>{poll.options.map(option => <li key={option.id}>{option.text}：{Object.values(poll.votes).filter(v => v === option.id).length} 票</li>)}</ul></div>)}
      </li>; })}</ol>
      {preview && <div className="backup-preview"><button onClick={() => setPreview(null)}>关闭附件预览</button>{preview.audio ? <audio controls src={preview.url} /> : <img src={preview.url} alt="恢复附件预览" />}</div>}
    </section></div>
  </main>;
}
