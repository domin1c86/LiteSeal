import { useCallback, useEffect, useRef, useState } from "react";
import { getDesktopApi } from "../lib/desktopApi";
import type { Contact } from "../types";
import type { GroupStorageStats, SentGroupInvites, GroupInspection, GroupMember, GroupMessage, GroupSnapshot } from "../../../electron/contracts";
import "./groups.css";

const empty: GroupSnapshot = { groups: [], invitations: [], errors: [], next_cursor: null };
const bytes = (text: string) => new TextEncoder().encode(text).length;
const validName = (name: string) => !!name.trim() && bytes(name) <= 160 && !/[\u0000-\u001f\u007f-\u009f]/.test(name);
type Dialog = { kind: "create" } | { kind: "inspect"; detail: GroupInspection; inviteId?: string }
  | { kind: "storage"; stats: GroupStorageStats; groupId: string; result?: string } | { kind: "sent"; page: SentGroupInvites; groupId: string } | { kind: "invite"; peer?: GroupMember } | { kind: "rename" } | { kind: "danger"; action: "leave" | "close" | "remove"; memberId?: string; label: string };
interface Props { target?: { id: string; nonce: number } | null; onActiveChange: (id: string | null) => void; userId: string; contacts: Contact[]; obscured: boolean; onClose: () => void; onBusyChange: (busy: boolean) => void }

export default function GroupPanel({ target, onActiveChange, userId, contacts, obscured, onClose, onBusyChange }: Props) {
  const [snapshot, setSnapshot] = useState(empty);
  const [ready, setReady] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [messages, setMessages] = useState<GroupMessage[]>([]);
  const [before, setBefore] = useState<number | null>(null);
  const [text, setText] = useState("");
  const [draftReady, setDraftReady] = useState(false);
  const [saving, setSaving] = useState(false);
  const [draftError, setDraftError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [name, setName] = useState("");
  const [peerId, setPeerId] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const mounted = useRef(true);
  const activeId = useRef<string | null>(null);
  const snapshotVersion = useRef(0);
  const consumedTarget = useRef<number | null>(null);
  const historyVersion = useRef(0);
  const dirty = useRef<{ id: string; text: string; version: number } | null>(null);
  const savedVersion = useRef(0);
  const writing = useRef<Promise<void> | null>(null);
  const busyRef = useRef(false);
  const listRef = useRef<HTMLDivElement>(null);
  const dialogRef=useRef<HTMLElement>(null);
  const group = snapshot.groups.find(item => item.id === selected);
  const owner = group?.owner === userId;

  const refresh = useCallback(async (network = false, afterId?: string) => {
    const version = ++snapshotVersion.current;
    const next = await getDesktopApi().get_groups({ refresh: network, afterId });
    if (mounted.current && version === snapshotVersion.current) { setSnapshot(next); setReady(true); }
    return next;
  }, []);
  const history = useCallback(async (id: string, reset = false) => {
    const version = ++historyVersion.current;
    const page = await getDesktopApi().get_group_history({ groupId: id });
    if (!mounted.current || activeId.current !== id || version !== historyVersion.current) return;
    if (reset) { setMessages(page.messages); setBefore(page.next_before); }
    else setMessages(previous => [...previous.filter(old => !page.messages.some(next => next.id === old.id)), ...page.messages]);
  }, []);
  const flush = useCallback(async () => {
    if (writing.current) return writing.current;
    if (!dirty.current || dirty.current.version === savedVersion.current) return;
    setSaving(true);
    const job = (async () => {
      while (dirty.current && dirty.current.version !== savedVersion.current) {
        const draft = dirty.current;
        await getDesktopApi().group_draft({ groupId: draft.id, text: draft.text });
        savedVersion.current = draft.version;
      }
      if (mounted.current) { setDraftError(null); setSaving(false); }
    })().catch(failure => { if (mounted.current) setDraftError(`草稿尚未保存：${String(failure)}`); throw failure; })
      .finally(() => { writing.current = null; });
    writing.current = job;
    return job;
  }, []);
  useEffect(() => {
    mounted.current = true;
    void refresh(true).catch(failure => { if (mounted.current) { setError(String(failure)); setReady(true); } });
    const changed = () => {
      void refresh().catch(failure => { if (mounted.current) setError(String(failure)); });
      if (activeId.current) void history(activeId.current).catch(failure => { if (mounted.current) setError(String(failure)); });
    };
    const timer = setInterval(changed, 10000);
    window.addEventListener("liteseal-groups-changed", changed);
    const guard = (event: BeforeUnloadEvent) => { if (busyRef.current || (dirty.current && dirty.current.version !== savedVersion.current)) { event.preventDefault(); event.returnValue = ""; } };
    window.addEventListener("beforeunload", guard);
    return () => { mounted.current = false; clearInterval(timer); window.removeEventListener("liteseal-groups-changed", changed); window.removeEventListener("beforeunload", guard); };
  }, [refresh, history]);
  useEffect(() => {
    onActiveChange(!obscured && !dialog ? selected : null);
    return () => onActiveChange(null);
  }, [selected, obscured, dialog, onActiveChange]);
  useEffect(() => {
    if (!target || !ready || busy || saving || draftError || consumedTarget.current === target.nonce) return;
    void run(async () => { await flush(); activeId.current = target.id; setSelected(target.id); consumedTarget.current = target.nonce; });
  }, [target?.nonce, ready, busy, saving, draftError]);
  useEffect(() => { onBusyChange(busy || saving || !!draftError); return () => onBusyChange(false); }, [busy, saving, draftError, onBusyChange]);
  useEffect(() => {
    const node=dialogRef.current;if(!dialog || !node)return;
    const previous=document.activeElement as HTMLElement | null;
    (node.querySelector('input,select,textarea') as HTMLElement | null ?? node.querySelector('button'))?.focus();
    const key=(event:KeyboardEvent)=>{
      if(event.key==='Escape' && !busyRef.current){event.preventDefault();setDialog(null);setConfirmed(false);}
      if(event.key!=='Tab')return;
      const items=Array.from(node.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled)'));
      const first=items[0],last=items[items.length-1];if(!first)return;
      if(event.shiftKey && (document.activeElement===first || !node.contains(document.activeElement))){event.preventDefault();last?.focus();}
      else if(!event.shiftKey && (document.activeElement===last || !node.contains(document.activeElement))){event.preventDefault();first.focus();}
    };
    document.addEventListener('keydown',key);return()=>{document.removeEventListener('keydown',key);if(previous?.isConnected)previous.focus();};
  },[dialog?.kind]);
  useEffect(() => {
    activeId.current = selected;
    setMessages([]); setBefore(null); setText(""); setDraftReady(false); dirty.current = null; savedVersion.current = 0;
    if (!selected || !group?.trusted) return;
    const id = selected;
    void Promise.all([getDesktopApi().group_draft({ groupId: id }), history(id, true)]).then(([draft]) => {
      if (!mounted.current || activeId.current !== id) return;
      dirty.current = { id, text: draft, version: 1 }; savedVersion.current = 1; setText(draft); setDraftReady(true);
    }).catch(failure => { if (mounted.current && activeId.current === id) setError(String(failure)); });
  }, [selected, group?.trusted, history]);
  useEffect(() => {
    const root = listRef.current;
    if (!root || !selected || obscured || dialog) return;
    const id = selected;
    const visible = new Set<string>();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const mark = () => {
      if (document.hidden || !document.hasFocus() || !visible.size) return;
      const ids = [...visible].slice(0, 100);
      void getDesktopApi().mark_group_seen({ groupId: id, ids }).then(() => refresh()).catch(() => {});
    };
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) { const messageId = (entry.target as HTMLElement).dataset.messageId!; if (entry.isIntersecting && entry.intersectionRect.height > 12) visible.add(messageId); else visible.delete(messageId); }
      clearTimeout(timer); timer = setTimeout(mark, 150);
    }, { root, threshold: [0, 0.1, 0.6] });
    root.querySelectorAll('[data-unseen="true"]').forEach(row => observer.observe(row));
    window.addEventListener("focus", mark); document.addEventListener("visibilitychange", mark);
    return () => { observer.disconnect(); clearTimeout(timer); window.removeEventListener("focus", mark); document.removeEventListener("visibilitychange", mark); };
  }, [selected, messages, obscured, dialog, refresh]);

  async function run(work: () => Promise<void>, reset = false) {
    if (busyRef.current) return;
    busyRef.current = true; setBusy(true); setError(null);
    const startedId=activeId.current;
    try { await work(); }
    catch (failure) { if (mounted.current) setError(String(failure)); }
    finally {
      try { await refresh(); if (activeId.current && activeId.current===startedId) await history(activeId.current, reset); } catch (failure) { if (mounted.current) setError(String(failure)); }
      busyRef.current = false; if (mounted.current) setBusy(false);
    }
  }
  async function choose(id: string) { await run(async () => { await flush(); activeId.current = id; setSelected(id); }); }
  function edit(value: string) {
    setText(value); if (!selected) return;
    dirty.current = { id: selected, text: value, version: (dirty.current?.version ?? 0) + 1 };
    void flush().catch(() => {});
  }
  async function inspect(groupId: string, inviteId?: string) {
    await run(async () => { const detail = await getDesktopApi().inspect_group({ groupId, inviteId }); setConfirmed(false); setDialog({ kind: "inspect", detail, inviteId }); });
  }
  async function send() {
    if (!selected) return;
    await run(async () => {
      await flush(); const result = await getDesktopApi().send_group_text({ groupId: selected, text });
      const version = (dirty.current?.version ?? 0) + 1; dirty.current = { id: selected, text: "", version }; savedVersion.current = version;
      if (mounted.current) { setText(""); if (result.error) setError(`消息已保留待重试：${result.error}`); }
    });
  }
  async function earlier() {
    if (!selected || before === null) return;
    await run(async () => { const page = await getDesktopApi().get_group_history({ groupId: selected, before }); if (activeId.current === selected) { setMessages(previous => [...page.messages.filter(old => !previous.some(next => next.id === old.id)), ...previous]); setBefore(page.next_before); } });
  }
  function closeDialog() { if (!busy) { setDialog(null); setConfirmed(false); } }
  const eligibleContacts = contacts.filter(contact => contact.user_id !== userId && contact.trust_state === "verified" && !contact.key_changed && contact.ed25519_pk?.length === 32 && !group?.members.some(member => member.user_id === contact.user_id));
  return <section className="group-panel" aria-label="群聊">
    <aside className="group-sidebar">
      <header><h2>群聊</h2><button disabled={busy || saving || !!draftError} onClick={() => { void run(async () => { await flush(); onClose(); }); }}>返回单聊</button></header>
      <div className="group-actions"><button disabled={busy} onClick={() => { setName(""); setDialog({ kind: "create" }); }}>创建群</button><button disabled={busy} onClick={() => { void run(async () => { await refresh(true); if (selected && group?.trusted) await getDesktopApi().sync_group({ groupId: selected }); }); }}>刷新</button></div>
      {!ready && <p role="status">正在恢复群聊…</p>}
      {ready && !snapshot.groups.length && <p className="group-muted">还没有群。创建后邀请已核实的联系人。</p>}
      <nav aria-label="群会话">{snapshot.groups.map(item => <button key={item.id} className={selected === item.id ? "group-selected" : ""} disabled={busy || saving || !!draftError} onClick={() => { void choose(item.id); }}><strong>{item.name}</strong><span>{item.closed ? "已关闭" : item.active ? `${item.members.length} 位成员` : item.trusted ? "不在当前成员中" : "待核实"}{item.unread > 0 ? ` · ${item.unread} 条未读` : ""}{item.pending ? " · 待发送" : ""}</span></button>)}</nav>
      {snapshot.next_cursor && <button disabled={busy} onClick={() => { void run(async () => { await refresh(true, snapshot.next_cursor!); }); }}>更多群记录</button>}
      <h3>待接受邀请</h3>{!snapshot.invitations.length && <p className="group-muted">暂无邀请</p>}
      {snapshot.invitations.map(invite => <div className="group-invite" key={invite.id}><span>群 {invite.group_id.slice(0, 8)}</span><small>有效期至 {new Date(invite.expires_at).toLocaleString()}</small><div className="group-actions"><button disabled={busy} onClick={() => { void inspect(invite.group_id, invite.id); }}>核实邀请</button><button disabled={busy} onClick={() => { void run(async () => { await getDesktopApi().decline_group_invite({ inviteId: invite.id }); }); }}>拒绝</button></div></div>)}
    </aside>
    <div className="group-chat">
      {(error || snapshot.errors.length > 0) && <div className="group-error" role="alert">{error ?? snapshot.errors.join("；")} <button disabled={busy} onClick={() => { void run(async () => { await refresh(true); }); }}>重试检查</button></div>}
      {busy && <p role="status" className="group-muted">处理中，请稍候…</p>}
      {!group ? <div className="group-empty"><h2>小型私密群</h2><p>选择一个群，或核实待接受的邀请。</p><p>首轮支持最多 10 位成员的加密文字聊天。</p></div> : <>
        <header className="group-heading"><div><h2>{group.name}</h2><small>{group.id}</small><p>{group.closed ? "群已关闭，本机历史仍可查看" : group.active ? "加密文字聊天" : "当前不可发送，可查看已有本机历史"}</p></div><div className="group-actions">{group.trusted && <button disabled={busy} onClick={() => { void run(async () => { const stats = await getDesktopApi().get_group_storage_stats({ groupId: group.id }); setConfirmed(false); setDialog({ kind: "storage", stats, groupId: group.id }); }); }}>群数据管理</button>}{group.trusted && <button disabled={busy} onClick={() => { void run(async () => { await getDesktopApi().set_group_muted({ groupId: group.id, muted: !group.muted }); }); }}>{group.muted ? "取消静音" : "群静音"}</button>}{group.trusted && <button disabled={busy} onClick={() => { void run(async () => { await getDesktopApi().sync_group({ groupId: group.id }); }); }}>补收消息</button>}{!group.trusted && <button disabled={busy} onClick={() => { void inspect(group.id); }}>核实并恢复</button>}{group.trusted && owner && <button disabled={busy} onClick={() => { void run(async () => { const page = await getDesktopApi().get_sent_group_invites({ groupId: group.id }); setDialog({ kind: "sent", page, groupId: group.id }); }); }}>已发邀请</button>}{group.active && owner && <><button disabled={busy || group.members.length >= 10} onClick={() => { setPeerId(""); setConfirmed(false); setDialog({ kind: "invite" }); }}>邀请成员</button><button disabled={busy} onClick={() => { setName(group.name); setDialog({ kind: "rename" }); }}>修改群名</button><button disabled={busy} onClick={() => { setConfirmed(false); setDialog({ kind: "danger", action: "close", label: "关闭群" }); }}>关闭群</button></>}{group.active && !owner && <button disabled={busy} onClick={() => { setConfirmed(false); setDialog({ kind: "danger", action: "leave", label: "退出群" }); }}>退出群</button>}</div></header>
        {group.trusted && <details className="group-members"><summary>成员（{group.members.length}）</summary><div>{group.members.map(member => <article key={member.user_id}><strong>{member.name}{member.user_id === group.owner ? " · 群主" : ""}</strong><small>账号：{member.user_id}<br />设备：{member.device_id}<br />指纹：{member.fingerprint}</small>{owner && group.active && member.user_id !== userId && <button disabled={busy} onClick={() => { setConfirmed(false); setDialog({ kind: "danger", action: "remove", memberId: member.user_id, label: `移除 ${member.name}` }); }}>移除成员</button>}</article>)}</div></details>}
        <div ref={listRef} className="group-message-list" role="log" aria-label="群消息">
          {before !== null && <button disabled={busy} onClick={() => { void earlier(); }}>更早消息</button>}
          {!messages.length && group.trusted && <p className="group-muted">暂无本机消息。新成员不会取得加入前的消息。</p>}
          {messages.map(message => <article key={message.id} data-message-id={message.id} data-unseen={message.status === "received" ? "true" : "false"} className={message.sender_user_id === userId ? "group-message group-message-own" : "group-message"}><header><strong>{message.sender_user_id === userId ? "我" : group.members.find(member => member.user_id === message.sender_user_id)?.name ?? message.sender_user_id}</strong><time>{new Date(message.sent_at).toLocaleString()}</time></header><p>{message.text}</p><small>{message.status === "queued" ? "待发送" : message.status === "accepted" ? "已提交" : "已接收"}</small>{message.status === "queued" && <div className="group-actions"><button disabled={busy} onClick={() => { void run(async () => { const result = await getDesktopApi().send_group_text({ groupId: group.id }); if (result.error) setError(result.error); }); }}>重试原消息</button><button disabled={busy} onClick={() => { void run(async () => { await getDesktopApi().cancel_group_send({ groupId: group.id }); }, true); }}>取消未发送</button></div>}</article>)}
        </div>
        {group.trusted && <footer className="group-composer"><textarea aria-label="群消息正文" placeholder={!group.active ? "当前无法发送" : group.members.length < 2 ? "邀请成员后开始聊天" : "输入群消息（Enter 发送，Shift+Enter 换行）"} disabled={busy || !draftReady || !group.active || group.pending || group.members.length < 2} value={text} onChange={event => edit(event.target.value)} onKeyDown={event => { if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing && text.trim() && bytes(text) <= 4096) { event.preventDefault(); void send(); } }} /><div className="group-actions"><span role="status">{draftError ?? (saving ? "草稿保存中…" : "草稿已加密保存在本机")}</span>{draftError && <button disabled={busy} onClick={() => { void flush().catch(() => {}); }}>重试保存</button>}<button disabled={busy || !draftReady || !group.active || group.pending || group.members.length < 2 || !text.trim() || bytes(text) > 4096} onClick={() => { void send(); }}>发送</button></div>{bytes(text) > 4096 && <p role="alert">文字过长，请缩短后发送。</p>}</footer>}
      </>}
    </div>
    {dialog && <div className="group-dialog-backdrop"><section ref={dialogRef} role="dialog" aria-modal="true" aria-label={dialog.kind === "create" ? "创建群" : dialog.kind === "inspect" ? "核实群身份" : dialog.kind === "invite" ? "邀请成员" : dialog.kind === "rename" ? "修改群名" : dialog.kind === "sent" ? "已发邀请" : dialog.kind === "storage" ? "群数据管理" : dialog.label} className="group-dialog"><button className="group-dialog-close" aria-label="关闭对话框" disabled={busy} onClick={closeDialog}>×</button>
      {(dialog.kind === "create" || dialog.kind === "rename") && <form onSubmit={event => { event.preventDefault(); void run(async () => { if (dialog.kind === "create") { await flush(); const id = await getDesktopApi().create_group({ name: name.trim() }); activeId.current = id; setSelected(id); } else if (selected) await getDesktopApi().change_group_membership({ groupId: selected, action: "rename", value: name.trim() }); closeDialog(); }); }}><h2>{dialog.kind === "create" ? "创建群" : "修改群名"}</h2><label>群名<input autoFocus value={name} onChange={event => setName(event.target.value)} /></label><p className="group-muted">最多 10 位成员。创建后可邀请已核实的联系人。</p><button disabled={busy || !validName(name)}>确认</button></form>}
      {dialog.kind === "inspect" && <><h2>{dialog.detail.name}</h2><p>群主：{dialog.detail.owner_name}</p><div className="group-identity">账号：{dialog.detail.owner_id}<br />设备：{dialog.detail.owner_device}<br />公钥指纹：<br />{dialog.detail.fingerprint}</div>{!dialog.detail.eligible && <p role="alert">{dialog.detail.reason}</p>}<label className="group-check"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />已通过可信渠道核对账号、设备和两组指纹</label><button disabled={busy || !confirmed || !dialog.detail.eligible} onClick={() => { void run(async () => { await flush(); const id = dialog.inviteId ? await getDesktopApi().accept_group_invite({ inviteId: dialog.inviteId, confirmedFingerprint: dialog.detail.fingerprint }) : (await getDesktopApi().recover_group({ groupId: dialog.detail.group_id, confirmedFingerprint: dialog.detail.fingerprint }), dialog.detail.group_id); activeId.current = id; setSelected(id); closeDialog(); }); }}>{dialog.inviteId ? "接受邀请" : "确认并恢复"}</button></>}
      {dialog.kind === "invite" && <><h2>邀请成员</h2><label>已核实的联系人<select aria-label="邀请联系人" value={peerId} disabled={busy} onChange={event => { setPeerId(event.target.value); setConfirmed(false); setDialog({ kind: "invite" }); }}><option value="">请选择</option>{eligibleContacts.map(contact => <option key={contact.user_id} value={contact.user_id}>{contact.username}</option>)}</select></label>{!eligibleContacts.length && <p>请先返回联系人页面添加并核实身份。</p>}<button disabled={busy || !peerId} onClick={() => { void run(async () => { const peer = await getDesktopApi().inspect_group_peer({ peerId }); setDialog({ kind: "invite", peer }); }); }}>查看设备和指纹</button>{dialog.peer && <><div className="group-identity">账号：{dialog.peer.user_id}<br />设备：{dialog.peer.device_id}<br />公钥指纹：<br />{dialog.peer.fingerprint}</div><label className="group-check"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />已核对目标账号、设备和两组指纹</label><button disabled={busy || !confirmed} onClick={() => { void run(async () => { if (!selected || !dialog.peer) return; await getDesktopApi().invite_group_member({ groupId: selected, peerId: dialog.peer.user_id, confirmedFingerprint: dialog.peer.fingerprint }); closeDialog(); }); }}>发送邀请</button></>}</>}
      {dialog.kind === "storage" && <><h2>群数据管理</h2><p>可见历史：{dialog.stats.visible_messages} 条 · 本机隐藏：{dialog.stats.hidden_messages} 条<br />未读：{dialog.stats.unread_messages} 条 · 待发任务：{dialog.stats.pending_tasks} 项</p><p>本群逻辑载荷：{dialog.stats.logical_bytes.toLocaleString()} B<br />全库数据库文件：{dialog.stats.database_bytes.toLocaleString()} B<br />全库 WAL 文件：{dialog.stats.wal_bytes.toLocaleString()} B</p><p className="group-muted">逻辑载荷包含保留的密文及协议数据，不含索引和数据库页开销。全库文件大小包含其他会话，不能视为本群占用。</p><button disabled={busy} onClick={() => { void run(async () => { const stats = await getDesktopApi().get_group_storage_stats({ groupId: dialog.groupId }); setDialog({ ...dialog, stats }); }); }}>刷新统计</button><h3>清空本机群历史</h3><p>仅隐藏当前已保存的历史，不撤回对方消息、不退出群。密文与验证证据、待发任务、待确认收件和草稿保留。仅本机隐藏，不保证释放磁盘空间。之后的新消息正常显示。</p><label className="group-check"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />我已了解并确认隐藏本机历史</label><button disabled={busy || !confirmed || dialog.stats.visible_messages === 0} onClick={() => { void run(async () => { await flush(); const count = await getDesktopApi().clear_group_history({ groupId: dialog.groupId }); ++historyVersion.current; setMessages([]); setBefore(null); setConfirmed(false); const stats = await getDesktopApi().get_group_storage_stats({ groupId: dialog.groupId }); setDialog({ ...dialog, stats, result: `已在本机隐藏 ${count} 条历史。待发任务和草稿已保留。` }); }, true); }}>确认清空本机历史</button>{dialog.result && <p role="status">{dialog.result}</p>}</>}
      {dialog.kind === "sent" && <><h2>已发邀请</h2><button disabled={busy} onClick={() => { void run(async () => { const page = await getDesktopApi().get_sent_group_invites({ groupId: dialog.groupId }); setDialog({ ...dialog, page }); }); }}>刷新邀请</button>{!dialog.page.invites.length && <p>暂无已发邀请</p>}{dialog.page.invites.map(invite => <article className="group-invite" key={invite.id}><div className="group-identity">账号：{invite.user_id}<br />设备：{invite.device_id}</div><p>有效期至 {new Date(invite.expires_at).toLocaleString()} · {({ pending: "待接受", accepted: "已接受", rejected: "已拒绝", revoked: "已撤销", expired: "已过期", invalidated: "群成员版本已变化或群已关闭" })[invite.status]}</p>{invite.status === "pending" && <button disabled={busy} onClick={() => { void run(async () => { try { await getDesktopApi().revoke_group_invite({ inviteId: invite.id }); } finally { const page = await getDesktopApi().get_sent_group_invites({ groupId: dialog.groupId }); setDialog({ ...dialog, page }); } }); }}>撤销邀请</button>}</article>)}{dialog.page.next_cursor && <button disabled={busy} onClick={() => { void run(async () => { const page = await getDesktopApi().get_sent_group_invites({ groupId: dialog.groupId, afterId: dialog.page.next_cursor! }); setDialog({ ...dialog, page: { ...page, invites: [...dialog.page.invites, ...page.invites] } }); }); }}>更多邀请</button>}<p className="group-muted">已接受的成员不能通过撤销邀请移除。失效后请重新核实设备和指纹再邀请。</p></>}
      {dialog.kind === "danger" && <><h2>{dialog.label}</h2><p>{dialog.action === "close" ? "关闭群后，所有成员停止后续收发。已保存在本机的历史仍可查看。" : dialog.action === "remove" ? "该成员停止后续收发，重新加入也不会恢复旧待收队列。已保存的历史不会被销毁。" : "退出后停止群收发。已保存的本机历史保留。"}</p><label className="group-check"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />我已了解并确认此操作</label><button disabled={busy || !confirmed} onClick={() => { void run(async () => { if (selected) await getDesktopApi().change_group_membership({ groupId: selected, action: dialog.action, value: dialog.memberId }); closeDialog(); }); }}>确认{dialog.action === "close" ? "关闭" : dialog.action === "leave" ? "退出" : "移除"}</button></>}
    </section></div>}
  </section>;
}
