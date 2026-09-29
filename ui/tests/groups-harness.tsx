import { createRoot } from 'react-dom/client';
import '../src/theme.css';
import GroupPanel from '../src/components/GroupPanel';
import type { DesktopApi, GroupView, GroupMessage, GroupCollaboration, CollaborationCommand } from '../../electron/contracts';

const root = createRoot(document.getElementById('root')!);
const copy = <T,>(value: T): T => structuredClone(value);
const pause = () => new Promise(resolve => setTimeout(resolve, 30));
const check = (value: unknown, message: string) => { if (!value) throw new Error(message); };
const wait = async (condition: () => unknown, label: string) => { for (let i = 0; i < 100; i++) { if (condition()) return; await pause(); } throw new Error('timeout: ' + label); };
const buttons = () => Array.from(document.querySelectorAll<HTMLButtonElement>('button'));
const button = (text: string) => buttons().find(node => node.textContent === text);
const click = async (text: string) => { await wait(() => button(text) && !button(text)!.disabled, text); button(text)!.click(); await pause(); };
const body = () => document.body.textContent ?? '';
const member = (id: string) => ({ user_id: id, device_id: 'device-' + id, name: id, fingerprint: 'synthetic fingerprint', joined_epoch: 1 });
let group: GroupView, messages: GroupMessage[], draft = '', hidden = 0, failDraft = false, conflict = false, generation = 0, clearCalls = 0;
let sentCalls: Array<string | undefined> = [];
let inviteStatus = 'pending';
let delayHistory: null | { started: boolean; resolve?: (value: unknown) => void } = null;
let delaySnapshot: null | { started: boolean; resolve?: (value: unknown) => void } = null;
let delayInvites: null | { started: boolean; resolve?: (value: unknown) => void } = null;
let collab: GroupCollaboration = { polls: [], pin: null, pin_unavailable: false, pin_revision: 0, pending: false, conflict: false, pending_message: null };
let collabSupported = true;
let failCollab = false;
let submitted: CollaborationCommand[] = [];
let active: string | null = null;
let busy = false;
const onActive = (id: string | null) => { active = id; };
const onBusy = (value: boolean) => { busy = value; };
const snapshot = () => ({ groups: [copy(group)], invitations: [], errors: [], next_cursor: null });
const invitation = (id: string, status: string) => ({ id, group_id: group.id, user_id: 'target-' + id, device_id: 'device-' + id, expires_at: 2000000000000, status });
const api = {
  get_group_collaboration: async ({ messageIds }: { messageIds?: string[] }) => ({ ...copy(collab), polls: copy(collab.polls.filter(poll => !messageIds || messageIds.includes(poll.id))) }),
  sync_group_collaboration: async () => collabSupported,
  retry_group_collaboration: async () => { const message=messages.find(m=>m.id===collab.pending_message);if(message)message.status='accepted';collab.pending = false;collab.pending_message=null; },
  discard_group_collaboration_conflict: async () => { collab.conflict = false; },
  submit_group_collaboration: async ({ command }: { command: CollaborationCommand }) => {
    submitted.push(copy(command));
    if (command.kind === "mention") draft = "";
    if (failCollab) { collab.pending = true;collab.pending_message='pending-mention'; if(command.kind==='mention') messages.push({id:'pending-mention',sender_user_id:'owner',sender_device_id:'device-owner',sent_at:1000000000012,text:command.text,status:'queued'}); throw new Error('synthetic collaboration network failure'); }
    if (command.kind === 'pin') { collab.pin = command.message; collab.pin_revision++; }
    if (command.kind === 'mention') messages.push({ id:'mention', sender_user_id:'owner', sender_device_id:'device-owner', sent_at:1000000000010, text:command.text, status:'accepted' });
    if (command.kind === 'poll') {
      collab.polls.push({ id:'poll', creator:'owner', question:command.question, options:command.options.map((text,i)=>({id:'option-'+i,text})), votes:{}, departed:[], closed:false, eligible:true, revision:1 });
      messages.push({ id:'poll', sender_user_id:'owner', sender_device_id:'device-owner', sent_at:1000000000011, text:'投票：'+command.question, status:'accepted' });
    }
    if (command.kind === 'vote') { const poll=collab.polls.find(p=>p.id===command.poll)!; if(poll.revision!==command.revision) throw new Error('stale vote'); poll.votes.owner=command.option;poll.revision++; }
    if (command.kind === 'close') { const poll=collab.polls.find(p=>p.id===command.poll)!;poll.closed=true;poll.revision++; }
  },
  get_groups: async () => { if (delaySnapshot && !delaySnapshot.started) { delaySnapshot.started = true; return new Promise(resolve => { delaySnapshot!.resolve = resolve; }); } return snapshot(); },
  get_group_history: async () => { if (delayHistory && !delayHistory.started) { delayHistory.started = true; return new Promise(resolve => { delayHistory!.resolve = resolve; }); } return { messages: copy(messages), next_before: null }; },
  group_draft: async (args: { text?: string }) => { if (args.text !== undefined) { if (failDraft) throw new Error('synthetic disk failure'); draft = args.text; } return draft; },
  set_group_muted: async ({ muted }: { muted: boolean }) => { group.muted = muted; },
  mark_group_seen: async () => {},
  get_sent_group_invites: async ({ afterId }: { afterId?: string }) => {
    sentCalls.push(afterId);
    if (delayInvites && !delayInvites.started) { delayInvites.started = true; return new Promise(resolve => { delayInvites!.resolve = resolve; }); }
    return afterId ? { invites: [invitation('2', 'expired')], next_cursor: null } : { invites: [invitation('1', inviteStatus)], next_cursor: '1' };
  },
  revoke_group_invite: async () => { inviteStatus = conflict ? 'accepted' : 'revoked'; if (conflict) throw new Error('synthetic acceptance conflict'); },
  get_group_storage_stats: async () => ({ visible_messages: messages.length, hidden_messages: hidden, unread_messages: group.unread, pending_tasks: messages.filter(m => m.status === 'queued').length, logical_bytes: 1234, database_bytes: 8192, wal_bytes: 2048 }),
  clear_group_history: async () => { clearCalls++; const before = messages.length; messages = messages.filter(m => m.status === 'queued'); const count = before - messages.length; hidden += count; group.unread = 0; collab.polls = collab.polls.filter(p=>messages.some(m=>m.id===p.id)); return count; },
};
window.desktop = api as unknown as DesktopApi;
async function mount(userId = 'owner') {
  root.render(<GroupPanel key={++generation} userId={userId} target={null} contacts={[]} obscured={false} onActiveChange={onActive} onBusyChange={onBusy} onClose={() => root.render(<p>Panel closed</p>)} />);
  await pause();
}
async function select() {
  await wait(() => !!document.querySelector('nav[aria-label="群会话"] button'), 'group list');
  (document.querySelector('nav[aria-label="群会话"] button') as HTMLButtonElement).click();
  await wait(() => !!button('群数据管理') && !busy, 'selected group');
  await wait(() => document.querySelector('textarea')?.getAttribute('placeholder')?.startsWith('输入群消息'), 'composer');
}
function reset() {
  group = { id: 'group-one', name: 'Trial group', owner: 'owner', epoch: 3, closed: false, active: true, trusted: true, members: [member('owner'), member('member')], unread: 1, pending: false, muted: false };
  messages = [{ id: 'old', sender_user_id: 'member', sender_device_id: 'device-member', sent_at: 1000000000000, text: 'Synthetic old message', status: 'received' }];
  draft = 'retained draft'; hidden = 0; failDraft = false; conflict = false; inviteStatus = 'pending'; clearCalls = 0; sentCalls = [];
  delayHistory = null; delaySnapshot = null; delayInvites = null;
  collab = { polls: [], pin: null, pin_unavailable: false, pin_revision: 0, pending: false, conflict: false, pending_message: null }; collabSupported = true; failCollab = false; submitted = [];
}
async function closeDialog() { (document.querySelector('[aria-label="关闭对话框"]') as HTMLButtonElement).click(); await wait(() => !document.querySelector('[role="dialog"]'), 'dialog closed'); }
async function input(text: string) {
  const node = document.querySelector('textarea')!;
  Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!.call(node, text);
  node.dispatchEvent(new Event('input', { bubbles: true })); await pause();
}
(window as any).runGroupTests = async () => {
  const passed: string[] = [];
  reset(); await mount(); await select();
  await click('群静音'); await wait(() => !!button('取消静音'), 'mute');
  await mount(); await select(); check(!!button('取消静音'), 'mute survives panel remount'); await click('取消静音');
  passed.push('mute toggles and reads persisted preference');
  await click('已发邀请'); await wait(() => !!button('更多邀请'), 'sent page');
  check(document.querySelector('[role="dialog"]')!.contains(document.activeElement), 'dialog receives focus');
  await click('更多邀请'); check(body().includes('target-2') && body().includes('已过期'), 'second page and status'); check(sentCalls.includes('1'), 'cursor forwarded');
  await click('刷新邀请'); check(!body().includes('target-2'), 'refresh resets pagination');
  await click('撤销邀请'); check(body().includes('已撤销') && !button('撤销邀请'), 'revocation refreshed');
  await closeDialog(); inviteStatus = 'pending'; conflict = true;
  await click('已发邀请'); await click('撤销邀请');
  check(body().includes('synthetic acceptance conflict') && body().includes('已接受') && !button('撤销邀请'), 'conflict refreshes authoritative accepted state');
  await closeDialog(); passed.push('sent invitation paging, refresh, revoke and acceptance conflict');
  messages.push({ id: 'queued', sender_user_id: 'owner', sender_device_id: 'device-owner', sent_at: 1000000000001, text: 'Synthetic pending message', status: 'queued' });
  await click('群数据管理');
  check(button('确认清空本机历史')!.disabled, 'clear requires explicit confirmation'); check(clearCalls === 0, 'opening dialog does not clear');
  check(body().includes('全库数据库文件') && body().includes('不保证释放磁盘空间'), 'storage scope explained');
  await click('刷新统计'); check(body().includes('待发任务：1'), 'pending task count');
  (document.querySelector('input[type="checkbox"]') as HTMLInputElement).click(); await pause(); await click('确认清空本机历史');
  check(clearCalls === 1 && hidden === 1 && draft === 'retained draft', 'only eligible history hidden and draft retained');
  check(body().includes('已在本机隐藏 1 条历史'), 'clear result'); await closeDialog();
  check(!document.querySelector('[role="log"]')!.textContent!.includes('Synthetic old message'), 'old history removed');
  check(body().includes('Synthetic pending message'), 'pending message retained'); check(group.unread === 0, 'unread refreshed');
  check((document.querySelector('textarea') as HTMLTextAreaElement).value === 'retained draft', 'draft text retained');
  passed.push('confirmed history hiding, pending task, draft and unread preservation');
  failDraft = true; await input('unsaved synthetic draft');
  await wait(() => body().includes('草稿尚未保存'), 'failed save');
  check(button('返回单聊')!.disabled, 'failed draft prevents close'); check((document.querySelector('textarea') as HTMLTextAreaElement).value === 'unsaved synthetic draft', 'failed draft remains editable');
  failDraft = false; await click('重试保存'); await wait(() => !busy, 'draft retry'); check(draft === 'unsaved synthetic draft', 'retry persisted');
  passed.push('draft failure preserves text and blocks close until saved');
  await input('hello @'); await click('提及 member');
  check(body().includes('移除提及 member'), 'selected member chip');
  await click('发送'); await wait(() => submitted.some(c=>c.kind==='mention'), 'mention submitted');
  const mention = submitted.find(c=>c.kind==='mention'); check(mention?.kind==='mention' && mention.mentions[0].joined===1 && mention.mentions[0].device==='device-member', 'mention binds member incarnation');
  await wait(() => !busy, 'mention idle');
  await click('置顶此消息'); check(!!button('定位置顶消息'), 'pin bar appears');
  await click('取消置顶'); check(!button('定位置顶消息'), 'pin removed');
  passed.push('member mention selection and owner pin replacement');
  await click('创建投票');
  const fill = async (label: string, value: string) => { const node=document.querySelector(`[aria-label="${label}"]`) as HTMLInputElement; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')!.set!.call(node,value);node.dispatchEvent(new Event('input',{bubbles:true}));await pause(); };
  check(button('发布投票')!.disabled, 'empty poll rejected');
  await fill('投票题目','UI poll');await fill('投票选项 1','First');await fill('投票选项 2','First');check(button('发布投票')!.disabled,'duplicate options rejected');
  await fill('投票选项 2','Second');await click('发布投票');await wait(()=>!document.querySelector('[role="dialog"]'),'poll dialog closed');
  await click('First · 0 票');await click('Second · 0 票');check(body().includes('First · 0 票') && body().includes('Second · 1 票 · 已选'),'vote replacement not additive');
  await click('关闭投票');check(body().includes('投票已关闭') && button('First · 0 票')!.disabled,'closed poll disabled');
  passed.push('poll validation, named vote replacement and closing');
  await input('retry @');await click('提及 member');failCollab=true;await click('发送');await wait(()=>!!button('重试协作任务'),'pending collaboration');
  check(body().includes('synthetic collaboration network failure'),'network failure visible');check(!document.querySelector('[data-message-id="pending-mention"]')!.textContent!.includes('重试原消息'),'collaboration does not use ordinary retry');check((document.querySelector('textarea') as HTMLTextAreaElement).value === '', 'persisted task does not leave a duplicate send draft');
  failCollab=false;await click('重试协作任务');check(!button('重试协作任务'),'retry clears pending');
  collab.conflict=true;window.dispatchEvent(new Event('liteseal-groups-changed'));await wait(()=>!!button('放弃冲突任务'),'conflict displayed');await click('放弃冲突任务');check(!button('放弃冲突任务'),'explicit conflict resolution');
  passed.push('collaboration pending retry and explicit conflict resolution');
  await mount('member'); await select(); check(!button('已发邀请') && !button('邀请成员') && !button('关闭群') && !button('修改群名'), 'member has no owner management');
  check(!button('置顶此消息') && !button('取消置顶'),'member cannot pin');
  passed.push('ordinary member has no owner management controls');
  collabSupported=false; await mount();await select();await wait(()=>body().includes('当前服务端不支持群协作'),'unsupported capability');check(button('创建投票')!.disabled && button('提及成员')!.disabled,'unsupported actions disabled');collabSupported=true;
  passed.push('unsupported relay disables collaboration without blocking ordinary history');
  // A delayed old snapshot cannot replace the newly mounted account.
  delaySnapshot = { started: false }; await mount(); await wait(() => delaySnapshot?.started, 'old snapshot begins');
  const oldSnapshot = snapshot(); const releaseSnapshot = delaySnapshot!.resolve!; delaySnapshot = null;
  group = { ...group, id: 'new-account-group', name: 'New account group', owner: 'new-account' }; messages = [];
  await mount('new-account'); await select(); releaseSnapshot(oldSnapshot); await pause();
  check(body().includes('New account group') && !body().includes('Trial group'), 'old snapshot cannot replace new account');
  passed.push('account remount discards delayed old snapshot');
  // Lock/close unmount the panel as the application does. Resume into a fresh instance.
  delayHistory = { started: false }; window.dispatchEvent(new Event('liteseal-groups-changed')); await wait(() => delayHistory?.started, 'old history begins');
  const releaseHistory = delayHistory!.resolve!; delayHistory = null;
  root.render(<p>Locked</p>); await pause(); releaseHistory({ messages: [{ id: 'late', text: 'STALE PRIVATE MESSAGE', status: 'received' }], next_before: null }); await pause(); check(!body().includes('STALE PRIVATE MESSAGE'), 'locked screen does not receive late history');
  await mount('new-account'); await select(); check(!body().includes('STALE PRIVATE MESSAGE'), 'unlock does not reuse stale history');
  delayInvites = { started: false }; await click('已发邀请'); await wait(() => delayInvites?.started, 'old invitation begins');
  const releaseInvites = delayInvites!.resolve!; delayInvites = null;
  root.render(<p>Panel closed</p>); await pause(); releaseInvites({ invites: [invitation('late', 'pending')], next_cursor: null }); await pause();
  await mount('new-account'); await select(); check(!document.querySelector('[role="dialog"]'), 'late dialog cannot reopen a new panel');
  passed.push('lock and close unmounts discard late history and dialogs');
  check(active === group.id, 'active group routing');
  await click('群数据管理'); check(active === null, 'dialog suppresses active conversation');
  await closeDialog(); check(active === group.id, 'active conversation restored');
  passed.push('notification active target tracks modal visibility');
  return passed;
};
(window as any).showStorage = async () => { await click('群数据管理'); };

(window as any).showCollaboration = async () => {
  reset(); group.name = '小组讨论';
  messages = [{ id:'intro',sender_user_id:'member',sender_device_id:'device-member',sent_at:Date.now(),text:'@owner 下次讨论的时间已整理好，可以在下方投票。',status:'received' }];
  await api.submit_group_collaboration({command:{kind:'poll',question:'下次群讨论选择哪个时间？',options:['周三 19:00','周四 20:00','周六 10:00']}});
  collab.polls[0].votes = { member:'option-0' }; collab.pin='intro'; collab.pin_revision=1;
  await mount();await select();
};
