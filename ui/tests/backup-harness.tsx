import { createRoot } from "react-dom/client";
import BackupPanel from "../src/components/BackupPanel";
import BackupArchive from "../src/components/BackupArchive";
import "../src/theme.css";
const root = createRoot(document.getElementById("root")!);
const calls: { name: string; args?: any }[] = [];
let status = "completed", deferred: ((value: any) => void) | null = null, delayHistory = false;
const jobStates = new Map<string, string>(); let nextJob = 0;
const newJob = () => { const id = `job-${++nextJob}`; jobStates.set(id, status); return id; };
const summary = { messages: 65, groups: 1, attachments: 1, missing_attachments: 2, skipped_attachments: 1 };
const info = { id: "archive-1", user_id: "synthetic-alice", device_id: "device-a", server_url: "http://offline.invalid", fingerprint: "encryption-fingerprint", signing_fingerprint: "signing-fingerprint", summary };
const poll = { id: "poll-1", creator: "synthetic-alice", question: "离线投票", options: [{ id: "a", text: "第一项" }, { id: "b", text: "第二项" }], votes: { alice: "a", bob: "b" }, departed: [], closed: true, eligible: false, revision: 3 };
const groupPage = { messages: [{ id: "poll-1", sender: "synthetic-alice", timestamp: 1, text: "投票记录", status: "seen" }], collaboration: { polls: [poll], pin: null, pin_unavailable: true, pending: false, conflict: false }, next_group: null, draft: "群草稿 🦭" };
const api: Record<string, any> = {
  start_backup_export: async (args: any) => { calls.push({ name: "export", args }); return newJob(); },
  start_backup_restore: async (args: any) => { calls.push({ name: "restore", args }); return newJob(); },
  get_backup_job: async ({ id }: { id: string }) => { const state = jobStates.get(id); return { id, state, completed: 1, total: 2, summary: state === "completed" ? summary : null, error: state === "failed" ? "备份口令错误或文件损坏" : null, restorable: state === "completed" }; },
  cancel_backup_job: async ({ id }: { id: string }) => { calls.push({ name: "cancel" }); jobStates.set(id, "cancelled"); },
  open_backup_archive: async () => { calls.push({ name: "open" }); return info; },
  get_backup_archive_info: async () => info,
  get_backup_conversations: async () => ({ items: [{ id: "dm:alice:bob", kind: "direct", name: "联系人 Bob" }, { id: "group-1", kind: "group", name: "恢复群组" }], next: null }),
  get_backup_history: async (args: any) => {
    calls.push({ name: "history" });
    if (args.kind === "group") return groupPage;
    if (delayHistory) return new Promise(resolve => { deferred = resolve; });
    return { messages: [{ id: args.beforeId ? "older" : "recent", sender: "bob", timestamp: 1, text: args.beforeId ? "更早中文历史" : "最新中文 🦭", status: "received" }], next: args.beforeId ? null : { id: "recent", time: 1 } };
  },
  close_backup_archive: async () => {},
};
window.desktop = new Proxy(api, { get(target, key: string) { if (!(key in target)) throw new Error("offline reader attempted " + key); return target[key]; } }) as any;
const sleep = () => new Promise(resolve => setTimeout(resolve, 100));
const check = (condition: unknown, message: string) => { if (!condition) throw new Error(message); };
const button = (text: string) => [...document.querySelectorAll<HTMLButtonElement>("button")].find(b => b.textContent?.trim() === text);
async function click(text: string) { const node = button(text); check(node, "button absent: " + text); node!.click(); await sleep(); }
async function fill(label: string, value: string) { const input = document.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!; check(input, "input absent"); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); await sleep(); }
let generation = 0;
const panel = (canExport = true) => { root.render(<BackupPanel key={++generation} canExport={canExport} onClose={() => root.render(<div />)} />); };
const viewer = () => { root.render(<BackupArchive key={++generation} id="archive-1" />); };
(window as any).runBackupTests = async () => {
  const results: string[] = []; status = "completed"; calls.length = 0; delayHistory = false;
  panel(); await sleep(); check(!document.querySelector<HTMLInputElement>('input[type="checkbox"]')!.checked, "attachments default must be off");
  await fill("独立备份口令", "independent backup password"); await fill("确认备份口令", "different confirmation"); check(button("创建加密备份")!.disabled, "confirmation mismatch accepted");
  await fill("确认备份口令", "independent backup password"); await click("创建加密备份");
  check(calls.find(c => c.name === "export")?.args.includeAttachments === false, "optional media flag wrong");
  check(document.querySelector<HTMLInputElement>('input[aria-label="独立备份口令"]')!.value === "", "password retained in form");
  check(document.body.textContent!.includes("65 条单聊历史"), "summary absent"); results.push("export confirmation, default options and password clearing");
  await click("打开离线只读档案"); check(calls.some(c => c.name === "open"), "archive handoff missing"); results.push("restore handoff without cancelling opened archive");
  status = "running"; panel(false); await sleep(); await fill("独立备份口令", "independent backup password"); await click("选择备份并隔离恢复"); await click("取消任务"); check(document.body.textContent!.includes("任务已取消"), "cancellation absent"); results.push("running job cancellation");
  status = "failed"; panel(false); await sleep(); await fill("独立备份口令", "independent backup password"); await click("选择备份并隔离恢复"); await sleep(); check(document.querySelector('[role="alert"]')?.textContent?.includes("口令错误"), "failure not shown"); results.push("wrong password recovery error");
  viewer(); await sleep(); await sleep(); await click("联系人 Bob"); check(document.body.textContent!.includes("最新中文 🦭"), "direct history absent"); await click("加载更早历史"); check(document.body.textContent!.includes("更早中文历史"), "pagination absent"); results.push("offline direct history pagination");
  delayHistory = true; await click("联系人 Bob"); await click("群 · 恢复群组"); deferred!({ messages: [{ id: "late", text: "late forbidden result" }], next: null }); await sleep(); check(!document.body.textContent!.includes("late forbidden result"), "late page replaced active conversation"); check(document.body.textContent!.includes("离线投票"), "poll absent"); check(!button("投票") && !button("发送"), "archive offers mutations"); results.push("read-only polls and stale conversation result rejection");
  await click("联系人 Bob"); root.render(<div>closed</div>); await sleep(); deferred!({ messages: [{ id: "late", text: "late forbidden result" }], next: null }); await sleep(); check(document.body.textContent === "closed", "closed viewer accepted late data"); results.push("closed archive ignores late decrypted results");
  delayHistory = false; return results;
};
(window as any).showBackupArchive = async () => { delayHistory = false; viewer(); await sleep(); await sleep(); await click("群 · 恢复群组"); };
