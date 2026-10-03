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
const activity={id:"activity-1",creator:"synthetic-alice",title:"恢复活动 🎉",start_at:1800000000000,timezone:"Asia/Singapore",location:"会议室",description:"固定内容",responses:{bob:"maybe" as const},participants:["synthetic-alice","bob"],departed:["bob"],closed:true,cancelled:true,eligible:false,can_manage:false,revision:3};
const extensions={activities:[activity],attachments:[{id:"file-1",blob:"blob-1",name:"恢复群图片.png",size:128,mime:"image/png",duration_ms:null}],pending:false,conflict:false,pending_root:null};
const extendedPage={...groupPage,messages:[...groupPage.messages,{id:"activity-1",sender:"synthetic-alice",timestamp:2,text:"[群附件或活动，请升级客户端查看]",status:"seen"},{id:"file-1",sender:"synthetic-alice",timestamp:3,text:"[群附件或活动，请升级客户端查看]",status:"seen"}],extensions};
const directPage={messages:[{id:"v3-edited",sender:"synthetic-bob",timestamp:1800000000000,text:"认证编辑后的离线文字 🦭",status:"processed",operation_revision:2},{id:"v3-retracted",sender:"synthetic-bob",timestamp:1800000000001,text:"[已撤回]",status:"retracted",operation_revision:1,retracted:true},{id:"v3-media",sender:"synthetic-bob",timestamp:1800000000002,text:"[附件]",status:"processed",media:{name:"完整离线图片.png",mime:"image/png",size:1024,included:true}},{id:"v3-missing",sender:"synthetic-bob",timestamp:1800000000003,text:"[附件]",status:"processed",media:{name:"部分下载未包含.txt",mime:"text/plain",size:2048,included:false}}],next_direct:1,draft:"v3 备份草稿 中文 🦭",muted:true};
const api: Record<string, any> = {
  get_backup_transferred_history:async()=>({messages:[],next_cursor:null}),
  export_backup_attachment:async(args:any)=>{calls.push({name:"group-export",args});return "saved";},
  start_backup_export: async (args: any) => { calls.push({ name: "export", args }); return newJob(); },
  start_backup_restore: async (args: any) => { calls.push({ name: "restore", args }); return newJob(); },
  get_backup_job: async ({ id }: { id: string }) => { const state = jobStates.get(id); return { id, state, completed: 1, total: 2, summary: state === "completed" ? summary : null, error: state === "failed" ? "备份口令错误或文件损坏" : null, restorable: state === "completed" }; },
  cancel_backup_job: async ({ id }: { id: string }) => { calls.push({ name: "cancel" }); jobStates.set(id, "cancelled"); },
  open_backup_archive: async () => { calls.push({ name: "open" }); return info; },
  get_backup_archive_info: async () => info,
  get_backup_conversations: async () => ({ items: [{ id: "dm:alice:bob", kind: "direct", name: "联系人 Bob" }, { id: "group-1", kind: "group", name: "恢复群组" },{id:"v3:synthetic-bob",kind:"direct_v3",name:"v3 Bob"}], next: null }),
  get_backup_history: async (args: any) => {
    calls.push({ name: "history", args });
    if(args.kind==="direct_v3")return args.beforeDirect?{...directPage,messages:[{id:"v3-earlier",sender:"synthetic-bob",timestamp:1,text:"v3 更早历史",status:"processed"}],next_direct:null}:directPage;
    if (args.kind === "group") return extendedPage;
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
  check(document.body.textContent!.includes("恢复活动 🎉")&&document.body.textContent!.includes("活动已取消"),"offline activity state missing");check(button("待定 (1)")!.disabled&&!button("取消活动"),"offline activity allows mutation");await click("保存已包含群附件");check(calls.find(c=>c.name==='group-export')?.args.groupId==='group-1',"offline group file scope absent");results.push("offline activity and group attachment remain read-only and scoped");
  await click("联系人 Bob"); root.render(<div>closed</div>); await sleep(); deferred!({ messages: [{ id: "late", text: "late forbidden result" }], next: null }); await sleep(); check(document.body.textContent === "closed", "closed viewer accepted late data"); results.push("closed archive ignores late decrypted results");
  delayHistory = false; viewer(); await sleep(); await sleep(); await click("v3 Bob");
  check(document.body.textContent!.includes("认证编辑后的离线文字 🦭")&&document.body.textContent!.includes("已编辑 · 版本 2")&&document.body.textContent!.includes("[已撤回]"),"v3 operation projection missing");
  check(document.body.textContent!.includes("v3 备份草稿 中文 🦭")&&document.body.textContent!.includes("备份时已静音"),"v3 settings missing");
  check(!button("发送")&&!button("编辑")&&!button("撤回")&&!button("继续原操作"),"v3 archive exposes mutation");
  await click("加载更早历史");check(document.body.textContent!.includes("v3 更早历史"),"v3 history paging missing");check(calls.find(c=>c.name==="history"&&c.args.beforeDirect===1)?.args.kind==="direct_v3","v3 cursor confused with legacy history");results.push("offline v3 edit/retract projection, drafts/preferences and independent cursor");
  viewer();await sleep();await sleep();await click("v3 Bob");check([...document.querySelectorAll("button")].filter(b=>b.textContent?.trim()==="保存已包含附件").length===1,"missing cache offers output");
  await click("保存已包含附件");check(calls.find(c=>c.name==="group-export"&&c.args.messageId==="v3-media")?.args.directV3===true,"v3 media scope absent");results.push("offline v3 outputs only included complete media and keeps original protocol scope");
  return results;
};
(window as any).showBackupArchive = async () => { delayHistory = false; viewer(); await sleep(); await sleep(); await click("群 · 恢复群组"); };
(window as any).showBackupDirect = async () => {delayHistory=false;viewer();await sleep();await sleep();await click("v3 Bob");};
