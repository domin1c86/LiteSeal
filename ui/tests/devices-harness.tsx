import { root } from "./device-harness-root";
import "./joining-harness";
import "./activation-harness";
import "./root-messaging-harness";
import "./root-session-harness";
import "./session-refresh-harness";
import "./normal-profile-harness";
import DeviceControlPanel from "../src/components/DeviceControlPanel";
import type { DeviceControlSnapshot, DeviceRequest, DeviceTask } from "../../electron/contracts";
import "../src/theme.css";

const request: DeviceRequest = { request_id: "synthetic-request", device_id: "synthetic-second", device_name: "第二台 Windows 🦭 <script>", encryption_fingerprint: "e".repeat(64), signing_fingerprint: "a".repeat(64), combined_fingerprint: "f".repeat(64), phase: "ready" };
let view: DeviceControlSnapshot;
let delay = false, deferred: ((value: DeviceControlSnapshot) => void) | null = null;
const calls: { name: string; args: unknown }[] = [];
const task = (kind: DeviceTask["kind"], phase: DeviceTask["phase"] = "prepared"): DeviceTask => ({ id: `task-${kind}`, kind, phase, revision: 1, request_id: request.request_id, event_id: null, root_fingerprint: null });
const reset = () => { view = { root_fingerprint: "b".repeat(64), supported: true, syncing: false, messaging_enabled: false, requests: [{ ...request }], tasks: [], authorized: null }; delay = false; calls.length = 0; };
const api = {
  get_root_messaging:async()=>({root_fingerprint:view.root_fingerprint,admission:"legacy" as const,pending:{messages:0,uploads:0,scheduled:0,operations:0,reactions:0,receipts:0},tasks:[]}),
  get_device_control: async () => delay ? new Promise<DeviceControlSnapshot>(resolve => { deferred = resolve; }) : structuredClone(view),
  inspect_device_request: async (args: unknown) => { calls.push({ name: "inspect", args }); return structuredClone(view.requests[0]); },
  prepare_device_challenge: async (args: unknown) => { calls.push({ name: "challenge", args }); view.tasks.push(task("challenge")); return view.tasks[view.tasks.length - 1]; },
  prepare_device_grant: async (args: unknown) => { calls.push({ name: "grant", args }); view.tasks.push(task("grant")); return view.tasks[view.tasks.length - 1]; },
  prepare_device_revoke: async (args: unknown) => { calls.push({ name: "revoke", args }); view.tasks.push(task("revoke")); return view.tasks[view.tasks.length - 1]; },
  device_task_step: async ({ id }: { id: string }) => {
    calls.push({ name: "step", args: { id } });
    const job = view.tasks.find(row => row.id === id)!;
    job.phase = job.phase === "cancelling" ? "cancelled" : "complete";
    if (job.kind === "challenge" && job.phase === "complete") view.requests[0].phase = "challenged";
    if (job.kind === "grant" && job.phase === "complete") { view.requests[0].phase = "authorized"; view.authorized = { device_id: request.device_id, combined_fingerprint: request.combined_fingerprint, encryption_fingerprint: request.encryption_fingerprint, signing_fingerprint: request.signing_fingerprint }; }
    return { task: structuredClone(job), condition: "terminal" as const, http_status: null };
  },
  cancel_device_task: async ({ id }: { id: string }) => { calls.push({ name: "cancel", args: { id } }); const job = view.tasks.find(row => row.id === id)!; job.phase = "cancelling"; return structuredClone(job); },
  discard_device_task: async ({ id }: { id: string }) => { calls.push({ name: "discard", args: { id } }); view.tasks = view.tasks.filter(row => row.id !== id); },
};
const installApi=()=>{window.desktop = new Proxy(api, { get(target, key: keyof typeof api) { if (!(key in target)) throw new Error("unexpected device API " + String(key)); return target[key]; } }) as any;};
const sleep = () => new Promise(resolve => setTimeout(resolve, 90));
const check = (condition: unknown, message: string) => { if (!condition) throw new Error(message); };
const button = (text: string) => [...document.querySelectorAll<HTMLButtonElement>("button")].find(row => row.textContent?.trim() === text);
async function click(text: string) { check(button(text), "missing button " + text); button(text)!.click(); await sleep(); }
async function confirm() { document.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click(); await sleep(); }
let generation = 0;
const panel = () => root.render(<DeviceControlPanel key={++generation} onClose={() => root.render(<div>closed</div>)} />);
(window as any).runDeviceTests = async () => {
  installApi();
  const results: string[] = []; reset(); panel(); await sleep(); await click("核对设备");
  check(document.body.textContent!.includes(request.encryption_fingerprint) && document.body.textContent!.includes(request.signing_fingerprint), "both fingerprints absent");
  check(button("验证新设备")!.disabled, "unchecked fingerprints accepted");
  await confirm(); await click("验证新设备");
  check((calls.find(row => row.name === "challenge")!.args as any).confirmedFingerprint === request.combined_fingerprint, "wrong public binding");
  check(document.body.textContent!.includes("待发送"), "durable task absent");
  results.push("dual fingerprint confirmation and safe device name rendering");
  await click("管理原设备协议切换");check(document.querySelector('section[aria-label="原设备单聊协议切换"]'),"root control entry missing");await click("收起协议切换");results.push("verified original-device control opens scoped root messaging management");
  await click("继续原任务"); check(document.body.textContent!.includes("已完成"), "task did not complete");
  check(!document.querySelector('section[aria-label="设备指纹确认"]'), "stage change retained confirmation");
  await click("清除已结束任务"); check(!view.tasks.length, "terminal task retained");
  results.push("original task step, terminal clearing and stage confirmation invalidation");
  reset(); view.requests[0].phase = "proved"; panel(); await sleep(); await click("核对设备");
  check(button("批准设备授权")!.disabled, "grant without confirmation"); await confirm(); await click("批准设备授权"); await click("继续原任务");
  check(document.body.textContent!.includes("聊天激活尚未开放"), "activation boundary absent");
  check(button("准备撤销授权")!.disabled, "revoke without confirmation"); await confirm(); await click("准备撤销授权");
  check((calls.find(row => row.name === "revoke")!.args as any).confirmedFingerprint === request.combined_fingerprint, "revoke target unbound");
  results.push("confirmed grant and target-bound revoke without messaging activation");
  await click("取消设备任务"); check(document.body.textContent!.includes("正在确认取消"), "cancel falsely complete"); await click("确认取消结果");
  check(document.body.textContent!.includes("已取消"), "confirmed cancellation absent"); results.push("cancellation remains pending until confirmed");
  reset(); view.tasks = [task("grant", "conflict")]; panel(); await sleep();
  check(button("继续原任务")!.disabled && !button("取消设备任务")!.disabled, "conflict can be resigned");
  await click("取消设备任务"); check(!calls.some(row => row.name === "grant"), "conflict automatically resigned"); results.push("conflict requires cancelling original task");
  reset(); view.supported = false; view.requests = []; panel(); await sleep();
  check(document.body.textContent!.includes("服务器尚未启用设备授权") && !button("批准设备授权"), "unsupported server offers authorization"); results.push("disabled server explicit status");
  reset(); panel(); await sleep(); delay = true; button("刷新设备状态")!.click(); await sleep();
  window.dispatchEvent(new Event("liteseal-app-locked")); deferred!(structuredClone(view)); await sleep();
  check(!document.body.textContent!.includes(view.root_fingerprint), "late locked result displayed"); results.push("lock clears public confirmation and rejects late result");
  delay = false; panel(); await sleep(); delay = true; button("刷新设备状态")!.click(); await sleep();
  root.render(<div>closed</div>); await sleep(); deferred!(structuredClone(view)); await sleep();
  check(document.body.textContent === "closed", "closed panel accepted late result"); results.push("closed panel ignores late result");
  return results;
};
(window as any).showDevicePanel = async () => { installApi();reset(); view.requests[0].phase = "proved"; panel(); await sleep(); await click("核对设备"); };
