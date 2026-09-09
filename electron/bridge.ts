import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { EventEmitter } from "node:events";
import { commandNames, type CommandName, type CommandMap } from "./contracts";

const MAX_FRAME_BYTES = 16 * 1024 * 1024;
const allowed = new Set<string>(commandNames);
type Pending = { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: NodeJS.Timeout };

/** Private stdio RPC. stdout contains only protocol frames; stderr is never forwarded to the renderer. */
export class DesktopBridge extends EventEmitter {
  private child?: ChildProcessWithoutNullStreams;
  private pending = new Map<number, Pending>();
  private nextId = 1;
  private buffer = Buffer.alloc(0);
  private ready = false;
  private stopped = false;
  private exitPromise?: Promise<void>;

  constructor(private readonly timeoutMs = 65_000) { super(); }

  async start(executable: string, args: string[] = []): Promise<void> {
    if (this.child || this.stopped) throw new Error("Desktop service already started");
    const child = this.child = spawn(executable, args, { stdio: "pipe", windowsHide: true, shell: false });
    this.exitPromise = new Promise(resolve => child.once("close", () => resolve()));
    // Core logs can contain remote errors. Keep them out of production logs and IPC.
    child.stderr.resume();
    child.stdin.on("error", () => this.fail(new Error("桌面服务管道已关闭，请重启应用")));
    child.on("error", () => this.fail(new Error("无法启动桌面服务，请检查安装文件")));
    child.on("exit", () => this.fail(new Error("桌面服务已退出，请重启应用")));
    const startup = new Promise<void>((resolve, reject) => {
      const finish = (error?: Error) => {
        clearTimeout(timer);
        this.off("ready", onReady);
        this.off("failure", onFailure);
        error ? reject(error) : resolve();
      };
      const onReady = () => finish();
      const onFailure = (error: Error) => finish(error);
      const timer = setTimeout(() => this.fail(new Error("桌面服务启动超时")), 15_000);
      this.once("ready", onReady);
      this.once("failure", onFailure);
    });
    child.stdout.on("data", (chunk: Buffer) => this.receive(chunk));
    return startup;
  }

  private receive(chunk: Buffer): void {
    if (this.stopped) return;
    this.buffer = Buffer.concat([this.buffer, chunk]);
    let end: number;
    while ((end = this.buffer.indexOf(10)) !== -1) {
      if (end > MAX_FRAME_BYTES) { this.fail(new Error("桌面服务响应过大")); return; }
      const line = this.buffer.subarray(0, end);
      this.buffer = this.buffer.subarray(end + 1);
      try {
        const message = JSON.parse(line.toString("utf8"));
        if (!this.ready) {
          if (message.ready !== true || message.version !== 1) throw new Error("Invalid handshake");
          this.ready = true;
          this.emit("ready");
          continue;
        }
        if (!Number.isSafeInteger(message.id) || (("result" in message) === ("error" in message))) throw new Error("Invalid response");
        if ("error" in message && typeof message.error !== "string") throw new Error("Invalid error response");
        const entry = this.pending.get(message.id);
        if (!entry) continue; // A timed-out call is never retried automatically.
        this.pending.delete(message.id);
        clearTimeout(entry.timer);
        if (typeof message.error === "string") entry.reject(new Error(message.error));
        else if ("result" in message) entry.resolve(message.result);
        else throw new Error("Invalid error response");
      } catch { this.fail(new Error("桌面服务通信异常，请重启应用")); return; }
    }
    if (this.buffer.length > MAX_FRAME_BYTES) this.fail(new Error("桌面服务响应过大"));
  }

  call<K extends CommandName>(name: K, args: CommandMap[K]["args"]): Promise<CommandMap[K]["result"]> {
    if (!this.ready || this.stopped || !this.child) return Promise.reject(new Error("桌面服务不可用，请重启应用"));
    if (!allowed.has(name) || !args || typeof args !== "object" || Array.isArray(args)) return Promise.reject(new Error("无效的桌面命令"));
    if (this.pending.size >= 128) return Promise.reject(new Error("等待中的操作过多"));
    const id = this.nextId++;
    let frame: string;
    try { frame = JSON.stringify({ id, command: { name, args } }) + "\n"; }
    catch { return Promise.reject(new Error("无效的命令参数")); }
    if (Buffer.byteLength(frame) > MAX_FRAME_BYTES) return Promise.reject(new Error("请求内容过大"));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("操作超时，结果可能尚未确定，请勿自动重复提交"));
      }, this.timeoutMs);
      this.pending.set(id, { resolve: value => resolve(value as CommandMap[K]["result"]), reject, timer });
      this.child!.stdin.write(frame, error => { if (error) this.fail(new Error("桌面服务管道已关闭")); });
    });
  }

  private fail(error: Error): void {
    if (this.stopped) return;
    this.stopped = true;
    this.ready = false;
    for (const entry of this.pending.values()) { clearTimeout(entry.timer); entry.reject(error); }
    this.pending.clear();
    this.child?.kill();
    this.emit("failure", error);
  }

  async stop(): Promise<void> {
    if (!this.child) return;
    this.stopped = true;
    this.ready = false;
    for (const entry of this.pending.values()) { clearTimeout(entry.timer); entry.reject(new Error("应用正在退出")); }
    this.pending.clear();
    this.child.stdin.end(); // EOF lets Rust disconnect and close SQLite.
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([this.exitPromise, new Promise<void>(resolve => {
      timer = setTimeout(() => { this.child?.kill(); resolve(); }, 3_000);
    })]);
    clearTimeout(timer);
  }
}
