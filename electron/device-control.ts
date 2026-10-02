import type { CommandName } from "./contracts";
import type { DesktopBridge } from "./bridge";

export const deviceCommands = new Set<CommandName>([
  "get_join_activation", "prepare_join_activation", "join_activation_step", "inspect_join_activation", "cancel_join_activation", "forget_join_activation", "save_join_activation", "clear_join_activation_session",
  "list_device_join_profiles", "create_device_join_profile", "get_device_join_profile", "confirm_device_join_root", "device_join_step", "cancel_device_join", "abandon_device_join", "forget_device_join_profile",
  "get_device_control", "inspect_device_request", "prepare_device_challenge", "prepare_device_grant",
  "prepare_device_revoke", "device_task_step", "cancel_device_task", "discard_device_task",
]);

/** Main owns suspension. Serialized transitions cannot unlock a later lock event. */
export class DeviceControlGate {
  private epoch = 0;
  private suspended = false;
  private transitions: Promise<unknown> = Promise.resolve();
  constructor(private bridge: Pick<DesktopBridge, "call">) {}
  capture(): number {
    if (this.suspended) throw new Error("设备授权已暂停，请解锁后重试");
    return this.epoch;
  }
  check(epoch: number): void {
    if (this.suspended || epoch !== this.epoch) throw new Error("设备授权结果已失效，请重新查询");
  }
  suspend(): void {
    this.suspended = true;
    this.epoch++;
    this.transitions = this.transitions.catch(() => {}).then(() => this.bridge.call("suspend_device_control", {}));
    void this.transitions.catch(() => {});
  }
  async resume(): Promise<void> {
    const epoch = ++this.epoch;
    this.suspended = true;
    this.transitions = this.transitions.catch(() => {}).then(() => this.bridge.call("resume_device_control", {}));
    await this.transitions;
    if (epoch === this.epoch) this.suspended = false;
  }
  invalidate(): void { this.epoch++; }
}
