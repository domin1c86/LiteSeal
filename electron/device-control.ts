import type { CommandName } from "./contracts";
import type { DesktopBridge } from "./bridge";

export const deviceCommands = new Set<CommandName>([
  "get_audio_targets","begin_audio_call","prepare_audio_signal","publish_audio_signal","open_audio_signal","retire_audio_call",
  "set_direct_history_pause",
  "direct_history_relay_step","cancel_direct_history_relay","receive_direct_history_relay","get_direct_history_transfers","prepare_direct_history_transfer","cancel_direct_history_transfer","export_direct_history_transfer","import_direct_history_transfer","get_transferred_history","hide_transferred_message","export_transferred_media",
  "get_direct_media_storage","clear_direct_media_cache","set_direct_media_transfer","get_direct_media_tasks","get_direct_media_info","select_direct_media","stage_direct_file","stage_direct_voice","stage_direct_clipboard","direct_media_step","prepare_direct_media","begin_direct_media_download","cancel_direct_media","clear_direct_media","export_direct_media","close_direct_media_preview",
  "get_direct_draft","save_direct_draft",
  "mark_direct_read","set_direct_muted",
  "set_direct_notification_context","take_direct_notification_target",
  "get_direct_chat","get_direct_history","inspect_direct_peer","confirm_direct_peer","prepare_direct_text","direct_task_step","cancel_direct_task","forget_direct_task","hide_direct_message",
  "get_normal_profile","select_normal_profile","clear_normal_profile",
  "get_session_refresh","prepare_session_refresh","session_refresh_step","cancel_session_refresh","forget_session_refresh",
  "get_root_session", "prepare_root_session", "root_session_step", "inspect_root_session", "cancel_root_session", "forget_root_session", "save_root_session",
  "get_root_messaging", "check_root_messaging", "prepare_root_messaging", "root_messaging_step", "cancel_root_messaging", "forget_root_messaging",
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
