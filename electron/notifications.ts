import { BrowserWindow, Notification } from "electron";
import type { DesktopBridge } from "./bridge";
import type { PollMessagesResult } from "../ui/src/types";

/** Only identifiers enter this class. Message bodies never enter the OS notification center. */
export class ChatNotifications {
  private userId: string | null = null;
  private activePeerId: string | null = null;
  private locked = false;
  private epoch = 0;
  private seen = new Set<string>();
  private lastShown = new Map<string, number>();
  private visible = new Map<string, Notification>();
  private target: { userId: string; peerId: string } | null = null;

  constructor(private window: () => BrowserWindow | undefined, private bridge: DesktopBridge) {}

  context(userId: string | null, activePeerId: string | null) {
    if (this.userId !== userId) {
      this.clear(); this.seen.clear(); this.lastShown.clear(); this.epoch++;
    }
    this.userId = userId;
    this.activePeerId = activePeerId;
    if (activePeerId && this.window()?.isFocused()) this.dismiss(activePeerId);
  }

  lock(value: boolean) { this.locked = value; this.clear(); this.epoch++; }
  clear() { for (const note of this.visible.values()) note.close(); this.visible.clear(); this.target = null; }
  dismiss(peerId: string) { this.visible.get(peerId)?.close(); this.visible.delete(peerId); if (this.target?.peerId === peerId) this.target = null; }
  takeTarget() { const target = this.locked ? null : this.target; this.target = null; return target; }

  async receive(batch: PollMessagesResult) {
    const userId = this.userId;
    const epoch = this.epoch;
    if (!userId || !batch.messages.length) return;
    const [preferences, contacts] = await Promise.all([
      this.bridge.call("get_conversation_preferences", { userId }),
      this.bridge.call("get_contacts", {}),
    ]);
    if (epoch !== this.epoch || userId !== this.userId) return;
    const muted = new Set(preferences.filter(row => row.muted).map(row => row.peer_id));
    const known = new Set(contacts.map(row => row.user_id));
    const peers = new Set<string>();
    for (const message of batch.messages) {
      const key = `${userId}:${message.message_id}`;
      if (this.seen.has(key)) continue;
      this.seen.add(key);
      if (this.seen.size > 20000) this.seen.delete(this.seen.values().next().value!);
      if (message.from !== userId && known.has(message.from) && !muted.has(message.from)
          && message.local_state !== "integrity_failed") peers.add(message.from);
    }
    if (this.locked || !Notification.isSupported()) return;
    for (const peerId of peers) {
      if (this.activePeerId === peerId && this.window()?.isFocused()) continue;
      if (Date.now() - (this.lastShown.get(peerId) ?? 0) < 30000) continue;
      this.lastShown.set(peerId, Date.now());
      this.dismiss(peerId);
      const note = new Notification({ title: "LiteSeal", body: "有新消息，打开应用查看", silent: false });
      this.visible.set(peerId, note);
      note.on("click", () => {
        if (this.locked || this.userId !== userId || this.epoch !== epoch) return;
        this.target = { userId, peerId };
        const window = this.window();
        if (window?.isMinimized()) window.restore();
        window?.show(); window?.focus();
      });
      note.on("close", () => { if (this.visible.get(peerId) === note) this.visible.delete(peerId); });
      note.show();
    }
  }
}
