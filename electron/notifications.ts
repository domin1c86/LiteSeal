import { BrowserWindow, Notification } from "electron";
import type { DesktopBridge } from "./bridge";
import type { CommandMap, GroupReport, NotificationConversation, NotificationIdentity } from "./contracts";
import type { PollMessagesResult } from "../ui/src/types";

/** Only identifiers enter this class. Message bodies never enter the OS notification center. */
export class ChatNotifications {
  private userId: string | null = null;
  private activePeerId: string | null = null;
  private activeGroupId: string | null = null;
  private identity: NotificationIdentity | null = null;
  private scope: string | null = null;
  private locked = false;
  private epoch = 0;
  private suppressionRevision = 0;
  private suppressedGroups = new Map<string, number>();
  private seen = new Set<string>();
  private lastShown = new Map<string, number>();
  private visible = new Map<string, Notification>();
  private target: ({ userId: string; serverUrl: string; deviceId: string } & NotificationConversation) | null = null;
  private directScope: string | null = null;
  private directPeer: string | null = null;
  private directEpoch = 0;
  private directSeen = new Set<string>();
  private directSuppressionRevision=0;
  private suppressedDirect=new Map<string,number>();
  private directTarget: {scope:string;peer:string} | null = null;

  constructor(private window: () => BrowserWindow | undefined, private bridge: DesktopBridge) {}

  context(userId: string | null, activePeerId: string | null, activeGroupId: string | null = null, identity: NotificationIdentity | null = null) {
    const scope = identity ? this.identityScope(identity) : null;
    if (this.userId !== userId || this.scope !== scope) {
      this.clear(); this.seen.clear(); this.lastShown.clear(); this.suppressedGroups.clear(); this.epoch++;
    }
    this.userId = userId;
    this.identity = identity; this.scope = scope; this.activeGroupId = activeGroupId;
    this.activePeerId = activePeerId;
    if (activePeerId && this.window()?.isFocused()) this.dismiss(activePeerId);
    if (activeGroupId && this.window()?.isFocused()) this.dismissGroup(activeGroupId);
  }

  lock(value: boolean) { this.locked = value; this.clear(); this.epoch++; this.directEpoch++; }
  clear() { for (const note of this.visible.values()) note.close(); this.visible.clear(); this.target = null; this.directTarget = null; }
  directGeneration() { return this.directEpoch; }
  directRevision() { return this.directSuppressionRevision; }
  directContext(scope:string|null, peer:string|null) {
    if(scope!==this.directScope){this.clear();this.directEpoch++;this.lastShown.clear();this.directSeen.clear();this.suppressedDirect.clear();}
    this.directScope=scope;this.directPeer=peer;
    if(peer&&this.window()?.isFocused())this.dismissDirect(peer);
  }
  dismissDirect(peer:string) {
    this.suppressedDirect.set(peer,++this.directSuppressionRevision);
    const key=`v3:${peer}`;this.visible.get(key)?.close();this.visible.delete(key);
    if(this.directTarget?.peer===peer)this.directTarget=null;
  }
  takeDirect(scope:string) {
    const target=!this.locked&&scope===this.directScope&&this.directTarget?.scope===scope?{peer:this.directTarget.peer}:null;
    this.directTarget=null;return target;
  }
  receiveDirect(report:CommandMap["process_direct_chat"]["result"], generation:number,revision=this.directSuppressionRevision) {
    if(generation!==this.directEpoch||this.locked||!report.notification_scope)return;
    if(this.directScope!==report.notification_scope)this.directContext(report.notification_scope,null);
    const scope=this.directScope!,epoch=this.directEpoch;
    if(!Notification.isSupported())return;
    for(const item of report.notifications??[]) {
      if((this.suppressedDirect.get(item.peer)??0)>revision)continue;
      const seen=`${scope}:${item.peer}:${item.id}`;if(this.directSeen.has(seen))continue;
      this.directSeen.add(seen);if(this.directSeen.size>20000)this.directSeen.delete(this.directSeen.values().next().value!);
      if(this.directPeer===item.peer&&this.window()?.isFocused())continue;
      const key=`v3:${item.peer}`;
      if(Date.now()-(this.lastShown.get(key)??0)<30000)continue;
      this.lastShown.set(key,Date.now());this.visible.get(key)?.close();
      const note=new Notification({title:"LiteSeal",body:"有新消息，打开应用查看",silent:false});this.visible.set(key,note);
      const peerRevision=this.suppressedDirect.get(item.peer)??0;
      note.on("click",()=>{if(this.locked||this.directScope!==scope||this.directEpoch!==epoch||peerRevision!==(this.suppressedDirect.get(item.peer)??0))return;
        this.directTarget={scope,peer:item.peer};const window=this.window();if(window?.isMinimized())window.restore();window?.show();window?.focus();window?.webContents.send("liteseal:direct-notification-target");});
      note.on("close",()=>{if(this.visible.get(key)===note)this.visible.delete(key);});note.show();
    }
  }
  dismiss(peerId: string) { this.visible.get(peerId)?.close(); this.visible.delete(peerId); if (this.target?.kind === "direct" && this.target.peerId === peerId) this.target = null; }
  generation() { return this.epoch; }
  private identityScope(identity: NotificationIdentity) {
    return JSON.stringify([new URL(identity.server_url.trim()).toString().replace(/\/+$/, ""), identity.user_id, identity.device_id]);
  }
  groupRevision() { return this.suppressionRevision; }
  suppressGroup(groupId: string) { this.suppressedGroups.set(groupId, ++this.suppressionRevision); this.dismissGroup(groupId); }
  dismissGroup(groupId: string) {
    const key = `group:${groupId}`;
    this.visible.get(key)?.close(); this.visible.delete(key);
    if (this.target?.kind === "group" && this.target.groupId === groupId) this.target = null;
  }
  receiveGroups(report: GroupReport, generation: number, revision = this.suppressionRevision) {
    if (generation !== this.epoch || !report.notification_identity || !this.scope || this.scope !== this.identityScope(report.notification_identity)) return;
    const identity = this.identity!;
    const groups = new Set<string>();
    for (const item of report.notifications) {
      if ((this.suppressedGroups.get(item.group_id) ?? 0) > revision) continue;
      const key = `group:${item.group_id}:${item.message_id}`;
      if (this.seen.has(key)) continue;
      this.seen.add(key);
      if (this.seen.size > 20000) this.seen.delete(this.seen.values().next().value!);
      groups.add(item.group_id);
    }
    if (this.locked || !Notification.isSupported()) return;
    for (const groupId of groups) {
      if (this.activeGroupId === groupId && this.window()?.isFocused()) continue;
      const key = `group:${groupId}`;
      if (Date.now() - (this.lastShown.get(key) ?? 0) < 30000) continue;
      this.lastShown.set(key, Date.now()); this.dismissGroup(groupId);
      const note = new Notification({ title: "LiteSeal", body: "有新群消息，打开应用查看", silent: false });
      this.visible.set(key, note);
      const groupRevision = this.suppressedGroups.get(groupId) ?? 0;
      note.on("click", () => {
        if (this.locked || this.epoch !== generation || groupRevision !== (this.suppressedGroups.get(groupId) ?? 0)) return;
        this.target = { kind: "group", groupId, userId: identity.user_id, serverUrl: identity.server_url, deviceId: identity.device_id };
        const window = this.window(); if (window?.isMinimized()) window.restore(); window?.show(); window?.focus();
      });
      note.on("close", () => { if (this.visible.get(key) === note) this.visible.delete(key); });
      note.show();
    }
  }
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
        this.target = { kind: "direct", userId, peerId, serverUrl: this.identity?.server_url ?? "", deviceId: this.identity?.device_id ?? "" };
        const window = this.window();
        if (window?.isMinimized()) window.restore();
        window?.show(); window?.focus();
      });
      note.on("close", () => { if (this.visible.get(peerId) === note) this.visible.delete(peerId); });
      note.show();
    }
  }
}
