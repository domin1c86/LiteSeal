import type { RegisterResult, ConnectResult, SendMessageResult, PollMessagesResult,
  MessageOperation, ConversationPreference, ConversationSummary, Message, Contact, RemoteDevice, UserSearchResult, StorageStats, Identity, EncryptedPayload
} from "../ui/src/types";

export type NotificationConversation = { kind: "direct"; peerId: string } | { kind: "group"; groupId: string };
export interface NotificationIdentity { user_id: string; device_id: string; server_url: string }
export interface GroupReport { changed: number; errors: string[]; notifications: { group_id: string; message_id: string }[]; notification_identity: NotificationIdentity | null }
export interface SentGroupInvite { id: string; group_id: string; user_id: string; device_id: string; expires_at: number; status: "pending" | "accepted" | "rejected" | "revoked" | "expired" | "invalidated" }
export interface SentGroupInvites { invites: SentGroupInvite[]; next_cursor: string | null }
export interface GroupStorageStats { visible_messages: number; hidden_messages: number; unread_messages: number; pending_tasks: number; logical_bytes: number; database_bytes: number; wal_bytes: number }
export interface CollaborationMember { user: string; device: string; joined: number }
export interface GroupPoll { id: string; creator: string; question: string; options: { id: string; text: string }[]; votes: Record<string,string>; departed: string[]; closed: boolean; eligible: boolean; revision: number }
export interface GroupCollaboration { polls: GroupPoll[]; pin: string | null; pin_unavailable: boolean; pin_revision: number; pending: boolean; conflict: boolean; pending_message: string | null }
export type CollaborationCommand = { kind: "mention"; text: string; mentions: CollaborationMember[] } | { kind: "poll"; question: string; options: string[] } | { kind: "vote"; poll: string; option: string; revision: number } | { kind: "close"; poll: string; revision: number } | { kind: "pin"; message: string | null; revision: number };
export interface CommandMap {
  get_normal_profile:{args:{};result:NormalProfileSnapshot};
  select_normal_profile:{args:{target:RefreshTarget;generation:number;scopeFingerprint:string};result:NormalProfileSnapshot};
  clear_normal_profile:{args:{generation:number};result:NormalProfileSnapshot};
  get_session_refresh:{args:{target:RefreshTarget};result:RefreshSnapshot};
  prepare_session_refresh:{args:{target:RefreshTarget};result:RefreshTask};
  session_refresh_step:{args:{target:RefreshTarget;id:string};result:RefreshProgress};
  cancel_session_refresh:{args:{target:RefreshTarget;id:string;confirmedFamilyExit:boolean};result:RefreshTask};
  forget_session_refresh:{args:{target:RefreshTarget;id:string};result:void};
  process_session_refreshes:{args:{};result:boolean};
  get_root_session: { args: {}; result: RootSessionSnapshot };
  prepare_root_session: { args: { username:string }; result: ActivationTask };
  root_session_step: { args: { id:string; password?:string }; result: ActivationProgress };
  inspect_root_session: { args: { id:string }; result: ActivationProgress };
  cancel_root_session: { args: { id:string }; result: ActivationTask };
  forget_root_session: { args: { id:string }; result: void };
  save_root_session: { args: { id:string }; result: RootSessionSaved };
  get_root_messaging: { args: {}; result: RootMessagingSnapshot };
  check_root_messaging: { args: {}; result: RootMessagingSnapshot };
  prepare_root_messaging: { args: { confirmedFingerprint:string }; result: ActivationTask };
  root_messaging_step: { args: { id:string }; result: ActivationProgress };
  cancel_root_messaging: { args: { id:string }; result: ActivationTask };
  forget_root_messaging: { args: { id:string }; result: void };
  get_join_activation: { args: { profileId: string }; result: JoinActivationSnapshot };
  prepare_join_activation: { args: { profileId: string }; result: ActivationTask };
  join_activation_step: { args: { profileId: string; id: string; password?: string }; result: ActivationProgress };
  inspect_join_activation: { args: { profileId: string; id: string }; result: ActivationProgress };
  cancel_join_activation: { args: { profileId: string; id: string }; result: ActivationTask };
  forget_join_activation: { args: { profileId: string; id: string }; result: void };
  save_join_activation: { args: { profileId: string; id: string }; result: NormalJoinProfile };
  clear_join_activation_session: { args: { profileId: string }; result: void };
  list_device_join_profiles: { args: {}; result: DeviceJoinListing[] };
  create_device_join_profile: { args: { origin: string; username: string; deviceName: string }; result: DeviceJoinSnapshot };
  get_device_join_profile: { args: { profileId: string }; result: DeviceJoinSnapshot };
  confirm_device_join_root: { args: { profileId: string; confirmedFingerprint: string }; result: DeviceJoinSnapshot };
  device_join_step: { args: { profileId: string; password?: string }; result: DeviceProgress };
  cancel_device_join: { args: { profileId: string }; result: DeviceJoinSnapshot };
  abandon_device_join: { args: { profileId: string }; result: DeviceJoinSnapshot };
  forget_device_join_profile: { args: { profileId: string }; result: void };
  get_device_control: { args: {}; result: DeviceControlSnapshot };
  inspect_device_request: { args: { requestId: string }; result: DeviceRequest };
  prepare_device_challenge: { args: { requestId: string; confirmedFingerprint: string }; result: DeviceTask | null };
  prepare_device_grant: { args: { requestId: string; confirmedFingerprint: string }; result: DeviceTask | null };
  prepare_device_revoke: { args: { confirmedFingerprint: string }; result: DeviceTask | null };
  device_task_step: { args: { id: string }; result: DeviceProgress };
  cancel_device_task: { args: { id: string }; result: DeviceTask };
  discard_device_task: { args: { id: string }; result: void };
  suspend_device_control: { args: {}; result: void };
  resume_device_control: { args: {}; result: void };
  get_group_extensions: { args: {groupId:string;messageIds:string[]}; result:GroupExtensions };
  sync_group_extensions: { args: {groupId:string}; result:boolean };
  submit_group_extension: { args: {groupId:string;command:GroupExtensionCommand}; result:null };
  retry_group_extension: { args: {groupId:string}; result:null };
  cancel_group_extension: { args: {groupId:string}; result:null };
  select_group_attachment: { args: {groupId:string}; result:AttachmentTask|null };
  stage_group_attachment_file: { args: {groupId:string;file:File}; result:AttachmentTask };
  stage_group_recorded_audio: { args: {groupId:string;encoded:string;durationMs:number}; result:AttachmentTask };
  stage_group_clipboard_image: { args: {groupId:string}; result:AttachmentTask };
  group_attachment_tasks: { args: {groupId:string}; result:AttachmentTask[] };
  group_attachment_step: { args: {groupId:string;id:string}; result:AttachmentTask };
  publish_group_attachment: { args: {groupId:string;id:string}; result:string };
  cancel_group_attachment: { args: {groupId:string;id:string}; result:null };
  begin_group_attachment_download: { args: {groupId:string;messageId:string}; result:AttachmentTask };
  export_group_attachment: { args: {groupId:string;id:string;preview?:boolean;media?:"image"|"audio"}; result:string|null };
  clear_group_attachment_cache: { args: {groupId?:string}; result:number };
  start_backup_export: { args: { password: string; includeAttachments: boolean }; result: string | null };
  start_backup_restore: { args: { password: string }; result: string | null };
  get_backup_job: { args: { id: string }; result: BackupJob };
  cancel_backup_job: { args: { id: string }; result: void };
  open_backup_archive: { args: { id: string }; result: BackupArchiveInfo };
  get_backup_archive_info: { args: { id: string }; result: BackupArchiveInfo };
  get_backup_conversations: { args: { id: string; after?: string }; result: { items: BackupConversation[]; next: string | null } };
  get_backup_history: { args: { id: string; kind: "direct" | "group"; conversationId: string; beforeTime?: number; beforeId?: string; beforeGroup?: number }; result: BackupHistory };
  export_backup_attachment: { args: { id: string; messageId: string; groupId?:string; preview?: boolean }; result: string | null };
  close_backup_archive: { args: {}; result: void };
  get_group_collaboration: { args: { groupId: string; messageIds?: string[] }; result: GroupCollaboration };
  sync_group_collaboration: { args: { groupId: string }; result: boolean };
  submit_group_collaboration: { args: { groupId: string; command: CollaborationCommand }; result: void };
  retry_group_collaboration: { args: { groupId: string }; result: void };
  discard_group_collaboration_conflict: { args: { groupId: string }; result: void };
  get_group_storage_stats: { args: { groupId: string }; result: GroupStorageStats };
  clear_group_history: { args: { groupId: string }; result: number };
  get_sent_group_invites: { args: { groupId: string; afterId?: string }; result: SentGroupInvites };
  revoke_group_invite: { args: { inviteId: string }; result: void };
  set_group_muted: { args: { groupId: string; muted: boolean }; result: void };
  sync_group: { args: { groupId: string }; result: number };
  get_groups: { args: { refresh?: boolean; afterId?: string }; result: GroupSnapshot };
  create_group: { args: { name: string }; result: string };
  inspect_group: { args: { groupId: string; inviteId?: string }; result: GroupInspection };
  inspect_group_peer: { args: { peerId: string }; result: GroupMember };
  recover_group: { args: { groupId: string; confirmedFingerprint: string }; result: void };
  invite_group_member: { args: { groupId: string; peerId: string; confirmedFingerprint: string }; result: void };
  accept_group_invite: { args: { inviteId: string; confirmedFingerprint: string }; result: string };
  decline_group_invite: { args: { inviteId: string }; result: void };
  change_group_membership: { args: { groupId: string; action: "rename" | "remove" | "leave" | "close"; value?: string }; result: void };
  get_group_history: { args: { groupId: string; before?: number }; result: { messages: GroupMessage[]; next_before: number | null } };
  group_draft: { args: { groupId: string; text?: string }; result: string };
  mark_group_seen: { args: { groupId: string; ids: string[] }; result: void };
  send_group_text: { args: { groupId: string; text?: string }; result: { message_id: string; state: string; error: string | null } };
  cancel_group_send: { args: { groupId: string }; result: void };
  process_groups: { args: {}; result: GroupReport };
  save_scheduled_message: { args: { id?: string; peerId: string; text: string; dueAt: number }; result: ScheduledTask };
  list_scheduled_messages: { args: {}; result: ScheduledTask[] };
  cancel_scheduled_message: { args: { id: string; removeSubmitted?: boolean }; result: void };
  send_scheduled_now: { args: { id: string }; result: ScheduledTask };
  process_scheduled_messages: { args: {}; result: number };
  suspend_scheduled_messages: { args: {}; result: void };
  configure_app_lock: { args: { enabled: boolean; password: string }; result: void };
  preview_attachment_task: { args: { id: string }; result: string };
  check_app_update: { args: {}; result: { current: string; latest: string; available: boolean } };
  open_app_release: { args: {}; result: void };
  app_lock_state: { args: {}; result: boolean };
  lock_app: { args: {}; result: void };
  unlock_app: { args: { password: string }; result: void };
  submit_reaction: { args: { targetId: string; peerId: string; emoji: string }; result: void };
  sync_reactions: { args: {}; result: number };
  get_read_receipt_enabled: { args: {}; result: boolean };
  set_read_receipt_enabled: { args: { enabled: boolean }; result: void };
  sync_read_receipts: { args: {}; result: number };
  get_read_receipts: { args: { conversationId: string }; result: string[] };
  mark_visible_messages: { args: { userId: string; ids: string[] }; result: void };
  get_typing_enabled: { args: {}; result: boolean };
  set_typing_enabled: { args: { enabled: boolean }; result: void };
  send_typing: { args: { peerId: string; active: boolean }; result: void };
  get_reactions: { args: { conversationId: string }; result: { target_id: string; actor: string; emoji: string }[] };
  list_contact_requests: { args: {}; result: { peer_id: string; username: string; status: string }[] };
  set_contact_policy: { args: { peerId: string; status: "accepted" | "blocked" | "rejected" | "pending" }; result: void };
  list_account_sessions: { args: {}; result: { id: string; device_id: string; name: string; revoked: boolean; current: boolean; expires_at: string }[] };
  get_public_profile: { args: { userId: string }; result: { user_id: string; username: string; display_name: string; avatar_png: string | null } };
  update_public_profile: { args: { displayName: string; avatarPng: string | null }; result: { user_id: string; username: string; display_name: string; avatar_png: string | null } };
  choose_profile_avatar: { args: {}; result: string | null };
  logout_all_sessions: { args: {}; result: void };
  change_password: { args: { currentPassword: string; newPassword: string }; result: void };
  select_attachment: { args: { peerId: string }; result: AttachmentTask | null };
  stage_attachment_file: { args: { peerId: string; file: File }; result: AttachmentTask };
  stage_clipboard_image: { args: { peerId: string }; result: AttachmentTask };
  list_attachment_tasks: { args: {}; result: AttachmentTask[] };
  attachment_step: { args: { id: string }; result: AttachmentTask };
  publish_attachment: { args: { id: string }; result: string };
  begin_attachment_download: { args: { messageId: string }; result: AttachmentTask };
  export_attachment: { args: { messageId: string; preview?: boolean; media?: "image" | "audio" }; result: string | null };
  stage_recorded_audio: { args: { peerId: string; encoded: string; durationMs: number }; result: AttachmentTask };
  forget_attachment_task: { args: { id: string }; result: void };
  attachment_cache_stats: { args: {}; result: { cache_bytes: number; database_allocated: number; database_reusable: number; disk_bytes: number; limit: number } };
  clear_attachment_cache: { args: { peerId?: string }; result: number };
  get_personal_organizer: { args: {}; result: string };
  save_personal_organizer: { args: { content: string }; result: void };
  get_message_context: { args: { userId: string; conversationId: string; messageId: string }; result: Message[] };
  set_conversation_muted: { args: { userId: string; peerId: string; muted: boolean }; result: void };
  set_notification_context: { args: { userId: string | null; activePeerId: string | null; activeGroupId?: string | null }; result: void };
  take_notification_target: { args: {}; result: ({ userId: string; serverUrl: string; deviceId: string } & NotificationConversation) | null };
  submit_message_operation: { args: { targetId: string; kind: "edit" | "revoke"; content: string; baseRevision: number }; result: string };
  sync_message_operations: { args: {}; result: number };
  get_message_operations: { args: { conversationId?: string }; result: MessageOperation[] };
  delete_message_locally: { args: { userId: string; conversationId: string; messageId: string }; result: void };
  get_locally_deleted_ids: { args: { userId: string; conversationId: string }; result: string[] };
  copy_message_text: { args: { text: string }; result: void };
  get_conversation_preferences: { args: { userId: string }; result: ConversationPreference[] };
  save_conversation_preference: { args: { userId: string; peerId: string; pinned?: boolean; archived?: boolean; draft?: number[] }; result: void };
  get_conversation_summaries: { args: { userId: string }; result: ConversationSummary[] };
  mark_messages_read: { args: { userId: string; ids: string[] }; result: void };
  get_local_message_page: { args: { userId?: string; conversationId: string; limit: number; beforeTimestamp?: number; beforeId?: string }; result: Message[] };
  sign_out: { args: {}; result: string | null };
  retry_message: { args: { messageId: string }; result: SendMessageResult };
  send_message: { args: { messageId?: string; senderId: string; ciphertext: number[]; signature: number[]; senderDeviceId: string; payloads: EncryptedPayload[] }; result: SendMessageResult };
  poll_messages: { args: {  }; result: PollMessagesResult };
  get_local_messages: { args: { conversationId: string; limit: number; offset: number }; result: Message[] };
  // Secret keys never cross this bridge: crypto uses the identity saved in Rust.
  encrypt_message: { args: { plaintext: number[]; recipientPublicKey: number[] }; result: number[] };
  decrypt_message: { args: { ciphertext: number[]; senderPublicKey: number[] }; result: number[] };
  sign_message: { args: { message: number[] }; result: number[] };
  verify_message: { args: { message: number[]; signature: number[]; senderPublicKey: number[] }; result: boolean };
  prepare_identity: { args: {  }; result: Identity };
  load_identity: { args: {  }; result: Identity };
  save_session: { args: { userId: string; token: string; refreshToken: string; deviceId: string; serverUrl: string }; result: Identity };
  clear_keypair: { args: {  }; result: null };
  register: { args: { inviteCode: string; username: string; password: string; serverUrl: string; publicKey: number[]; ed25519Pk: number[] }; result: RegisterResult };
  login: { args: { username: string; password: string; serverUrl: string; publicKey: number[]; ed25519Pk: number[]; deviceId?: string | null }; result: RegisterResult };
  refresh_session: { args: { serverUrl: string; refreshToken: string }; result: RegisterResult };
  connect_relay: { args: { serverUrl: string; userId: string; token: string; deviceId: string }; result: ConnectResult };
  disconnect: { args: {  }; result: null };
  validate_invite: { args: { serverUrl: string; inviteCode: string }; result: boolean };
  add_contact: { args: { userId: string; username: string; publicKey: number[]; ed25519Pk?: number[] | null }; result: { success: boolean } };
  get_contacts: { args: {  }; result: Contact[] };
  remove_contact: { args: { userId: string }; result: { success: boolean } };
  set_contact_trust: { args: { userId: string; trustState: string }; result: { success: boolean } };
  get_user_devices: { args: { serverUrl: string; userId: string; accessToken: string }; result: RemoteDevice[] };
  search_users: { args: { serverUrl: string; query: string; accessToken: string }; result: UserSearchResult[] };
  get_storage_stats: { args: {  }; result: StorageStats };
  clear_expired_messages: { args: {  }; result: number };
  clear_downloaded_attachments: { args: {  }; result: number };
}
export interface ActivationTask { id: string; revision: number; kind: "enable" | "login"; stage: "prepared" | "started" | "proving" | "conflict" | "complete" | "cancelled" | "ineligible" | "ended"; cancel_requested: boolean; closed?: { reason: "cancelled" | "expired" | "directory_changed" | "credentials_changed" | "session_ended"; accepted: boolean } }
export interface ActivationProgress { task: ActivationTask; condition: "complete" | "cancelled" | "ineligible" | "needs_password" | "session_required" | "retry" | "conflict" | "pending" | "ended"; http_status: number | null }
export interface NormalJoinProfile { id: string; origin: string; username: string; device_name: string; account: string; device: string; root_fingerprint: string; encryption_fingerprint: string; signing_fingerprint: string; revision: number; has_saved_session: boolean; access_expired: boolean; eligible: boolean }
export interface JoinActivationSnapshot { profile_id: string; tasks: ActivationTask[]; normal: NormalJoinProfile | null }
export interface RootMessagingSnapshot { root_fingerprint:string; admission:"legacy"|"switching"|"v3"; pending:{messages:number;uploads:number;scheduled:number;operations:number;reactions:number;receipts:number}; tasks:ActivationTask[] }
export interface RootSessionSnapshot { root_fingerprint:string; tasks:ActivationTask[]; has_local_credentials:boolean }
export interface RootSessionSaved { user_id:string; device_id:string; server_url:string; public_key:number[]; ed25519_pk:number[] }
export type CommandName = keyof CommandMap;
export interface DeviceJoinProfile { id: string; origin: string; username: string; device_name: string; local_device_id: string; encryption_fingerprint: string; signing_fingerprint: string }
export interface DeviceJoinListing { id: string; profile: DeviceJoinProfile | null; error: string | null }
export interface DeviceJoinSnapshot { profile: DeviceJoinProfile; join: { task: DeviceTask; local_abandonment: boolean; device_id: string | null; root_origin: string | null; root_account: string | null; root_device: string | null }; messaging_enabled: boolean }
export type DeviceTaskPhase = "draft" | "awaiting_root_confirmation" | "awaiting_challenge" | "awaiting_authorization" | "prepared" | "cancelling" | "conflict" | "complete" | "cancelled" | "expired" | "revoked";
export interface DeviceTask { id: string; kind: "join" | "challenge" | "grant" | "revoke"; phase: DeviceTaskPhase; revision: number; request_id: string | null; event_id: string | null; root_fingerprint: string | null }
export interface DeviceRequest { request_id: string; device_id: string; device_name: string; encryption_fingerprint: string; signing_fingerprint: string; combined_fingerprint: string; phase: "begun" | "ready" | "challenged" | "proved" | "authorized" | "cancelled" | "expired" | "revoked" }
export interface DeviceControlSnapshot { root_fingerprint: string; supported: boolean; syncing: boolean; messaging_enabled: boolean; requests: DeviceRequest[]; tasks: DeviceTask[]; authorized: { device_id: string; combined_fingerprint: string; encryption_fingerprint: string; signing_fingerprint: string } | null }
export interface DeviceProgress { task: DeviceTask; condition: "advanced" | "waiting" | "needs_password" | "needs_confirmation" | "syncing" | "retry" | "session_required" | "unsupported" | "conflict" | "terminal" | "unsigned_abandoned"; http_status: number | null }
export interface BackupSummary { messages: number; groups: number; attachments: number; missing_attachments: number; skipped_attachments: number }
export interface BackupJob { id: string; state: "running" | "completed" | "failed" | "cancelled"; completed: number; total: number; summary: BackupSummary | null; error: string | null; restorable: boolean }
export interface BackupArchiveInfo { id: string; user_id: string; device_id: string; server_url: string; fingerprint: string; signing_fingerprint: string; summary: BackupSummary }
export interface BackupConversation { id: string; kind: "direct" | "group"; name: string }
export interface BackupHistory { messages: { id: string; sender: string; timestamp: number; text: string; status: string }[]; next?: { time: number; id: string } | null; next_group?: number | null; collaboration?: GroupCollaboration; extensions?:GroupExtensions; draft?: string; reactions?: { target_id: string; actor: string; emoji: string }[] }
export interface GroupMember { user_id: string; device_id: string; name: string; fingerprint: string; joined_epoch: number }
export interface GroupView { id: string; name: string; owner: string; epoch: number; closed: boolean; active: boolean; trusted: boolean; members: GroupMember[]; unread: number; pending: boolean; muted: boolean }
export interface GroupMessage { id: string; sender_user_id: string; sender_device_id: string; sent_at: number; text: string; status: string }
export interface GroupInspection { group_id: string; name: string; owner_id: string; owner_name: string; owner_device: string; fingerprint: string; eligible: boolean; reason: string }
export interface GroupSnapshot { groups: GroupView[]; invitations: { id: string; group_id: string; expires_at: number }[]; errors: string[]; next_cursor: string | null }
export interface ScheduledTask { id: string; peer_id: string; due_at: number; text: string; state: string; error: string; sealed: boolean }
export interface AttachmentTask { id: string; peer_id: string; message_id: string; name: string; size: number; mime: string; duration_ms?: number; offset: number; total: number; direction: string }
export type RefreshTarget={kind:"root"}|{kind:"join";profileId:string};
export interface NormalProfileChoice{target:RefreshTarget;scope_fingerprint:string;origin:string;account:string;device:string;device_name:string;protocol:string;has_session:boolean;eligible:boolean;access_expired:boolean}
export interface NormalProfileSnapshot{generation:number;explicit:boolean;selected:NormalProfileChoice|null;error:string|null;profiles:{target:RefreshTarget;profile:NormalProfileChoice|null;error:string|null}[]}
export interface RefreshCurrent{generation:number;account:string;device:string;session:string;has_credentials:boolean;access_expired:boolean;eligible:boolean;access_expires_at:number;refresh_expires_at:number}
export interface RefreshTask{id:string;revision:number;stage:"prepared"|"started"|"proving"|"conflict"|"complete"|"cancelled"|"ended";current:boolean;cancel_requested:boolean}
export interface RefreshProgress{task:RefreshTask;condition:"complete"|"cancelled"|"ended"|"superseded"|"ineligible"|"retry"|"conflict"|"pending";http_status:number|null}
export interface RefreshSnapshot{target:RefreshTarget;current:RefreshCurrent|null;tasks:RefreshTask[]}
export type DesktopApi = {
  // The mapped business API never exposes private attachment descriptors.
  [K in Exclude<CommandName, "suspend_device_control" | "resume_device_control" | "process_session_refreshes">]: (args: CommandMap[K]["args"]) => Promise<CommandMap[K]["result"]>;
};
export type GroupAnswer="yes"|"no"|"maybe";
export interface GroupActivity { id:string;creator:string;title:string;start_at:number;timezone:string;location:string;description:string;responses:Record<string,GroupAnswer>;participants:string[];departed:string[];closed:boolean;cancelled:boolean;eligible:boolean;can_manage:boolean;revision:number }
export interface GroupExtensions { attachments:{id:string;blob:string;name:string;size:number;mime:string;duration_ms:number|null}[];activities:GroupActivity[];pending:boolean;conflict:boolean;pending_root:string|null }
export type GroupExtensionCommand={kind:"activity";title:string;start_at:number;timezone:string;location:string;description:string}|{kind:"respond";activity:string;answer:GroupAnswer;revision:number}|{kind:"close"|"cancel";activity:string;revision:number};
export const commandNames = [
  "get_normal_profile","select_normal_profile","clear_normal_profile",
  "get_session_refresh","prepare_session_refresh","session_refresh_step","cancel_session_refresh","forget_session_refresh",
  "get_root_messaging", "check_root_messaging", "prepare_root_messaging", "root_messaging_step", "cancel_root_messaging", "forget_root_messaging",
  "get_root_session", "prepare_root_session", "root_session_step", "inspect_root_session", "cancel_root_session", "forget_root_session", "save_root_session",
  "get_join_activation", "prepare_join_activation", "join_activation_step", "inspect_join_activation", "cancel_join_activation", "forget_join_activation", "save_join_activation", "clear_join_activation_session",
  "list_device_join_profiles", "create_device_join_profile", "get_device_join_profile", "confirm_device_join_root", "device_join_step", "cancel_device_join", "abandon_device_join", "forget_device_join_profile",
  "get_device_control", "inspect_device_request", "prepare_device_challenge", "prepare_device_grant", "prepare_device_revoke", "device_task_step", "cancel_device_task", "discard_device_task",
  "get_group_extensions", "sync_group_extensions", "submit_group_extension", "retry_group_extension", "cancel_group_extension", "select_group_attachment", "stage_group_attachment_file", "stage_group_recorded_audio", "stage_group_clipboard_image", "group_attachment_tasks", "group_attachment_step", "publish_group_attachment", "cancel_group_attachment", "begin_group_attachment_download", "export_group_attachment", "clear_group_attachment_cache",
  "start_backup_export", "start_backup_restore", "get_backup_job", "cancel_backup_job", "open_backup_archive", "get_backup_archive_info", "get_backup_conversations", "get_backup_history", "export_backup_attachment", "close_backup_archive",
  "get_group_collaboration", "sync_group_collaboration", "submit_group_collaboration", "retry_group_collaboration", "discard_group_collaboration_conflict",
  "sync_group",
  "get_group_storage_stats", "clear_group_history", "get_sent_group_invites", "revoke_group_invite", "set_group_muted", "get_groups", "create_group", "inspect_group", "inspect_group_peer", "recover_group", "invite_group_member", "accept_group_invite", "decline_group_invite", "change_group_membership", "get_group_history", "group_draft", "mark_group_seen", "send_group_text", "cancel_group_send", "process_groups",
  "save_scheduled_message", "list_scheduled_messages", "cancel_scheduled_message", "send_scheduled_now", "process_scheduled_messages", "suspend_scheduled_messages",
  "configure_app_lock",
  "preview_attachment_task",
  "check_app_update", "open_app_release",
  "app_lock_state", "lock_app", "unlock_app",
  "submit_reaction", "sync_reactions", "get_reactions",
  "get_read_receipt_enabled", "set_read_receipt_enabled", "sync_read_receipts", "get_read_receipts", "mark_visible_messages",
  "get_typing_enabled", "set_typing_enabled", "send_typing",
  "list_contact_requests", "set_contact_policy", "list_account_sessions", "get_public_profile", "update_public_profile", "choose_profile_avatar", "logout_all_sessions", "change_password",
  "select_attachment", "stage_attachment_file", "stage_clipboard_image", "stage_recorded_audio", "list_attachment_tasks", "attachment_step", "publish_attachment", "begin_attachment_download", "export_attachment", "forget_attachment_task", "attachment_cache_stats", "clear_attachment_cache",
  "get_personal_organizer",
  "save_personal_organizer",
  "get_message_context",
  "set_conversation_muted",
  "set_notification_context",
  "take_notification_target",
  "submit_message_operation",
  "sync_message_operations",
  "get_message_operations",
  "delete_message_locally",
  "get_locally_deleted_ids",
  "copy_message_text",
  "get_conversation_preferences",
  "save_conversation_preference",
  "get_conversation_summaries",
  "mark_messages_read",
  "get_local_message_page",
  "sign_out",
  "send_message",
  "retry_message",
  "poll_messages",
  "get_local_messages",
  "encrypt_message",
  "decrypt_message",
  "sign_message",
  "verify_message",
  "prepare_identity",
  "load_identity",
  "save_session",
  "clear_keypair",
  "register",
  "login",
  "refresh_session",
  "connect_relay",
  "disconnect",
  "validate_invite",
  "add_contact",
  "get_contacts",
  "remove_contact",
  "set_contact_trust",
  "get_user_devices",
  "search_users",
  "get_storage_stats",
  "clear_expired_messages",
  "clear_downloaded_attachments",
] as const satisfies readonly CommandName[];
