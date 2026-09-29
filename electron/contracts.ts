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
export type CommandName = keyof CommandMap;
export interface GroupMember { user_id: string; device_id: string; name: string; fingerprint: string; joined_epoch: number }
export interface GroupView { id: string; name: string; owner: string; epoch: number; closed: boolean; active: boolean; trusted: boolean; members: GroupMember[]; unread: number; pending: boolean; muted: boolean }
export interface GroupMessage { id: string; sender_user_id: string; sender_device_id: string; sent_at: number; text: string; status: string }
export interface GroupInspection { group_id: string; name: string; owner_id: string; owner_name: string; owner_device: string; fingerprint: string; eligible: boolean; reason: string }
export interface GroupSnapshot { groups: GroupView[]; invitations: { id: string; group_id: string; expires_at: number }[]; errors: string[]; next_cursor: string | null }
export interface ScheduledTask { id: string; peer_id: string; due_at: number; text: string; state: string; error: string; sealed: boolean }
export interface AttachmentTask { id: string; peer_id: string; message_id: string; name: string; size: number; mime: string; duration_ms?: number; offset: number; total: number; direction: string }
export type DesktopApi = {
  [K in CommandName]: (args: CommandMap[K]["args"]) => Promise<CommandMap[K]["result"]>;
};
export const commandNames = [
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
