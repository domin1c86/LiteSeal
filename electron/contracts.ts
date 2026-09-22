import type { RegisterResult, ConnectResult, SendMessageResult, PollMessagesResult,
  MessageOperation, ConversationPreference, ConversationSummary, Message, Contact, RemoteDevice, UserSearchResult, StorageStats, Identity, EncryptedPayload
} from "../ui/src/types";

export interface CommandMap {
  set_conversation_muted: { args: { userId: string; peerId: string; muted: boolean }; result: void };
  set_notification_context: { args: { userId: string | null; activePeerId: string | null }; result: void };
  take_notification_target: { args: {}; result: { userId: string; peerId: string } | null };
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
export type DesktopApi = {
  [K in CommandName]: (args: CommandMap[K]["args"]) => Promise<CommandMap[K]["result"]>;
};
export const commandNames = [
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
