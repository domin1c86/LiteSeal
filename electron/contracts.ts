import type { RegisterResult, ConnectResult, SendMessageResult, PollMessagesResult,
  Message, Contact, RemoteDevice, UserSearchResult, StorageStats, KeystoreData, EncryptedPayload
} from "../ui/src/types";

export interface CommandMap {
  retry_message: { args: { messageId: string }; result: SendMessageResult };
  send_message: { args: { messageId?: string; senderId: string; ciphertext: number[]; signature: number[]; senderDeviceId: string; payloads: EncryptedPayload[] }; result: SendMessageResult };
  poll_messages: { args: {  }; result: PollMessagesResult };
  get_local_messages: { args: { conversationId: string; limit: number; offset: number }; result: Message[] };
  encrypt_message: { args: { plaintext: number[]; recipientPublicKey: number[]; senderSecretKey: number[] }; result: number[] };
  decrypt_message: { args: { ciphertext: number[]; senderPublicKey: number[]; recipientSecretKey: number[] }; result: number[] };
  sign_message: { args: { message: number[]; signingKey: number[] }; result: number[] };
  verify_message: { args: { message: number[]; signature: number[]; senderPublicKey: number[] }; result: boolean };
  generate_keypair_cmd: { args: {  }; result: [number[], number[], number[], number[]] };
  save_keypair: { args: { data: KeystoreData }; result: null };
  load_keypair: { args: {  }; result: KeystoreData };
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
  get_user_devices: { args: { serverUrl: string; userId: string }; result: RemoteDevice[] };
  search_users: { args: { serverUrl: string; query: string }; result: UserSearchResult[] };
  get_storage_stats: { args: {  }; result: StorageStats };
  clear_expired_messages: { args: {  }; result: number };
  clear_downloaded_attachments: { args: {  }; result: number };
}
export type CommandName = keyof CommandMap;
export type DesktopApi = {
  [K in CommandName]: (args: CommandMap[K]["args"]) => Promise<CommandMap[K]["result"]>;
};
export const commandNames = [
  "send_message",
  "retry_message",
  "poll_messages",
  "get_local_messages",
  "encrypt_message",
  "decrypt_message",
  "sign_message",
  "verify_message",
  "generate_keypair_cmd",
  "save_keypair",
  "load_keypair",
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
