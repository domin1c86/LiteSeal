export interface User {
  id: string;
  username: string;
  created_at: number;
}

export interface Message {
  id: string;
  conversation_id: string;
  sender_id: string;
  sender_device_id: string;
  sender_seq: number;
  timestamp: number;
  message_type: string;
  local_state?: "pending" | "delivered" | "offline" | "received" | "failed" | string;
  ciphertext: number[];
  signature: number[];
  prev_hash: number[];
}

export interface Conversation {
  id: string;
  conversation_type: string;
  created_at: number;
  updated_at: number;
}

export interface RegisterResult {
  user_id: string;
  token: string;
  access_token?: string;
  refresh_token?: string;
  device_id?: string;
}

export interface ConnectResult {
  connected: boolean;
}

export interface KeystoreData {
  user_id: string;
  token: string;
  refresh_token: string;
  device_id: string;
  server_url: string;
  public_key: number[];
  secret_key: number[];
  ed25519_pk: number[];
  ed25519_sk: number[];
}

export interface SendMessageResult {
  message_id: string;
}

export interface EncryptedPayload {
  recipient_user_id: string;
  recipient_device_id: string;
  ciphertext: number[];
  signature: number[];
}

export interface RemoteDevice {
  id: string;
  name: string;
  public_key: number[];
  ed25519_pk: number[];
  revoked: boolean;
}

export interface IncomingMessage {
  message_id: string;
  from: string;
  conversation_id: string;
  ciphertext: number[];
  signature: number[];
  sender_device_id: string;
  sender_seq: number;
  prev_hash: number[];
  recipient_device_id: string;
  timestamp: number;
  local_state: Message["local_state"];
}

export type RelayEvent =
  | { type: "delivered"; message_id: string }
  | { type: "offline"; message_id: string; to: string }
  | { type: "delivery_update"; message_id: string; recipient_device_id: string; status: string }
  | { type: "error"; code: string; message: string };

export interface PollMessagesResult {
  messages: IncomingMessage[];
  events: RelayEvent[];
}

export interface Contact {
  user_id: string;
  username: string;
  public_key: number[];
  ed25519_pk?: number[];
  trust_state: "unverified" | "verified" | "key_changed" | string;
  fingerprint: string;
  key_changed: boolean;
  added_at: number;
}

export interface UserSearchResult {
  user_id: string;
  username: string;
  public_key: number[];
  ed25519_pk?: number[];
}

export interface AppState {
  user: User | null;
  token: string | null;
  serverUrl: string;
  connected: boolean;
  conversations: Conversation[];
  activeConversation: string | null;
  messages: Record<string, Message[]>;
  contacts: Contact[];
}

export interface StorageStats {
  message_count: number;
  ciphertext_bytes: number;
  attachment_count: number;
  attachment_bytes: number;
  conversation_count: number;
  total_bytes: number;
}

export interface ConversationSummary {
  conversation_id: string;
  latest: Message;
  unread_count: number;
}

export interface ConversationPreference { peer_id: string; pinned: boolean; archived: boolean; draft: number[] }
export interface Draft { text: string; messageId?: string }
