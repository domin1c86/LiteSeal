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
}

export interface ConnectResult {
  connected: boolean;
}

export interface SendMessageResult {
  message_id: string;
}

export interface IncomingMessage {
  message_id: string;
  from: string;
  conversation_id: string;
  ciphertext: number[];
  signature: number[];
  sender_device_id: string;
  sender_seq: number;
  timestamp: number;
}

export interface AppState {
  user: User | null;
  token: string | null;
  serverUrl: string;
  connected: boolean;
  conversations: Conversation[];
  activeConversation: string | null;
  messages: Record<string, Message[]>;
  contacts: User[];
}
