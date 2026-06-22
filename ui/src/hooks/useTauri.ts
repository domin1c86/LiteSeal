import { invoke } from "@tauri-apps/api/tauri";
import type {
  RegisterResult,
  ConnectResult,
  SendMessageResult,
  IncomingMessage,
  Message,
} from "../types";

export function useTauri() {
  async function register(
    username: string,
    serverUrl: string
  ): Promise<RegisterResult> {
    return invoke<RegisterResult>("register", { username, serverUrl });
  }

  async function connectRelay(
    serverUrl: string,
    userId: string,
    token: string
  ): Promise<ConnectResult> {
    return invoke<ConnectResult>("connect_relay", {
      serverUrl,
      userId,
      token,
    });
  }

  async function disconnect(): Promise<void> {
    return invoke("disconnect");
  }

  async function sendMessage(
    to: string,
    conversationId: string,
    ciphertext: number[],
    signature: number[],
    senderDeviceId: string,
    senderSeq: number
  ): Promise<SendMessageResult> {
    return invoke<SendMessageResult>("send_message", {
      to,
      conversationId,
      ciphertext,
      signature,
      senderDeviceId,
      senderSeq,
    });
  }

  async function pollMessages(): Promise<IncomingMessage[]> {
    return invoke<IncomingMessage[]>("poll_messages");
  }

  async function getLocalMessages(
    conversationId: string,
    limit: number,
    offset: number
  ): Promise<Message[]> {
    return invoke<Message[]>("get_local_messages", {
      conversationId,
      limit,
      offset,
    });
  }

  return {
    register,
    connectRelay,
    disconnect,
    sendMessage,
    pollMessages,
    getLocalMessages,
  };
}
