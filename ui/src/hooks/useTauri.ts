import { invoke } from "@tauri-apps/api/core";
import type {
  RegisterResult,
  ConnectResult,
  SendMessageResult,
  IncomingMessage,
  Message,
  Contact,
  UserSearchResult,
} from "../types";

export function useTauri() {
  async function register(
    username: string,
    serverUrl: string,
    publicKey: number[] = [],
    ed25519Pk: number[] = []
  ): Promise<RegisterResult> {
    return invoke<RegisterResult>("register", {
      username,
      serverUrl,
      publicKey,
      ed25519Pk,
    });
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

  async function addContact(
    userId: string,
    username: string,
    publicKey: number[]
  ): Promise<Contact> {
    return invoke<Contact>("add_contact", { userId, username, publicKey });
  }

  async function getContacts(): Promise<Contact[]> {
    return invoke<Contact[]>("get_contacts");
  }

  async function removeContact(userId: string): Promise<void> {
    return invoke("remove_contact", { userId });
  }

  async function searchUsers(
    query: string,
    serverUrl: string
  ): Promise<UserSearchResult[]> {
    return invoke<UserSearchResult[]>("search_users", { query, serverUrl });
  }

  async function encryptMessage(
    plaintext: number[],
    recipientPublicKey: number[],
    senderSecretKey: number[]
  ): Promise<number[]> {
    return invoke<number[]>("encrypt_message", {
      plaintext,
      recipientPublicKey,
      senderSecretKey,
    });
  }

  async function decryptMessage(
    ciphertext: number[],
    senderPublicKey: number[],
    recipientSecretKey: number[]
  ): Promise<number[]> {
    return invoke<number[]>("decrypt_message", {
      ciphertext,
      senderPublicKey,
      recipientSecretKey,
    });
  }

  async function signMessage(
    message: number[],
    secretKey: number[]
  ): Promise<number[]> {
    return invoke<number[]>("sign_message", { message, secretKey });
  }

  async function verifyMessage(
    message: number[],
    signature: number[],
    senderPublicKey: number[]
  ): Promise<boolean> {
    return invoke<boolean>("verify_message", {
      message,
      signature,
      senderPublicKey,
    });
  }

  async function generateKeypair(): Promise<
    [number[], number[], number[], number[]]
  > {
    return invoke<[number[], number[], number[], number[]]>(
      "generate_keypair_cmd"
    );
  }

  return {
    register,
    connectRelay,
    disconnect,
    sendMessage,
    pollMessages,
    getLocalMessages,
    addContact,
    getContacts,
    removeContact,
    searchUsers,
    encryptMessage,
    decryptMessage,
    signMessage,
    verifyMessage,
    generateKeypair,
  };
}
