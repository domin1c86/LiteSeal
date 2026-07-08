import { invoke } from "@tauri-apps/api/core";
import type {
  RegisterResult,
  ConnectResult,
  KeystoreData,
  SendMessageResult,
  PollMessagesResult,
  Message,
  Contact,
  UserSearchResult,
  StorageStats,
  EncryptedPayload,
  RemoteDevice,
} from "../types";

export function useTauri() {
  async function register(
    username: string,
    password: string,
    serverUrl: string,
    publicKey: number[] = [],
    ed25519Pk: number[] = []
  ): Promise<RegisterResult> {
    return invoke<RegisterResult>("register", {
      username,
      password,
      serverUrl,
      publicKey,
      ed25519Pk,
    });
  }

  async function login(
    username: string,
    password: string,
    serverUrl: string,
    publicKey: number[] = [],
    ed25519Pk: number[] = [],
    deviceId?: string
  ): Promise<RegisterResult> {
    return invoke<RegisterResult>("login", {
      username,
      password,
      serverUrl,
      publicKey,
      ed25519Pk,
      deviceId,
    });
  }

  async function refreshSession(
    serverUrl: string,
    refreshToken: string
  ): Promise<RegisterResult> {
    return invoke<RegisterResult>("refresh_session", {
      serverUrl,
      refreshToken,
    });
  }

  async function connectRelay(
    serverUrl: string,
    userId: string,
    token: string,
    deviceId: string
  ): Promise<ConnectResult> {
    return invoke<ConnectResult>("connect_relay", {
      serverUrl,
      userId,
      token,
      deviceId,
    });
  }

  async function disconnect(): Promise<void> {
    return invoke("disconnect");
  }

  async function sendMessage(
    conversationId: string,
    senderId: string,
    ciphertext: number[],
    signature: number[],
    senderDeviceId: string,
    senderSeq: number,
    payloads: EncryptedPayload[]
  ): Promise<SendMessageResult> {
    return invoke<SendMessageResult>("send_message", {
      conversationId,
      senderId,
      ciphertext,
      signature,
      senderDeviceId,
      senderSeq,
      payloads,
    });
  }

  async function getUserDevices(
    serverUrl: string,
    userId: string
  ): Promise<RemoteDevice[]> {
    return invoke<RemoteDevice[]>("get_user_devices", { serverUrl, userId });
  }

  async function pollMessages(): Promise<PollMessagesResult> {
    return invoke<PollMessagesResult>("poll_messages");
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
    publicKey: number[],
    ed25519Pk?: number[]
  ): Promise<Contact> {
    return invoke<Contact>("add_contact", { userId, username, publicKey, ed25519Pk });
  }

  async function getContacts(): Promise<Contact[]> {
    return invoke<Contact[]>("get_contacts");
  }

  async function removeContact(userId: string): Promise<void> {
    return invoke("remove_contact", { userId });
  }

  async function setContactTrust(
    userId: string,
    trustState: "unverified" | "verified" | "key_changed"
  ): Promise<void> {
    return invoke("set_contact_trust", { userId, trustState });
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

  async function getStorageStats(): Promise<StorageStats> {
    return invoke<StorageStats>("get_storage_stats");
  }

  async function clearExpiredMessages(): Promise<number> {
    return invoke<number>("clear_expired_messages");
  }

  async function clearDownloadedAttachments(): Promise<number> {
    return invoke<number>("clear_downloaded_attachments");
  }

  async function saveKeypair(data: KeystoreData): Promise<void> {
    return invoke("save_keypair", { data });
  }

  async function loadKeypair(): Promise<KeystoreData> {
    return invoke("load_keypair");
  }

  async function clearKeypair(): Promise<void> {
    return invoke("clear_keypair");
  }

  return {
    register,
    login,
    refreshSession,
    connectRelay,
    disconnect,
    sendMessage,
    getUserDevices,
    pollMessages,
    getLocalMessages,
    addContact,
    getContacts,
    removeContact,
    setContactTrust,
    searchUsers,
    encryptMessage,
    decryptMessage,
    signMessage,
    verifyMessage,
    generateKeypair,
    getStorageStats,
    clearExpiredMessages,
    clearDownloadedAttachments,
    saveKeypair,
    loadKeypair,
    clearKeypair,
  };
}
