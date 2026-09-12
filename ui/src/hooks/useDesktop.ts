import type { CommandMap, CommandName } from "../../../electron/contracts";

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

async function invoke<K extends CommandName>(name: K, args: CommandMap[K]["args"]): Promise<CommandMap[K]["result"]> {
  if (!window.desktop) throw new Error("请通过 Electron 桌面应用使用此功能；浏览器仅支持界面预览");
  const method = window.desktop[name] as (value: CommandMap[K]["args"]) => Promise<CommandMap[K]["result"]>;
  return method(args);
}
export function useDesktop() {
  async function register(
    username: string,
    password: string,
    serverUrl: string,
    publicKey: number[] = [],
    ed25519Pk: number[] = [],
    inviteCode: string = ""
  ): Promise<RegisterResult> {
    return invoke("register", {
      inviteCode,
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
    return invoke("login", {
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
    return invoke("refresh_session", {
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
    return invoke("connect_relay", {
      serverUrl,
      userId,
      token,
      deviceId,
    });
  }

  async function disconnect(): Promise<void> {
    await invoke("disconnect", {});
  }

  async function sendMessage(
    senderId: string,
    ciphertext: number[],
    signature: number[],
    senderDeviceId: string,
    payloads: EncryptedPayload[],
    messageId?: string
  ): Promise<SendMessageResult> {
    return invoke("send_message", {
      messageId,
      senderId,
      ciphertext,
      signature,
      senderDeviceId,
      payloads,
    });
  }

  async function getUserDevices(
    serverUrl: string,
    userId: string
  ): Promise<RemoteDevice[]> {
    return invoke("get_user_devices", { serverUrl, userId });
  }

  async function pollMessages(): Promise<PollMessagesResult> {
    return invoke("poll_messages", {});
  }

  async function getLocalMessages(
    conversationId: string,
    limit: number,
    offset: number
  ): Promise<Message[]> {
    return invoke("get_local_messages", {
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
  ): Promise<{ success: boolean }> {
    return invoke("add_contact", { userId, username, publicKey, ed25519Pk });
  }

  async function getContacts(): Promise<Contact[]> {
    return invoke("get_contacts", {});
  }

  async function removeContact(userId: string): Promise<void> {
    await invoke("remove_contact", { userId });
  }

  async function setContactTrust(
    userId: string,
    trustState: "unverified" | "verified" | "key_changed"
  ): Promise<void> {
    await invoke("set_contact_trust", { userId, trustState });
  }

  async function searchUsers(
    query: string,
    serverUrl: string
  ): Promise<UserSearchResult[]> {
    return invoke("search_users", { query, serverUrl });
  }

  async function encryptMessage(
    plaintext: number[],
    recipientPublicKey: number[],
    senderSecretKey: number[]
  ): Promise<number[]> {
    return invoke("encrypt_message", {
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
    return invoke("decrypt_message", {
      ciphertext,
      senderPublicKey,
      recipientSecretKey,
    });
  }

  async function signMessage(
    message: number[],
    signingKey: number[]
  ): Promise<number[]> {
    return invoke("sign_message", { message, signingKey });
  }

  async function verifyMessage(
    message: number[],
    signature: number[],
    senderPublicKey: number[]
  ): Promise<boolean> {
    return invoke("verify_message", {
      message,
      signature,
      senderPublicKey,
    });
  }

  async function generateKeypair(): Promise<
    [number[], number[], number[], number[]]
  > {
    return invoke("generate_keypair_cmd", {});
  }

  async function getStorageStats(): Promise<StorageStats> {
    return invoke("get_storage_stats", {});
  }

  async function clearExpiredMessages(): Promise<number> {
    return invoke("clear_expired_messages", {});
  }

  async function clearDownloadedAttachments(): Promise<number> {
    return invoke("clear_downloaded_attachments", {});
  }

  async function saveKeypair(data: KeystoreData): Promise<void> {
    await invoke("save_keypair", { data });
  }

  async function loadKeypair(): Promise<KeystoreData> {
    return invoke("load_keypair", {});
  }

  async function clearKeypair(): Promise<void> {
    await invoke("clear_keypair", {});
  }

  return {
    signOut: () => invoke("sign_out", {}),
    retryMessage: (messageId: string) => invoke("retry_message", { messageId }),
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

export function validateInvite(serverUrl: string, inviteCode: string): Promise<boolean> {
  return invoke("validate_invite", { serverUrl, inviteCode });
}
