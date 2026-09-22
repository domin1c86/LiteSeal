import type { CommandMap, CommandName } from "../../../electron/contracts";

import type {
  RegisterResult,
  ConnectResult,
  Identity,
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
    userId: string,
    accessToken: string
  ): Promise<RemoteDevice[]> {
    return invoke("get_user_devices", { serverUrl, userId, accessToken });
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
    serverUrl: string,
    accessToken: string
  ): Promise<UserSearchResult[]> {
    return invoke("search_users", { query, serverUrl, accessToken });
  }

  // Encryption, decryption and signing use the identity saved in Rust.
  async function encryptMessage(
    plaintext: number[],
    recipientPublicKey: number[]
  ): Promise<number[]> {
    return invoke("encrypt_message", { plaintext, recipientPublicKey });
  }

  async function decryptMessage(
    ciphertext: number[],
    senderPublicKey: number[]
  ): Promise<number[]> {
    return invoke("decrypt_message", { ciphertext, senderPublicKey });
  }

  async function signMessage(message: number[]): Promise<number[]> {
    return invoke("sign_message", { message });
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

  async function getStorageStats(): Promise<StorageStats> {
    return invoke("get_storage_stats", {});
  }

  async function clearExpiredMessages(): Promise<number> {
    return invoke("clear_expired_messages", {});
  }

  async function clearDownloadedAttachments(): Promise<number> {
    return invoke("clear_downloaded_attachments", {});
  }

  /** The saved identity, or freshly generated keys (`saved: false`) for a new account. */
  async function prepareIdentity(): Promise<Identity> {
    return invoke("prepare_identity", {});
  }

  async function loadIdentity(): Promise<Identity> {
    return invoke("load_identity", {});
  }

  async function saveSession(args: CommandMap["save_session"]["args"]): Promise<Identity> {
    return invoke("save_session", args);
  }

  async function clearKeypair(): Promise<void> {
    await invoke("clear_keypair", {});
  }

  return {
    submitMessageOperation: (targetId: string, kind: "edit" | "revoke", content: string, baseRevision: number) => invoke("submit_message_operation", { targetId, kind, content, baseRevision }),
    syncMessageOperations: () => invoke("sync_message_operations", {}),
    getMessageOperations: (conversationId?: string) => invoke("get_message_operations", { conversationId }),
    deleteMessageLocally: (userId: string, conversationId: string, messageId: string) => invoke("delete_message_locally", { userId, conversationId, messageId }),
    getLocallyDeletedIds: (userId: string, conversationId: string) => invoke("get_locally_deleted_ids", { userId, conversationId }),
    copyMessageText: (text: string) => invoke("copy_message_text", { text }),
    getConversationPreferences: (userId: string) => invoke("get_conversation_preferences", { userId }),
    saveConversationPreference: (args: CommandMap["save_conversation_preference"]["args"]) => invoke("save_conversation_preference", args),
    getConversationSummaries: (userId: string) => invoke("get_conversation_summaries", { userId }),
    markMessagesRead: (userId: string, ids: string[]) => invoke("mark_messages_read", { userId, ids }),
    getLocalMessagePage: (conversationId: string, limit: number, beforeTimestamp?: number, beforeId?: string, userId?: string) => invoke("get_local_message_page", { userId, conversationId, limit, beforeTimestamp, beforeId }),
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
    getStorageStats,
    clearExpiredMessages,
    clearDownloadedAttachments,
    prepareIdentity,
    loadIdentity,
    saveSession,
    clearKeypair,
  };
}

export function validateInvite(serverUrl: string, inviteCode: string): Promise<boolean> {
  return invoke("validate_invite", { serverUrl, inviteCode });
}
