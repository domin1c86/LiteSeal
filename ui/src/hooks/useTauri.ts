import { invoke } from "@tauri-apps/api/core";
import { useMemo } from "react";
import type {
  AuthOutcome,
  BootstrapState,
  Contact,
  DisplayMessage,
  PollEventsResult,
  SendMessageResult,
  SessionView,
  StorageStats,
  UserSearchResult,
} from "../types";

export function useTauri() {
  return useMemo(() => ({
    bootstrap: () => invoke<BootstrapState>("bootstrap"),
    register: (username: string, password: string, inviteCode: string, serverUrl: string) =>
      invoke<SessionView>("register", { username, password, inviteCode, serverUrl }),
    login: (username: string, password: string, serverUrl: string, replaceDevice: boolean) =>
      invoke<AuthOutcome>("login", { username, password, serverUrl, replaceDevice }),
    logout: () => invoke<void>("logout"),
    logoutAll: () => invoke<void>("logout_all"),
    sendText: (recipientUserId: string, plaintext: string) =>
      invoke<SendMessageResult>("send_text", { recipientUserId, plaintext }),
    pollEvents: () => invoke<PollEventsResult>("poll_events"),
    getMessages: (recipientUserId: string, limit: number, offset: number) =>
      invoke<DisplayMessage[]>("get_messages", { recipientUserId, limit, offset }),
    addContact: (userId: string, username: string, publicKey: number[], ed25519Pk?: number[]) =>
      invoke<void>("add_contact", { userId, username, publicKey, ed25519Pk }),
    getContacts: () => invoke<Contact[]>("get_contacts"),
    removeContact: (userId: string) => invoke<void>("remove_contact", { userId }),
    setContactTrust: (userId: string, trustState: "unverified" | "verified" | "key_changed") =>
      invoke<void>("set_contact_trust", { userId, trustState }),
    searchUsers: (query: string) => invoke<UserSearchResult[]>("search_users", { query }),
    getStorageStats: () => invoke<StorageStats>("get_storage_stats"),
    clearExpiredMessages: () => invoke<number>("clear_expired_messages"),
    clearDownloadedAttachments: () => invoke<number>("clear_downloaded_attachments"),
  }), []);
}
