import { latestOperations } from "../lib/messageOperations";
import { decodeContent } from "../lib/messageContent";
import { useEffect, useState } from "react";
import { useDesktop } from "./useDesktop";
import { dmConversationId } from "../lib/conversation";
import type { Contact } from "../types";

export interface ConversationPreview { text: string; timestamp: number; unread: number }

export function useConversationSummaries(userId: string, secretKey: number[], signingPublicKey: number[], contacts: Contact[]) {
  const [previews, setPreviews] = useState<Record<string, ConversationPreview>>({});
  const [error, setError] = useState<string | null>(null);
  const { getConversationSummaries, decryptMessage, verifyMessage, getMessageOperations } = useDesktop();
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const cache = new Map<string, string>();
    async function refresh() {
      try {
        const [summaries, operations] = await Promise.all([getConversationSummaries(userId), getMessageOperations()]);
        const latest = latestOperations(operations);
        const currentKeys = new Set(summaries.map(summary => `${summary.latest.id}:${summary.latest.local_state}`));
        for (const key of cache.keys()) if (!currentKeys.has(key)) cache.delete(key);
        const byId = new Map(summaries.map(summary => [summary.conversation_id, summary]));
        const entries = await Promise.all(contacts.map(async contact => {
          const summary = byId.get(dmConversationId(userId, contact.user_id));
          if (!summary) return [contact.user_id, { text: "暂无消息", timestamp: 0, unread: 0 }] as const;
          const message = summary.latest;
          const operation = latest.get(message.id);
          if (operation) return [contact.user_id, { text: operation.kind === "revoke" ? "此消息已撤回" : `[已编辑] ${decodeContent(operation.content ?? "").text.replace(/\s+/g, " ").slice(0, 120)}`, timestamp: message.timestamp, unread: summary.unread_count }] as const;
          const cacheKey = `${message.id}:${message.local_state}`;
          let text = cache.get(cacheKey);
          if (text === undefined) {
            text = "[加密消息，无法预览]";
            try {
              const key = message.sender_id === userId ? signingPublicKey : contact.ed25519_pk;
              if (message.local_state === "integrity_failed") text = "[消息完整性异常]";
              else if (key?.length && await verifyMessage(message.ciphertext, message.signature, key)) {
                const plaintext = await decryptMessage(message.ciphertext, contact.public_key, secretKey);
                text = `${message.sender_id === userId ? "我：" : ""}${decodeContent(new TextDecoder().decode(new Uint8Array(plaintext))).text.replace(/\s+/g, " ").slice(0, 120)}`;
              }
            } catch { /* Keep an explicit encrypted placeholder. */ }
            cache.set(cacheKey, text);
          }
          return [contact.user_id, { text, timestamp: message.timestamp, unread: summary.unread_count }] as const;
        }));
        if (active) { setPreviews(Object.fromEntries(entries)); setError(null); }
      } catch (failure) { if (active) setError(`会话列表更新失败：${String(failure)}`); }
      finally { if (active) timer = setTimeout(refresh, 2000); }
    }
    void refresh();
    return () => { active = false; clearTimeout(timer); };
  }, [userId, secretKey, signingPublicKey, contacts]);
  return { previews, error };
}
