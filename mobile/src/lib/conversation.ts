// Mirrors ui/src/lib/conversation.ts and canonical_conversation_id in
// core/src/chat.rs: both sides derive the same id regardless of sender.
export function dmConversationId(a: string, b: string): string {
  const [lo, hi] = a <= b ? [a, b] : [b, a];
  return `dm:${lo}:${hi}`;
}
