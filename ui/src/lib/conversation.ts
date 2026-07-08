// Must stay in sync with canonical_conversation_id in src-tauri/src/commands/chat.rs.
export function dmConversationId(a: string, b: string): string {
  return a <= b ? `dm:${a}:${b}` : `dm:${b}:${a}`;
}
