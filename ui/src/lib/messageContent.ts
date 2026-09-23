export interface MessageReference { messageId: string; sender: string; text: string }
export interface MessageContent { text: string; reply?: MessageReference; forwarded?: MessageReference; attachment?: { id: string; name: string; size: number; mime: string; durationMs?: number } }
const prefix = "\u001eLiteSeal:1:";
function reference(value: unknown): value is MessageReference {
  if (!value || typeof value !== "object") return false;
  const item = value as Record<string, unknown>;
  return typeof item.messageId === "string" && item.messageId.length <= 128
    && typeof item.sender === "string" && item.sender.length <= 256
    && typeof item.text === "string" && item.text.length <= 500;
}
export function decodeContent(value: string): MessageContent {
  if (value.startsWith("\u001eLiteSeal:2:")) {
    try {
      const item = JSON.parse(value.slice("\u001eLiteSeal:2:".length));
      if (item.version === 1 && typeof item.id === "string" && typeof item.name === "string" && typeof item.size === "number" && typeof item.mime === "string") {
        const durationMs = Number.isInteger(item.duration_ms) && item.duration_ms > 0 && item.duration_ms <= 60_000 ? item.duration_ms : undefined;
        return { text: durationMs && item.mime === "audio/webm" ? `[语音] ${Math.ceil(durationMs / 1000)} 秒` : `[附件] ${item.name} (${item.size} B)`, attachment: { id: item.id, name: item.name, size: item.size, mime: item.mime, durationMs } };
      }
    } catch { /* Never show unknown attachment internals or key material. */ }
    return { text: "[不支持或损坏的附件消息]" };
  }
  if (value.startsWith(prefix)) {
    try {
      const content = JSON.parse(value.slice(prefix.length));
      if (typeof content.text === "string" && (!content.reply || reference(content.reply))
          && (!content.forwarded || reference(content.forwarded))) return content;
    } catch { /* Legacy text stays readable. */ }
  }
  return { text: value };
}
export function encodeContent(content: MessageContent): string {
  return prefix + JSON.stringify(content);
}
