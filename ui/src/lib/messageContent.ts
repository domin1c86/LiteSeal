export interface MessageReference { messageId: string; sender: string; text: string }
export interface MessageContent { text: string; reply?: MessageReference; forwarded?: MessageReference }
const prefix = "\u001eLiteSeal:1:";
function reference(value: unknown): value is MessageReference {
  if (!value || typeof value !== "object") return false;
  const item = value as Record<string, unknown>;
  return typeof item.messageId === "string" && item.messageId.length <= 128
    && typeof item.sender === "string" && item.sender.length <= 256
    && typeof item.text === "string" && item.text.length <= 500;
}
export function decodeContent(value: string): MessageContent {
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
