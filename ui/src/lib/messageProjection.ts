import { decodeContent } from "./messageContent";
import type { MessageOperation } from "../types";

export function projectMessage(original: string, operation?: MessageOperation) {
  const revoked = operation?.kind === "revoke";
  const content = decodeContent(revoked ? "" : operation?.kind === "edit" && operation.content !== null ? operation.content : original);
  return { revoked, content };
}
