import type { MessageOperation } from "../types";
export function latestOperations(operations: MessageOperation[]): Map<string, MessageOperation> {
  const latest = new Map<string, MessageOperation>();
  for (const operation of operations) {
    if (operation.status !== "accepted") continue;
    const previous = latest.get(operation.target_id);
    if (!previous || (previous.kind !== "revoke" && (operation.kind === "revoke" || operation.revision > previous.revision))) latest.set(operation.target_id, operation);
  }
  return latest;
}
