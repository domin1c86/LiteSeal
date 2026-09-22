/** Transport acknowledgement never means the recipient has read the message. */
export function deliveryStatusLabel(state: string): string {
  return ({
    pending: "待发送或等待服务端确认",
    queued: "服务端已保存，等待设备确认",
    stored_offline: "服务端已保存，等待离线设备接收",
    offline: "对方离线，尚未确认设备送达",
    received: "目标设备已保存（非已读）",
    partially_received: "部分目标设备已保存（非已读）",
    delivered: "旧版投递确认（非已读）",
    failed: "投递失败，可重试原消息",
    integrity_failed: "完整性校验异常",
  } as Record<string, string>)[state] ?? "投递状态未知";
}
