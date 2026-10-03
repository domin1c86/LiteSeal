# T24 单人语音通话可运行验证

2026-10-02 UTC：完成独立共享信令协议、原生合成身份网关及 Chromium 的真实音频链路验证。没有接入正式应用呼叫入口或生产信令服务；这是清单要求的首个设计与可运行交付物，T24 整体验收保持未勾选。

2026-10-03 增量：`VoiceCallPlayback` 已接试验引擎，只播放经过原生认证并由 PeerConnection 交付的远端音频。每个流使用独立媒体元素，挂断/暂停清掉 `srcObject`；默认输出、设备选择失败、播放权限拒绝及明确重试均有可见状态。输出选择迟到只作用于已退役元素，不能切换下一通话的音频；不保存输出设备编号。

最新真实 Chromium 12/12 通过，`target/test-results/voice-call-trial-cgEduO/result.json`、`voice-playback-chromium-final.log`。包含前述 9 项及实际静音媒体播放/默认输出/缺失输出拒绝、迟到设备选择、播放拒绝与重试，0 renderer 错误。两端各收 78 包、2977 RTP payload 字节，仅为本轮合成短测。新增输出仍未接生产界面，未播放真实扬声器、测试真实设备切换或不同 NAT；不能作为这些系统场景通过证据。

## 当前源码与运行

`shared/src/voice_call.rs` 对 origin、账号、独立设备、当前双方目录、随机 256 bit 通话编号、方向序号、事件类型及三十秒期限签名，使用两端独立加密密钥加密 SDP。域为 `LiteSeal/audio-call-signal/v1`，每方向最多 128 个事件，单 SDP 最多 32 KiB、单 wire 最多 256 KiB。原生验当前目录/设备、完整签名、时间、解密后的头绑定与 audio-only SDP 后才允许业务处理；重放栅栏只接受连续序号，同摘要末次重复不触发第二事件，终态不能重连。

只允许一个音频媒体区、DTLS-SRTP、SHA-256 证书指纹、rtcp-mux 和 Opus；拒绝视频/数据通道、SDES、弱/缺失/冲突指纹。整个 SDP（含 DTLS 指纹和 ICE 凭据）在签名密文内，不能用未经身份绑定的明文 SDP 替换。Rust 中临时明文在 drop 时清零。浏览器必须持有自己的 WebRTC 临时媒体证书/状态和解密后的 SDP，它不持有 LiteSeal 身份私钥。

`ui/src/lib/voiceCallTrial.ts` 实现呼叫、响铃、明确接听、拒绝、挂断、输入设备选择、ICE 重连和公开质量统计。来电先走原生认证；响铃不占用输入设备，只有接听才采集。拒绝/挂断立即关闭 PC 和全部音轨，即使网络失败；接听采集失败向呼叫方签名终止。锁定、切身份、卸载、休眠必须调用 `pause()`，它退役异步结果并停止迟到采集。该生命周期仍需接正式应用事件，不能凭独立引擎声称生产已完成。

运行 `node scripts/test-voice-call-trial.mjs`。脚本先类型检查、构建 Rust `voice_call_trial` 示例，再启动自有临时 Electron 档案。示例内部生成两组合成身份，私钥只在 Rust 内存，不加载用户目录、文件或真实会话；固定白名单仅 begin/seal/open/retire。Chromium 使用假音频设备，静音，无真实麦克风、扬声器或外部 STUN/TURN。测试结束关闭自有窗口和原生子进程，报告不保存 IP、SDP、ICE 凭据或身份密钥。

## 信令接入设计与剩余验证

正式实现需复用当前正式会话和短时事件业务通道，服务端检查双向联系人/请求策略、拉黑、当前设备目录及限频；在运行中仅转发有界密文，不写聊天历史或离线呼叫队列，不产生消息 ACK/未读。原生 begin/open 还须核对当前身份租约、联系人独立钉住根和调用权限；设备撤销、退出会话、锁定或切身份应关闭在途呼叫，旧范围信令不能打开麦克风。孤立试验网关不能替代这些生产许可。

当前非 trickle ICE：收齐候选后把完整 SDP 一次签名加密发送，降低候选移植和顺序复杂度。双方各一条音轨，发送上限请求 24 kbps；真实语音、DTX、编解码和网络开销需另测。默认试验 `iceServers=[]`，仅同机 host 路径；不得以此声称不同 NAT 可用。正式 STUN/TURN 地址须经运营配置，TURN 使用短时凭据，不将持久服务器凭据放页面。隐私要求中继时应用 relay policy；普通 P2P 对端可见网络地址，服务端日志不能保存 SDP/地址。

不同 NAT、强制 relay、丢包/延迟、断网后重连、双 Windows 输入/输出切换及系统权限还未执行。已有 `restartIce()` 真实调用/新 ICE 凭据/恢复收包用例用于基础验证，不等于互联网断线恢复验收。静音媒体元素的播放与输出设备 API 已接可运行试验；生产按钮/信令、实际系统输入/输出切换及通话日志仍待接。

质量报告只含字节、包数、丢包、抖动、RTT、DTLS 状态、候选类别和 codec。TURN 成本按实测双端中继网络字节 × 运营方单位价格计算，须区分发送/接收计费和 GB/GiB，当前没有部署 TURN 或取得实际价格，不填估算费用。RTP payload 字节不含全部网络开销，不能直接当中继账单。

协议/API 依据：[W3C WebRTC](https://www.w3.org/TR/webrtc/) 的 DTLS、ICE restart 和媒体接口，[W3C WebRTC Statistics](https://www.w3.org/TR/webrtc-stats/) 的 RTP 字节/包、candidate-pair 和 transport 统计；LiteSeal 的身份绑定和资源约束是本项目设计。

输出 API 依据：[W3C Audio Output Devices API](https://www.w3.org/TR/audio-output/)；权限、设备可用性和 `setSinkId` 支持由运行环境决定，失败不自动切到其他设备。

## 实际证据

共享协议 3/3 通过（`target/test-results/voice-call-shared.log`）；shared all-target Clippy `-D warnings` 通过（`voice-call-clippy-final.log`）。最终 Chromium 9 项通过（`voice-call-trial-GlLizr/result.json`）：认证失败不采集、密文篡改/重复、输入选择、双向 DTLS-SRTP/Opus、ICE 重连、退役重放、呼叫方权限拒绝/无设备、接听方拒绝和锁定迟到采集。两端各收到 78 包、2915 RTP payload 字节，DTLS connected，候选为 host，短测丢包 0；这些是合成音频短测，不作为真实语音质量指标。

初轮 `voice-call-trial-LOhED3/result.json` 在 ICE restart 后界面状态停在 connecting，改为在应用 answer 后核对既有 PC connected 状态；最终检查新 ICE 凭据及恢复收包通过。最初 TypeScript 用断言签名窄化跨 await 可变状态，修正测试断言；Clippy 大枚举告警改用 Box，没有忽略告警或跳过失败用例。系统/网络/独立审查待执行。
