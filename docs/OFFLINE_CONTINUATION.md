# 离线接续记录

更新时间：2026-10-03 02:27 UTC。用户外出后优先实现功能；耗时本地验收延后，恢复连接后按本文件执行。`docs/` 是权威需求，清单 T00–T26 未勾选不等于源码尚未实现。最新用户明确授权在断连前将任务改动提交/推送到一个新的专用开发分支，持续更新同一分支；这替换此前的禁止提交/推送限制。不得新增 CI、使用 GitHub 自动化测试、强推、合并、部署或创建 PR；不创建持久凭据、不修改安全设置、不读取真实身份或聊天数据库。

## 本轮安全交接

父任务已要求完成手头最小增量后停止本地写入，交由云端唯一接续；这不是取消项目。最后功能/测试源码提交 `3ffa22a1b768d34725691731ac37b152ac672c3f` 已推送并通过 `git ls-remote` 核对，Actions 为 0。本文档所在的最后推送提交为正式交接点，精确 SHA 由最终回报提供；云端须先核对该点再开始写入。本地不再启动新功能、测试或后台写入任务。

02:26 UTC 检查：任务源码已全部提交，没有未提交跟踪文件；未跟踪仅为原有 `deisgn-preview.html`、`mobile-deisgn-preview.html`、`src-tauri/`，不纳入当前 Electron 任务，未修改。Android 原调试签名文件保留本地且已忽略；`target/` 内构建缓存、隔离测试证据和未上传 ZIP 保留本地，不推送。没有本任务自启的 Cargo/Rust/桌面/中继/Gradle 执行进程，之前未知 Node 进程从未终止。

最新轻量验证：正式业务 Rust check（7.03 秒）、Electron/UI TypeScript（各退出 0）、正式合成测试源码 check（14.17 秒）和提交 diff whitespace check 通过。最近一批共享签名域测试及四项 HTTP/原生测试只写入/编译，未执行；不得据此更新接受框或宣称正式通话全通过。下一源代码任务仍为手机 v3/正式媒体/备份、正式阅后即焚、音频剩余边界；原清单已有实现不重写，历史持续授权仍单独等待产品回答。

## 工作区与写入所有权

首个远端快照已于 02:19 UTC 推送：[专用分支](https://github.com/domin1c86/LiteSeal/tree/codex/feature-continuation-20261003)，SHA `e77828a6675670f20b1bd5c67d616d9f4d21e0a5`，远端核对一致，Actions 运行数 0。保存 148 个任务文件变更，根目录用户预览/Tauri 工作保留；这是 public 仓库的源码快照，不包含真实用户数据、凭据、日志或构建产物。云端使用该分支的精确后续 SHA 接续，无需 Library。

最新音频业务入口：Rust 增量 check 7.03 秒通过；`npx tsc --noEmit -p electron/tsconfig.json` 和 `npx tsc --noEmit -p ui/tsconfig.json` 均退出 0，证据 `audio-business-entry-check.log`、`audio-electron-types.log`、`audio-ui-types.log`。未运行最新正式 HTTP/GUI/系统验收。后续轻量源码检查与耗时验收必须分别登记，不能沿用旧试验通过数字。

第二个远端增量 `6d984be48bb9a963fa14c3a860b607a6387dad61` 已核对，Actions 仍为 0：即使本轮没有新信令，活动呼叫也同步双方目录，目录变化时关闭；隐藏页面拒绝展示新来电并结束对应原预留。修正移动嵌套 `.gitignore` 中的调试签名例外，本地文件现已忽略。随后新增正式音频 4 项 HTTP/原生测试与共享签名域测试，`cargo check --locked -p liteseal-server --tests` 14.17 秒退出 0，仅证明测试源码可编译，尚未执行。

- 本地仓库 `D:\Coding\LiteSeal`，接续起点分支 `dev`，HEAD `a1de0814bbee71adbb0e3ba003b6c8d0e1e72645`。专用分支 `codex/feature-continuation-20261003` 基于此点，接续的是现有未提交工作，不能 reset/checkout 覆盖。
- 当前只有本接续任务写入。云端接续前必须由父任务确认本地写入已停止；文件包是指定时间快照，不能当作实时共享目录。回传时比较清单 SHA256，只应用对应任务实际修改，禁止整包覆盖后来变化。
- 2026-10-03 02:11 UTC：命令可执行；对阶段起点 138 个改动文件核对，除本轮已知编辑外无变化；没有本任务遗留 Cargo/Rust 编译进程。现有 Node 进程来源未确定，均不操作。
- 起点证据：`target/test-results/production-audio-start-checkpoint.json`。原有 `deisgn-preview.html`、`mobile-deisgn-preview.html`、`src-tauri/` 保留在本地，不属于当前 Electron 必需源码。

## 最新源码范围和验证边界

T23 操作协调、编辑/撤回入口、v3 便携备份/只读档案、明确选择历史文件/中继、后台暂停/恢复/取消与原签名收讫重试已接入。历史未来编辑/撤回的持续授权仍待产品回答：默认关闭、最长 7 天仅是可改假设，不能宣称用户确认或为真实数据启用。

T24 已新增正式源码：`shared/src/voice_call.rs` 的独立呼叫预留/取消签名；`server/src/direct_messages/audio.rs` 的内存短期信令路由；`core/src/trusted_devices/messages/audio_coordinator.rs` 的原生协调与一次性句柄；`desktop/src/commands/direct_audio.rs`、协议枚举与 Electron 私有轮询/业务 IPC；`ui/src/components/AudioCallPanel.tsx` 的发起、明确接听/拒绝、挂断、音频输入/输出和质量展示。当前只配置直接连接，无部署 STUN/TURN。中继要求当前 v3 资格、双方已接受联系、目标近期在线；每设备一通话，64 房间/1024 在线/1024 结束栅栏，每方向一个待确认密文，30 秒建立、10 秒在线租约、最长 1 小时。呼叫不进入聊天历史、离线队列、未读或通知。签名/解密在 Rust，票据不进 JS。最新 Rust 业务入口增量 check 通过（`audio-business-entry-check.log`，7.03 秒）；TypeScript、正式 HTTP/GUI 与安全场景验证尚未执行，不能称为生产验收通过。

T25 已完成 Android 原生身份/密钥边界、迁移重试、前后台互斥、固定私有目录、WorkManager/JNI 与双架构隔离 APK 源码/构建。手机 v3 业务选中身份、正式媒体、备份仍要实现；供应商推送和真实系统终止验收待设备。构建辅助脚本新增仅清理本轮创建的临时调试签名文件，不读文件内容、不动仓库原有签名文件。

T26 已完成独立签名到期协议与原生统一读取闸门试验；正式新消息设置/能力协商、服务端准入时钟、正式备份/历史格式、前台定时退场和通知撤销尚待接入。

最近已执行证据保持历史有效，但不覆盖之后的新源码：30 Node/Electron + 400 普通 Rust；专用 PostgreSQL 88；FFI 库 59（其中移动专用 11）；移动 Jest 9；音频 Chromium 12；历史 Chromium 44、原签名收讫 HTTP 3。Windows Release 3 分 31 秒、双 ABI APK/ELF/16 KiB 对齐与四个 JNI 导出验证通过。具体日志见 `P0_P1_ACCEPTANCE_RECORD.md`、`ANDROID_ALIGNMENT.md` 和 `target/test-results/`。Android 3 项 instrumentation 仅编译，未执行。新正式音频首编译四处错误已修正，修正后原生/中继 check 通过（`audio-native-second-check.log`）；更晚的 IPC/面板增量待复核。

## 待恢复连接后的测试

全部使用随机隔离身份、标记测试库和独立 keystore 路径；不得打开真实用户 DB/Keystore。失败时保留原任务/密文，固定错误文本，不把测试令牌或网络正文写入日志。

| 范围 | 命令/前提 | 预期结果与需记录场景 |
| --- | --- | --- |
| 最新静态检查 | `cargo fmt --all -- --check`；`cargo check --locked -p liteseal-desktop -p liteseal-server`；`npm run build:electron`；`npm run build --workspace liteseal-ui`；`git diff --check` | 编译/类型/格式通过；私有轮询不在 preload，档案窗口无法调用音频业务；记录实际退出码 |
| 音频共享协议 | `cargo test --locked -p liteseal-shared --test voice_call_test` | 独立签名域、错误参与者、变更目录/目标/时间/密文、重放与取消栅栏拒绝；有效音频能验证解密 |
| 正式音频中继/原生 | 专用 PostgreSQL 16；`pwsh -File scripts/test-audio-relay.ps1`，现有 `liteseal-postgres-1` 专用容器且可访问 | 已写 4 项合成源码：原编号重试/取消先到/错误签名票据、密文收讫与序号失败不改变状态、双方联系/离线/忙线/策略撤销、原生单次句柄/会话退场/无聊天任务。当前未执行。另补目录撤销、超时/容量/迟到租约、坏 ACK 故障场景；默认 ignored 不算通过 |
| 音频 Chromium/系统 | `node scripts/test-voice-call-trial.mjs`；再新增真实正式 transport harness；专用两设备、测试麦克风/扬声器与不同 NAT | 保持现有 12 场景；正式入口发起/明确接听才取麦克风；拒绝/取消/锁定/注销/切换/隐藏/休眠立即停止 track，迟到 capture/SDP 不复活；不同 NAT/TURN 成本另验，不以同机替代 |
| 全量短回归 | `npm test`；`pwsh -File scripts/test-ephemeral-database.ps1`；Docker 专用 `liteseal-postgres-1` 已存在且可访问 | 所有普通测试和专用库测试实际通过；默认忽略 PostgreSQL 不算已通过；临时 DB/角色必须 finally 删除 |
| 移动原生/渲染 | `cargo test --locked -p liteseal-core --features ffi --lib`；在 `mobile/` 运行 `npm test -- --runInBand`、`npx tsc --noEmit` | 保持 59/11 原生与 9 Jest 已有场景；新 v3/媒体增量另外增加覆盖，不沿用旧数字 |
| Android 构建 | 已安装 JDK/SDK/NDK；各 ABI 对应 libsodium 和原生 Rust archive；`pwsh -File scripts/build-android-trial.ps1 -Architecture x86_64 -WithInstrumentation`；arm64-v8a 同脚本 | 嵌入 JS 的 isolatedtrial APK；正确 ABI、16 KiB LOAD/zipalign、JNI 符号；临时新生成签名文件删除；不安装、不发布 |
| Android 系统 | 先具备完整且许可已确认的隔离系统镜像或专用合成数据设备；当前未具备，不下载/接受新许可、不使用真实手机 | 执行 3 instrumentation；Keystore 断电/高水位持久性、进程强杀/WorkManager/前后台切换、锁定后 UI/网络退场、后台任务超时；记录设备和实际结果 |
| Windows 发布与全表验收 | 静态/回归通过后 `cargo build --locked --release -p liteseal-desktop`；两专用 Windows 用户/设备；安装签名/更新渠道需用户另授权 | 新正式音频版本 Release；T00–T26 对应系统/双机/离线/72h 条件按真实执行填写；不自动发布或勾选未执行项目 |

## 下一写入顺序

1. 正式音频已补 4 项中继/原生合成测试源码与专用库 runner，另新增共享预留/取消签名域测试；继续检查取消、接收句柄时限、状态机和后台边界。轻量编译错误直接修复，耗时本地执行登记后续。
2. 接手机 v3 业务与媒体/备份：先原生正式身份/会话选择，不把私钥/原始 JWT 或任意 raw crypto 再暴露给 JS。
3. 将阅后即焚试验接正式新消息协议、能力/服务端时间准入、所有读取/导出/通知入口与格式；默认关闭，旧记录不能自动变成到期消息。
4. 按权威功能表找仍缺源码的项目继续实现；既有源码仅欠系统验收时记录待测，不重复重写。产品持续历史授权仅暂停对应权限扩展。

## 云端文件传递

Library 存在受支持的本地文件上传工具。已用 `scripts/pack-offline-source.ps1` 形成 505 文件、约 1.96 MB 的本地源码快照，包含未提交补丁与逐文件 SHA256；排除 `.git`、依赖缓存/构建产物、`.env`、所有 keystore/私钥/证书凭据、SQLite/用户数据、未知本地预览及过时 Tauri 工程。未上传 Library。最新用户授权改用 GitHub 专用分支作为云端接续来源，Library 上传暂缓；本地 ZIP 路径不表示已交付。

本地忽略目录有 `.github/workflows/windows-desktop.yml`（push/pull_request/workflow_dispatch），Actions 登记接口也返回这个名称；但读取远端 main/dev 的完整 Git tree 后确认两者当前均没有工作流文件，本地 HEAD 亦未跟踪工作流。专用源码分支不得加入工作流，每次提交仍带 `[skip ci] [skip actions]`，不创建 PR 或手动 dispatch，不修改仓库 Actions 设置。GitHub 官方说明 skip 标记适用于 push/pull_request，若后续有工作流须再检查 create、workflow_run 等额外触发器。首个快照提交包含此前全部任务相关源码和文档，未知预览/Tauri 工作保留本地不纳入。

仓库原有 Android 调试签名文件不读取、不上传：仅从新分支索引移除 `mobile/android/app/debug.keystore`，本地文件保留，并加入忽略规则。恢复 Android 构建需继续使用已有本地开发签名；云端源码不含此文件，也不自动生成持久签名凭据。既有分支/历史不重写。
