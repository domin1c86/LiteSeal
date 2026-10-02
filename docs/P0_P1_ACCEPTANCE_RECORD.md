# P0/P1 验收记录（待执行）

## 2026-10-03 v3 媒体存储与按会话整理短测

基线 `cc79a66` 加本轮工作树；合成身份、隔离原生保护、临时 SQLite/Chromium 目录与已有标记专用 PostgreSQL，不操作真实资料、不启动新长期、不推送。服务端生产协议、迁移和 T22 v1/v2 格式不变。

- `target/test-results/direct-media-storage-core-2026-10-03.txt`：16 项媒体存储短测通过（5.07 秒），新增两项批量整理场景。覆盖原未知发布批次不变、按会话不跨范围、当前范围孤立密文收集/其他身份保留、已接受发送任务整理后仍可清理、消息历史保留/重复清理、错密钥/坏元数据在删除前拒绝。扩展现有部分下载与隐藏取消用例，正在下载被保护，隐藏已取消下载可整理且历史不恢复。统计不返回名称、密钥或路径。
- `direct-media-storage-ipc-2026-10-03.txt`：真实 Rust/SQLite/隔离原生的桌面范围用例通过（3.06 秒）。新增错范围/非法账号拒绝、待发不清理、统计真实非零数据库分配/文件占用、可复用空间不超过已分配、恢复后旧 scope 拒绝和已取消缓存批量清理断言；原密钥文件不变。最终三项磁盘观察断言在完整工程之后补充，该用例重新执行通过。
- `direct-media-storage-ui-2026-10-03.txt` / `direct-ui-HfzQWP/result.json`：真实 Electron Chromium，1280×900/390×844 与浅深色四组合，各 24 项通过、无 renderer 错误/横向溢出（24 秒）。新增离线统计、逻辑/文件占用区分、取消确认不执行、选择会话与保护计数、暂停拒绝迟到结果。保存四张独立 storage 截图，已检查浅色窄屏和深色宽屏；小文件使用 B/KiB，避免被 MiB 舍入成零。业务 API 为夹具，不算实际系统窗口/双机验收。
- 完整 `npm test` 为 23 项 Node/351 项普通 Rust 通过、0 失败，78 项 PostgreSQL 默认 ignored，报告 `direct-media-storage-delivery-2026-10-03.txt`；新增 PostgreSQL 整理断言另由真实库回归执行。接入初轮被 TypeScript TS2367 拒绝（替换误插入到已缩窄的通知分支），移除该插入后复验通过，未放宽权限规则。
- 最终格式、全 workspace/all-targets Clippy（-D warnings）、核心 FFI 检查通过，报告 `direct-media-storage-static-final-2026-10-03.txt`；生产构建通过，release 49.79 秒，报告 `direct-media-storage-build-2026-10-03.txt`，既有链接警告保留。
- 群 UI 宽窄两组通过，`direct-media-storage-group-ui-2026-10-03.txt` / `group-ui-vU0vET`；风格回归通过，72 张既有浅深色/宽窄截图范围、无 renderer 错误，`direct-media-storage-style-2026-10-03.txt` / `ui-style-O58VTd`。

- `target/test-results/direct-media-storage-postgres-2026-10-03.json`：专用 PostgreSQL 16.14 全部 **78 通过/0 失败/0 跳过**，脱敏失败诊断为空。新增实际协调器往返断言覆盖一块下载的真实逻辑统计/批量保护、离线整理已认证缓存、远端过期后清理再下载 404，以及已接受发送结果整理后批量清理原缓存。沿用只读观察认证 IP 窗口，计数 36/36/38 时分别等待 18/25/27 秒到期（合计 70 秒），不删除计数或重试失败用例；运行脚本 `run-media-storage-paced.mjs` / `run-local-media-storage.ps1` 保存在测试目录。

- `target/test-results/direct-media-storage-group-integration-2026-10-03.txt`：真实 PostgreSQL/服务端与同机三个隔离 Rust 桌面进程的 11 阶段全部通过，包含群文字/协作、群文件/合成语音/活动，以及 T22 v2 缓存/投票/草稿/隐藏历史；是既有功能回归，不作为新 v3 存储界面双机或系统验收。

逻辑密文字节与档案数据库/WAL/SHM 文件观察值分别记录，未执行物理压缩；清理成功不保证文件立即缩小。没有新增实际磁盘满、权限拒绝、进程强杀、系统锁屏/休眠、双 Windows 或独立审查证据。传输调度、已准备对象过期恢复、原设备编辑/撤回、v3 备份与选定历史授权保持后续实施。

## 2026-10-03 Windows v3 媒体 IPC、文件与录音组件短测

基线 `e5ead4f` 加本轮工作树，全部使用合成身份、临时文件/数据库、隔离原生命名空间和 Chromium 用户目录。文件与录音数据不经 stdio，密钥不进入页面；未运行新长期，未操作真实用户资料或推送。

- `target/test-results/direct-media-desktop-ipc-2026-10-03.txt`：新增真实 Rust/SQLite/隔离原生范围测试通过（2.33 秒）。错范围在读取/输出前拒绝，暂存认证写入与摘要一致，目标存在不覆盖、取消后不输出、暂停拒绝、恢复必须使用新范围、秘密/额外参数拒绝和原密钥文件不变通过。首轮夹具在恢复后沿旧范围清理失败，改为获取实际新范围；生产范围保护未放宽。
- 主进程媒体独立 4 项 Node 用例通过：随机预览 URL 不泄露路径，Range/坏范围、临时文件篡改、隐藏/代次失效退役、既有导出目标保留、切范围不提交、录音主进程落临时文件/Rust IPC 不含字节且暂存后删除。最终 `direct-media-desktop-node-focused-2026-10-03.txt` 共 11 项媒体/preload/真实 bridge 子集通过，增加 File 路径转换、Blob ArrayBuffer 转换及私有路径命令不可访问断言。
- `target/test-results/direct-media-desktop-ui-2026-10-03.txt` / `direct-ui-3CNyeT/result.json`：真实 Electron Chromium，1280×900 与 390×844、浅深色四组合，各 22 项通过、无 renderer 错误/横向溢出（21 秒）。新增选择/暂存/发送前预览与关闭、上传取消后迟到结果不能准备消息、历史媒体下载/预览及暂停清除、模拟麦克风拒绝/60 秒停止/目标范围/设备释放。网络和麦克风均为夹具，不是双 Windows、实际系统权限或播放验收。截图隔离到新加载页面并等待媒体任务/卡片出现后采集；已核对窄屏换行与宽屏媒体区域，不以测试后的暂停截图冒充产品布局。
- 完整 `npm test` 为 23 项 Node/349 项普通 Rust 通过，0 失败，78 项 PostgreSQL 默认 ignored，报告 `direct-media-desktop-delivery-2026-10-03.txt`。后续只修改额外 preload/UI 测试断言及截图夹具，最新 11 项 Node 子集和四组合 UI 另复验通过。
- `direct-media-desktop-core-2026-10-03.txt`：8 项媒体存储短测通过（2.69 秒），新增断言发送前认证读取与原字节一致，取消/准备后不能借暂存读取。格式、全 workspace/all-targets Clippy（-D warnings）、核心 FFI 编译通过，报告 `direct-media-desktop-static-2026-10-03.txt`；最终生产构建通过，release 49.18 秒，报告 `direct-media-desktop-build-2026-10-03.txt`，既有链接警告保留。

主进程夹具首轮假设只注册一个协议导致启动断言失败，已允许应用与媒体两个固定协议并复跑通过；UI 夹具原 CSP 不允许模拟 data 图片，已仅在无网络测试页面允许 data/blob 并复跑。不能将这两项夹具调整称为生产安全问题修复。真实库与群回归结果另记如下。

群 UI 宽窄两组通过，报告 `direct-media-desktop-groups-ui-2026-10-03.txt`，包含共享录音组件的模拟权限拒绝/无设备/60 秒、释放和群目标回归。风格回归通过、无 renderer 错误，报告 `direct-media-desktop-style-2026-10-03.txt` / `ui-style-PxBBIs`，保持原 72 张浅深色/宽窄截图范围。

专用库首轮 `direct-media-desktop-postgres-first-failure-2026-10-03.json` 为 77 通过/1 失败/0 跳过。失败是既有四设备协调器用例，保留脱敏诊断定位在 `direct_message_tests.rs:107` 的正式会话 begin，不是编译/链接/权限错误；未记录原始错误值，原因不能认定。`direct-media-desktop-diagnostic-2026-10-03.json` 三次定向均通过、未复现；未修改生产挑战或权限规则。独立顺序全库复跑结果另记。

第二轮 `direct-media-desktop-postgres-second-failure-2026-10-03.json` 为 76 通过/2 失败/0 跳过；四设备 begin 再失败，另一个 stale-wire/cancel 用例在加入接口期望 200、实际 429。认证按 IP 的生产窗口为 60 秒/60 次，多个独立进程使用同一回环 IP 和专用库。仅凭 429 不能追认首轮 begin 的具体原因；追加短测使用只读观察专用库该 IP 的窗口，在计数超过 35 且窗口未到期时等待到期再启动下一用例，不删除计数、不重试失败用例、不放宽生产限流，结果另记。

最终 `target/test-results/direct-media-desktop-postgres-paced-2026-10-03.json` 为 **78 通过/0 失败/0 跳过**，脱敏失败诊断为空。实际三次观察计数为 36、36、38，分别等待 18、26、28 秒（合计 72 秒）；全部用例各执行一次，包含七项 v3 媒体真实库往返及原设备、会话、群和额度回归。运行脚本为 `target/test-results/run-desktop-media-paced.mjs` / `run-local-desktop-media-paced.ps1`，只读检查已由既有入口验证标记的专用库。生产权限/限流及服务端代码未更改；这一轮通过支持跨用例共享窗口干扰的判断，但不能证明两次未保存完整错误值的 begin 失败原因。

`target/test-results/direct-media-desktop-group-integration-2026-10-03.txt` / `group-integration.json`：真实专用 PostgreSQL 16.14、服务端与同机三个隔离 Rust 桌面进程的 11 阶段通过，包含原群文字/协作、群附件/合成语音/活动、T22 v2 离线缓存/投票/草稿/隐藏历史；不能代替新 v3 媒体桌面双机与实际录音验收。

真实麦克风/音频播放/文件对话框、通知/锁屏/休眠、磁盘满/权限拒绝/强杀后的预览临时文件清理、双 Windows 和独立审查继续待验收。预览句柄当前只保存在主进程，临时媒体正文由 main 退役/关闭清理；没有运行强杀恢复场景，不能声称该边界已验证。

## 2026-10-03 v3 下载续传、认证与只读短测

基线 `eea8431` 加本轮工作树。测试跨 10-02/10-03 UTC+8 执行，保留开始时的报告文件名；所有身份、文件、目录与原生保护命名空间均为合成，数据库为已有标记专用 PostgreSQL 16.14。只短测，没有新长期、业务库/真实用户数据操作或推送。

- `target/test-results/direct-media-download-store-2026-10-02.txt`：最终媒体存储 14 项通过（4.82 秒），新增 6 项下载用例。中文/emoji 两块续传重开、部分下载拒绝读取、全量认证及每次重新认证、坏最终对象进入 Failed/显式原描述重试、错误长度不推进、不可用仍保留签名历史、隐藏/取消拒绝迟到块、原生提交间隙恢复到原认证缓存、共享 256 MiB 额度拒绝且进度不变通过。既有 8 项上传/缓存/备份防遗漏同时通过。
- `target/test-results/direct-media-download-coordinator-2026-10-02.txt`：1 项 HTTP 故障短测通过（1.92 秒），覆盖四种等待期间变化：取消、隐藏、会话轮换、锁定/解锁。迟到回复均被拒绝、不落入可读缓存；允许重试时沿原编号完成，签出后认证读取，缓存完成再隐藏后信息/任务/正文拒绝。使用 HTTP 夹具，不算系统锁屏验收。
- `target/test-results/direct-media-download-postgres-2026-10-02.json`：7 项媒体真实库专项通过。扩展实际协调器上传/收件场景为接收方下载一块后关闭重开、继续完整认证、签出只读、远端过期后已缓存副本仍可读、清理后重新下载 404/Unavailable、隐藏不可读，以及源端原缓存只读。新增 Voice 真实 HTTP/事务往返，验证 60,001 ms 声明拒绝、60,000 ms 声明保留、audio/webm 描述和认证字节一致。音频为短 WebM/Opus 格式标记夹具，不能称真实 60 秒录音、编解码或播放通过；服务器仍只限制密文大小。
- 完整 `npm test` 为 19 项 Node/348 项普通 Rust 通过，0 失败，78 项 PostgreSQL 默认 ignored，报告 `direct-media-download-delivery-2026-10-02.txt`。收尾补齐隐藏后任务/暂存入口的检查及断言，最终 14 项存储/1 项 HTTP 专项复验通过；真实全库和最终静态/构建证据另记，未把先前全工程报告当作收尾断言之后又完整执行。
- 格式、全 workspace/all-targets Clippy（-D warnings）、核心 FFI 编译通过，报告 `direct-media-download-static-2026-10-02.txt`。最终生产构建通过，release 55.39 秒，报告 `direct-media-download-build-2026-10-03.txt`；保留既有 LNK4098/LNK4099。
- 全库首轮 `direct-media-download-postgres-all-2026-10-03.json` 为 73 通过/5 失败/0 跳过，报告保留。失败为既有目录冲突、禁用/会话隔离、四设备 ACK、非法受众及完整媒体上传用例；5 项均在 `direct-media-download-diagnostic-2026-10-03.json` 定向复跑通过、未复现。没有保存首轮原始失败输出，原因仍未确定，不能据此认定环境问题或生产逻辑已修复。随后在构建结束后独立顺序全库复跑，并加入不含凭据的失败分类诊断，最终结果另记。
- 独立顺序全库最终报告 `direct-media-download-postgres-final-2026-10-03.json` 为 **78 通过/0 失败/0 跳过**，失败分类诊断为空；包含最终可见性检查、全部 7 项媒体场景及原有设备、会话、单聊、群与额度用例。该次全库没有并行 Rust 构建，但首轮未保留原始错误，仍不足以证明其失败由构建或 Windows 文件占用造成；没有为未确定原因放宽生产检查。
- `target/test-results/direct-media-download-group-integration-2026-10-03.txt`：真实专用 PostgreSQL/服务端/同机三个隔离 Rust 桌面进程 11 阶段通过，包含旧文字/群协作、群文件/合成语音/活动和 T22 v2 缓存/投票/草稿/隐藏历史。服务端生产协议/迁移、界面与备份格式未改；没有重复模拟 UI 来替代系统或双机验收。

新增业务目前在共享 Rust 核心，字节不经页面或 stdio，未接桌面预览/播放/另存为、录音权限、存储界面或 v3 T22。未执行真实磁盘满/权限拒绝/强杀、真实系统生命周期、双 Windows 或独立审查，不将短测勾为这些场景通过。

## 2026-10-02 v3 媒体持久任务与收件落库短测

基线 `85671b9` 加本轮工作树；全部使用合成账号、文件、原生保护命名空间、临时 SQLite 和标记专用 PostgreSQL。没有新长期测试、推送或真实用户数据操作。

- `target/test-results/direct-media-tasks-store-2026-10-02.txt`：最终 8 项持久化/认证短测全部通过（2.49 秒）。包含中文/emoji 超过一个分块的暂存与重开、同编号拒绝换内容、已准备批次确定性重绑定、SQLite 不含明文名称/文件密钥、取消与迟到进度拒绝、未知发布不能清理、编号清理标记、损坏块/错身份拒绝、隐藏后重放不恢复、非法描述持久拒绝 ACK 且后续消息可继续、原生提交故障及前一 SQLite 快照恢复后原任务/密文一致、旧群/v3 共享 256 MiB 边界、仅有暂存任务时旧备份拒绝。恶意缓存触发器不能删除已覆盖的原任务。
- `target/test-results/direct-media-tasks-coordinator-2026-10-02.txt`：5 项协调器测试通过，新增一项覆盖三个媒体等待场景：取消、换会话及锁定/解锁拒绝迟到上传回复；原进度不推进，允许继续时使用同一任务，准备/发布与历史按原编号保存。HTTP 夹具只注入网络等待，不能替代真实系统锁屏。
- `target/test-results/direct-media-tasks-postgres-2026-10-02.json`：最终 6 项媒体真实库测试通过。新增共享协调器在实际 PostgreSQL/HTTP 上传一块后关闭重开，继续上传、原编号准备/发布、重复查询接受结果、收件验证并持久 ACK，ACK 后待收为空；隐藏后历史不可见，退出会话后源历史仍可读，清理返回逻辑字节数。此前五项原授权/下载/过期/共享配额测试同批通过。
- `target/test-results/direct-media-tasks-delivery-2026-10-02.txt`：完整 `npm test` 为 19 项 Node/341 项普通 Rust 通过，0 失败；77 项 PostgreSQL 默认 ignored，另按真实库报告计。最终格式、全 workspace/all-targets Clippy（-D warnings）和核心 FFI 编译通过，报告 `direct-media-tasks-static-2026-10-02.txt`。最终生产构建通过，release 52.57 秒，报告 `direct-media-tasks-build-2026-10-02.txt`；既有链接警告保留。
- 完整真实库首轮为 75 通过/2 失败/0 跳过，报告 `direct-media-tasks-postgres-first-failure-2026-10-02.json` 保留。两个既有服务器用例为 `directory_conflict_revoke_rejoin_and_old_result_do_not_reencrypt`、`disabled_missing_session_and_join_credential_never_activate_chat`；定向均通过、未复现，见 `direct-media-tasks-diagnostic-2026-10-02.json`。首轮没有保存原始错误，因此不能认定已定位环境原因或修复回归。生产权限/服务器逻辑未为此更改，独立顺序全库复跑结果另追加。
- 最终顺序全库复跑 `direct-media-tasks-postgres-all-2026-10-02.json` 为 **77 通过/0 失败/0 跳过**，包含最终缓存结构加固后的全部六项媒体场景；新旧设备控制/正式会话、目录冲突、原结果、独立 ACK、群附件/活动和并发额度全部实际执行。最终通过不抹去首轮波动，原因仍未确定。
- `target/test-results/direct-media-tasks-group-integration-2026-10-02.txt`：真实 PostgreSQL/服务端/同机三个隔离 Rust 桌面进程的 11 阶段通过，覆盖旧文字/群协作、文件/合成语音/活动及 T22 v2 离线缓存/投票/草稿/隐藏。未改界面，未把这一轮当成原生系统或双 Windows 通过。
- 收尾检查补齐“已接受发送任务被整理后仍可清理媒体缓存”：通过保留的认证历史判断接受状态，既不重建发送任务，也不清除未知发布。最后这一局部调整在上述完整工程/77 项全库/群回归之后进行；最终 8 项存储、5 项协调器（3.05 秒）、6 项真实媒体库专项和格式/Clippy/FFI/生产构建重新验证通过，相关报告已更新。完整回归的执行顺序和首轮失败均保留，不将旧报告误记成最后调整之后重新全跑。

这一批未交付按需下载/播放/导出、桌面文件/录音 IPC、存储界面或 v3 新备份；传输字节不经页面或 stdio。真实磁盘满/进程强杀、麦克风、系统锁屏/休眠、双 Windows 和独立审查没有新增证据。缓存清理记录逻辑密文字节，SQLite 实际占用由既有 DB/WAL 统计另查，不把删除缓存声称为立即释放同量磁盘。

## 2026-10-02 共享媒体 HTTP 客户端短测与真实库联调

基线 `7041957` 加本轮工作树；全部账号、文件、目录与密钥均为合成测试数据。Docker 中仅使用已有标记专用 PostgreSQL 16.14，不读取或修改业务库，凭据仅在子进程环境，不保存到源码或报告。

- `target/test-results/direct-media-client-http-focused-2026-10-02.txt`：12 项 HTTP 测试通过，包含新增 6 项媒体场景。创建结果错编号拒绝、上传严格 204/长度、1 MiB 完整分块和尾块、截断/长度过大/chunked 超额、非法路由/编号/分块/令牌请求前拒绝、损坏签名/错 origin 本地拒绝、错收据拒绝、发布和上传响应丢失后原签名/编号/密文完全相同、307 不转发凭据通过。本机 HTTP 夹具是故障短测，不是远端系统验收。
- `target/test-results/direct-media-client-http-postgres-2026-10-02.json`：5 项媒体真实库测试全部通过，0 失败/跳过，包括新增共享 Rust DirectApi 的完整分块上传、部分上传发布 409/原结果 Unknown、原批次重试、四原设备下载、中文/emoji 摘要/MAC 解密往返，以及对象过期后 404/原接受结果保持。另四项覆盖原授权隔离、共享配额并发、取消、损坏和清理；没有把服务器响应模拟成数据库结果。
- 最终完整 `npm test` 为 19 项 Node/332 项普通 Rust 通过，0 失败；76 项 PostgreSQL 默认 ignored 不计通过，真实库证据另见本节五项专项及此前 75 项完整回归。报告 `direct-media-client-http-delivery-2026-10-02.txt`，此前已通过的中间复跑另存 `direct-media-client-http-delivery-initial-2026-10-02.txt`。
- 格式、全 workspace/all-targets Clippy（-D warnings）及核心 FFI 编译通过，报告 `direct-media-client-http-checks-2026-10-02.txt`。`npm run build` 的 UI/Electron/Rust release 构建通过，release 52.05 秒，报告 `direct-media-client-http-build-2026-10-02.txt`；保留既有 LNK4098/LNK4099 警告。本批未改变 UI，未重复执行模拟界面或原生系统检查。

只交付共享客户端受限传输接口，尚未接协调器持久任务/缓存、桌面 IPC/录音或 v3 离线备份。普通收件协调器仍保留未支持媒体不 ACK；未执行真实双 Windows、系统或独立审查，本批不启动新长期。此前完整 75 项库、三客户端与六轮群短测证据仍有效于其各自版本，不据此勾选新增媒体整体验收。

## 2026-10-02 Docker 恢复后的十账号多群短负载

`node scripts/test-group-soak.mjs --smoke` 实际通过：十个隔离账号、十个群，每个账号参与全部十群；六轮、279 秒、九次故障注入，六轮待发积压均为 0。覆盖文字/文件/合成 WebM/Opus/活动与实名报名、临时断网、客户端重启、原消息/扩展响应丢失重试、令牌续期及移除/重加入阶段隔离；重加入后旧附件远端下载明确拒绝。报告 `target/test-results/group-soak-2026-10-02T14-39-49-893Z.json`，入口输出 `restored-group-smoke-2026-10-02.txt`。

六个样本的服务端与十客户端（每轮 11 个进程）总工作集为 291.91、295.74、298.05、300.05、302.03、304.89 MiB。短窗口有增长，不足以证明长期稳定或内存泄漏；没有运行新的 24 小时测试。原脚本 `catchup_ms` 从整个周期起点计时，含发送、媒体/活动、同步和统计，实际 44.899–46.263 秒，应解释为整轮时间而非纯补收耗时。后续若要分析补收瓶颈需单独计时，不能借该字段声称补收延迟已达标。

本轮只启用标记专用库、随机临时客户端目录和进程凭据；原有后台/用户数据保留，短测结束按既有入口清理自己的子进程/临时目录，项目 PostgreSQL 保持运行。对应源码基线为 `5dcf5ec` 加已提交的媒体工作树（现为 `f7347ca`）；不证明真实双 Windows、麦克风/锁屏/休眠或独立协议审查。完整库 75 项、三客户端及媒体 4 项实际证据见下方记录。

## 2026-10-02 v3 媒体基础工程与真实 PostgreSQL 短测

基线 `8f8c856` 加本轮媒体工作树；所有文件、账号、密钥和目录均为合成测试数据，没有新长期或真实双机测试。

Docker 恢复并修正加入档案夹具后，`restored-postgres-all-2026-10-02.json` 全部 **75 项真实 PostgreSQL 用例通过，0 失败/跳过**；首次 74/1 失败报告另存保留，不冒充成功。`restored-group-integration-2026-10-02.txt` 同机真实 PostgreSQL/服务端/三个 Rust 桌面通过，包含群附件失响应/重启下载、合成 WebM/Opus 解码/加密往返、活动改选/关闭/取消及重新加入隔离，还有 T22 v2 离线活动/缓存/投票/草稿/隐藏历史。此处补上原因 Docker/配置而未执行的库与联调证据；真实双 Windows、系统交互和独立审查仍不关闭。

- `direct-media-foundation-delivery-2026-10-02.txt`：19 Electron/Node、326 普通 Rust 通过，0 失败；75 专用 PostgreSQL 默认 ignored，不计库通过。最终格式、全 workspace/all-targets Clippy（-D warnings）、核心 FFI 通过；完整生产构建通过，release 51.41 秒，实际服务端二进制构建通过，既有链接警告保留。报告为 `direct-media-foundation-static-final-2026-10-02.txt`、`direct-media-foundation-build-2026-10-02.txt` 和 `direct-media-foundation-server-build-2026-10-02.txt`。
- `direct-media-foundation-focused-2026-10-02.txt`：5 项共享媒体测试通过，数据库用例编译通过。原文字四字段批次和收据摘要保持；加密描述往返、原批次确定性重绑定、签名字段篡改、错编号/类型/密钥长度、截断、重排、MAC、MIME、20 MiB/空文件/分块边界和 60 秒声明限制通过。短音频格式夹具不表示真实录音或播放验收，服务端不检验加密音频实际时长。
- Docker 恢复后使用原标记测试库 `liteseal_test_t21_4f313d6c7233`，PostgreSQL 16.14，迁移 22 实际通过；凭据仅在测试子进程环境，报告无密码/令牌/私钥。`direct-media-postgres-2026-10-02.json` 新增 4 项全部实际通过：完整上传/分块幂等、损坏或不完整分块拒绝发布、原四设备下载及解密、原批次重试、过期后的接受结果、撤销/新授权隔离、当前拉黑策略、取消不投递、孤立清理、2000 对象及 512 MiB 边界，旧附件/v3 并发最后配额只接受一个且不死锁。未发布或非法数据未进入接收队列。
- 旧引擎不可用报告 `direct-media-foundation-database-2026-10-02.txt` / `direct-media-foundation-integration-2026-10-02.txt` 的 not_executed 保留为历史证据，不再描述当前状态。只结束本轮无响应的只读 Docker 状态探针 CLI，未停止引擎或原后台；用户启动 Docker 后只启动本项目 PostgreSQL。完整库首轮 74/1 夹具失败见下方记录，失败报告为 `restored-postgres-first-failure-2026-10-02.json`。
- 本批只改 shared/server，未开放客户端媒体 IPC、传输/缓存/预览/录音，未把模拟 UI 当作媒体可用性证明。协调器仍保留未支持媒体不 ACK，T22 白名单、媒体桌面接入、系统、真实双 Windows 与独立审查继续待完成/验收。

## 2026-10-02 Docker 恢复后的加入档案夹具修正

用户启动 Docker 后，本轮仅启动本项目现有 `liteseal-postgres-1`，通过系统目录确认 `liteseal_test_t21_4f313d6c7233` 专用标记，再由进程环境恢复连接配置。PostgreSQL 16.14；未连接业务库，未写凭据到仓库或报告，也未重启其他容器或原有后台测试。

完整专用库首轮 `target/test-results/restored-postgres-first-failure-2026-10-02.json` 为 74 通过/1 失败/0 跳过，失败为真实加入 Windows 档案与 DPAPI 会话用例。定向复现定位到 `prepare_grant`：测试仅签署本地持钥证明，没有执行提交原证明的下一步；远端仍非 Proved，因此严格权限检查拒绝。补齐提交步骤并断言本地 AwaitingAuthorization、远端 Proved 后，原用例实际通过，包含服务端设备编号、会话重开/清除、密钥文件不变和不泄露令牌。生产核心及服务端授权规则没有放宽。修正后完整 75 项数据库及三客户端回归通过，首轮失败报告保留。

## 2026-10-02 v3 会话、已读与通知短测

基线 `486190b` 与本轮工作树；合成身份、随机临时数据库、隔离原生保护目标，未访问真实用户资料，未启动新长期或推送。

- `direct-conversation-delivery-2026-10-02.txt`：完整 `npm test` 19 Electron/Node、321 普通 Rust 通过，0 失败；71 PostgreSQL ignored 不计库验收。共享 direct store 共 15 项，新增账号分页/读边界、写入故障及仅有设置的备份拒绝场景。格式、全 workspace/all-targets Clippy（-D warnings）及 FFI 通过，报告 `direct-conversation-static-2026-10-02.txt`；完整生产构建通过，release 47.20 秒，报告 `direct-conversation-build-2026-10-02.txt`，既有链接警告保留。
- 共享核心：三个账号交错历史在过滤后分页，6+2 条没有漏项/重复；已读只推进显示的原编号，查询后新到达的一条仍未读，旧边界重试不后退。错误账号/隐藏编号拒绝；隐藏后重放不恢复未读。静音重开保持，过时修订拒绝；同一数据库的另一设备独立读取原消息且不继承已读/静音。本账号副本和拒绝正文不领取来信通知。领取后重试/重开不重复；模拟安全存储写入失败时未读、静音和领取一起保持原值，恢复后可领取一次。
- 排序篡改：保持签名/正文不变，只改变 SQLite rowid，分页、会话统计、通知领取和已读全部拒绝。新记录与排序绑定同事务；旧记录初次补建当前顺序，不声称复原旧排序。真实备份入口对仅有会话设置、尚无历史的身份明确失败，目标文件不存在且静音仍保留。
- 实际 Rust AppState/DPAPI/受保护 SQLite + 合成 HTTP：最终 workspace 中 38.48 秒通过。验证受范围绑定通知报告、分页、已读/静音重开、ACK 丢失重试、隐藏重放、52 条历史和锁定迟到结果；原密钥文件保持。这是合成协议服务，不能证明真实 PostgreSQL 或两台 Windows。
- `direct-conversation-ui-delivery-2026-10-02.txt`、`direct-ui-80ldwa/`：真实 Chromium、模拟业务 API，浅深色/宽窄四种配置各 18 项，共 72 项检查，15 秒通过，无 renderer 错误/横向溢出。新增账号过滤切换、显示边界与迟到来信、静音重开/修订冲突、固定通知事件选择正确会话；保留草稿和原任务用例。窄浅界面截图已核对。
- Electron 通知单元与主进程测试覆盖通用正文、编号去重/节流、前台抑制、静音后的迟到报告、scope 变化、锁定后旧点击拒绝；上下文由 Rust 再验证，错误范围/未知账号/旧请求/暂停后的回包拒绝，不查询旧联系人。离线窗口和锁定状态拒绝新命令，固定 preload 事件验证通过。系统提示是尽力而为，领取后的桥接响应丢失或通知中心失败可能无提示；历史/未读仍保持。
- 档案界面 `direct-conversation-devices-ui-final-2026-10-02.txt`、`devices-ui-JTbWQ9/`：28 组/208 项，76 秒通过；群界面 `group-ui-7X0hBL/` 宽窄各 16 类通过；风格 `ui-style-WBlCYz/` 72 张截图/四配置通过。首次档案 UI 的旧组件卸载取新 mock 接口失败（`devices-ui-UCjPUg/`）已改为捕获原接口；主进程夹具补齐焦点 API 后通过。失败报告保留于 `direct-conversation-engineering-final-2026-10-02.txt`，最终交付以 delivery 报告为准。
- `direct-conversation-database-2026-10-02.txt`、`direct-conversation-integration-2026-10-02.txt` 均 `not_executed`：没有标记专用库进程配置；未借用业务库/卷或停止旧测试。本机短测不代替系统通知中心、真实锁屏/休眠、双 Windows、长时间负载和独立审查，这些继续待验收。
- 本批没有服务端或 PostgreSQL 迁移。T23 媒体、原设备编辑/撤回、v3 备份与选定历史授权仍未完成，T22 不声称已支持新的设置；实现状态、后续计划与边界文档已同步，原有未跟踪预览和 src-tauri/ 保留。

## 2026-10-02 v3 持久草稿与原子清理短测

基线 `0fb27f6` 与本轮改动工作树；合成账号/原密钥、随机临时库和隔离原生目标。报告在 `target/test-results/`，没有新长期、真实用户数据操作或推送。

- `direct-draft-engineering-2026-10-02.txt`：完整 `npm test` 18 Node/Electron、318 普通 Rust 通过，0 失败，71 PostgreSQL ignored；格式、全 workspace/all-targets Clippy（-D warnings）和核心 FFI 通过。后续最终定向/静态验证为 `direct-draft-final-focused-2026-10-02.txt`、`direct-draft-final-static-2026-10-02.txt`，通过。`direct-draft-final-build-2026-10-02.txt` 完整生产构建通过，release 46.70 秒，既有链接警告保留；最终草稿状态文案的 UI 构建 `direct-draft-delivery-ui-build-2026-10-02.txt` 通过。没有新迁移或服务端协议变化。
- 共享保护库：12 个 direct store 用例通过，其中新增 3 个草稿用例。中文/emoji/换行重开一致，数据库字节不含合成正文；过时保存/正文不匹配不改变草稿或任务。草稿消耗修订和原任务同事务，旧修订以不同候选编号重试仍返回原编号/摘要，后续新正文保存后拒绝旧消费。相同数据库两个消息拥有者不能读到对方草稿；未知账号拒绝。模拟安全存储写入失败发生在事务回调后，准备任务与清空一起回滚，正文/修订仍保持原值。最初用触发器注入的夹具被原生 schema 校验拒绝，已改为独立 SecureStore 故障，不弱化保护规则。
- 实际 Rust AppState/DPAPI/受保护 SQLite + 合成 HTTP：最终 36.32 秒通过。桌面保存草稿后重开读取，携带修订准备后正文为空且有原任务标记；相同原消费重试不换编号，再沿原任务完成失响应、收件/ACK、52 条分页、隐藏和锁定迟到响应既有场景。此处是合成协议服务，不能证明真实 PostgreSQL、多机器和系统锁定。
- `direct-draft-ui-delivery-2026-10-02.txt`、`direct-ui-YooXHS/`：真实 Chromium、模拟业务 API，四种浅深色/宽窄配置，各 14 项共 56 项检查，12 秒通过，无 renderer 错误/横向溢出。新增重开草稿、旧保存期间继续编辑、磁盘满模拟后保持正文/明确重试、他处修订变化保留双方正文并需确认重新读取、不同聊天账号切换独立保存；原准备响应丢失、原编号继续、取消竞争、锁定清空和已退出历史保持继续通过。最终窄浅/宽深草稿控件已核对；模拟磁盘满/锁定不代替系统故障验收。
- 主进程在锁屏/离线窗口拒绝两个草稿业务接口，保持固定 preload 和原有锁定/窗口保护；后台不使用页面草稿修订。`direct-draft-devices-ui-2026-10-02.txt`、`devices-ui-yowaGK/` 28 组/208 项、78 秒通过；群 UI `group-ui-i3ALZY/` 宽窄/16 类通过；风格 `ui-style-HgWGcx/` 72 张截图和四种配置检查通过，无 renderer 错误。
- 实际 T22 导出入口验证仅有 v3 草稿也拒绝，并不生成目标文件；草稿/任务和身份密钥保留。当前白名单仍不含 v3 草稿，空准备标记也会阻止旧导出，不能声称已纳入可携带恢复。该边界以最终核心用例为证据。
- `direct-draft-database-2026-10-02.txt`、`direct-draft-integration-2026-10-02.txt` 均 `not_executed`：无专用库进程配置，DockerDesktopLinuxEngine 管道仍缺失；71 ignored 不计实际库通过。没有访问业务库/卷或停止旧后台。实际强制中断、磁盘满/权限拒绝、系统锁屏/休眠、多人/双 Windows 和独立审查继续待验收。
- 已确认保存的草稿可重开，仍在保存中的最后输入不算持久完成。会话列表/未读/静音通知、媒体/原设备操作、v3 新历史/草稿备份与选定历史授权继续实现，T23 整体未完成。保留预览和 `src-tauri/` 未跟踪文件。

## 2026-10-02 选中身份的 v3 文字收发短测

基线 `74c12be` 和改动工作树，合成账号/原密钥、随机临时数据库与隔离原生目标。报告在 `target/test-results/`；只做短测，没有新长期、业务资料操作或推送。

- `direct-chat-engineering-2026-10-02.txt`：完整 `npm test` 18 Node/Electron、315 普通 Rust 通过，0 失败，71 PostgreSQL ignored；格式、全 workspace/all-targets Clippy（-D warnings）及核心 FFI 通过。`direct-chat-build-2026-10-02.txt` 全生产构建通过，release 45.73 秒，既有链接警告保留。最终界面/主进程小修后的定向证据分别在 `direct-chat-final-main-2026-10-02.txt` 和 `direct-chat-delivery-ui-build-2026-10-02.txt`，均通过；没有新服务端协议或迁移。
- `direct-chat-final-native-2026-10-02.txt`：实际 Rust AppState/DPAPI/保护 SQLite + 合成 HTTP，33.24 秒通过；工程全跑同场景 32.92 秒。原签名 enable/login 任务及真实 SDK 会话检查来源建立两账号正式记录；只有切换没有正式记录时不使用旧 beta 能力网络请求。对方候选根不自动 pin，错指纹拒绝；原设备 DPAPI 文件字节保留。加入端已有四项激活回归另覆盖选择后消息视图使用自身服务端设备编号/原账号与独立库，不借本机原设备身份。
- 实际消息路径：首个发送已被合成服务接受但响应丢失，持久 Publishing 原任务重开，以原编号/摘要查询 Accepted，发布次数仍为 1。接收先验签解密落库，ACK 服务处理后故意丢响应，原 ACK 再发确认；隐藏后重放同批次不显示卡片。以同一受保护核心另外准备/接受 51 条文字，桌面六条一页读取总计 52 个唯一编号，无跳过/重复；不是声称 52 条均经过真实服务发送。锁定时挂起原 lookup 回包，迟到结果拒绝且不落库，解锁沿原编号恢复；停止使用后没有后台请求/历史借用。合成服务不代表真实 PostgreSQL 事务验收。
- `direct-chat-main-2026-10-02.txt`、最终主进程报告：锁屏/离线窗口拒绝九个 v3 命令，私有后台没有页面 handler/preload 方法；两秒 tick 串行，暂停后迟到后台事件拒绝。身份保存和加入会话清除先退役消息租约，旧结果不能恢复失效能力；正式原设备保存后界面重新查询选中档案。原有会话、文件选择、备份和窗口隔离测试继续通过。
- `direct-chat-ui-delivered-2026-10-02.txt`：真实 Chromium、模拟业务接口，宽窄/浅深色四组合各 9 项文字检查，8 秒左右；覆盖只读挂载、52 条分页、React 转义正文、隐藏后刷新、独立完整根指纹确认、准备响应丢失查询原任务并阻止替代发送、原编号未知结果、取消期间迟到成功拒绝、锁定清空和已退出本机历史可读。截图使用已完成查询的全新视图，最终窄浅/宽深文字排版已核对；模拟锁定不是系统实机场景。
- `direct-chat-devices-ui-2026-10-02.txt`、`devices-ui-AgsNLP/`：28 组/208 项、84 秒通过；`direct-chat-group-ui-2026-10-02.txt`、`group-ui-3WoMoP/` 群宽窄/16 类通过；`direct-chat-style-2026-10-02.txt`、`ui-style-axZnC9/` 72 张风格截图及既有四组合检查通过，无 renderer 错误/横向溢出。首次新夹具路由/依赖和界面控制流编译问题已修正，失败日志保留，不计通过。
- `direct-chat-database-2026-10-02.txt`、`direct-chat-integration-2026-10-02.txt` 仍 `not_executed`：专用测试库未配置、DockerDesktopLinuxEngine 管道缺失。没有读取业务库、重置引擎或停止旧后台。71 ignored 不算实际数据库通过，真实多人/双 Windows、系统交互和独立审查保持待验收。
- 本轮仅完成基础 v3 文字路径。会话列表/准确未读、静音通知与前台/锁屏抑制、持久草稿、媒体/原设备编辑权限、新历史备份和选定历史授权继续实施；含 v3 历史的旧备份仍明确拒绝，T23 整体不关闭。原预览文件及 `src-tauri/` 未纳入功能提交。

## 2026-10-02 正常档案选择、恢复与选中续期短测

基线 `fb665a9` 和本轮改动工作树；只用合成身份、随机临时数据库/密钥文件及隔离原生目标。报告在 `target/test-results/`，没有启动新长期、停止旧后台或读取真实用户资料。

- `profile-selection-engineering-2026-10-02.txt`：完整 `npm test` 18 Node/Electron、314 普通 Rust 通过，0 失败，71 PostgreSQL 用例 ignored；格式、全 workspace/all-targets Clippy（-D warnings）、核心 FFI 通过。`profile-selection-build-2026-10-02.txt` 完整生产构建通过，release 43.99 秒，既有链接警告保留。后续最终 Node 和定向源码回归分别保存在下方报告，忽略的库测试不计通过。
- `profile-selection-core-2026-10-02.txt`、`profile-selection-final-focused-2026-10-02.txt`：两个保护选择测试及 4 加入/10 原设备测试通过。明确原设备→加入→空选择重开、代次 CAS 竞争拒绝、无效目标拒绝、回滚 SQLite 拒绝通过；首次夹具未创建数据库导致原生目标定位失败，修正夹具后通过。公开视图无合成会话能力，错误指纹/过时代次/暂停选择拒绝，身份文件原字节保留。
- 加入端实际 Rust/合成 HTTP：保存原正式会话后选择同一服务端设备编号，在同目录但无原设备密钥文件的 AppState 中重开选择与续期视图；选中续期使用自己的任务库，旧身份/联系人/清理接口拒绝，旧定时/群调度返回零。清除加入会话后无自动请求，停止使用重开不回退，明确选回原设备恢复原接口。合成 HTTP 与本机保护测试不等于真实 PostgreSQL、多端或 Windows 系统验收。
- `profile-selection-node-final-2026-10-02.txt`：18 Node 通过，3.08 秒。选择命令在锁屏和离线窗口拒绝，固定选择事件透传；选择确认接受自己的结果、失效旧授权结果，清除通知/备份窗口与 IPC 代次；既有暂停/迟到续期保护继续通过。
- `profile-selection-ui-completed-2026-10-02.txt`、`devices-ui-anS6Ge/`：真实 Chromium、模拟业务接口，四种宽窄/浅深色组合，28 组共 208 项检查，84 秒，无 renderer 错误/横向溢出。各新增 7 项覆盖明确选择目标/代次/完整指纹、拒绝确认、停止无回退、不可用档案、暂停/迟到、加入重启不调用旧根接口、范围变化清旧首页及绑定错误不回退。最终首页按钮留白也复跑；此前 `devices-ui-R8FCIK/` 暴露 StrictMode 首次查询跳过，修正后通过。浅色窄选择与深色宽首页截图已核对。
- `profile-selection-group-ui-2026-10-02.txt`、`group-ui-C94EJV/` 群宽窄/16 类检查通过；`profile-selection-style-verified-2026-10-02.txt`、`ui-style-xrNZXf/` 72 张风格截图及四种配置检查通过。首次风格夹具缺新启动选择接口导致聊天未挂载，补合成 API 后复跑，失败证据保留。最终工程以通过结果为准，不把模拟麦克风/系统暂停当作实机验收。
- `profile-selection-database-2026-10-02.txt`、`profile-selection-integration-2026-10-02.txt`：既有隔离入口环境检查均 `not_executed`；当前无专用测试库进程配置，DockerDesktopLinuxEngine 管道仍缺失，没有访问业务库/卷或重置引擎。真实数据库、多人、双 Windows、系统锁屏/休眠及独立审查继续待验收。
- 正常选择和选中续期已接；v3 收发/历史/媒体/备份/选定历史未因此完成，独立加入首页明确尚未开放聊天，T23 整体不关闭。没有推送，原预览文件及 `src-tauri/` 保留未跟踪。

## 2026-10-02 正式会话续期桌面与调度短测

基线 `f5268a4` 与本轮改动工作树；仅合成身份、随机临时数据库/密钥文件和隔离原生保护目标，报告在 `target/test-results/`。只做短测，没有启动新长期或操作真实用户资料。

- `session-refresh-final-engineering-2026-10-02.txt`：完整 `npm test` 18 Node/Electron、311 普通 Rust 通过，0 失败，71 PostgreSQL 用例 ignored；格式检查、全 workspace/all-targets Clippy（-D warnings）及核心 FFI 编译通过。此批无服务端线格式或数据库迁移变化。
- `session-refresh-final-build-2026-10-02.txt`：完整 `npm run build` 通过，Rust release 43.86 秒；保留既有 LNK4098/LNK4099 链接警告。汇总 `session-refresh-summary-2026-10-02.json` 同时登记工程、界面和未执行环境范围。
- Rust：7 核心续期与 9 原设备桌面用例通过。两种拥有者原任务/重开、受保护当前记录、失响应后原证明重试、锁定/清除/独立新登录拒绝迟到、家族退出后继与独立登录隔离继续通过；新增未确认的已发取消不改变修订/意图、未发取消仍只撤销任务。桌面严格目标与未知字段/秘密/路径注入拒绝、错误加入目标不能借根任务、公开视图无能力、重启原编号、锁定拒绝、自动创建/重试同一任务、本机退出不再自动调度通过。3 个调度选择测试覆盖成功后代次变化的明确退出优先、旧/终态不重启、冲突保留原编号。完整 HTTP 家族事务仍须真实 PostgreSQL 验证。
- Node：锁屏/休眠期间五个业务接口拒绝、离线窗口全部拒绝、私有后台命令不进入 preload/页面、重复 tick 串行、暂停拒绝迟到通知、恢复后可调度均通过。初轮私有桥接白名单遗漏和根目标 unit variant 忽略附加字段已修正；原子取消确认和退出优先也分别补测试。失败日志保留，以最终通过结果为准。
- `session-refresh-ui-final-2026-10-02.txt`、`devices-ui-OvqZyE/`：真实 Electron Chromium、模拟业务接口，四种浅深色/宽窄组合，24 组共 180 项检查，75 秒通过，无 renderer 错误/横向溢出。续期各 7 项覆盖明确准备、原编号未知重试、未发取消/整理、加入独立范围与退出确认、Prepared→Started 竞争、取消期间迟到成功、系统暂停清空和档案切换。最终浅色窄窗截图已人工核对，深色宽窗也核对过；模拟暂停不代表 Windows 实际锁屏/休眠验收。
- `session-refresh-group-ui-2026-10-02.txt`、`group-ui-SIl3cW/`：群 UI 宽窄及 16 类既有检查通过；`session-refresh-style-2026-10-02.txt`、`ui-style-pkqacU/`：72 张风格截图和既有四种配置检查通过，无 renderer 错误。附件/语音/活动模拟界面继续可用，不冒充麦克风/真实多人验收。
- `session-refresh-database-2026-10-02.txt`、`session-refresh-group-integration-2026-10-02.txt`：隔离入口实际执行了环境检查，结果均为 `not_executed`，当前进程没有专用测试库配置，DockerDesktopLinuxEngine 管道仍缺失；没有读取业务库、重置 Docker 或停止原后台。71 ignored 不计通过。
- 原设备已有正式记录可自动续期，加入档案仍手动，未选档案不后台请求。正常档案选择、v3 收发/历史/媒体/备份和选定历史仍待实现；真实系统/双 Windows、故障中断及独立审查保持待验收，T23 整体不关闭。不推送，预览文件和 `src-tauri/` 不纳入功能提交。

## 2026-10-02 原设备与加入档案正式凭据来源短测

基线 `6e04c3e` 和改动工作树，汇总 `session-routing-summary-2026-10-02.json`，报告位于 `target/test-results/`，隔离数据/身份与合成 HTTP。

- `session-routing-verified-engineering-2026-10-02.txt`：完整 18 Node/Electron、307 普通 Rust、0 失败；71 PostgreSQL 用例 ignored，格式、全 workspace/all-targets Clippy 和核心 FFI 通过。`session-routing-verified-build-2026-10-02.txt` 最终生产构建通过，release 41.07 秒，既有链接警告保留。
- 加入档案 8 项通过，其中新增合成续期：初始保存同时有当前记录，接受后继后重新打开档案读取新访问/刷新能力，原档案修订保持；本机清除同时清空档案与当前记录，续期协调器不能再取能力。原保存错误刷新能力、签名移除、锁定/退出迟到等回归保持。`session-routing-active-final-2026-10-02.txt` 为专项，最终工程再次覆盖。
- 原设备 8 项最终通过，`session-routing-root-verified-2026-10-02.txt` 5.57 秒；保存后当前记录完整会话/重开读取与安全公开标记正确，DPAPI 原身份文件字节不变，清除当前记录后本进程和已打开另一个进程状态对象都返回空能力，不使用原文件旧凭据。原锁定、退出、替换能力与错误刷新摘要不覆盖当前身份的反例继续通过。桌面加入激活 4 项、设备控制 2 项回归也被最终工程覆盖。
- 早期完整回归暴露“未确认原根已有保护记录被凭据读取误拦截”的暂停错误；修正可选读取仅验证保护，明确首次保存使用已确认原根初始化。修正后设备暂停专项通过；一次复跑使用修正前构建导致首次保存超时，原日志保留，最终工程/专项全部通过，不计早期失败为成功。此变化没有取消回退保护或默许重新 pin。
- 初次测试编译遇到磁盘满；测得项目 `target/debug/incremental` 可重建缓存总长度 56.76 GiB。核对绝对目标在项目内且无重解析点后仅清理此缓存，清理后 D 盘空闲 47.50 GiB；保留报告、exe、源文件和既有后台测试。本轮验证进程设 `CARGO_INCREMENTAL=0`，不修改用户环境配置。
- `session-routing-database-preflight-2026-10-02.txt`：Docker 引擎管道仍缺失，实际专用库/多人未执行。没有新迁移、线格式、UI 或业务 IPC，不以模拟界面替代自动调度验证。只做短测，没有新长期、停止后台、业务数据修改、推送或纳入未跟踪预览/src-tauri。
- 本轮仅完成正式读取/保存/本机清除接线；续期任务业务 API/页面与自动调度、正常档案选择、v3 后台等仍待实现。系统/双 Windows、真实磁盘中断场景和独立审查继续待验收，T23 不关闭。

## 2026-10-02 原续期持久任务与当前会话核心短测

基线 `686c94d` 和改动工作树，汇总 `refresh-jobs-summary-2026-10-02.json`，报告在 `target/test-results/`；合成身份、随机临时 SQLite 和隔离原生目标，不使用真实资料。

- `refresh-jobs-core-2026-10-02.txt`：新增 7/7、14.13 秒。根/加入设备的当前初始化、公开视图无能力、原请求重开、单当前待处理、未发布取消、整理与跨拥有者隔离通过；数据库字节不含合成刷新能力明文。初始元数据只来自原登录任务和真实 SDK 来源标记，原模式的目录点必须已验证。
- 合成 HTTP：首次 proof 响应丢失后保存 Proving，重开发同一编号/证明原字节，成功后原任务结果和当前代次/完整能力一并可读；整理成功结果后当前能力仍保留，下一续期绑定后继。锁定后解锁、本机清除及另一个已检查初始登录都拒绝迟到 begin，未保存挑战、未发后续证明；错误登录任务拥有者和锁定期间初始化不替换原当前记录。
- 在 proof 等待期间保存取消，迟到 Accepted 拒绝，不替换当前记录；随后原访问能力的 SDK 204 家族退出才记录 Ended/清除对应当前能力。连续两次续期后退出原家族清除最新后继，家族回执支持安全整理；独立新初始登录不被旧家族退出清除。签名撤销保留元数据、拒绝能力取用/网络请求；恢复旧 SQLite 在隔离原生高水位下拒绝。HTTP 服务为合成响应，不证明真实 PostgreSQL 家族事务。
- `refresh-jobs-engineering-2026-10-02.txt`：完整 18 Node/Electron、306 普通 Rust、0 失败，71 PostgreSQL 用例 ignored；格式、全 workspace/all-targets Clippy、核心 FFI 通过。新增夹具监听器所有权和证明擦除 Drop 后的字段移动编译问题已修正，最终绿结果为准。`refresh-jobs-build-2026-10-02.txt` 生产构建通过，release 45.14 秒，既有链接警告保留。
- `refresh-jobs-database-preflight-2026-10-02.txt`：Docker 引擎管道仍缺失，真实专用库/多人未执行；无新迁移或线格式。没有 UI/IPC 改动，不以新增模拟截图证明桌面自动续期。只做短测，没有启动新长期、停止旧后台、操作业务资料、推送或纳入预览/src-tauri。
- 仅交付共享核心任务/当前元数据。桌面原身份/加入档案接线、任务业务 API/界面、自动调度和正常档案选择仍待完成；系统/双 Windows、磁盘故障/中断和独立审查继续待验收，T23 整体不关闭。

## 2026-10-02 续期协议、事务与 SDK 短测

基线 `d0a73dd` 和改动工作树，汇总 `session-refresh-summary-2026-10-02.json`，报告位于 `target/test-results/`；只使用合成或既有隔离测试入口。

- `session-refresh-engineering-2026-10-02.txt`：完整 18 Node/Electron、299 普通 Rust、0 失败，71 数据库用例 ignored；格式、全 workspace/all-targets Clippy 与核心 FFI 通过。共享激活最终 14 项，其中新增 2 项覆盖根/加入设备的原会话签名、窗口、双密钥、错刷新能力/私钥、原请求修改、原会话移植、未知字段、密文损坏和加密结果无明文令牌。SDK 最终 15 项，新增 3 项覆盖真实合成 HTTP 的路径/原刷新 bearer/原请求、正确 Accepted 解密、错摘要/字段/设备/密文、发送前错原点/能力/私钥零网络，以及 proof 的不同原挑战/非 Accepted 拒绝。合成 HTTP 不代表真实数据库事务。
- `session-refresh-server-compile-2026-10-02.txt` 为服务测试编译通过。新增两项真实 PostgreSQL 测试待执行：begin/proof 成功回包丢失、重复/并发原证明得到同一后继和密文、过期访问仍可续期、仅一次消费、家族退出不影响原设备独立会话；多原编号并发只成功一次、同编号改签冲突、错 bearer、过期原刷新与签名设备撤销不产生新会话。既有“原激活结束不撤销有效后继”改为真实新续期路径；旧通用 v3 刷新拒绝另验。这些只有编译证据，不计业务通过。
- `session-refresh-build-2026-10-02.txt`：UI/Electron/Rust 生产构建通过，release 1 分 08 秒，既有链接警告保留。此前编译中的测试借用/函数名遮蔽错误已修正，早期 Clippy 失败日志保留，最终工程绿结果为准。Windows 映射文件限制使首次格式写入失败，按相同 rustfmt 输出补齐后最终格式检查通过。没有 UI 或 IPC 变更，不重跑模拟截图来证明自动续期。
- `session-refresh-database-preflight-2026-10-02.txt`：Docker 引擎管道仍不存在，专用 PostgreSQL/真实多人未执行，没有读取或修改业务库。没有新长期测试，不停止既有后台，不推送或纳入未跟踪预览/src-tauri。
- 只交付共享格式、服务持久结果与 SDK 网络原语。客户端原任务持久化、完整元数据/CAS、重开恢复、自动调度和界面仍待实现，不据此关闭自动续期、退出生命周期或 T23。系统/双 Windows、磁盘故障和独立审查继续待验收。

## 2026-10-02 原设备正式会话恢复短测

基线 `b05f18b` 与改动工作树，汇总 `root-session-summary-2026-10-02.json`；报告在 `target/test-results/`，没有真实身份或凭据。

- `root-session-final-engineering-2026-10-02.txt`：完整 `npm test` 为 18 Node/Electron、294 普通 Rust、0 失败；69 PostgreSQL 用例 ignored，未计入通过。格式、全 workspace/all-targets Clippy、核心 FFI 通过。早期工程日志与专项保留，最终文件覆盖 SDK 正面事实和首次登录兼容修正；初次测试夹具缺少 begin、引用类型错误已修正，不计初次失败为通过。
- 原设备桌面 `root_messaging.rs` 最终 8 项中新增 5 项，合成 TCP、随机隔离 SQLite/DPAPI/原生目标：七命令拒绝密钥/令牌/路径/mode/档案注入及 enable 类型任务；原正式会话成功保存只改变凭据，私钥、公钥、账号、设备和服务器一致，重开可读；锁定后解锁、退出、另一次凭据保存及错误刷新摘要均拒绝迟到结果，当前身份文件不改；退出后无 bearer 查询原签名配置，原编号准备/取消/整理；原启用响应未知时保存实际已启用事实，原启用任务保持；无已绑定身份的旧首次登录仍能请求服务器，不创建身份文件。成功后的 load/prepare 页面结果只有存在标记，旧保存/刷新/中继拒绝。这些不等于真实 PostgreSQL 或双机验收。
- 核心 `activation_api_test.rs` 最终 12 项，新 binding 用例的 8 个分支：正确两凭据和原会话绑定成功并更新服务器期限；错访问凭据、刷新凭据、编号、账号、设备、授权和启用摘要均拒绝。原点、范围、过期、未知字段与签名引导既有回归通过。
- `devices-ui-uM41s1/result.json`：实际 Electron Chromium、模拟业务 API、69 秒，浅深色/宽窄四配置各 9 原设备、11 加入、7 激活、6 切换、5 原会话用例，0 renderer 错误/横向溢出。登录入口、显式原任务和保存、口令清除、unknown 不重建、取消竞争与锁定迟到拒绝通过，最终窄浅截图已核对；此前 `devices-ui-T4k3FJ` 65 秒报告保留。主进程工程用例验证七接口系统锁/档案窗口拒绝，成功保存不会拒绝自身结果且失效之前的授权回包。
- `root-session-build-2026-10-02.txt`：UI/Electron/Rust 生产构建通过，Rust release 45.60 秒，既有 LNK4098/LNK4099 保留；最初受沙箱限制的 esbuild EPERM 后在批准的本地执行环境构建成功。两个设备 UI 脚本语法检查通过，群 UI `group-ui-IXkXEN` 宽窄各 16 项通过。
- 数据库预检 `root-session-database-preflight-2026-10-02.txt`：Docker 引擎管道缺失，专用 PostgreSQL 与真实多人本轮未执行；未读取/修改业务库或凭据文件。只做短测，未运行新长期、停止旧后台、修改真实资料、推送或纳入未跟踪预览/src-tauri。
- 最终风格回归 `ui-style-0umxYs/result.json`：72 张截图入口通过、0 错误；`root-session-style-2026-10-02.txt` 保留实际输出。模拟风格与群 UI 不替代原生系统或真实服务验收。
- 本轮没有新服务端迁移或线格式。正常档案选择/自动刷新、v3 后台/消息界面、媒体/操作、新备份与历史授权仍需实现；磁盘满/中断、双 Windows、系统交互和独立审查继续待验收，T23 不关闭。

## 2026-10-02 根设备切换产品接线与发送门禁短测

- `root-messaging-engineering-2026-10-02.txt`：完整 `npm test` 18 Node/Electron、288 普通 Rust、0失败，69数据库用例 ignored，不计通过。新两个库单测验证切换等待持有的旧读许可、等待期间没有启用任务、暂停后解锁仍拒绝原准备，以及 dispatcher 在写许可释放后才重新检查旧发送准入。这个共享门禁是当前sidecar内存范围，不是所有任意SDK进程的跨进程发送锁。
- 新 `desktop/tests/root_messaging.rs` 3/3：根确认/秘密和路径参数拒绝，逐个类型化生产入口在准备后拒绝；后台定时tick返回0且保留记录，本机已读不生成旧回执。上传被拒绝，已有下载进入自身认证流程（损坏测试缓存仍失败，未当作可用附件），旧密文和原账号文件保持。取消未发布原任务恢复旧准入；原点绑定配置观察保持，锁定后有效迟到配置不落库，重开仍保持已启用。
- 合成TCP核对真实SDK的 GET启用状态→POST启用：使用保存的同一原事件/编号/签名字节，完成后准入为v3。调用取消返回实际complete，不撤销启用；整理complete拒绝，重开仍为v3。首个新增用例误以为已接受取消应该报错，修正为真实幂等complete语义后通过；未修改底层取消行为或以初次失败当作成功。合成服务不替代PostgreSQL/真实多人。
- `devices-ui-Kkw7Dd/result.json`：实际Electron Chromium/模拟业务接口、55秒，深浅色与宽窄四配置各9原设备、11加入、7激活、6根切换用例，0renderer错误/横向溢出。检查父页面入口、不可撤回/暂停影响、原指纹、积压禁用、原编号继续、已接受不退回、远端观察不新签、取消竞争与暂停迟到拒绝；窄浅/宽深切换截图已核对。
- `group-ui-O9qgpP` 宽窄各16项、`ui-style-4H82yn` 72截图入口通过。`root-messaging-build-2026-10-02.txt` 生产构建完成，Rust release54.65秒；格式、全workspace/all-targets Clippy、核心FFI及两脚本语法通过，既有LNK4098/LNK4099保留。主进程工程回归验证六新命令在锁定及只读档案窗口拒绝。
- 本轮无新服务端迁移或wire格式，现有Docker引擎管道不可用，专用库/多人联调未执行；旧报告不证明此批接线。没有新长期测试，不操作真实资料/业务库/旧后台，不纳入未跟踪预览/src-tauri，不推送。当前切换允许用户明确暂停旧单聊；新消息后台尚未接入，界面已提示。原设备正式会话恢复、正常档案选择/刷新、媒体、旧操作、新备份/历史授权及双Windows/系统/独立审查仍待完成或验收。

## 2026-10-02 原设备旧协议切换核心短测

- 最终汇总 `legacy-mode-summary-2026-10-02.json` 标明基线 `bce335f` 和有改动工作树。`legacy-mode-final-engineering-2026-10-02.txt` 为完整 18 Node/Electron、283 普通 Rust、0 失败；69 数据库用例 ignored，不计实际通过。`legacy-mode-build-2026-10-02.txt` 构建完成，Rust release 57.11 秒；格式、全 workspace/all-targets Clippy、核心 FFI 和专项脚本语法检查通过，既有链接警告保留。早期 `legacy-mode-engineering-2026-10-02.txt` 保留，最终重跑覆盖 SDK 来源标记；全部缺表的强化反例随后五项专项再次通过。没有 UI 改动，不重复模拟截图替代新核心测试。

- `legacy-mode-final-core-2026-10-02.txt`：5/5、0.86 秒，随机隔离 SQLite/原生目标及合成 TCP。六类待处理记录逐项处理前，受检查准备都失败且启用任务数保持零；全部终态后准备成功，旧密文仍保留。准备状态阻止重建，取消未发布原任务恢复旧协议状态；其他账号/设备和已完成记录不误计，未知设备元数据计为待处理，非法 JSON 明确失败。
- 新库的准入查询不创建 T23 表或原生记录。删除任务、根、事件和 SQLite witness 全部标记表后，确认本机这些表数为零，仍因原生记录存在拒绝重开；不重置系统高水位。此检查不覆盖系统凭据和数据库同时回退的既有平台边界。
- SDK 返回 `VerifiedMode` 来源标记，不支持公开 JSON 构造；原点/账号/根设备/原阶段匹配且启用签名/目录前缀正确后才保存。重复同一配置幂等；另一启用事件、坏签名、未启用或另一根的查询不能替换事实。库内加密配置正文不含可直接搜索的原点，错密钥无法读取；准入状态重开为 v3。TCP 是合成响应，不代表真实 HTTP/PostgreSQL 验收。
- 原激活任务 9 项与 SDK 11 项专项通过。此增量没有新服务端 SQL 或 wire 变化；专用 PostgreSQL/多人联调仍受 Docker 引擎故障影响，旧绿报告不能替代本轮。只做短测，没有操作真实资料/业务库、启动新长期或推送。
- 当前仅提供共享核心事务门槛、准入读取和已启用事实。既有桌面发送路径尚未统一接新检查，跨请求并发、切换界面/正常档案选择、会话刷新和后台仍需继续实现；不据核心短测关闭这些产品场景或双 Windows/系统/独立审查。

## 2026-10-02 加入端正式激活桌面接线短测

汇总 `join-activation-summary-2026-10-02.json` 记录测试前提交 `213fc30` 与有改动工作树，保留工程、最终桌面、界面和构建证据；报告均在 `target/test-results/`，不包含真实凭据。

- 完整 `npm test`：`join-activation-engineering-2026-10-02.txt` 为 18 Node/Electron、278 普通 Rust、0 失败，69 数据库用例默认 ignored。新增 `desktop/tests/device_activation.rs` 四项，随机隔离 DPAPI/SQLite/原生目标和合成 HTTP：八命令拒绝密钥/令牌/路径/mode 注入及未确认档案；准备/取消/整理保留原编号与原账号/加入身份文件；锁定后解锁、切加入档案或清除会话均拒绝迟到引导，不创建激活任务；接受原结果后只保存独立正常档案，清除会话阻止迟到保存，不恢复凭据。
- 四项最后专项复跑见 `join-activation-final-desktop-2026-10-02.txt`，临时目录在缓存 SQLite 句柄及隔离原生记录释放后清理。原加入 3 项、原生保护 2 项回归通过。测试夹具先修正 Accepted 的 Box 类型后执行成功；此前无通过记录替代失败。保存/检查 HTTP 使用合成响应，不代表真实 PostgreSQL 服务验收。
- Electron 主进程最终补验 2/2、0.37 秒：新八命令都受系统锁门禁限制，并在离线档案窗口拒绝；这两项与 18 项工程入口重叠，不重复累加。Rust 协调器和主进程双重失效保护，无页面解锁底层入口。API 继续使用已有 60 秒 Rust dispatch / 65 秒桥超时，超时保留原任务；未新增秘密或文件字节的桥传输。
- `devices-ui-1DuQ5z/result.json`：实际 Electron Chromium，模拟业务接口、47 秒，深浅色/宽窄四配置各 8 原设备、11 加入、7 正式激活用例，0 renderer 错误/横向溢出。验证父面板入口的档案范围、明确准备、原编号继续、口令清除、接受后单独保存、终态事实/整理、取消竞争、冲突/unknown 不重建、系统暂停与关闭丢弃迟到结果。两张同版激活宽深/窄浅截图已核对；此前 `devices-ui-jHPha4` 报告保留，最终报告增加实际组件入口检查，不将模拟界面当作服务联调。
- `group-ui-NTeikv` 宽窄各 16 项和 `ui-style-s4kO18` 72 张截图回归入口通过。`join-activation-build-2026-10-02.txt` 生产构建完成，Rust release 48.69 秒；格式、全 workspace/all-targets Clippy、核心 FFI 和两专项脚本语法检查通过。既有 LNK4098/LNK4099 保留；首次受沙箱限制的 esbuild spawn EPERM 后在批准的本地构建执行环境成功，不计首次失败为通过。
- 本轮服务器没有新增迁移；新增桌面命令依赖已实现的原激活/会话验证。专用库和真实多人联调因 Docker 引擎启动故障未执行，69 ignored 不计通过。没有新长期测试，没有操作真实用户资料/业务库/后台测试或纳入原未跟踪预览和 `src-tauri/`，不推送。正常档案选择、原设备明确切换、刷新和消息后台尚未开放，实机/双 Windows/独立审查继续待验。

## 2026-10-02 首次激活配置引导短测

- 最终完整工程 `activation-bootstrap-engineering-2026-10-02.txt`：18 Node/Electron、274 普通 Rust、0 失败；69 数据库用例 ignored，不计通过。生产构建 `activation-bootstrap-build-2026-10-02.txt` 完成，Rust release 1 分 47 秒；格式、全 workspace/all-targets Clippy、核心 FFI 通过，既有链接警告保留。再次执行专用激活入口，仍在测试库准备阶段失败；Docker 引擎管道仍不可用，未修改业务数据或运行长期测试。

- 共享 `device_activation_test` 12/12、0.02 秒；SDK `activation_api_test` 11/11、0.09 秒。新增签名查询覆盖原设备/第二设备、账号/原点/两公钥/原授权/编号/时间/签名篡改、撤销及未加入状态、极端 i64 时间不溢出、查询签名不能转作协议启用。查询有效期两分钟，允许最多 30 秒客户端时钟提前；未启用响应只阻止准备，不作为任何任务终态。
- 合成 TCP 实际核对 POST `/auth/v3/mode` 无 Authorization 头，正确签名/本次摘要/启用或未启用成功；错摘要、坏根签名、未知版本/字段、其他账号事件拒绝。错本机私钥在发送前拒绝，无网络请求。原 SDK 共用的响应上限/重定向拒绝继续覆盖。
- 新真实 HTTP/PostgreSQL 用例已编译，覆盖授权后无会话读取未启用/已启用状态，查询不新增 operational 设备、会话或激活申请，以及非法请求、过期/撤销拒绝。实际专用入口仍在准备测试库时失败，尚未运行；不能将编译或合成 TCP 当作真实服务通过。

## 2026-10-02 正常会话档案核心短测与数据库环境限制

- `active-profile-engineering-2026-10-02.txt`：完整 `npm test` 18 Node/Electron、271 普通 Rust、0 失败；68 PostgreSQL 用例默认 ignored，不计实际通过。新增核心档案 7/7，覆盖未确认身份拒绝、原授权/服务端编号绑定、DPAPI 保存与重新打开、原私钥/身份文件保留、并发旧修订拒绝、刷新凭据错配拒绝、撤销后仅保留离线身份、退出/锁定拒绝迟到的有效 HTTP 结果，以及加入整理不能删除正常档案。合成 TCP 返回值不替代真实服务验收。
- SDK 9/9、共享协议 11/11：会话版本、账号/设备两公钥、授权阶段、启用摘要、访问/刷新期限与刷新摘要校验；未知字段和错范围拒绝。私钥、访问/刷新令牌只在 Rust，公开档案视图不含秘密。退出使用擦除而非只清空字符串；原 DPAPI 身份文件保持字节一致。
- `active-profile-build-2026-10-02.txt`：`npm run build` 完成，Rust release 50.59 秒。格式、全 workspace/all-targets Clippy（-D warnings）、核心 FFI 编译和专项脚本语法检查通过；保留既有 LNK4098/LNK4099。静态及环境记录 `active-profile-static-environment-2026-10-02.txt`。
- 实际执行 `run-isolated-validation.ps1 -ActivationOnly`，在专用角色/标记库准备阶段失败，尚未执行 SQL 或测试。Docker 的 Linux engine 命名管道不存在，backend 报告运行时 `sailor-ingest.sock` 无法访问。启动和保留运行时目录的恢复尝试未成功；重新检查仍只有原 `run` 目录，无已完成的移动。不执行 factory reset，不清理业务库、卷或真实资料。没有本地 PostgreSQL 二进制可供替代。
- 两项新真实 HTTP/PostgreSQL 用例已纳入服务器测试并编译：完整加入→授权→正式激活→DPAPI 正常档案，以及当前设备会话范围/旧会话/撤销拒绝；本轮尚未运行，仍待补验。原 66 项实际数据库绿报告证明原提交，不证明本轮新增接口。数据库、多人联调及新增功能双 Windows/系统/独立审查继续待验；未重复无界面改动的模拟 UI 截图，未启动新长期测试。
- 此切片仅 Rust 档案核心和受认证元数据接口。桌面还未选择正常加入档案或连接 v3 后台，自动刷新未实现；过期/无效会话保留原档案并要求后续刷新或重新认证，不偷偷生成新身份。原未跟踪预览和 `src-tauri/` 保留，不纳入功能提交。

## 2026-10-02 原申请终态与再申请短测

- 共享原语10/10、0.03秒：查询与取消签名域分离，查询不能转作取消签名；原编号/设备/凭据和查询摘要绑定、非法版本/接受事实/未知挑战拒绝。SDK8/8、0.09秒：正向终态只认原查询，错摘要、accepted与过期事实矛盾、未知版本拒绝；沿用跳转/上限/密文反例。无明文令牌返回页面。
- `activation-closure-final-core-2026-10-02.txt` 核心9/9、6.02秒：随机临时SQLite/原生测试目标及合成TCP。正向结构化终态重开为ended，释放同类待处理范围；410仍是retry/started，不能整理或创建另一同类任务。未完成和complete拒绝删除，只有明确ended/cancelled/ineligible整理；已接受但签名目录撤销后会话不可读，转ineligible后可整理。取消修订和锁定后解锁均拒绝迟到的有效终态，原任务不被覆盖。
- `device-activation-2026-10-02T03-35-14-510Z.json` 18/18、92.49秒含构建/等待，PostgreSQL16.14、新随机标记库/真实Axum/HTTP和隔离原生任务库。unknown不写终态、不取消、不签发；pending保留原挑战，坏签名和查询当取消均拒绝。旧期限SQL调为已过，begin成功回包丢失后原查询确认expired，终态成功回包再丢失后重开得到同一ended；迟到原begin410，显式新编号/同一设备证明成功，不自动新申请。
- 原会话真实刷新后旧会话撤销，检查得到accepted=true的session_ended；刷新后的新访问凭据仍有效，记录会话数2（原+后继），查询没有签发第三条。密码hash变化与真实签名目录前进使未接受申请分别结束；原阶段已撤销继续依赖验签目录，HTTP拒绝不替代该证据。SQL期限注入不代表实际经过10分钟/30天，短测不代替长期负载。
- 完整专用PostgreSQL `database-2026-10-02T03-40-46-318Z.json` 66/66、0失败/跳过：新迁移20、原单设备/群/附件/活动和授权/v3/正式申请终态均实际执行，专项18项与该入口重叠不累计。格式、全workspace/all-targets Clippy、核心FFI `activation-closure-static-2026-10-02.txt`通过。生产构建`activation-closure-build-2026-10-02.txt`完成，Rust release57.36秒，既有LNK4098/LNK4099保留。
- 首次完整工程因会话中断停在direct_store_test中途，原`activation-closure-engineering-2026-10-02.txt`保留，不计通过。续接确认原执行句柄已不存在、没有工作区cargo/测试进程后完整复跑，`activation-closure-final-engineering-2026-10-02.txt`为18项Node/Electron、262项普通Rust、0失败；66 ignored由上述专用库另行实际执行。未因观察超时重启仍在运行的测试，也未重复已完成数据库/构建。
- 本轮没有正常Windows身份档案/IPC/页面或群协议接线，不重复模拟UI/风格截图/原三客户端演示，不关闭系统/双Windows/独立审查。原真实资料、旧后台及未跟踪预览/src-tauri保留；正常档案/会话字段、后台与桌面接口、媒体/旧操作、新备份/历史授权继续实现，T23整体未完成。没有新长期、安装、推送、签名或发布。

## 2026-10-02 原激活任务持久化短测

- `activation-jobs-final-core-2026-10-02.txt` 7/7、3.97 秒：随机临时 SQLite、隔离 Windows Credential Manager/DPAPI 目标；原请求凭据/编号/挑战/证明重开一致，密码和合成明文令牌不在任务密文，任务公开视图无秘密；两类/身份范围、一个同类待处理任务、旧授权视图不误读新行、未发布本机取消幂等。已接受结果重开仅 Rust 解封；取消修订阻止迟到接受覆盖，接受竞争保留原会话及取消意图。
- 原挑战错编号/损坏密文在落库前拒绝、事务未改原任务；恢复旧 SQLite 后原生外部记录拒绝打开。验签目录撤销后已有任务仍是历史 complete，但不能打开其在线会话。真实本机 TCP/同步屏障：取消、锁定后解锁、会话轮换使旧启用查询失效，不发后续请求；迟到401不能返回“需要口令”提示。是短控制场景，不是断电/强制终止或原生系统锁屏。
- 最终 `device-activation-2026-10-02T03-05-45-825Z.json` 14/14、61.90 秒含构建：PostgreSQL 16.14、真实 Axum/reqwest、隔离原生任务库和合成两套设备密钥。启用/begin/proof成功回包丢失后重开，原编号/凭据/挑战/证明一致、仅一次第二端会话；未知启用任务保留期间，原设备不带旧访问/刷新 bearer 以密码和双密钥证明取得新会话，再确认同一原启用事件。此为协议/核心真服务，不是 Windows 产品登录页面。
- begin已接受但未落挑战后持久取消，取消成功回包丢失后重开得到原 cancelled，迟到原密码请求410、无设备会话；证明已接受但本机未知后取消，接受回包再次丢失，重开确认 complete和原结果、保留取消标记，原会话有效且只一条。此前13项版本报告 `device-activation-2026-10-02T02-55-43-429Z.json` 通过，保留阶段范围。
- 全库 `database-2026-10-02T03-00-12-881Z.json` 62/62、0失败/跳过，覆盖原单设备/群/附件/活动、授权、v3和新增三项持久任务真服务。之后补齐任务类型范围的原设备恢复边界，最终14项激活专项及7项核心再通过，其他服务协议/迁移未改；重叠项不累计更多测试。初次Rust编译的MutexGuard解引用/借用和未使用导入已修正后复跑，无失败数据库报告。
- 完整工程 `activation-jobs-engineering-2026-10-02.txt` 18 项 Node/Electron、256 项普通 Rust、0失败；默认62 ignored另由上面的隔离专用入口实际执行。生产构建 `activation-jobs-build-2026-10-02.txt` 通过，Rust release42.08秒、既有LNK4098/LNK4099保留。最终格式、全workspace/all-targets Clippy和核心FFI `activation-jobs-final-static-2026-10-02.txt`通过，阶段静态日志另存。设备专项脚本新增7项任务测试入口，`node --check`通过，其目标已在完整工程实际运行；本轮未另跑整份专项脚本，不声称额外专项总数。
- 本轮没有页面、群协议或正常身份文件接线，不重复模拟UI/风格截图/原三客户端演示；没有启动新长期测试、安装、推送、签名或发布。用户允许短测，不以本机SQLite和HTTP代替双 Windows、真实系统或独立审查。原用户资料、旧后台及未跟踪预览/src-tauri保留；正常Windows档案、会话终态整理/过期明确再申请、后台/IPC/页面、媒体/旧操作、新备份/选定历史仍待实现，T23整体不勾选。

## 2026-10-02 启用与激活取消短测

- 共享原语 8/8、0.02 秒（原 6 + 2 取消签名用例）：独立取消域、完整原事件摘要，设备/原点/账号/授权阶段/启用记录/凭据哈希绑定；改字段、错密钥或已撤销阶段拒绝。Rust SDK 6/6、0.10 秒，证据 `activation-cancel-sdk-2026-10-02.txt`：精确原取消摘要和 accepted 事件，未知字段/unknown/错挑战/坏会话密文拒绝；沿用重定向与大小限制。均为合成数据，重叠项不加成更多测试。
- `device-activation-2026-10-02T02-34-09-062Z.json` 11/11、66.15 秒含构建/锁等待，PostgreSQL 16.14、随机标记隔离库/真实 Axum 和 HTTP：取消早于 begin、成功取消回包丢失后原编号重试、迟到密码请求拒绝；挑战建立后取消阻止原证明和重取挑战；两轮短并发证明/取消只有一个终态。已接受证明回包丢失后取消返回原挑战/会话密文，过期挑战仍可取得已接受原结果，不另签发、不撤销有效会话。
- 原根取消阻止迟到启用，已启用时取消返回原 accepted、不逆转协议；后续使用新编号启用也不改变旧取消记录的终态。后一个幂等边界在最终全库复跑实际通过。错误签名/凭据/账号/启用摘要及同编号不同设备范围拒绝，不写错误记录。每类 4,096 取消记录额度用 SQL 合成行短测，超限拒绝且原记录重试仍成功；这不代表 4,096 次实际请求或长期负载。
- 完整数据库首轮 `database-2026-10-02T02-35-29-134Z.json` 为 58/59，唯一失败是既有 `directory_conflict_revoke_rejoin_and_old_result_do_not_reencrypt`；隔离新库单项 1/1、2.66 秒随后通过，未复现，首轮错误原因未确定。最终新隔离库 `database-2026-10-02T02-38-25-639Z.json` 为 59/59、0 失败/跳过，含原单设备/群附件/活动、授权目录、v3 消息和全部激活取消用例。保留首轮报告，不以通过复跑抹掉失败。
- 首次误用 Windows PowerShell 5 启动现有 UTF-8 隔离脚本，解析失败，未进入数据库/测试；改用当前 PowerShell 7 后专项正常执行。临时单项诊断脚本首次缺 `PSScriptRoot` 同样未开始 SQL，明确工作目录后通过。没有修改工程脚本或打印凭据。
- 完整 `npm test` 18 项 Node/Electron、249 项普通 Rust、0 失败，证据 `activation-cancel-engineering-2026-10-02.txt`；默认 59 ignored 不算通过，以上独立标记库入口已实际另跑。最终生产构建 `activation-cancel-final-build-2026-10-02.txt` 通过，保留既有 LNK4098/LNK4099；首次沙箱内构建为 Vite externalize-deps 的 spawn EPERM，原失败日志 `activation-cancel-build-2026-10-02.txt` 保留，获准的本机环境复跑通过，无源码修复。最终格式、全 workspace/all-targets Clippy 与核心 FFI 通过，证据 `activation-cancel-final-static-2026-10-02.txt`，此前静态日志亦保留。源码没有页面改动，不重复模拟群 UI/风格截图或三客户端演示；群服务器回归在完整 59 项中实际执行，原三客户端证据保留。
- 本轮只实现 Rust/服务器取消及密文结果接口，不增加业务 IPC或页面。原凭据、私钥和会话令牌不进入页面，T22 格式不变。未运行新长期测试，用户允许的短测不计作双 Windows、系统交互、强制终止或独立审查。真实用户资料/旧后台测试/未跟踪预览和 src-tauri 保留；本机激活任务/取消意图持久化、正常 Windows 档案/租约/后台/IPC、媒体/旧操作、新备份/历史仍待接，T23 整体不勾选。

## 2026-10-02 明确协议启用与设备激活短测

- 新共享激活原语 6/6、0.02 秒：原根签名/完整目录、第二端不能启用、Curve/Ed 两私钥一致性，原证明摘要/字节重试；原点/阶段/时限/未知版本/坏密文/篡改秘密/签名及挑战移植均拒绝，撤销阶段不能激活。访问/刷新令牌仅设备专属密文返回，另一密钥不能解封；固定合成令牌不在公开 JSON 中。不是独立协议审查或内存取证。
- Rust SDK 3/3、0.09 秒：已确认根签名及状态一致性、未知字段/响应上限、307 不转发、错本机设备不发送口令；本机合成 TCP，无真实账户。实际 SDK 的状态/挑战读取及证明/解封由下述 v3 真服务联调覆盖；私密输入/证明/会话无 Debug，不在业务 IPC 中。
- `device-activation-2026-10-02T02-00-16-851Z.json` 5/5、45.27 秒，新的随机标记 PostgreSQL/真实 Axum/HTTP、合成身份：原设备明确启用、旧待收队列拒绝及清空后幂等切换、迟到旧投递拒绝；新 challenge/证明成功回包丢失后原编号/原证明重试、只两设备/一第二端会话、结果密文一致；刷新竞争一次消费，原会话结束后原证明不能再恢复。
- 已激活第二设备旧密码登录/群 GET/无签名删除原设备均拒绝，原设备群仍 200，账号单公钥查询返回原根公钥；有效设备/错误申请凭据/坏证明/原阶段撤销拒绝、没有签发第二端会话；签发后的撤销使访问/刷新失效，密码 hash 变化后的旧申请不能完成。这是服务 API 证据，尚未执行 Windows 真实群 UI 的第二端入口隔离。
- 原 `direct-delivery-2026-10-02T01-52-56-039Z.json` 11/11、78.52 秒：改为真实原根启用与双密钥激活接口，未通过 SQL 插入第二端 operational 会话；旧负载 SQL 夹具仍只用于额度边界，合法旧协议在已切换账号前被升级门禁拒绝。后续全专用入口 `database-2026-10-02T02-05-55-275Z.json` 53/53、0 失败/跳过，覆盖更新后的 Rust SDK、四存储/独立 ACK、取消重试和旧单设备/群/注册刷新基线。报告旧 scope 文本仍保留当时值，当前测试入口已更新说明。
- 完整工程 `device-activation-engineering-2026-10-02.txt` 为18 Node/Electron、244 普通 Rust、0 失败；默认 53 ignored 不算通过，以上专用入口单独执行。生产构建 `device-activation-build-2026-10-02.txt`、最终格式/全 workspace/all-targets Clippy/核心 FFI `device-activation-final-static-2026-10-02.txt` 全通过，保留 LNK4098/LNK4099。
- 设备专项 `trusted-devices-2026-10-02T02-13-53-742Z.json` passed，98 项及既有离线示例，90 秒含构建；新增原语和 SDK 均已纳入可重复入口。初次编译缺已有时钟引用/事务生命周期及测试两个 Challenge 名称冲突已修正并复跑，不把编译失败算测试通过；事务内刷新验证改用同一连接避免额外连接池等待，静态和实际刷新竞争通过。
- 本轮只触及 Rust/服务器/专用入口，无页面改动，不重复模拟 UI/风格截图。原客户端资料、后台测试、未跟踪预览/src-tauri 保留；未启动新长期测试，不推送、安装、签名。服务端正式会话已实现，Windows 激活原任务/证明持久化、会话选择与后台/IPC/页面、媒体/旧操作、新备份/历史授权仍待接；双 Windows/真实系统/独立审查与平台整体回退边界待验，T23 整体不勾选。

## 2026-10-02 v3 消息协调器短测

- `direct_api_test` 6/6（0.06 秒）：原点/编号/摘要/时间及 ACK 受众绑定，unknown 只可作为查询结果，取消返回 unknown 拒绝；错字段/重复 ACK/非法页/越界、32 KiB 声明及分块累计、截断均失败。真实本机 TCP 返回 307 后另一个监听器未收到请求，ACK 非 204 不清队列。均为合成服务响应，不是伪造实际服务器接受证明。
- `direct_coordinator_test` 4/4（1.38 秒）：原生保护临时 SQLite、真实本机 TCP/同步屏障；查询期间取消增加修订，旧接受回包不覆盖意图；令牌轮换和锁定后解锁仍拒绝旧租约，原任务保留，续步只处理原包。未发布取消本机幂等，无消息查询/提交。另旧加密封套缺取消字段的兼容用例通过。不是 Windows 原生锁屏、强制终止或内存取证。
- 设备专项 `trusted-devices-2026-10-02T01-17-33-115Z.json` passed，89 项及原离线示例，235 秒包含构建/竞争等待；仅随机系统目标和隔离资料。专用 PostgreSQL 16.14 `database-2026-10-02T01-16-39-858Z.json` 为 48/48、0 失败/跳过；普通 ignored 不算通过。无业务库读写、凭据输出或仓库保存。
- v3 实际专项 `direct-delivery-2026-10-02T01-13-11-637Z.json` 初批 11/11、49.84 秒；最后 `direct-delivery-2026-10-02T01-30-28-064Z.json` 11/11、37.43 秒。两新增协调器用例使用真实 HTTP/PostgreSQL及四份 Windows 原生保护 SQLite：丢接受回包后本机请求取消，重开查询确认实际已经接受；独立 ACK 成功回包丢失后原 ACK 重试，自己的副本及第二端回复通过。未钉源根时不解密/不落记录，错误指纹拒绝；独立确认后继续原队列。SQL 仅一条原接受记录，未重新签发副本。
- 目录前进后旧包冲突仍保留原 wire；持久取消后重开，取消 fence 回包丢失再查原结果完成；旧包迟到仍 cancelled、无受众队列，显式新建才有新编号。处理最后一个包仍提示本机 ACK 工作，发送并确认后队列可空。第二设备 operational 会话由 SQL 夹具写入，不是正式激活、普通登录或四个实际 Windows 客户端；poll 包计数不被称为新增未读或通知。
- 首轮工程 `message-coordinator-engineering-2026-10-02.txt` 在并行执行专用入口时，服务器测试 EXE 因 OS error 32 未启动，按失败保留；相关进程完成后单独复跑 `message-coordinator-engineering-final-2026-10-02.txt` 18 Node/Electron、235 Rust 通过。最后 ACK 工作标记修改后，顺序完整复跑 `message-coordinator-engineering-complete-2026-10-02.txt` 18/235、0 失败，随后生产构建 `message-coordinator-final-build-2026-10-02.txt` 通过；此前构建日志同样保留，既有 LNK4098/LNK4099 不隐藏。
- 初次编译错误的指纹函数引用、同步锁解引用和后续 Clippy 测试模块位置已修正。最终格式/全 workspace/all-targets Clippy/FFI `message-coordinator-final-static-2026-10-02.txt` 通过；初版静态日志另存 `message-coordinator-static-2026-10-02.txt`。没有把未启动的服务器测试当作通过，也没有改变旧 SQLite/服务器迁移。
- 本轮无页面/群协议/原产品网络入口变更，不重复群模拟 UI、风格截图或三客户端演示；原产品 PostgreSQL 回归在上述 48 项实际执行，前批三 Rust 客户端证据保留。没有运行新长期测试、推送、安装或签名。正式激活、应用后台及 IPC/页面、旧操作/媒体、新备份/历史授权仍待实现；双 Windows、真实系统场景及独立审查继续待验，T23 全体验不勾选。

## 2026-10-02 v3 HTTP 原子投递短测

- 新随机标记 PostgreSQL 16.14、真实 Axum/reqwest HTTP、合成隔离身份；`database-2026-10-02T00-51-27-925Z.json` 全量 45/45、0 失败/跳过（原 37 + 初批 8）。新增联调修复后 `direct-delivery-2026-10-02T00-55-54-010Z.json` 专项 9/9、47.17 秒含构建/锁等待；最后发送方拉黑/媒体拒绝反例复跑 `direct-delivery-2026-10-02T00-58-39-505Z.json` 为 9/9、0 失败/跳过，24.32 秒。新增真实本机存储联调单独执行，重叠项不重复计数。普通 npm 的 ignored 只表示另行测试，不算通过。
- 两账号/四套独立密钥真实 HTTP：原端或第二端发送，完整三目标、本人另一端副本、原 digest/时间重试和查询；各设备 processed/rejected 独立签名 ACK、响应丢失后的重复请求不改变结果、其他队列不受影响；全部目标完成后密文清除、回执及 ACK 仍可查询。第二设备 operational 会话由测试 SQL 夹具写入，不声称生产激活/登录已开放。
- unknown 不当作取消；提交与取消并发只出现同一终态，取消先完成后原包始终 cancelled、无队列；已接受先完成则取消仍返回 accepted。修改原摘要、遗漏受众、错签名/账号/会话、漏序及伪造/改选 ACK 拒绝，无部分收件或 head；超过 8 KiB ACK 请求明确 413。此为短竞争用例，不称为完整长期负载。
- 目录前进使未接受旧包冲突，原历史取消仍可验签；已接受结果不因对方目录前进重加密。撤销原队列 ineligible、operational 会话失效；重新加入的新阶段无旧队列，从新序号阶段接新包。双方联系策略在取包/发布时核对；65 条中文/emoji补收分页/ACK顺序、拉黑后不可读取及解除后原队列继续通过。最大正文的返回页实际不超过 512 KiB。
- 两发送者并发竞争最后额度、v2/v3 共享 1,000 项/10 MiB、配额失败无本人副本部分提交或发送链前进；ACK 释放后相同原包可接受。999 项和 10 MiB 旧负载由测试 SQL 构造，仅验证额度边界，不称为已实际发送这些正文。
- 新真实 HTTP/原生存储联调：发送状态先落库，接受结果不落本机后重开，原包字节一致，经实际原结果查询确认原子历史；接收后关闭/重开仍保留原 ACK，HTTP 原 ACK 重试可释放队列，隐藏后原包重放只排原 ACK，不重新显示。两临时 SQLite、随机原生目标，固定合成正文；不是强制终止/断电、双 Windows 或完整后台协调器。
- 首轮 `direct-delivery-2026-10-02T00-48-04-459Z.json` 为迁移预检 not_executed，列名修正后初批 8 项通过（`00-49-32-835Z`）；编译中的错误测试函数引用已修正。新增第九项首轮失败保留 `00-54-15-577Z`：夹具先请求路径绑定原生保护而未创建 SQLite 文件；调整为既有初始化顺序后最后 9 项通过。没有隐藏失败或输出/保存测试凭据。
- 完整工程 18 Node/Electron、224 普通 Rust、0 失败（`direct-delivery-engineering-2026-10-02.txt`）；生产构建 `direct-delivery-build-2026-10-02.txt`、最终格式/全 workspace/all-targets Clippy/FFI `direct-delivery-final-static-2026-10-02.txt` 全通过，保留 LNK4098/LNK4099。新联调夹具最终静态检查通过；普通工程运行在新增第九个 ignored 专项之前，其实际运行另以上述专项为准。
- 三个真实隔离 Rust 客户端、真实服务及另一个新随机标记库短回归通过（`group-integration-2026-10-02T00-56-23-100Z.json`）：群补收/丢 ACK/重开、权限阶段、协作、附件认证下载、合成 WebM/Opus、活动及 T22 v2 档案。旧产品链路结果不作为新增 v3 正常激活、实际麦克风或双 Windows 证据。
- 没有修改页面，不复跑模拟 UI/风格截图，不启动新长期测试；保留现有后台测试及真实资料。正常激活/后台租约、媒体/旧操作、新备份/选定历史仍待实现，双 Windows/原生系统/独立审查保持待验。T23 全功能不勾选。

## 2026-10-02 v3 消息持久化与覆盖升级短测

- `direct_store_test` 9/9，最终完整运行 13.40 秒：原消息号/密文/签名重开不重加密，发布结果未知不得本机取消，明确未接受后保留冲突再取消；接受原子历史/发送链，重复确认不新增，清终态后旧编号不能重建。四份独立临时 SQLite、四套密钥和随机系统记录收件，同设备 ACK 字节重开/重试一致，本人副本与对方来信/对端元数据区分，重复补收重排原 ACK且不恢复隐藏卡片。
- 签名/资格不符无收件/ACK；已认证头的正文移植失败被隔离，rejected 原 ACK 持久化，后续正确序号继续。当前撤销拒绝原资格，错身份/私钥拒绝；历史 prefix 读取不降低当前目录，过时待发保留原包且不重签。65 条中文/emoji分页及重开、隐藏、重放通过。收到包/结果均由测试夹具构造，不是实际 v3 HTTP/WS。
- 原生凭据仍最新时恢复接收前旧 SQLite 被拒绝，源码中的固定测试正文在源 SQLite 字节中不存在。确定性外部准备/最终写失败验证无部分正文/head/ACK返回；同句柄重试恢复原变更，仅一记录/ACK。内存外部记录用于故障注入、journal 实际 DPAPI；不称为磁盘满、断电或完整内存取证。
- witness 新增 3 项，合计 13/13：缺 coverage 字段/旧 marker 表的 v1 实际升级保留原任务；v2 回退拒绝；pending 升级在 SQLite before/after 分支恢复，未保护消息表和缺日志拒绝。原生 6 项与此前控制/档案回归也通过。暴露的 SQLite 外层 UPSERT 覆盖触发器 OR IGNORE 导致唯一键失败，改为显式不存在判断并通过第二条接收/历史/同句柄恢复测试；临时 SQL 诊断仅打印约束名称且已移除，未输出秘密。初次 Clippy 参数数量/冗余问号已修正。
- T22 四项回归确认五张 v3 空/待发表不进入恢复库，v1/v2 继续可读；第九项存储用例确认当前身份含 v3 历史时导出明确失败、无结果文件且原正文仍可读。新载荷/离线展示尚未实现，不把“拒绝遗漏”当作备份接入完成。
- 最终 `npm test` 18 Node/Electron、224 普通 Rust、0 失败（`direct-store-final-regression-2026-10-02.txt`）；初轮 223 项报告保留 `direct-store-regression-2026-10-02.txt`。局部最后 9 存储/13 witness/4 备份、全 workspace Clippy/FFI 另见 `direct-store-final-checks-2026-10-02.txt`；最终静态 `direct-store-final-static-2026-10-02.txt`，生产构建 `direct-store-build-2026-10-02.txt` 全通过，保留 LNK4098/LNK4099。
- 设备专项 `trusted-devices-2026-10-02T00-31-13-830Z.json` passed（79 项及既有离线示例，116 秒含构建和锁等待）；新随机标记库实际 37/37、0 失败/跳过（`database-2026-10-02T00-29-51-730Z.json`），为原授权/单设备/群基线，不是 v3 事务投递测试。没有访问业务库或保存测试凭据。
- 另一个新随机标记库、真实服务及三个隔离 Rust 客户端短回归通过（`group-integration-2026-10-02T00-39-00-667Z.json`）：ACK/发布回包丢失、重启补收、隐藏重放、成员移除/再加入、提及/置顶/投票、群附件认证下载、合成语音、活动报名/关闭/取消及 T22 v2 离线档案。验证现有产品链路，不作为新增 v3 网络投递或真实麦克风/双 Windows 的证据。
- 本轮无页面/网络入口修改，不重复模拟 UI/风格截图或启动新长期测试。正常第二设备消息/会话仍禁用，远端原子投递/结果认证、独立 ACK 队列、媒体/备份/选定历史和旧编辑仍待接；平台及源数据同时回退、初始未提交分配、双 Windows/原生系统与独立审查继续待验。T23 完整体验不勾选。

## 2026-10-02 多设备单聊协议短测

- `direct_message_test` 9/9（0.05 秒）：两账号各根/第二设备、共四套独立 Rust 密钥，单/双设备与根/第二发送组合逐目标中文/emoji往返；对方全部设备及自己的另一台设备必须齐全，源设备不是网络目标，原 wire 重试与 digest 一致。均为同一测试进程纯协议，不是四个网络客户端。
- 修改公共头/源阶段/对方根/授权阶段/时间/类型/序号/密文/承诺/签名拒绝；遗漏/重复/额外目标/乱序及伪造物化目录拒绝。发送者重新签署移植正文时，外层认证可通过但内部上下文拒绝；替换一个目标为另一正文/盐后拒绝内容承诺，其他正确副本仍可读。没有打印正文私密盐或设备私钥。
- 旧授权目录与撤销/重新加入后的当前快照不匹配；新设备无法用其独立密钥读取旧受众密文。成员前进后新阶段首条从 1 开始，旧 head 不能用于新阶段；同阶段漏序/错 hash/重放拒绝。旧已接受记录只能对照精确旧证据验证；本次没有实现远端授权/队列，不能声称这些纯函数已经拒绝真实远端下载。
- 独立 ACK 验证 processed/rejected、账号/设备/原授权阶段/原批次绑定与相同 ACK 重试；错设备/发送者代签、结果修改和跨批次移植拒绝。16 KiB 正文边界、超限/空文/非法 UTF-8、错 Curve/Ed 私钥、未知版本/字段、空签名和 wire/ACK 总量限制通过。临时正文/盐有擦除路径；测试不构成内存取证或独立安全审查。
- `npm test`：18 Node/Electron、212 普通 Rust、0 失败，`direct-protocol-regression-2026-10-02.txt`。格式、全 workspace Clippy/FFI `direct-protocol-checks-2026-10-02.txt`，生产构建 `direct-protocol-build-2026-10-02.txt` 均通过，LNK4098/LNK4099 保留。测试初次 Clippy 拒绝复杂闭包类型，改用函数指针后全检查通过，不掩盖失败。
- 设备专项 `trusted-devices-2026-10-01T23-35-18-862Z.json` 为 67 项及既有离线示例 passed，96 秒含构建锁等待；专用 PostgreSQL `database-2026-10-01T23-36-21-774Z.json` 37/37、0 失败/跳过，为现有授权/群/单设备投递回归，不是新增 v3 事务测试。只使用新随机标记库、隔离身份/DPAPI 路径与精确随机系统测试目标。
- 最后将明文内部帧一次预分配，避免追加私密盐/正文时扩容释放旧副本，并补签名无效的拒绝 ACK 对照；9 项协议短测、全 workspace Clippy/FFI 再通过（`direct-protocol-final-checks-2026-10-02.txt`），最终生产构建日志 `direct-protocol-final-build-2026-10-02.txt`。仍不把局部擦除路径描述为已完成全部内存取证。
- 本轮没有修改页面或网络入口，不重复模拟界面/三客户端/长期测试；上一产品增量结果保留，不能算作本次 v3 多人联调。v3 待发/收件落库、实时原子接收与独立队列 ACK、正常激活、旧消息操作、附件授权/备份/历史迁移仍待接入；第二设备普通登录仍拒绝。双 Windows、系统故障、独立审查和系统凭据同时回退边界继续待验。

## 2026-10-02 T23 默认桌面高水位短回归

- 普通构造与自定义 keystore 构造选择生产保护，隔离配置必须显式传入并具备数据库/keystore 文件。原设备和加入端 `open_protected` 在业务读写/网络授权前验证，现有类型化 IPC 数量不变，无私钥、记录正文或 namespace 进入页面。
- 新核心短测：同库两身份/设备合法任务变更、错 scope 隔离及重开；首次原任务成功捕获代次 1；终态整理遇未知文件保留，删除已确认终态后只清随机目标，另一档案系统记录不变，生产拒绝清理。核心目录/任务/DPAPI 原回归全部通过。
- 新桌面 2/2（0.53 秒完整运行）：原设备旧授权目录拒绝且保留正常 keystore；加入端恢复取消前活动任务拒绝、放弃/整理也拒绝，密钥字节不变，另一档案可读且不激活聊天。新构造测试确认默认生产配置，原 2 原设备/3 加入端锁定、令牌、档案切换、迟到回包和句柄清理用例均通过。
- 原生 6/6（3.48 秒完整运行，含一个由主用例启动的子进程 helper）：子进程用临时 DPAPI 文件读钥，native pending 成功后、SQLite commit 前 `process::exit(23)`，不运行析构；重开恢复原任务号、原凭据、修订 1/请求取消，journal 清理。原生互斥/八目标并发/旧库与缺记录拒绝同样通过。此为真实进程终止，但不是断电或磁盘满，也没有证明 Windows 系统凭据和数据库一起回退可检测。
- 真实 Node/Rust stdio 用例强制终止子进程后重开原草稿；保存本机放弃后恢复旧 SQLite，查询/整理被固定安全错误拒绝；恢复匹配终态副本后可整理，原身份文件字节不变。私有测试参数缺路径/namespace 时在启动默认资料之前拒绝，页面命令不包含测试清理；结束全部进程后精确清随机目标。
- 完整 `npm test` 18 Node/Electron、203 普通 Rust、0 失败；`device-protection-regression-2026-10-02.txt`。格式、全 workspace Clippy、FFI `device-protection-checks-2026-10-02.txt`，生产构建 `device-protection-build-2026-10-02.txt` 全部通过，保留 LNK4098/LNK4099。设备专项 `trusted-devices-2026-10-01T23-05-02-104Z.json` 为 58 项及离线示例 passed（53 秒含构建）。实现中测试方法名/返回类型和 Clippy 测试模块位置错误已修正并复跑，不把编译失败称为通过。
- 专用 PostgreSQL 37/37、0 失败/跳过（`database-2026-10-01T23-03-40-892Z.json`），真实原端/加入档案HTTP授权各阶段回包丢失及重开现使用同一随机原生保护配置；另三真实 Rust 客户端群附件/合成语音/活动/T22 v2 通过（`group-integration-2026-10-01T23-06-57-113Z.json`）。使用新随机标记库、隔离身份和临时路径，无业务库读写或凭据保存。
- Chromium 36 秒、深浅/宽窄各 8 项原端和 10 项加入端，0 错误；`devices-ui-9xbHqC/result.json`。实际核对深色宽窗加入指纹与浅色窄窗原端截图，无横向溢出；模拟业务 API 且无网络，不代表真实 GUI/服务端一体联调或双 Windows。页面/CSS 本轮未修改，不重复风格/群/备份截图。
- 创建在首次任务持久化之前中断可能留下未初始化密钥分配，继续保留且不重新生成已知申请；未知临时文件保留供修复。首次登记前的新鲜度、系统凭据和库同时回退、另一 Windows 用户/机器、原生锁屏/休眠/断电/磁盘满以及独立协议审查仍待验；未运行新长期测试。正常第二设备登录/消息/历史仍未开放，T23 完整体验不关闭。

## 2026-10-02 用户级原生同步短测

桌面防护接线的并行测试出现 SQLite marker 尚存、`CredReadW` 返回缺记录；单项通过不能解释该失败。临时仅调用栈诊断定位首次/重开校验，诊断代码已移除。八个随机原生目标同时各 20 次 DPAPI 写入/重读，直接复现缺记录；未输出真实身份或凭据。此次证据只能说明本运行环境的并发行为，未归因于所有 Windows 环境或声称完成系统独立审查。

互斥范围从单目标改为当前用户 SID 绑定的 Global 锁，全部本应用目标的同步提交/清理串行，不跨 await；数据库/随机命名空间的绑定保持，缺记录仍拒绝，生产不能重置。5/5 原生入口通过（3.18 秒，包含一个由主用例实际启动的子进程 helper），`device-native-user-lock-2026-10-02.txt`；包含八目标/160 次写读、父子各 30 次共同记录更新、2048 字节与路径隔离、SQLite 回退和缺记录拒绝。随机目标精确清理，核心 Clippy 通过。产品接线的测试另记，不能把这项底层修复当作默认桌面流程已交付。

## 2026-10-02 T23 外部高水位核心短测

- 引擎 9/9：旧任务库/撤销前目录回退无需调用者 checkpoint 即拒绝；缺外部记录、非法绑定/结构、pending 日志缺失/损坏拒绝；安全存储准备失败不提交，提交后完成失败可重开，恢复原变更/编号/密文；首次捕获中断及根确认/终态删除。内存外部记录用于确定性故障注入，日志实际使用同用户 DPAPI；不是强制断电或磁盘满。
- 原生入口 4/4（0.62 秒完整工程运行；其中一个 helper 在普通运行空返回，父用例真实启动该子进程）：随机隔离 Credential Manager 目标、2048 字节 DPAPI 记录、路径隔离/生产删除拒绝、旧 SQLite/缺记录拒绝、父子各 30 次并发更新结果 60。测试目标精确清理，无凭据枚举/业务身份读取。首次受限环境父子读取失败；另一个夹具使用无效非 UUID 设备编号，修正后以原生测试权限复跑 4/4（0.77 秒），随后完整工程并行运行也通过。未把首轮失败隐去。
- T22 原生保护任务库导出/恢复 4/4（9.29 秒）：恢复库无 `device_control_tasks`、`device_state_witness`、授权根/事件及加入绑定，正常 65 条历史往返保留，原外部状态随后验证仍有效。只涉及随机测试记录，不操作真实凭据。
- `npm test` 17 Node/Electron、196 普通 Rust、0 失败；`device-witness-core-regression-2026-10-02.txt`。新增 `synchronous=FULL` 后构建/核心与专项重编译通过；格式、全 workspace Clippy、FFI 日志 `device-witness-core-checks-2026-10-02.txt`，生产构建 `device-witness-core-build-2026-10-02.txt`，保留 LNK4098/LNK4099。专项 `trusted-devices-2026-10-01T22-42-38-966Z.json` 为 52 项及离线示例 passed，48 秒含构建。所有报告在 `target/test-results/`。
- 数据库首轮显式调用旧 Windows PowerShell，UTF-8 脚本解析失败，尚未连接数据库；随后使用当前 PowerShell 7 和原隔离入口重跑 37/37、0 失败/跳过（`database-2026-10-01T22-43-44-457Z.json`）。未保存/输出测试凭据，未访问业务库；原生防护与协议/产品默认流程分开验证。
- 三个真实 Rust 客户端群回归通过，报告 `group-integration-2026-10-01T22-46-16-715Z.json`：ACK/发布回包丢失、重开、移除/再加入、协作、文件认证、合成语音、活动及 T22 v2。不能替代真实双 Windows/麦克风验收；本轮无页面改动，未复跑模拟界面和风格截图。
- 最后复核增加“初始化失败后的同一句柄仍拒绝操作”，9 引擎/4 原生/7 任务/8 目录共 28 项复跑通过，格式、全 workspace Clippy、FFI 再通过（`device-witness-core-final-checks-2026-10-02.txt`）。备份改用原生隔离记录后 4 项另行通过；最终生产构建另记 `device-witness-core-final-build-2026-10-02.txt`。没有将先前完整测试当作这些后续修改的唯一验证。
- 本次完成显式核心接口及原生适配，桌面授权协调器默认启用/加入档案生命周期未接通；不声称页面实际授权已获防回滚。只保证系统凭据未一起回退时的应用目录/SQLite 回退拒绝；无硬件单调计数器，不能抵御凭据和数据库同时恢复。另一 Windows 用户/机器、原生系统锁/强制进程终止、完整短联调和独立审查仍待执行。未运行新长期测试，T23 全体验保持未验收。

## 2026-10-02 T23 加入端短测

- 独立 DPAPI 4 项通过：正常身份文件字节保留、独立双密钥及原任务重开、档案/任务库移植和公私钥/版本/令牌/大小拒绝、任务库缺失不重建、十次并发分配仅八份成功、未知文件/非法路径保留和空分配清理。临时 DPAPI 文件为同 Windows 用户，不代替另一用户/机器。
- 桌面 3 项通过：业务命令拒绝私钥/路径/令牌、普通身份保留、锁定及令牌更新后的原任务恢复、本机放弃/整理幂等；真实 TCP 延迟 401 后切档案，旧请求不发送密码；开始请求等待时暂停/恢复、旧结果不落库，旧 SQLite 句柄仍存活时拒绝整理。删除任务行/任务库作为故障夹具，拒绝生成新编号，不称为实际磁盘满或强制终止。
- 新 Node 用例使用真实 Rust 子进程和明确临时数据库/keystore，验证 stdio 创建/查询、未知服务器不发密码 POST、进程正常停止重开保持原编号/指纹、本机放弃/整理及原身份保留。主进程固定暂停事件和全部加入接口在锁定/离线档案中拒绝；不是实际 OS 锁屏。
- 真实双端桌面命令/HTTP/PostgreSQL：原根独立确认、新设备双指纹一致，申请/意向/挑战/证明/授权各一次成功后 503，档案/进程状态对象重开后查询原任务；取消 DELETE 回包丢失后确认远端取消并整理，未启用服务器显示未启用且本机未签署结束单独标记。原 keystore 字节不变，加入端正常 keystore 不存在，普通设备数仍一台、第二设备普通登录 403。完整专用 PostgreSQL 37/37、0 失败/跳过（`database-2026-10-01T21-55-36-199Z.json`）。这里数据库/对象重开不是强制终止实机验收。
- 最终 `npm test`：17 Node/Electron、183 普通 Rust、0 失败，默认 ignored 的 37 项已由专用入口全部执行。设备专项 39 项及离线示例通过（`trusted-devices-2026-10-01T21-56-21-726Z.json`，76 秒含构建）；完整构建/格式/全 workspace Clippy/FFI 通过，日志 `device-join-final-regression-2026-10-02.txt`。保留既有 LNK4098/LNK4099。
- Chromium 模拟业务 API、无网络：深浅色/1280×900 与 390×844，各 8 组原设备及 10 组加入端，40 秒、0 renderer 错误/横向溢出；`devices-ui-tNDe5w/result.json`，实际核对深色宽窗与浅色窄窗加入指纹截图。覆盖真实登录页入口、React StrictMode、密码清空、独立根指纹输入、原申请恢复、并发取消与迟到结果、档案切换、系统暂停、损坏保留及空分配清理。此结果不代表真实双 Windows 或完整前后端 GUI 联调。
- 既有真实三 Rust 客户端群/附件/合成语音/活动/T22 v2 回归通过（`group-integration-2026-10-01T22-02-47-958Z.json`）；群 UI 宽窄各 16 组（`group-ui-LrJb20`）、备份各 8 组（`backup-ui-zm8P9m`）、风格 72 截图（`ui-style-fvIvte`）通过。

只使用合成身份、明确临时目录、新随机标记库，不访问业务资料，不启动新长期测试，不安装/推送。未执行或未实现：另一 Windows 用户/机器、真实锁屏/休眠/强制终止、磁盘满/权限拒绝实机场景、外部可信高水位、正常多设备收发/激活、历史授权、独立协议审查。T23 仍保留未勾选；短测满足本轮用户执行约定，不能扩大为这些结论。

## 2026-10-02 T23 取消边界短测

36/36 专用 PostgreSQL 实际通过，新增场景使原挑战提交成功但回包丢失，由另一原设备调用路径授权后，再由加入任务和原挑战任务同时请求取消；两端从签名目录确认原授权完成，未出现反复冲突或伪取消。报告 `database-2026-10-01T21-23-12-670Z.json`，普通设备仍为一台。

新增核心用例使用真实本机 TCP 401 对照未签署/已签署意向：前者记录仅本机结束并清除申请凭据，重开标记保留；后者保持取消待确认及原意向/凭据，不把认证失败当作远端取消。专项共 32 项及离线示例（`trusted-devices-2026-10-01T21-24-39-478Z.json`）、完整 16 Node/Electron/176 普通 Rust、生产构建/格式/全 workspace Clippy/FFI 通过，日志 `device-cancel-race-2026-10-02.txt`。上述本机结束不保证远端行已删除；未发布意向使其不能授权，迟到开始的行可能保留至过期，不等待完整期限。

本轮只做短测，不代替双 Windows、原生系统或独立审查；加入端独立档案/页面继续实现。未启动新长期测试，未操作业务资料或推送。

## 2026-10-02 T23 原设备桌面短测

- 新增真实 Rust 桌面命令/HTTP/PostgreSQL 场景通过：DPAPI 保存及重开、核对错误指纹拒绝、挑战/授权、授权成功回包丢失后恢复原任务、目标不符的撤销拒绝、取消结果确认、正式撤销、切换隔离身份及默认关闭服务器。原普通设备仍只有一台，`messaging_enabled=false`，公开视图不含令牌/私钥/申请凭据。完整专用 PostgreSQL 35/35、0 失败/跳过，报告 `database-2026-10-01T21-07-14-183Z.json`。
- 新增两个 Windows Rust 用例通过：业务命令拒绝私钥/令牌/口令和缺少撤销确认；真实 TCP 请求等待时暂停并更新令牌、恢复后拒绝原迟到结果，清除身份后拒绝操作。临时 DPAPI 文件仅限同用户，不代替跨用户/机器。
- 主进程模拟用例分别以未启用/已启用启动锁运行：系统锁屏立即拒绝业务，解锁仍拒绝旧回包，休眠恢复不覆盖锁屏；暂停/恢复不出现在页面 API，离线档案不能调用授权。这里注入 Electron 事件，不是实际锁屏/休眠。最终 `npm test` 为 16 Node/Electron、175 普通 Rust、0 失败，35 项默认 ignored 已由专用入口执行。工程日志 `device-desktop-final-test-2026-10-02.txt`。
- 专项 `trusted-devices-2026-10-01T21-14-39-575Z.json` 共 31 项及离线示例通过。真实三客户端群集成通过（`group-integration-2026-10-01T21-12-55-103Z.json`），含群文件发布回包丢失/重启、合成语音往返、活动改选/关闭/取消/重新加入与 T22 v2 离线恢复。
- 设备界面真实 Chromium、模拟 API：深浅色/1280×900 与 390×844，各 8 组、14 秒，0 renderer 错误/横向溢出；`devices-ui-XDCZdD/result.json`，实际查看深色宽窗及浅色窄窗的完整指纹确认截图。群 UI 各 16 组（`group-ui-OVri8E`）、备份各 8 组（`backup-ui-4mZs26`）、风格 72 截图（`ui-style-w0x703`）回归通过。早期错误/过渡帧报告保留，只采用最终证据。
- 生产构建、格式、全 workspace/all-targets Clippy、核心 FFI 通过；日志 `device-desktop-regression-2026-10-02.txt`、`device-desktop-final-build-2026-10-02.txt`，保留既有链接警告。专用随机标记库及合成身份，不访问业务资料，不启动新的长期测试，不推送。

未执行/未完成：加入端独立 Windows 档案和页面、正常第二设备登录/多设备消息/历史、外部可信高水位、双 Windows、真实系统锁屏/休眠、强制进程终止和独立协议审查。本次只完成原设备授权管理，不勾选 T23 或相关实机验收项。

## 2026-10-02 T23 协调器短测

实际 PostgreSQL 34/34、0 失败/跳过，报告 `database-2026-10-01T20-46-40-814Z.json`。新增协调器直接驱动两端隔离库，验证未知申请需要新输入密码、五阶段成功后 503 的原任务恢复、目标/原根错误指纹拒绝、仅验链确认成功、取消回包丢失幂等及另一撤销事件让原版本进入冲突且不重签。

新增 3 项核心测试：在真实 TCP 请求等待期间失效租约，迟到票据不改变任务；令牌轮换保持已锁定；历史时间夹具使原挑战过期结束且原签名不变，无需等待完整租约。专项 29 项及离线示例通过（`trusted-devices-2026-10-01T20-52-21-904Z.json`）。完整 `npm test` 为 15 Node/Electron、173 普通 Rust、0 失败，默认 ignored 的 34 项由上述专用入口执行；输出 `device-coordinator-regression-2026-10-02.txt`。生产构建、格式、Clippy、FFI 通过，既有链接警告保留。桌面真实锁定/退出接线及进程终止、跨 Windows 未验收；未新增长期测试。

## 2026-10-02 T23 加密任务及取消短测

- 专项 26 项及离线示例 passed，报告 `trusted-devices-2026-10-01T20-29-07-319Z.json`；新增 7 项验证原编号/凭据/意向/挑战/证明/签名重开一致、密文跨身份行移植/篡改及错私钥拒绝、指纹错误/旧确认不钉根、版本冲突、失效租约/旧回调不提交、终态无凭据。
- 同一 Windows 用户、显式临时 DPAPI 文件重载后重建绑定及原任务；未测不同用户或机器。数据库写失败用 SQLite 触发器注入，不称为实际磁盘满。
- 专用 PostgreSQL 33/33、0 失败/跳过（`database-2026-10-01T20-24-43-062Z.json`）：签名取消/接受竞争、迟到授权/撤销拒绝、错根/摘要、4096 组合额度与边界幂等通过；额度只用路由元数据夹具。
- 两个独立客户端库的真实 Rust/HTTP/SQL 场景通过。代理在服务器接受申请、意向、挑战、证明、授权后各改一次 503；重开查询原记录，原签名不变。模拟失效租约拒绝迟到页，重新取得租约后验签确认成功；取消撤销后旧提交拒绝。
- 完整 `npm test`：15 Node/Electron、170 普通 Rust 通过，默认 ignored 的 33 项数据库已另行实际执行。输出 `target/test-results/device-task-regression-2026-10-02.txt`。生产构建、格式、全 workspace/all-targets Clippy、FFI 通过；T22 往返确认不含任务表，单项复跑通过，保留 LNK4098/LNK4099。

依用户要求只做相应短测，无新长期测试。后台协调器/IPC/真实锁定和身份切换、真正进程终止恢复、双 Windows、正常设备收发/激活、历史、平台高水位与独立审查尚待实现/验收，本次不勾选。原用户资料和未跟踪文件保留。

## 2026-10-02 T23 Rust 客户端短测

最终 `npm test`：15 项 Node/Electron、163 项普通 Rust、0 失败，31 项数据库默认 ignored（下方专用入口已全部实际执行）。完整输出 `target/test-results/device-client-regression-2026-10-02.txt`；生产 `npm run build` 通过，保留既有 LNK4098/LNK4099。本轮未启动长期测试或执行安装、推送、发布；原未跟踪预览文件和 `src-tauri/` 保留。

专用 PostgreSQL 31/31、0 失败/跳过，报告 `database-2026-10-01T19-54-47-098Z.json`。新增真实 Rust 控制客户端覆盖两轮独立密钥申请/证明/授权/撤销、本账号证据分页、可信根核对、原编号回包查询/重试、撤销后旧授权不复活及本机 SQLite 重开验链；取消/撤销/跨申请凭据不能获取授权页。每次申请保持普通登录/收发关闭。使用新随机标记库、合成账号和临时客户端文件。

`npm run test:devices:trial` 报告 `trusted-devices-2026-10-01T19-57-51-796Z.json` 共 19 项及离线示例通过；新增核心场景为末页头不符、分页断号/重复/错根/more 错误及第二条坏签名均不落库，HTTP 重定向不转发凭据、过大/非类型响应拒绝且错误不泄露正文。全 workspace/all-targets Clippy、格式和核心 FFI 编译通过。加密待发授权任务重启、平台高水位防整体回滚、桌面、历史迁移和真正多设备聊天尚待实现；双 Windows/独立审查仍待验收。

## 2026-10-02 T23 服务端短测

`./scripts/run-isolated-validation.ps1 -DatabaseOnly` 创建随机角色和标记专用库；PostgreSQL 16.14 下 30 项用例全部实际通过、0 失败/跳过。报告 `target/test-results/database-2026-10-01T19-45-11-117Z.json`。

新增 6 项真实 HTTP/SQL 场景：完整申请/挑战/证明/授权/撤销及 1 项分页补收；同账号并发申请只有一个成功；原票据重试保留设备编号/挑战；取消和授权互斥；取消后迟到提交拒绝；跨申请证明、错根/操作者及服务器挑战篡改拒绝；模拟已过期租约与修改密码使未完成申请失效；签名日志截断后读写拒绝且证据不修补；控制流程默认关闭。另验证申请凭据不能访问普通接口，授权不创建普通会话/设备，旧账号仍单设备。

模拟租约过去时间通过只修改合成测试申请的时间字段完成，没有等待 10 分钟。本批不是第二设备聊天或跨 Windows 实机验收；新单聊协议、桌面、历史迁移、目录防整体回滚和独立审查尚待实现/验证。

完整工程回归 `npm test`：15 项 Node/Electron、159 项普通 Rust、0 失败，30 项数据库在默认命令中 ignored（已由上述专用入口执行）。格式、全 workspace/all-targets Clippy 与核心 FFI 编译通过；输出 `target/test-results/device-control-regression-2026-10-02.txt`。未执行或勾选跨机/原生系统/独立审查验收。

`npm run build` 生产前端/Electron/Windows sidecar 通过；既有 LNK4098/LNK4099 保留，未打安装包或发布。

## 2026-10-02 T23 持久化验证

报告 `trusted-devices-2026-10-01T19-31-15-151Z.json`：9 项协议 + 6 项 SQLite 持久化测试及离线示例通过。实际执行重启、原编号幂等、批量中途错误整批回滚、两连接并发只有一项接受、错误根和账号隔离、日志/头篡改、已知高水位下截断/回滚拒绝。全 workspace/all-targets Clippy 和 FFI 编译通过。整份库及其中高水位同时回滚在无外部可信高水位时仍不可检测，在线目录及平台防回滚后续实现。

首次完整 `npm test` 的 15 项 Node 和所有已执行的 core/desktop 测试通过；旧 HTTP 请求大小测试发生 Windows 10053 本机连接中断，单项复跑通过，完整复跑随后记录。不把首轮整体写成通过。

最终完整复跑通过：15 项 Node/Electron、159 项 Rust、0 失败；24 项 PostgreSQL 用例在 `npm test` 中仍为 ignored，本轮没有把它们计入通过数。完整输出 `target/test-results/devices-workspace-regression-2026-10-02.txt`。`npm run build`、格式、全 workspace/all-targets Clippy（-D warnings）及核心 FFI 编译通过，保留既有 LNK4098/LNK4099。未改 UI 或 IPC，本轮不重复模拟界面验收。新增代码仍是离线基础模块，不替代服务端事务、真实第二设备登录、历史迁移或双 Windows 验证。

## 2026-10-02 T23 原语验证与短测约定

按用户最新要求，长期负载本轮使用六轮相应短测并如实记录覆盖范围，不再以完成 24h 作为本轮门槛。此前 PID 4716 已不存在，新版旧报告最终停在 216 轮/24,692 秒，保留但不记通过。本轮独立短测结果随后追加。

共享 Rust T23 新增 9 项测试及可运行离线示例通过；shared 全部 59 项测试与 shared/all-targets Clippy 通过。覆盖独立双密钥证明、签名字段篡改、错根/跨账号/跨服务器、挑战移植、边界期限、并发授权、错误撤销、原编号重试和撤销后不复活。不是两台 Windows、真实授权服务或独立协议审查证据；T23 尚未完成在线流程。

实际报告：`trusted-devices-2026-10-01T19-27-49-996Z.json` 为 passed，9 项协议测试和离线示例通过。十账号/十群/100 成员关系短测 `group-soak-2026-10-01T19-22-39-195Z.json` 为 smoke/passed，六轮、271 秒，各轮任务积压为 0，补收约 43.6–46.3 秒；涵盖文字、群文件、合成语音、活动报名、刷新、断网、重启、成功回包丢失及原阶段下载隔离。不声称长期内存稳定或完整 24h。首次本地报告入口因沙箱子进程限制未执行成功，提升执行权限后独立复跑通过，失败报告保留。

## 2026-10-01 新版 24h 执行中

独立测试 PID `4716`、执行提交 `6237ec8`，从 2026-10-01 04:23:25 SGT 开始计时；十账号、十群、100 个成员关系完成初始化，报告 `group-soak-2026-09-30T20-22-42-071Z.json` 为 running。完整时长、最终积压/补收/内存趋势及失败阶段待最终报告；不勾选长期验收。旧中断报告保留，不合并采样。

## 2026-10-01 最终自动化增量

全部 24 项专用 PostgreSQL 用例通过，包含新增单聊/群共享最后字节与最后对象额度的真实并发竞争，未突破 512 MiB / 2,000 对象。报告 `database-2026-09-30T20-19-28-447Z.json`。提交 `3b3f664` 的同机三个真实 Rust 客户端联调再次通过，报告 `group-integration-2026-09-30T20-20-08-405Z.json`。

新版十账号/十群六轮短测通过，315 秒，采样待发任务均为 0；故障记录实际含扩展回包丢失后的发布者重启和原任务恢复，以及重新加入旧附件远端下载拒绝。报告 `group-soak-2026-09-30T20-13-12-292Z.json`。短测不证明 24h 或长期内存稳定，完整运行另记。

## 2026-10-01 群扩展 Windows 与离线档案验证

| 已执行场景 | 结果与证据 |
| --- | --- |
| 同机真实三 Rust 客户端群文件 | 发布成功响应丢失、重启原任务、原编号唯一、断点上传、认证下载/另存为、取消未发布任务通过；`group-integration-2026-09-30T20-08-32-598Z.json` |
| 群语音传输 | Chromium 合成振荡器录制 WebM/Opus 并解码，Rust 加密往返及导出字节一致；60,001 ms 字段拒绝。没有使用真实麦克风 |
| 活动 | 未回应/待定、报名覆盖改选、非管理者拒绝关闭、群主关闭后不能改选、发起人取消、离开标记/重新加入资格拒绝、隐藏后不重现通过 |
| 群附件权限 | 重新加入旧远端下载拒绝，已认证本机副本可读；专用库覆盖块篡改、共享配额与清理/编号复用拒绝 |
| T22 v2 | 新版活动状态/群缓存恢复、隐藏记录、离线读取零网络请求；旧读取器实际拒绝 v2，原文件不变。`group-integration-2026-09-30T20-05-15-012Z.json` |
| 模拟接口 Chromium | 群宽窄各 16 项、备份各 8 项、72 张风格截图通过；目录 `group-ui-LwVNS9`、`backup-ui-iKebte`、`ui-style-3CrEar` |
| 工程 | 15 Node/Electron、144 Rust 通过；格式、Clippy、FFI、生产构建通过，保留既有链接警告 |

报告位于 `target/test-results/`。旧长测原报告仍写 running，但最后一轮为 204、19,511 秒，原 PID 已不存在；保留证据并登记“未完成”，不能将其升级为 24h 通过。

待验收：双 Windows、新旧客户端真实混合交互、另一 Windows 用户/机器恢复、实际麦克风和声卡播放、原生权限/失焦/锁屏/通知/休眠、磁盘满、强制进程中断、完整新版 24h 和独立协议审查。共享协议占位解密反例与旧备份读取器实测只覆盖各自边界，不替代这些场景。

## 2026-10-01 群附件与活动：核心/服务端增量

专用 PostgreSQL 23/23 通过，0 失败、0 跳过；报告 `target/test-results/database-2026-09-30T19-58-00-300Z.json`。新增三项覆盖详情失败不提交文字根、重复提交、并发活动版本、取消后迟到拒绝、重新加入无旧详情、完整分块发布、篡改块拒绝、旧附件远端隔离、单聊/群共享配额、过期清理后编号不能复用、100 项分页与 10,000 条保留上限。配额使用隔离库合成元数据，不分配真实用户文件。

本地群 18 项及共享扩展 3 项通过，验证加密持久化、错误回执/损坏页回滚、历史隐藏、任务重启、20 MiB 超限及 60 秒字段边界。格式与全 workspace Clippy 通过。本增量没有双 Windows、真实麦克风/录音时长、系统通知/锁屏或独立协议审查证据，保持待验收。

## 2026-09-30 本轮收尾与 T22

| 场景 | 实际结果 |
| --- | --- |
| `ce0cb58` 基线 | 15 项 Node、132 项 Rust、20 项标记 PostgreSQL 用例及真实三进程 T20/T21 通过 |
| T22 核心/桌面 | 5 项新增 Rust 测试；完整 15 项 Node、137 项 Rust 通过；20 项数据库忽略项另行实际通过 |
| T22 群恢复 | 真实 PostgreSQL/服务及隔离 Rust 进程通过提及、投票、草稿、隐藏及句柄失效 |
| T22 模拟 UI | Chromium 宽窄各 7 项通过；确认/口令清除、取消/失败、分页、只读投票及迟到拒绝；截图核对 |
| 原有群/风格 | 宽窄各 12 项群回归及 72 张浅深色/宽窄截图通过 |
| 工程 | 构建、格式、全 workspace Clippy、FFI 通过，保留既有链接警告 |
| 长期入口 | 10 账号各参加 10 个群，六轮短测通过；新版另验证令牌刷新及 exe 隔离 |
| 24h 最终结果 | 2026-09-30 05:52 SGT 已隐藏启动，PID 14328；`group-soak-2026-09-29T21-52-05-540Z.json` 为 running，最终结果待补；短测不能替代完整运行 |
| Windows 原生/双机/跨用户恢复 | 未执行，不覆盖真实通知中心、锁屏/休眠/麦克风及另一用户/机器 |
| 磁盘满/强制中断、独立审查 | 未执行 |

新建随机标记测试库，凭据仅在进程环境；业务库/卷、真实用户资料及原有未跟踪文件未改动。实机项不勾选，安装/签名/部署暂缓。一次 npm test 因测试 exe 占用中断，完整复跑通过；长期入口随后改为临时 exe 副本。

以下人工/实机场景表为执行模板，结果均为**未执行**；新增自动化证据单独记录，不替代人工验收。开发状态见 [源码交付记录](FEATURE_IMPLEMENTATION_STATUS.md)。

## 环境记录

执行时填写：日期、执行人、提交、两台 Windows 版本、安装包 SHA256/签名、服务端提交、隔离账号、数据库和密钥目录、网络与故障注入方式。禁止使用真实用户数据。

每个场景记录步骤、起止时间、实际表现、预期对比、失败复现、证据文件和复测结果。证据不包含密码、密钥、令牌或真实聊天正文。

| 场景 | 操作与预期 | 结果 |
| --- | --- | --- |
| T00 安装与身份 | 双机安装、注册、互加和指纹核对 | 未执行 |
| T00 文本 | 双向中文/emoji/多行，重启保留历史 | 未执行 |
| T00 断网/离线 | 发送前后断网，原编号重试、离线补收无重复 | 未执行 |
| T00 ACK 丢失 | 落库后阻断 ACK，重放只显示一次并再次 ACK | 未执行 |
| T00 乱序 | 延迟前序信封，核对完整性异常与恢复 | 未执行 |
| T00 变更晚到 | 原文/编辑/撤回按不同顺序补收，最终一致 | 未执行 |
| T00 退出登录 | 普通退出再登录保留身份/历史/草稿，错账号不覆盖密钥 | 未执行 |
| T01 状态 | 逐一观察待发送/服务端保存/设备送达/失败，无对方已读 | 未执行 |
| T02 通知 | 前台不弹、后台点击定位，100 条补收不刷屏 | 未执行 |
| T02 静音与锁屏 | 重启保留静音，锁屏无预览，账号切换旧通知失效 | 未执行 |
| T02 退出 | 关闭到托盘、恢复、完整退出，无 Electron/Rust 残留 | 未执行 |
| T03 搜索 | 10,000 条，中文/大小写/emoji，定位早于第 50 条 | 未执行 |
| T03 可见性 | 编辑后旧词消失，撤回/删除不可搜，合法快照保留 | 未执行 |
| T03 取消与性能 | 首批耗时/峰值内存，取消/改词/切账号不串结果 | 未执行 |
| T03 损坏 | 跳过坏密文计数可见，不伪装完整扫描 | 未执行 |
| T04 大小 | 空文件、20 MiB、超 1 字节，双端限制生效 | 未执行 |
| T04 权限 | 第三账号持 URL 拒绝，密文篡改/错密钥不生成目标文件 | 未执行 |
| T04 恢复 | 上传中断、取消、发送失败、重启，沿用同一编号 | 未执行 |
| T04 下载 | 离线补收后下载，ACK 不等同下载完成 | 未执行 |
| T04 文件系统 | 磁盘满、保存取消、超长名和路径穿越安全处理 | 未执行 |
| T05 图片 | PNG/JPEG/WebP 确认/取消/预览，坏图和超大图不阻塞聊天 | 未执行 |
| T06 列表 | 筛选不改已读，空列表、删除列表、归档/静音独立 | 未执行 |
| T07 联系人 | 备注不改身份、同名可区分、删除/恢复保留历史；公开昵称/头像双端同步且不改变验签身份 | 未执行 |
| T08 请求 | 接受前无正常通知/未读，直接协议请求不能绕过，上限 100 | 未执行 |
| T08 拉黑 | 在线/离线阻止投递，解除仍待接受，隔离队列按规则恢复 | 未执行 |
| T09 键盘 | 中文选词不发送，Enter/Shift+Enter、Esc、emoji 方向键 | 未执行 |
| T09 缩放 | Ctrl +/-/0，75%–200%，窄窗口按钮仍可达 | 未执行 |
| T10 回应 | 替换/撤销、离线重试不累加、伪造他人事件拒绝、撤回隐藏 | 未执行 |
| T11 收藏便笺 | 重启、撤回/删除占位、取消收藏，便笺不向联系人发出 | 未执行 |
| T12 缓存 | 上限提示、按会话清理、待发保留、重下/过期、实际文件变化 | 未执行 |
| T13 会话 | 全部退出后原 HTTP/WS/refresh 失效，失败状态可见 | 未执行 |
| D-08 修改密码 | 错旧密码拒绝；成功后旧 HTTP/WS/refresh 均失效，原设备用新密码登录后身份和历史可读 | 未执行 |
| T14 应用锁 | 启用前验密、锁屏/超时/重启，快捷键/通知/待返回 IPC 不读正文 | 未执行 |
| T15 升级 | 按升级指南，旧/新安装、快照校验、失败回滚、身份/历史保留 | 未执行 |

双机验收后再由 2 人试用 24 小时，稳定后扩展 5–10 人 72 小时。只记录主动反馈和必要诊断；丢消息、越权或身份混淆必须先修复，不能据源码完成直接发布。

2026-09-24 本机生成未签名 NSIS 安装包，`verify-package.mjs` 资源校验通过；安装包、应用和 Rust sidecar 均未签名。尚无干净 Windows 安装、升级、回滚和双机操作记录，以上场景结果保持“未执行”。

## T16–T20 验收补充（2026-09-30）

每次填写提交、服务/数据库版本、客户端设备、隔离身份和数据目录、步骤、实际结果及脱敏证据。失败修复后附复测结果；不保存密码、令牌、私钥或真实聊天正文。

| 场景 | 操作与预期 | 实际环境结果 |
| --- | --- | --- |
| T16 录音与权限 | 实际麦克风录制、拒绝权限、取消、失焦/锁定停止；60 秒边界与试听 | 未执行 |
| T16 语音传输 | 双端加密上传、离线下载、认证失败拒绝播放及中断重试 | 未执行；加密语音时长服务端约束方案仍待明确 |
| T17 阅读回执 | 默认关闭；可见窗口阅读、滚动/遮挡、离线回执补收及伪造身份拒绝 | 未执行 |
| T18 输入提示 | 实际输入刷新、停止/失焦/锁定过期；断线不补发，联系人权限撤销生效 | 未执行 |
| T19 定时消息 | 到期发送、错过时间确认、修改/取消、重启原编号重试及身份变化停止 | 未执行 |
| T20 群身份与成员 | 3–10 个隔离账号，双指纹邀请；第 11 人拒绝，普通成员管理越权拒绝 | 未执行 |
| T20 群数据库 | 迁移、并发邀请/撤销、原子扇出、ACK、取消、配额、移除/重新加入隔离 | 未执行：专用库未配置 |
| T20 三客户端联调 | 真实服务与三个同机 Rust 进程；离线、ACK 故障、重启、隐藏重放和重新加入 | 未执行：专用库未配置；已有运行入口 |
| T20 群系统通知 | 前台抑制、静音持久化、节流、点击定位、系统锁屏/托盘、跨账号旧目标失效 | 未执行：需实际系统交互 |
| T20 已发邀请界面 | 刷新、分页、撤销、过期/失效、接受竞争后状态刷新 | 真实服务未执行；模拟接口 Chromium 回归通过 |
| T20 本机维护 | 统计区分全库/群逻辑数据；确认隐藏、重启/补收不恢复、保留草稿/待发/ACK/链 | 真实服务未执行；核心/桥接及模拟界面自动化通过 |
| T20 长期与双机 | 双 Windows、托盘、休眠恢复、断网、长期多群轮转；独立协议审查 | 未执行 |

### 本批自动化证据

- `npm test`：15 项 Electron/Node、127 项 Rust 通过；18 项 PostgreSQL ignored，未计作通过。
- `npm run test:groups:ui`：真实 Electron Chromium、真实 GroupPanel、模拟桌面接口；1280×900 与 390×844 各 8 组通过。结果与截图保存于 `target/test-results/group-ui-*`。账号/锁定测试通过组件重新挂载或卸载模拟生命周期，不执行 Windows 密码验证。
- `npm run test:database` 和 `npm run test:groups:integration`：缺失专用库，返回 not_executed。另以本机关闭端口验证数据库连接失败安全退出。成功连接、真实迁移和业务集成均未执行。
- 生产构建、Rust 格式检查、全 workspace/all-targets Clippy 与核心 ffi 编译通过。保留既有 LNK4098/LNK4099 警告。

自动化证据不关闭人工验收项；T00–T26 复选框维持原状态，T20 不勾选。安装、签名、发布部署继续暂缓。

## 2026-09-30 数据库与 T21 验收更新

此前表格为各阶段执行记录，本节记录本批新增实际证据，不将历史未执行改成当时通过。

| 范围 | 本次结果 |
| --- | --- |
| PostgreSQL 专用测试库 | 16.14；全部 20 项实际通过，0 失败/跳过；迁移、群事务、协作竞争、权限与编号隔离 |
| T20/T21 同机三客户端 | 真实服务、三个临时 Rust 数据库/DPAPI 身份；基线及协作完整流程通过 |
| 提及 | 当前成员阶段绑定、原密文响应丢失后重启重试、仅一条历史通过 |
| 置顶 | 群主权限、取消、重新加入者不能取得旧目标、可访问成员正常定位通过 |
| 实名投票 | 创建、改票不累计、群主关闭、关闭后拒绝、新加入阶段无旧资格通过 |
| 本机维护 | 损坏不 ACK/不推进游标、隐藏重放/重启、草稿与任务边界、100 条详情上限及旧详情定位通过 |
| Chromium 模拟接口 | 两种窗口尺寸各 12 组通过，包括越权入口、冲突/待发、切账号/卸载迟到结果 |
| 全量工程验证 | 15 项 Electron/Node、132 项 Rust、生产构建、格式、Clippy、核心 ffi 通过；既有链接警告保留 |
| Windows 原生交互/双机 | 未执行 |
| 长期多群/独立协议审查 | 未执行 |

普通 npm test 默认忽略的 20 项 PostgreSQL 已通过专用入口另行执行，不能把 ignored 本身解释为通过。T20/T21 仍需完整实机和审查证据，保持未勾选。未执行安装、签名、部署。
