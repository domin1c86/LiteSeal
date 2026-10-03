# T25 Android 对齐：原生身份与补收

## 2026-10-03 01:50 UTC 双 ABI 自包含构建与边界修复

已完成 x86_64 与 arm64-v8a 的实际 NDK libsodium/Rust/FFI 链接和自包含试验 APK。arm64 libsodium 的全部 102 个成员核对为 AArch64，Rust 链接 1 分 33 秒；最终 x86_64 试验 APK 44 秒、arm64 1 分 41 秒成功。原生链接日志为 `android-local-boundary-linked-x86_64.log`、`android-local-boundary-linked-arm64.log`；构建结果为 `android-isolated-x86_64-20261003T014308857Z.json` 与 `android-isolated-arm64-v8a-20261003T014653512Z.json`，均在 `target/test-results/`。

新增 `isolatedTrial` 变体，包名 `com.litesealmobile.isolatedtrial`、独立应用数据范围，内置 JS/Hermes，使用已有开发测试签名。它不依赖 Metro，不是生产发布包；没有安装/启动到设备或连接真实账号。原有 Debug 构建仍需要 Metro。默认构建 ABI 改为本轮有原生库的 arm64-v8a/x86_64，32 位 ABI 尚无构建证据。

可重跑：设置已有 JDK/SDK 的 `JAVA_HOME`、`ANDROID_HOME`，准备对应原生 archive 后执行 `pwsh -NoProfile -File scripts/build-android-trial.ps1 -Architecture x86_64 -WithInstrumentation` 或 `-Architecture arm64-v8a`。脚本只构建并记录结果，不安装 SDK、不接受许可、不安装 APK；缓存放在项目 `target/`。独立留存 APK 为 `target/test-results/android-isolated-x86_64.apk` 与 `android-isolated-arm64-v8a.apk`。`android-isolated-apk-validation.json` 记录 SHA256、内置 bundle 和每 ABI 14 个实际原生库；两包 ZIP 对齐与全部 ELF LOAD 段均满足 16 KiB 检查。这不是 Android 系统执行或硬件兼容验收。

修复 React Native 发送迟到结果可恢复后台已清正文的问题：展示绑定前台、账号/设备/服务器、会话、联系人双公钥和信任状态，变化/卸载退役回调；失败不输出原生传输细节。移动 Jest 9/9（新增 5 项实际组件延迟回包场景）和类型检查通过，`android-ui-lifecycle-jest-verified.log`、`android-ui-lifecycle-types-final.log`。

本机联系人读取/修改与存储统计/整理也必须经过原生前台及已确认身份门禁；JNI 秘密数组以固定 4096 字节块清零，不为清理再申请整段内存，并检查全局 Java 引用分配失败。FFI core 单元集 59/59，其中移动专项 11 项，`android-native-eleven-tests-final.log`；FFI all-target Clippy 通过，`android-local-boundary-clippy.log`。7 方法 JNI 严格检查见 `android-native-jni-bounded-wipe-final.log`。原生方法签名没有增加秘密输出，现有真实生成绑定保持。

3 项隔离 instrumentation 用例已随最终 x86_64 测试 APK 编译，包名通过实际 `aapt2` 核对为 `com.liteseal.nativeisolatedtests`；未在 Android 系统执行。当前没有完整可用的隔离镜像/命令行管理器，未接受新条款，未使用真实 AVD/手机。Keystore、后台/推送、进程终止、手机 v3 与完整媒体业务、系统权限和独立审查仍待完成。以下检查点保留为历史。

## 2026-10-03 当前构建与接续点（UTC）

最新移动 FFI 10/10 通过（`target/test-results/android-native-ten-tests.log`），包括真实回环 HTTP 原操作落库后 ACK、坏签名拒绝，以及旧 keychain 清除失败后重开：先读取新保护身份，保持原密钥，仅重试清除旧项，不重新注册/生成身份。清除完成标志再次持久化失败也保留可重试状态。原生构造将数据库限制为应用私有目录的固定 `liteseal.db`，拒绝不同父目录、链接或异常文件；后台与前台复用同一规范路径和租约。路径由第 7 个私有 JNI 方法提供，不经 JSI 输出。

当前 Android x86_64 libsodium/Rust 静态库实际链接通过（19 秒，`android-native-current-linked-final.log`）；7 方法 JNI 严格 NDK 语法检查通过（`android-native-jni-seven-methods.log`）。最新应用 Debug APK 和隔离 instrumentation APK 实际构建成功（45 秒，`android-apk-current-final.log`、`android-apk-current-final-result.json`），大小/SHA256 见 `current-built-artifacts.json`。修正了 CMake archive 路径、真实 codegen/autolink 配置、头目录定位、React Native 官方重复库打包规则及 Kotlin JNI 方法名。未更改 SDK 安全设置或真实 AVD，未安装到实际手机。

`NativeBoundaryTest` 的 3 项系统用例已编译：合成秘密保护/解保护/损坏拒绝；4096 字节公开见证头及重复最高代次拒绝；无身份后台不建库与错误私有路径拒绝。测试宿主固定 `com.liteseal.nativeisolatedtests`，只清除本测试创建的 alias/目录。没有可用的完整隔离系统镜像/SDK 命令行管理器，尚未运行这些测试；Keystore 别名限制、系统持久性、断电/进程终止和真实后台不能据 APK 构建认定通过。没有接受新的 SDK 许可条款。

移动类型检查和真实 Metro 生产 bundle 已通过；Debug APK 未嵌入该 bundle，依赖 Metro，并非独立发布构建。当前只有 x86_64 原生链接/APK，arm64 仍待构建。完整普通工作区 400 Rust + 30 Node、另跑 PostgreSQL 88 项与 FFI/工作区 all-target Clippy 通过，详见 [验收记录](P0_P1_ACCEPTANCE_RECORD.md)。以下较早检查点保留为执行历史，不代表当前仍缺这些已完成构建。

继续：arm64/独立离线 APK、隔离 Android 系统测试、v3 移动业务与媒体完整入口、推送供应商接入及实际手机后台/进程终止。推送只应触发原生补收，不携带可展示正文；需要外部提供商配置，不创建持久凭据。T25 整体仍不勾选。

## 2026-10-02 接续检查点

执行环境短暂断连后已恢复。未提交、未推送；已有用户修改和未知进程保留。T25 仍在开发，不能认定手机验收通过。

已接入原生 `MobileIdentity`、Android Keystore AES-GCM 包装、JNI 私有适配和原生正文投影。私钥、签名私钥及会话令牌不再作为移动会话传给 React Native；原生注册在网络请求前保存原密钥，未知结果继续使用原密钥，退出保留离线身份。旧 keychain 从 JS 模块注册退役；迁移只通过 Kotlin/Rust，在新保护副本保存并重新核验后清除旧条目。

生成绑定已使用本机 `ubrn 0.31.0-3` 和真实 core FFI DLL 重新生成。React Native 模块原先声明包含生成代码，但仓库没有 `NativeLitesealSpec`；现改为 Gradle 自动 codegen，autolink 指向实际 build 输出。Android Keystore 包装密钥不可导出；这不意味着 Ed25519 私钥运行时不进入原生内存，也不保证设备提供硬件安全模块。

实际执行证据：

- `target/test-results/android-native-unit-final.log`：原生身份 3 项故障/范围/退出测试及附件描述白名单投影 1 项通过。
- `android-types-final.log`、`android-native-clippy.log`：移动 TypeScript、core FFI all-target Clippy 通过（后台增量前）。
- `android-native-library.log`、`android-bindgen-final.log`：Windows 主机 FFI 库和重新生成绑定通过；不是 Android 原生链接证据。
- `android-native-jni-syntax-final.log`：实际 Android NDK clang++ 对 JNI 适配头的严格语法检查通过。
- `android-rust-target-first.log`：x86_64 Android Rust target check 通过；尚未完成 Android libsodium/Rust 静态库和 APK 链接。
- `android-kotlin-codegen-retry.log`：Android 模块 Kotlin 和 codegen 实际构建通过，15 秒。早期缺 codegen、Kotlin 沙箱外缓存及 PowerShell Gradle 参数失败保留在原日志中；最终通过不覆盖尚未实现的后台代码。

接续点：加入 WorkManager 有界补收、共享原生生命周期/网络门禁和前台迟到结果拒绝；扩展正文真实签名、编辑/撤回、隐藏和篡改夹具；验证 Android 原生链接及移动 bundle。推送服务尚未配置，不能声称推送或真实手机进程终止恢复通过。Android v3 多设备、媒体完整业务界面和系统验收仍需后续。

## 2026-10-03 后台与外部高水位增量

已加入 WorkManager 唯一周期/唤醒任务、网络/存储约束、20 秒/256 条原生补收上限；后台不生成身份、不向 WorkData/JS 传凭据或正文。JNI 生命周期代次和共享网络门禁拒绝前后台切换、退出后的迟到结果；前台暂停轮询并清除消息/会话预览，恢复时从本机重投影。原生 HTTP 操作补收有界验签、解密和落库后才 ACK，单独返回变更标记刷新界面，不增加消息未读。

新增 Android 外部见证适配：小型公开状态摘要记录存入 Android Keystore 的有代次别名，创建新头后才清理旧别名；SQLite/应用文件不承担外部高水位，文件锁协调 native 同步写入。失去 Keystore 状态或坏记录时拒绝回退重置。该方案已通过 Kotlin 及 Android Rust target 编译，但未在 Android 系统实际执行，不能将别名大小/持久性、硬件实现、断电恢复或 v3 手机体验视为通过。没有 JS 高水位读写或生产重置 API。

增量证据：`android-native-nine-tests.log` 9/9 通过，其中新增实际回环 HTTP 变更补收和坏签名不落库/不 ACK；`android-kotlin-background.log`、`android-kotlin-witness.log` Kotlin/codegen 通过；`android-native-witness-target.log` Android target check 通过；`android-mobile-types-native-final.log` 和 `android-mobile-bundle-final.log` TypeScript/真实 Metro 生产 bundle 通过。共享正文使用 Windows 同一纯 TS codec。NDK 从缓存源码构建的 libsodium 已完成，`android-sodium-elf-check.log` 确认全部 x86_64 ELF，Android Rust 最终链接与 APK 正在验证。

T26 已有独立协议与原生门禁的 3 项可运行验证，见 [消失消息验证](DISAPPEARING_MESSAGES_TRIAL.md)；生产入口和兼容中继尚待接。

后台方案采用唯一 WorkManager 任务、网络/存储约束、每轮固定时间和记录上限，不把密钥/令牌/正文放进 WorkData。推送只应触发补收，不能作为消息真实性或可展示正文来源。Android 官方规定周期工作最小 15 分钟，系统和约束可能延迟执行；强制停止后的及时唤醒不能保证。参考 [WorkManager 版本](https://developer.android.com/jetpack/androidx/releases/work)、[工作请求与执行限制](https://developer.android.com/develop/background-work/background-tasks/persistent/getting-started/define-work)、[Android Keystore](https://developer.android.com/privacy-and-security/keystore)。

T24：原生签名/加密信令与双 PeerConnection 的 Opus/DTLS-SRTP 验证已完成，`voice-call-trial-GlLizr/result.json` 9 项通过；生产入口、中继、NAT/TURN 和真实系统音频仍待接。见 [通话验证](VOICE_CALL_TRIAL.md)。T26 原生技术验证 3 项通过，生产接线尚待完成。

T23 历史：文件、中继、后台原任务继续及放弃暂存已验证；未来变更转发仍待独立持续授权。不能将一次快照授权自动扩张为未来明文授权。当前全量历史回归证据见 [验收记录](P0_P1_ACCEPTANCE_RECORD.md)。
