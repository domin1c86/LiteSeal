# AGENTS.md

本文面向在本仓库工作的编码代理。架构、命令和协议以当前源码及配置为准；README 与历史计划可能滞后，不要将功能设想当作已实现能力。

## 工作与提交约定

- 修改前检查 `git status --short`，保留用户已有修改和未跟踪文件；只提交本次任务涉及的文件。
- 每项独立修改完成并做相应验证后，立即创建本地提交。执行 `git push` 或其他离开本地仓库的操作前先征求用户同意。
- 提交消息严格只有以下两个部分；条目前使用制表符，时间为提交时的本地时间，不添加署名或其他尾注：

```text
completed:
	- <本次完成的修改>
time: MM-DD HH:mm
```

## 仓库结构与职责

```text
LiteSeal/
  shared/       liteseal-shared：libsodium 加密原语、协议与共享类型
    src/crypto.rs
    src/protocol.rs
    tests/      加密、协议和集成测试
  core/         liteseal-core：桌面与移动端共用的 Rust 业务核心
    src/client.rs       客户端状态与安全消息处理
    src/db/             本地 SQLite、迁移与消息存取
    src/network/        WebSocket 客户端
    src/api.rs          HTTP API 客户端
    src/ffi.rs          可选 UniFFI 接口
    src/secret_store.rs 平台凭据存储抽象与 Windows DPAPI
    tests/db_test.rs    本地数据库集成测试
  src-tauri/    liteseal-app：Tauri 2 桌面壳、会话管理与 IPC 命令
    src/commands/       auth、chat、contacts、keystore、storage
  server/       liteseal-server：Axum HTTP/WebSocket 服务
    src/auth/           注册、登录与令牌管理
    src/relay/          消息验证、转发与 ACK
    src/db.rs           Postgres 存储及内嵌 schema/迁移 SQL
    src/state.rs        内存连接与限流状态
  ui/           桌面 React 18 + TypeScript + Vite 8 前端
  mobile/       React Native 0.86 + React 19 Android 客户端
    modules/react-native-liteseal/  UniFFI 原生模块与生成代码
  scripts/      Windows beta 检查脚本
  deploy/       部署配置
  docs/compose/ 历史设计与实施计划
```

- Cargo workspace 有 `shared`、`core`、`src-tauri`、`server` 四个成员。
- 通用业务逻辑放在 `core/`，桌面 IPC 适配放在 `src-tauri/`；不要在两端重复实现加密或消息处理。
- 桌面前端位于 `ui/`，不是根目录 `src/`；Tauri 的构建产物路径为 `../ui/dist`。
- 测试既有 crate 级集成测试，也有源码内 `#[cfg(test)]` 单元测试；按现有模块组织新增测试，不写死测试数量。

## 开发与验证命令

以下命令默认在仓库根目录执行，适用于 PowerShell。

```powershell
# 安装桌面前端的锁定依赖
npm ci --prefix ui

# Rust 编译与质量检查
cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# 按修改范围运行测试
cargo test -p liteseal-shared
cargo test -p liteseal-core
cargo test -p liteseal-server
cargo test -p liteseal-app

# 桌面前端类型检查与生产构建
npm run build --prefix ui

# 启动桌面端（需安装 cargo-tauri，自动启动 Vite）
Push-Location src-tauri
cargo tauri dev
Pop-Location

# 仅构建桌面可执行文件，不生成安装包
Push-Location src-tauri
cargo tauri build --no-bundle
Pop-Location

# 配置服务端环境变量并启动 Postgres 后运行
cargo run -p liteseal-server
```

- Tauri hooks 使用 `npm run dev --prefix ui` 和 `npm run build --prefix ui`；Vite 开发地址为 `http://localhost:1420`。
- Rust 改动按范围执行测试；涉及共享协议、跨 crate 接口或依赖时执行 workspace 检查与测试。前端改动至少执行前端构建。纯文档改动核对源码、路径、命令及 `git diff --check` 即可。
- Postgres 并发集成测试需要 `LITESEAL_TEST_DATABASE_URL` 指向专用测试数据库。未设置时测试会跳过，不能据此声称已验证真实数据库行为。
- `scripts/check-windows-beta.ps1` 汇集格式、Clippy、测试、前端构建、依赖审计和 Release 构建。检查各外部命令的退出码，不能仅凭脚本结束判定全部通过。
- 发布验证还需遵循 `SECURITY.md` 的依赖审计例外和复查期限，以及 `BETA_READINESS.md` 的验收门槛；历史通过记录不是本次验证结果。

## 环境与服务端配置

- Windows 桌面需要 Rust/MSVC 工具链、WebView2、Node/npm 及 Tauri CLI。Node 版本需满足当前前端依赖的 engines；移动端明确要求 Node `>=22.11.0`。
- `libsodium-sys` 依赖原生库构建环境；遇到链接问题时核对目标架构与 `SODIUM_LIB_DIR`、`SODIUM_INCLUDE_DIR`。
- 服务端使用 Postgres，持久化账号、设备、令牌与离线密文；DashMap 用于运行时状态，服务端不是无数据库的纯内存中继。
- `DATABASE_URL` 和 `LITESEAL_CORS_ALLOW_ORIGIN` 必须设置；通配 CORS 和默认 `postgres:postgres` 凭据会被拒绝。`LITESEAL_BIND` 默认为 `0.0.0.0:3000`。
- 可用 `LITESEAL_BOOTSTRAP_INVITE_CODE` 初始化邀请码。配置参考 `.env.example` 与 `docker-compose.yml`；直接 `cargo run` 需在进程环境中设置变量，不要假定会自动加载 `.env`。
- Docker 内使用的 `postgres` 主机名不等于本机连接地址；Compose 默认未将 Postgres 端口发布给宿主机。

## 协议与安全边界

- `shared/src/crypto.rs` 是加密原语的统一入口；签名验证使用 `verify_with_public_key()`。
- 协议定义以 `shared/src/protocol.rs` 为准，客户端和服务端 JSON 枚举均使用 `#[serde(tag = "type")]`。
- WebSocket 首帧认证包含 `user_id`、`token`、`device_id`。新消息使用 `send_v2` / `message_v2`，确认使用 `ack_v2`；不要复制旧文档中的简化 `send` 示例。
- `SignedEnvelopeV2::signing_bytes()` 使用确定性、带域分隔的编码，覆盖身份、路由、顺序、时间、消息类型和密文。改动信封字段必须同步检查签名编码、客户端处理、服务端校验与协议测试。
- 服务端拒绝新的 v1 发送；历史消息保留明确的 legacy 验证状态，不能升级标记为 v2 真实性已验证。
- ACK 必须绑定已认证设备，并在客户端处理和持久化之后发出；保留无效载荷隔离、缺失联系人密钥时暂不确认的行为。
- 桌面 React/WebView 不得接收访问令牌、刷新令牌或私钥，也不得重新暴露原始加密、签名或密钥导出 IPC。Rust 负责会话、加解密、验证、存储与确认。
- 账号数据目录按服务器 origin 与 user id 隔离；修改迁移或登录逻辑时保留账户隔离、迁移校验和备份。
- `LitesealClient` 对同步数据库使用 `std::sync::Mutex`，对异步 WebSocket 状态使用 `tokio::sync::Mutex`；不要持有同步锁跨越 `.await`。
- 不在日志、提交、测试快照或错误报告中写入凭据、私钥、消息正文和邀请码。

## Android 与 UniFFI

- 构建环境与完整流程见 `mobile/README.md`，需要 JDK 17、Android SDK/NDK 和 Rust Android targets。
- 在根目录可运行 `npm ci --prefix mobile`、`npm test --prefix mobile -- --runInBand`、`npm run lint --prefix mobile`。
- 修改 `core/src/ffi.rs` 后检查 `cargo check -p liteseal-core --features ffi`，并在 `mobile/modules/react-native-liteseal/` 执行 `npm run ubrn:android` 重新构建和生成绑定。
- 生成的 TypeScript、C++ 和 Android 胶水代码已纳入版本控制；修改接口时同步更新，不手改生成文件代替生成流程。
- `core/Cargo.toml` 中的 UniFFI `=0.31.0` 与移动端 `uniffi-bindgen-react-native` 版本关联，升级时一并检查。
- Android 原生 libsodium 构建的 Windows/WSL 注意事项见移动端 README；模拟器访问宿主机服务使用 `http://10.0.2.2:3000`。

## 已知限制与状态来源

- 本地数据库使用 rusqlite 的 `bundled` SQLite，未集成 SQLCipher；不能宣称整个数据库已加密。Windows 凭据使用 DPAPI 是独立的保护层。
- `core/src/secret_store.rs` 中非 Windows 平台的安全存储仍有限制；不能将 Windows 的凭据保护能力直接视为 Android 已具备。
- Windows beta 尚有设备替换历史消息排空、设备密钥历史、未知发送者流程、端到端验收及安装包验证等待办。执行相关工作前核对 `BETA_READINESS.md` 与当前源码，不重复报告已记录缺口，除非本次修改影响它们或发现新证据。
