# Windows 开发与内测验证指南

本指南对应当前 Tauri 2、React 桌面端和 Postgres 服务端。内测范围与准入结论见 [BETA_READINESS.md](BETA_READINESS.md)。

## 环境

需要 Rust/MSVC、WebView2、Tauri CLI、满足 ui 依赖要求的 Node/npm，以及独立的 Postgres。libsodium 链接环境按 [AGENTS.md](AGENTS.md) 检查。

以下命令在仓库根目录执行。不要对生产数据库运行集成测试；测试会创建账号、消息、邀请码和临时 schema。

```powershell
npm ci --prefix ui
cargo check --workspace
cargo test --workspace
```

普通测试中的 Postgres 用例明确显示 ignored，不能把 ignored 计作已验证。运行真实数据库测试：

```powershell
# 在当前终端配置专用测试库，值由本地环境提供，切勿提交真实连接凭据。
$env:LITESEAL_TEST_DATABASE_URL = 'postgres://<test-user>:<test-password>@127.0.0.1:<port>/<test-db>'
cargo test -p liteseal-server -- --ignored

# 包括真实数据库测试在内的整个 workspace
cargo test --workspace -- --include-ignored
```

本地 Docker 可用于测试数据库。选择不冲突的本机端口、独立容器名和随机密码，使用已有 Postgres 镜像；不要复用现有业务容器或数据库。结束后删除自己创建的临时容器和连接文件。

## 开发启动

终端 A：准备独立开发数据库，并配置服务端变量。

```powershell
$env:DATABASE_URL = 'postgres://<dev-user>:<dev-password>@127.0.0.1:<port>/<dev-db>'
$env:LITESEAL_CORS_ALLOW_ORIGIN = 'http://localhost:1420'
$env:LITESEAL_BOOTSTRAP_INVITE_CODE = '<one-time-random-invite>'
cargo run -p liteseal-server
```

直接 cargo run 不自动读取 `.env`。Compose 内的数据库主机名 `postgres` 不能直接用于宿主机；当前 Compose 未默认发布数据库端口。

终端 B：

```powershell
Push-Location src-tauri
cargo tauri dev
Pop-Location
```

开发服务地址为 `http://localhost:3000`，远程服务必须使用 HTTPS。账号注册需要用户名、密码和未使用的邀请码。每个注册账号需要独立邀请码；勿使用 mock 用户作为真实内测账号。

双人验收使用两台 Windows 或两个独立 Windows 用户环境，避免同一用户的活动配置文件互相覆盖。不要把启动两个 cargo tauri dev 窗口当作账户隔离验收。

## 自动化门禁

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
npm run build --prefix ui

# 验证检查脚本自身能拦截失败；无需数据库或网络。
./scripts/test-windows-beta-gate.ps1

# 完整 Windows beta 门禁；必须先配置专用 LITESEAL_TEST_DATABASE_URL。
# 包含真实数据库用例、在线依赖审计和 Release exe 构建。
./scripts/check-windows-beta.ps1
```

脚本任一外部命令非零退出就中止。依赖审计例外以 [SECURITY.md](SECURITY.md) 为准，不能通过新增 ignore 项掩盖新问题。

```powershell
# 只构建本地 Release 可执行文件
Push-Location src-tauri
cargo tauri build --no-bundle
Pop-Location
```

`--no-bundle` 不生成安装包。安装、签名、升级和卸载需要单独验收。

## 两机验收记录

每次记录版本/commit、Windows 版本、场景、预期、实际结果、脱敏日志和是否通过。不要记录密码、令牌、私钥、邀请码或聊天正文。

| 场景 | 通过条件 |
| --- | --- |
| 注册与登录 | 邀请码单次使用；无效密码和邀请码有明确错误；普通账号可正常进入。 |
| 添加联系人 | 双方搜索、添加、比对指纹后可发送；未验证或密钥变化时有明确处理提示。 |
| 双向消息与重启 | 两端正文一致、顺序正确，重启后历史可读，无重复、丢失或跨会话显示。 |
| 断网、睡眠、服务重启 | 恢复联网后自动重连；待发消息按原顺序重试；状态如实变化。当前仍是待完成门槛。 |
| 离线积压与慢连接 | 超过 128 条积压可持续排空；实时混发不导致合法消息被隔离；配额边界明确。 |
| 退出登录 | logout/logout-all 后旧连接不能收发；无网退出后重启也不自动显示历史会话。 |
| 账号切换 | 联系人、历史和凭据分离，不残留上一账号的 UI 数据。 |
| 设备替换 | 按首批策略限制或明确确认；不能隐瞒历史与待收消息的可用性影响。 |
| 安装包 | 干净 Windows 普通用户可安装启动；升级和卸载符合约定的数据保留策略。 |

观察顺序见 BETA_READINESS.md。测试不通过时保留脱敏复现步骤，不直接发给更多人。

## 故障定位

- 服务端不启动：先检查 DATABASE_URL、Postgres 就绪情况、非默认凭据、非通配 CORS；检查 `/healthz` 和 `/readyz`。
- 网络恢复后不收消息：目前缺少完整自动重连/outbox，是已确认待办，不应靠刷新窗口认定问题已解决。
- 前端构建失败：保留准确命令和错误；区分依赖/类型错误、原生库链接错误和运行环境权限限制。
- 历史数据在账号隔离目录 `profiles/<hash>/data.db` 中，位置由桌面 AppState 的 base_dir 决定；不要继续依赖旧文档中的单一全局数据库路径。
- 调试时不要加密钥、令牌或消息正文日志；仅看密文字节也不能证明端到端安全，必须依靠验证测试与明确的安全边界。
