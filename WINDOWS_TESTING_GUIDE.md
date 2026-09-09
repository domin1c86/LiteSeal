# Windows 界面入口、功能与完整测试指南

适用范围：当前仓库 Windows 桌面客户端；移动端不在本次验收范围内。核对日期：2026-09-09。本文根据当前工作区代码编写，功能“已实现”表示有代码与界面入口，不代表已经通过 Windows 实机验收。旧 README / TESTING_GUIDE 中的版本、启动依赖和双实例测试步骤请以本文为准。

## 1. 怎么进入前端

前端位于 `ui/`，入口链路为 `ui/index.html → ui/src/main.tsx → ui/src/App.tsx`。首次显示 Login / Register；保存过有效会话时会尝试恢复到主界面。

| 目的 | 命令和入口 | 能测什么 |
| --- | --- | --- |
| 浏览器查看登录页 | 仓库根目录执行 `npm ci --prefix ui`，再执行 `npm run dev --prefix ui`；打开 `http://localhost:1420` | 登录页布局、输入框、登录/注册切换、按钮禁用状态 |
| Windows 完整功能测试 | 按下文启动 PostgreSQL、服务端，再在 `src-tauri` 执行 `cargo tauri dev` | 桌面 IPC、账号、联系人、收发消息、本地数据 |
| 构建后的程序 | Windows 构建后运行 `target\release\liteseal-app.exe`，或安装生成的安装包 | 脱离开发服务器的桌面使用体验 |

浏览器中没有 Tauri 的 `invoke` 环境，点击登录/注册会在调用原生命令时失败；仅启动 Vite 不能完成聊天测试。端口 **1420 是前端**，**3000 是 API / WebSocket 服务端**，**5432 是 PostgreSQL**。根目录的 `package.json` 没有前端启动脚本，命令需要指定 `--prefix ui` 或进入 `ui`。

## 2. Windows 首次环境准备

以下命令使用 **Windows PowerShell**，示例仓库路径为 `C:\coding\LiteSeal`，请替换为你的实际路径。客户端应在 Windows 本机运行；WSL 的 Linux 程序不能替代 Windows DPAPI 密钥保存测试。

准备以下依赖：

- Git、Node.js 和 npm。当前项目使用 Vite 8，要求 Node.js 20.19+ 或 22.12+，不要沿用旧文档的 Node 18；本次构建环境为 Node 24.14.1。参见 [Vite 官方要求](https://vite.dev/guide/)。
- Rust stable 的 Windows MSVC 工具链、Visual Studio C++ Build Tools 的“使用 C++ 的桌面开发”工作负载和 Windows SDK，以及 WebView2 Runtime。安装说明见 [Tauri Windows 前置要求](https://v2.tauri.app/start/prerequisites/)。
- Tauri CLI **2.x**，与仓库的 Tauri 2 依赖匹配。安装命令依据 [Tauri CLI 文档](https://v2.tauri.app/reference/cli/)。
- libsodium 的 Windows MSVC 库；如编译器无法自动准备，按第 9 节配置。
- PostgreSQL；下文使用已安装并启动的 Docker Desktop，通过仓库 Compose 启动数据库。也可以使用本机 PostgreSQL，创建对应账号和数据库后修改连接串。

```powershell
Set-Location C:\coding\LiteSeal
node --version
npm --version
rustc --version
cargo --version
rustup show active-toolchain
cargo install tauri-cli --version '^2.0.0' --locked
cargo tauri --version
npm ci --prefix ui
```

`npm ci` 使用 `ui/package-lock.json`，需要联网下载尚未缓存的依赖。首次 Cargo 构建也可能需要下载依赖；不要把编译时间误判为界面卡死。

## 3. 启动完整 Windows 开发环境

### 终端 A：数据库与服务端

```powershell
Set-Location C:\coding\LiteSeal
docker compose up -d postgres
docker compose ps postgres
docker compose exec postgres pg_isready -U liteseal -d liteseal
$env:DATABASE_URL = 'postgres://liteseal:liteseal@localhost:5432/liteseal'
$env:LITESEAL_BIND = '0.0.0.0:3000'
$env:LITESEAL_CORS_ALLOW_ORIGIN = 'http://localhost:1420'
$env:LITESEAL_INVITE_CODES = 'LITESEAL-WIN-ALPHA,LITESEAL-WIN-BRAVO,LITESEAL-WIN-CHARLIE'
$env:RUST_LOG = 'info'
cargo run -p liteseal-server
```

等待数据库可接受连接后启动 Rust 服务端；数据库表由服务端启动时初始化。服务端出现 `Server listening on 0.0.0.0:3000` 后保持终端运行。

当前 `server/src/config.rs` 直接读取进程环境变量，没有自动加载 `.env`。仅复制 `.env.example` 不会给 `cargo run` 设置连接串。Compose 内的 `postgres` 主机名供容器互访；Windows 本机启动服务端应使用 `localhost`。上面的账号密码是仓库提供的本地开发值。

### 终端 B：健康检查与桌面窗口

```powershell
Set-Location C:\coding\LiteSeal
Invoke-RestMethod http://localhost:3000/healthz
Set-Location .\src-tauri
cargo tauri dev
```

健康检查应返回 `ok`。Tauri 会执行配置里的 `npm run dev --prefix ui` 并打开 1024×768 的可调整窗口；一般不需要另开 Vite。先前预览启动的 Vite 应先用 Ctrl+C 停止，避免 1420 端口冲突。

登录页填写：

- Server URL：`http://localhost:3000`（不是 1420，不要填写 `/ws`）。
- 首次使用选择 **Register**，输入独立测试用户名，例如 `alice_win_01`。
- Invite code：填写下节任一已配置的测试邀请码。
- 密码至少 8 个字符，在 Confirm password 再输入一次相同密码；所有输入校验通过后点击 **Register & Connect**。
- 已注册账号选择 **Login**，输入原用户名和密码。

成功标志是进入含 `chats` / `contacts` 的主界面。未添加联系人时显示 `no contacts yet`，聊天区显示 `no conversation selected`，属于正常空状态。

关闭测试环境：客户端和服务端终端各按 Ctrl+C；需要停止数据库时在根目录执行 `docker compose stop postgres`。保留数据库卷可以继续使用测试账号。

### 可重复使用的测试邀请码

本轮提供三个测试码：`LITESEAL-WIN-ALPHA`、`LITESEAL-WIN-BRAVO`、`LITESEAL-WIN-CHARLIE`。区分大小写，输入首尾空格会去除；没有使用次数限制，可供不同用户名重复注册。

本机 `cargo run`：务必在启动服务端的 PowerShell 先设置上面的 `LITESEAL_INVITE_CODES` 环境变量，然后启动/重启服务端。仅复制 `.env.example` 不会自动生效。`docker compose up -d --build server` 使用 Compose 中的这三个默认测试码，也可通过同名变量覆盖。测试码不是客户端硬编码白名单；由服务端配置决定是否有效。

未配置或配置为空时，新注册关闭；已有账号仍可登录。移除某个码并重启服务端可停用它。测试码仅用于开发测试，正式部署时替换为你自己的邀请码。

注册每行右侧显示提示灯，同时显示说明文字：灰色表示未填写，黄色表示邀请码正在向服务器验证，绿色表示通过对应检查，红色表示不符合要求或验证失败。邀请码输入停止约 400 毫秒后发起验证，网络失败可以点击“重新验证邀请码”。修改地址/邀请码后旧验证结果立即失效。用户名绿灯只表示非空，重名仍在注册时判断；服务器地址绿灯只表示 HTTP(S) 格式有效。密码按 Unicode 字符数量检查至少 8 个字符；确认密码必须与原密码完全相同。确认密码只在本地比较，不发送给服务端。

客户端通过 `validate_invite` IPC 调用 `POST /auth/invite/validate`，提交注册时还会由 `POST /auth/register` 强制再次验证 `invite_code`；省略、错误或停用的邀请码返回 403。不能通过跳过前端绕过邀请码限制。本次仅接通 Windows 注册界面，旧移动端尚无邀请码输入，不能在开启此限制的服务端注册新账号。

新增手动检查（本次按要求不执行界面交互测试）：

- 用同一个测试码分别注册两个不同用户名，应均成功；重复用户名仍不允许。
- 空码、错误码、停用码应无法注册；断网时显示验证失败，可重试。
- 输入 7 个字符、8 个字符和中文密码，观察密码灯；确认密码不一致时禁用注册，修改原密码后确认灯同步更新。
- 修改服务器地址后旧邀请码绿灯应失效；切换 Login 时不要求邀请码和确认密码。

## 4. 当前界面和功能清单

| 界面/入口 | 当前实现 | 测试时如何理解 |
| --- | --- | --- |
| Login / Register | 用户名密码注册、登录、服务器地址配置 | 密码不足 8 字符或用户名为空时提交禁用 |
| 启动恢复 | 读取本地密钥与会话、尝试连接；失败后尝试刷新令牌 | 网络不可达时可能进入离线会话，进入主界面不等于在线 |
| 左上角 `+` | 按用户名搜索并添加本地联系人 | 自己显示 You，已添加显示 Already added，缺少公钥显示 Missing key |
| `chats` | 选择联系人，单聊文本发送和接收、消息状态、本地历史 | 当前列表以联系人为基础，没有最近消息摘要或未读数 |
| `contacts` | 联系人详情、指纹、Verify / Unverify、Message 跳转 | Verify 是手动信任标记，点击本身不等于核实对方身份 |
| 聊天区 | 加密/签名、按收件设备生成密文、接收时验证和解密 | 收消息由 App 每 2 秒轮询一次；预留数秒观察时间 |
| 消息状态 | pending、delivered、stored_offline 等状态事件 | delivered 不表示用户已经阅读，也不能替代对端看到正确明文的验收 |
| 左上角 `⚙` | Storage Manager：消息、附件、会话及 Total 统计 | Total 来自密文和附件大小汇总，不是磁盘实际占用 |
| 存储清理 | Clear Expired Messages / Clear Unpinned Attachments | 清理过期消息记录与未固定附件记录；没有数据时返回 0 正常 |
| 左上角 `⏻` | Logout：断开连接、删除保存的密钥、回到登录页 | 不等同于普通关闭窗口，见第 7 节 |
| Windows 密钥保存 | 使用 DPAPI 保存 `keystore.bin` | 与 Windows 用户环境绑定，跨用户复制文件不能作为迁移方案 |
| 服务端能力 | PostgreSQL 账号/设备数据、会话接口、离线密文排队及上线投递 | 需要真实双客户端测试验证端到端效果 |

当前桌面界面没有图片/文件发送下载、语音/视频、群聊、消息搜索、撤回、联系人删除按钮、设备管理、密码重置和密钥导入导出入口。部分底层接口已经存在，不能据此算作桌面功能完成。没有消息过期时间设置入口，正常发送的消息一般不会被“清理过期消息”删除。

历史查询目前按时间升序取 `50` 条、偏移 `0`，没有加载更多入口。因此超过 50 条后重新打开会话可能只看到最早的 50 条，应作为 Windows 完善项记录。

## 5. 双人聊天怎么测

不要在同一个 Windows 用户下开两个 `cargo tauri dev` 当作 Alice / Bob：它们会争用 Vite 端口，还会共用数据库和密钥文件。复制仓库目录也不会隔离用户数据；当前没有实现测试用 profile / 数据目录参数。

推荐使用两台 Windows 电脑，或一台电脑加 Windows 虚拟机，各运行一个客户端。也可以使用两个独立 Windows 用户会话运行已构建程序，必须保证数据目录独立。

1. 机器 A 运行数据库与服务端，客户端 A 使用 `http://localhost:3000`。
2. 如果 B 是另一台电脑/虚拟机，客户端 B 的 Server URL 填 A 的可达局域网 IP，例如 `http://192.168.1.10:3000`；B 的 localhost 指的是 B 自己。
3. 在 B 先执行 `Invoke-RestMethod http://192.168.1.10:3000/healthz`，确认返回 ok。需要时允许 A 的防火墙在测试用私有网络接收入站 TCP 3000；不需要对 B 开放 1420 或 5432。
4. A 注册 `alice_win_01`，B 注册 `bob_win_01`，保持双方在线。
5. Alice 点 `+` 搜索 Bob 并 Add；Bob 同样搜索 Alice 并 Add。添加操作是本地的，不会自动互加。
6. 双方在 chats 选择对方，先后发送 `Alice → Bob 001` 和 `Bob → Alice 001`。
7. 验收以双方实际看到正确文字、发送方向正确、消息无重复为准，再观察消息状态。

## 6. 手动验收用例

建议按编号执行，在“结果”栏填写通过/失败/未执行，并附截图或错误文本。每次回归使用本轮独立测试账号；先完成基础闭环再测退出登录和密钥变化。

| 编号 | 操作 | 预期/检查点 | 结果 |
| --- | --- | --- | --- |
| W01 | 新环境启动窗口 | 出现 Login / Register，无白屏；可调整窗口大小 | 未执行 |
| W02 | 输入空用户名、7 字符密码，再改为有效值 | 前两者提交禁用，有效值可提交 | 未执行 |
| W03 | Register 新账号 | 进入主界面，空联系人/会话提示正确 | 未执行 |
| W04 | 在另一隔离环境尝试重复注册、错误密码登录 | 显示错误，不进入主界面；再使用正确密码可以登录 | 未执行 |
| W05 | 搜索不存在用户、自己、已添加用户 | No results / You / Already added 状态合理 | 未执行 |
| W06 | 双方互加并互发文本 | 双方均看到原文与正确方向，无重复 | 未执行 |
| W07 | 发送中文、emoji、标点，连续发 10 条编号消息 | 内容完整、顺序合理；空白输入不能发送 | 未执行 |
| W08 | Bob 切到 contacts 或不选会话，Alice 发消息 | 等待数秒后 Bob 打开会话可以看到已接收消息 | 未执行 |
| W09 | 普通关闭 Bob 窗口，再重新启动（不 Logout） | 恢复同一账号，联系人和原有历史仍可读 | 未执行 |
| W10 | Bob 普通关闭后 Alice 发 3 条编号消息，再启动 Bob | 观察离线状态与补投递；Bob 应收到 3 条且不重复；失败要记录 | 未执行 |
| W11 | 保留本地会话，关闭服务端后重启客户端 | 可尝试离线读历史；发送失败不得被当作成功送达 | 未执行 |
| W12 | 启动服务端后重新启动客户端，发送消息 | 重新连接后可以互发；当前没有明确的自动重连 UI，不把原窗口自动恢复作为保证 | 未执行 |
| W13 | 联系人详情点击 Verify，再 Unverify，再点 Message | 信任标签同步变化，Message 打开正确会话；不据此断言安全身份验证完成 | 未执行 |
| W14 | 打开 Storage Manager，收发后重新打开 | 计数有合理变化；Total 是逻辑大小，不与 data.db 文件大小硬比较 | 未执行 |
| W15 | 在测试数据上点击两项清理 | 显示清理数量并刷新统计；无过期/附件数据时应为 0 | 未执行 |
| W16 | 调整窗口至 1024×768、较窄尺寸，Windows 缩放 100% / 150% | 输入和发送按钮可达、弹窗关闭按钮可见、长用户名/消息不遮挡关键内容 | 未执行 |
| W17 | 输入未发送文字后切换联系人，再测试断网发送 | 核查草稿是否串到其他联系人、失败后文字是否丢失；当前发送前清空输入，是重点观察项 | 未执行 |
| W18 | 连续发送超过 50 条后重新打开会话 | 记录历史显示范围；当前没有分页加载，不作为完整历史浏览验收通过 | 未执行 |
| W19 | 最后执行 Logout，然后同账号重新登录 | 返回登录页；核查新的设备/密钥导致的历史解密及联系人指纹变化，不预设无损恢复 | 未执行 |
| W20 | 使用安装包在另一 Windows 测试环境安装并启动 | 无 Node/Rust 开发环境也能显示界面；连接服务端后完成 W06；关闭、重开和卸载可执行 | 未执行 |

长时间在线、令牌过期、服务器重启及多设备收件尚需单独回归。不要把一次发送成功当作这些场景已通过。密文日志也不能单独证明整个端到端加密链路正确，应结合对端明文、签名/篡改测试和错误密钥测试。

## 7. 数据位置、退出与重新测试

当前路径来自 `src-tauri/src/main.rs` 和 `core/src/keystore.rs`：

| 数据 | Windows 路径 |
| --- | --- |
| 联系人、消息、会话数据库 | `%APPDATA%\liteseal\data.db` |
| DPAPI 密钥/会话文件 | `%LOCALAPPDATA%\liteseal\keystore.bin` |
| 旧密钥迁移文件（仅旧环境可能存在） | `%LOCALAPPDATA%\liteseal\keystore.json`、`keystore.json.migrated.bak` |
| 服务端数据 | Compose 的 PostgreSQL 命名卷，项目名前缀随目录/Compose 配置变化 |

PowerShell 查看文件是否存在：

```powershell
Get-Item "$env:APPDATA\liteseal\data.db" -ErrorAction SilentlyContinue
Get-Item "$env:LOCALAPPDATA\liteseal\keystore.bin" -ErrorAction SilentlyContinue
```

普通关闭窗口会保留保存的密钥，适合重启和离线补投递测试。**Logout 会清除密钥文件，但不会同时清空本地数据库**；下次登录可能创建新密钥/设备，旧历史可能出现 `[encrypted]`，当前不要将退出登录当作无损切换账号功能。

需要从零测试时，优先换独立 Windows 用户或虚拟机快照。若确实要重置现有测试环境，先关闭所有客户端，备份上述两个 liteseal 目录，再将目录改名保留；重新启动后使用新的测试账号。只重置客户端不会删除服务端已注册用户名。不要为普通重测删除 PostgreSQL 数据卷，也不要在日志或问题报告中上传密钥文件、令牌或密码。

## 8. 自动化检查与 Windows 打包

在仓库根目录执行：

```powershell
npm run build --prefix ui
cargo check --workspace
cargo test --workspace
```

按模块验证：

```powershell
cargo test -p liteseal-shared
cargo test -p liteseal-core
cargo test -p liteseal-core --test db_test
```

共享测试覆盖加解密、签名、篡改、序列化等；当前数据库集成测试在 `core/tests/db_test.rs`，不在旧文档的 `src-tauri/tests/`。通过这些检查不等于真实桌面 IPC、数据库服务、网络、DPAPI 和双人聊天均已通过。

Windows 上生成安装包：

```powershell
Set-Location C:\coding\LiteSeal\src-tauri
cargo tauri build
```

构建会自动执行前端 build。默认产物位于 workspace 的 `target\release\`，安装包位于 `target\release\bundle\`。若只想验证 NSIS 安装包，可执行 `cargo tauri build --bundles nsis`。具体打包环境要求参考 [Tauri Windows Installer](https://v2.tauri.app/distribute/windows-installer/)。安装后的客户端仍需要可达的 LiteSeal 服务端，安装包不会替你启动 PostgreSQL 或中继服务。

## 9. 常见问题定位

| 现象 | 检查与处理 |
| --- | --- |
| 根目录 npm run dev 报 Missing script | 使用 `npm run dev --prefix ui`，或进入 ui |
| Vite 提示 Node 版本不兼容 | 检查 `node --version`，满足第 2 节版本要求后重装前端依赖 |
| PowerShell 阻止 npm.ps1 | 可用 `npm.cmd` 执行相同命令 |
| no such command: tauri | 安装 Tauri CLI 2.x，重新打开终端，检查 Cargo bin 是否在 PATH |
| link.exe / Windows SDK 缺失 | 检查 C++ Build Tools 工作负载和 Windows SDK，使用 MSVC 工具链 |
| libsodium-sys 编译或链接失败 | 阅读第一条构建错误；手动库必须与 Rust 的 x64 / MSVC 和 Debug/Release 链接需求匹配，不能混用 MinGW 库 |
| failed to connect to Postgres | 检查 Docker 已运行、postgres 服务健康、5432 可达、DATABASE_URL 已在当前终端设置 |
| 注册失败 / 登录失败 | 先检查 healthz，再检查模式、账号密码、服务端终端错误；注册可能已成功而后续连接/保存失败，此时尝试 Login |
| 浏览器出现 invoke / Tauri 内部对象错误 | 切换到 `cargo tauri dev` 打开的桌面窗口 |
| 等待 frontend dev server / 1420 被占用 | 检查 Vite 输出，关闭自己先前的预览进程；tauri.conf.json 使用 strictPort 对应的 1420 |
| 3000 被占用 | `Get-NetTCPConnection -LocalPort 3000 -State Listen` 查看 OwningProcess，再用 `Get-Process -Id <PID>` 确认；不要盲目结束未知进程 |
| WebView2 错误或白屏 | 检查 WebView2 Runtime、Tauri/Vite 终端以及开发版 Ctrl+Shift+I 中的 Console 错误 |
| 消息未到达 | 确认双方用同一服务端、互加联系人、对方在线或正在补投递；等待数秒，记录消息状态及两端错误 |
| [signature invalid] / [decryption failed] / [encrypted] | 记录是否曾 Logout、换用户、重置数据或新增设备；不要把该占位符当作消息正文或忽略 |
| Storage Manager 一直 Loading | 查看开发者工具和 Rust 终端，当前读取失败主要写控制台 |
| Linux 报 Secret store is not implemented | 当前非 Windows 的密钥保存实现不支持，Windows 功能验收需要回到 Windows |

手动指定 libsodium 静态库的示例（路径替换为实际包含 MSVC `libsodium.lib` 的目录）：

```powershell
$env:SODIUM_LIB_DIR = 'C:\deps\libsodium\lib'
Remove-Item Env:SODIUM_STATIC -ErrorAction SilentlyContinue
Remove-Item Env:SODIUM_SHARED -ErrorAction SilentlyContinue
Remove-Item Env:SODIUM_USE_PKG_CONFIG -ErrorAction SilentlyContinue
```

本次解析到的 `libsodium-sys 0.2.7` 默认静态链接，设置 `SODIUM_STATIC` 反而会报弃用错误；它不读取 `SODIUM_INCLUDE_DIR`。使用动态库需要另外配置 `SODIUM_SHARED` 并保证运行时能找到 DLL。重新运行失败的 Cargo 命令。库来源及 Windows 构建说明参见 [libsodium 官方安装说明](https://doc.libsodium.org/installation)。

## 10. 本次核查记录与问题报告模板

2026-09-08 文档任务仅修改文档，未修改应用功能。已完成代码入口、界面操作、配置和数据路径核对；前端 TypeScript 检查和 Vite 生产构建通过。`cargo test --offline -p liteseal-shared -p liteseal-core` 通过，共 54 项测试（core 单元 12、数据库 16、shared 加密 3、集成 22、协议 1）。未执行全 workspace 检查与测试。当前运行环境为 Linux，未执行 Windows 桌面、DPAPI、安装包及真实双人联调；上表均保留“未执行”，需要 Windows 实测填写。

问题报告建议复制：

```text
代码提交：
Windows 版本 / 缩放比例：
运行方式：tauri dev / release exe / 安装包
Node / Rust / Tauri CLI 版本：
用例编号：
双方是否独立 Windows 数据环境：
操作步骤：
预期结果：
实际结果和出现时间：
客户端错误 / 服务端日志（去除密码、令牌和密钥）：
截图：
是否能稳定复现：
```

代码定位：界面在 `ui/src/components/`，会话恢复在 `ui/src/App.tsx`，原生桥接在 `ui/src/hooks/useTauri.ts` 与 `src-tauri/src/commands/`，客户端核心在 `core/src/`，服务端启动配置在 `server/src/main.rs`、`server/src/config.rs`。后续完成一个任务后，先记录验证结果，再单独提交该任务涉及的文件，避免把其他未完成改动混入提交。

2026-09-09 注册增强：新增可重复邀请码的服务端校验、Windows 表单确认密码和逐行提示灯。`npm run build --prefix ui`、`cargo check --offline --workspace` 均通过；`cargo test --offline -p liteseal-server -p liteseal-core -p liteseal-shared` 共 60 项测试通过，含 HTTP 邀请码校验与拒绝绕过测试。按用户要求未执行界面交互测试；未执行 Windows 实机注册或真实 PostgreSQL 的多账号注册联调。
