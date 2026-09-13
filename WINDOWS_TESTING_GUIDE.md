# Windows 界面入口、功能与完整测试指南

适用范围：当前仓库 Windows 桌面客户端；移动端不在本次验收范围内。核对日期：2026-09-09。本文根据当前工作区代码编写，功能“已实现”表示有代码与界面入口，不代表已经通过 Windows 实机验收。桌面端现使用 Electron + Rust 子进程，启动与打包均从仓库根目录执行。

## 1. 怎么进入前端

前端位于 `ui/`，入口链路为 `ui/index.html → ui/src/main.tsx → ui/src/App.tsx`。首次显示 Login / Register；保存过有效会话时会尝试恢复到主界面。

| 目的 | 命令和入口 | 能测什么 |
| --- | --- | --- |
| 浏览器查看登录页 | 仓库根目录执行 `npm ci`，再执行 `npm run dev --prefix ui`；打开 `http://127.0.0.1:1420` | 登录页布局、输入框、登录/注册切换、按钮禁用状态 |
| Windows 完整功能测试 | 按下文启动 PostgreSQL、服务端，再在仓库根目录执行 `npm run dev` | 桌面 IPC、账号、联系人、收发消息、本地数据 |
| 构建后的程序 | Windows 构建后运行 `release\win-unpacked\LiteSeal.exe`，或安装生成的安装包 | 脱离开发服务器的桌面使用体验 |

浏览器没有 Electron preload 提供的 `window.desktop`，仅用于页面预览，业务操作会提示通过桌面应用使用。端口 **1420 是开发前端**，**3000 是 API / WebSocket 服务端**，**5432 是 PostgreSQL**。`npm run dev` 启动完整桌面应用；`npm run dev --prefix ui` 仅启动预览。正式安装包加载内置页面，不需要 1420 端口。

## 2. Windows 首次环境准备

以下命令使用 **Windows PowerShell**，示例仓库路径为 `C:\coding\LiteSeal`，请替换为你的实际路径。客户端应在 Windows 本机运行；WSL 的 Linux 程序不能替代 Windows DPAPI 密钥保存测试。

准备以下依赖：

- Git、Node.js **24 或更新版本**和 npm；依赖锁定在根目录 `package-lock.json`。
- Rust stable 的 Windows x64 MSVC 工具链、Visual Studio C++ Build Tools 的“使用 C++ 的桌面开发”工作负载和 Windows SDK。
- Electron 由 npm 依赖管理，首次使用会下载运行时；不再需要桌面框架 CLI 或 WebView2。
- libsodium 的 Windows MSVC 库；如编译器无法自动准备，按第 9 节配置。
- PostgreSQL；下文使用已安装并启动的 Docker Desktop，通过仓库 Compose 启动数据库。也可以使用本机 PostgreSQL，创建对应账号和数据库后修改连接串。

```powershell
Set-Location C:\coding\LiteSeal
node --version
npm --version
rustc --version
cargo --version
rustup show active-toolchain
npm ci
```

`npm ci` 使用根目录 `package-lock.json`，统一安装 Electron 和 ui workspace 依赖，需要联网下载尚未缓存的依赖。首次 Cargo 构建也可能需要下载依赖；不要把编译时间误判为界面卡死。

## 3. 启动完整 Windows 开发环境

### 终端 A：数据库与服务端

```powershell
Set-Location C:\coding\LiteSeal
docker compose up -d postgres
docker compose ps postgres
docker compose exec postgres pg_isready -U liteseal -d liteseal
$env:DATABASE_URL = 'postgres://liteseal:liteseal@localhost:5432/liteseal'
$env:LITESEAL_BIND = '0.0.0.0:3000'
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
npm run dev
```

健康检查应返回 `ok`。开发脚本构建 Rust 子进程及 Electron 主进程/preload，启动 Vite 后打开 1024×768 的可调整窗口；一般不需要另开 Vite。React 修改支持热更新，修改 Electron 或 Rust 后重启 `npm run dev`。先前预览启动的 Vite 应先用 Ctrl+C 停止，避免 1420 端口冲突。

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
| 左上角 `⏻` | Logout：断开连接、清除登录凭据、保留本机密钥、回到登录页 | 不等同于普通关闭窗口，见第 7 节 |
| Windows 密钥保存 | 使用 DPAPI 保存 `keystore.bin` | 与 Windows 用户环境绑定，跨用户复制文件不能作为迁移方案 |
| 服务端能力 | PostgreSQL 账号/设备数据、会话接口、离线密文排队及上线投递 | 需要真实双客户端测试验证端到端效果 |

当前桌面界面没有图片/文件发送下载、语音/视频、群聊、消息搜索、撤回、联系人删除按钮、设备管理、密码重置和密钥导入导出入口。部分底层接口已经存在，不能据此算作桌面功能完成。没有消息过期时间设置入口，正常发送的消息一般不会被“清理过期消息”删除。

历史默认读取最近 50 条，通过“加载更早消息”按时间与消息编号游标向前分页，避免新消息插入导致偏移量变化。此功能已完成开发，交互验收按当前约定暂未执行。

## 5. 双人聊天怎么测

不要在同一个 Windows 用户下开两个开发命令当作 Alice / Bob：它们会争用 Vite 端口，还会共用数据库和密钥文件。Electron 启用单实例锁，重复启动已打包程序会聚焦现有窗口。复制仓库目录不会隔离数据；Rust 的 `--db-path` 仅供桥接自动化测试隔离数据库，不改变密钥路径，不是双账号 profile。升级时先关闭旧版客户端。

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
| W12 | 启动服务端后重新启动客户端，发送消息 | 重新连接后可以互发；检查在线/离线/重连状态和自动恢复；鉴权失效应提示重新登录 | 未执行 |
| W13 | 联系人详情点击 Verify，再 Unverify，再点 Message | 信任标签同步变化，Message 打开正确会话；不据此断言安全身份验证完成 | 未执行 |
| W14 | 打开 Storage Manager，收发后重新打开 | 计数有合理变化；Total 是逻辑大小，不与 data.db 文件大小硬比较 | 未执行 |
| W15 | 在测试数据上点击两项清理 | 显示清理数量并刷新统计；无过期/附件数据时应为 0 | 未执行 |
| W16 | 调整窗口至 1024×768、较窄尺寸，Windows 缩放 100% / 150% | 输入和发送按钮可达、弹窗关闭按钮可见、长用户名/消息不遮挡关键内容 | 未执行 |
| W17 | 输入未发送文字后切换联系人，再测试断网发送 | 核查草稿是否串到其他联系人、失败后文字是否丢失；发送成功才清空输入，失败可重试原消息 | 未执行 |
| W18 | 连续发送超过 50 条后重新打开会话 | 记录历史显示范围；使用“加载更早消息”，确认无重复漏项并保留滚动位置 | 未执行 |
| W19 | 最后执行 Logout，然后同账号重新登录 | 返回登录页；核查新的设备/密钥导致的历史解密及联系人指纹变化，不预设无损恢复 | 未执行 |
| W20 | 使用安装包在另一 Windows 测试环境安装并启动 | 无 Node/Rust 开发环境也能显示界面；连接服务端后完成 W06；关闭、重开和卸载可执行 | 未执行 |

长时间在线、令牌过期、服务器重启及多设备收件尚需单独回归。不要把一次发送成功当作这些场景已通过。密文日志也不能单独证明整个端到端加密链路正确，应结合对端明文、签名/篡改测试和错误密钥测试。

## 7. 数据位置、退出与重新测试

当前路径来自 `desktop/src/main.rs` 和 `core/src/keystore.rs`：

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

普通关闭窗口会保留保存的密钥，适合重启和离线补投递测试。**Logout 清除本地令牌但保留密钥和数据库**，并尝试撤销服务器会话；服务器不可达会明确提示远端撤销未确认。重新登录原账号沿用原密钥，不自动覆盖设备身份。当前本机保持单身份，切换账号使用独立 Windows 用户环境；密钥丢失后，仅凭账号密码无法恢复旧消息。

需要从零测试时，优先换独立 Windows 用户或虚拟机快照。若确实要重置现有测试环境，先关闭所有客户端，备份上述两个 liteseal 目录，再将目录改名保留；重新启动后使用新的测试账号。只重置客户端不会删除服务端已注册用户名。不要为普通重测删除 PostgreSQL 数据卷，也不要在日志或问题报告中上传密钥文件、令牌或密码。

## 8. 自动化检查与 Windows 打包

在仓库根目录执行：

```powershell
npm run build
cargo check --locked --workspace
npm test
```

按模块验证：

```powershell
cargo test -p liteseal-shared
cargo test -p liteseal-core
cargo test -p liteseal-core --test db_test
cargo test -p liteseal-desktop
node --test electron/tests/*.test.cjs
```

共享测试覆盖加解密、签名、篡改和序列化；数据库测试位于 `core/tests/`。`npm test` 构建桥接及 Rust 子进程，运行 Node 桥接测试和全部 Rust 测试。Node 测试使用真实 Rust 子进程、临时 SQLite、模拟 HTTP 服务及管道故障，既不打开界面，也不读写用户真实密钥。Windows 另执行隔离文件上的 DPAPI 兼容测试。

Windows x64 上生成安装包：

```powershell
Set-Location C:\coding\LiteSeal
npm run dist:win
```

该命令先构建所有组件，再用 electron-builder 生成 NSIS 安装包，并检查 Rust exe、前端页面和 preload 是否进入安装包。安装包位于 `release\`，免安装目录为 `release\win-unpacked\`。单独的 `target\release\liteseal-desktop.exe` 是内部 Rust 服务，没有界面，不是应用入口。安装包自带 Electron 和 Rust 程序，用户无需 Node、Rust 或 WebView2；仍需要可达的 LiteSeal 服务端。构建不签名、不发布、不内置服务端或 PostgreSQL。

`.github/workflows/windows-desktop.yml` 配置 Windows 编译、自动化测试、NSIS 构建与产物上传。工作流文件已提供，但只有远端实际运行成功后才能将 Windows 构建记为通过。

## 9. 常见问题定位

| 现象 | 检查与处理 |
| --- | --- |
| npm 找不到桌面依赖 | 在仓库根目录执行 `npm ci`，不要仅安装 ui 依赖 |
| Vite 提示 Node 版本不兼容 | 检查 `node --version`，满足第 2 节版本要求后重装前端依赖 |
| PowerShell 阻止 npm.ps1 | 可用 `npm.cmd` 执行相同命令 |
| Electron failed to install / 下载失败 | 检查运行时下载网络，根目录执行 `npm exec -- install-electron --no` 后重试 |
| link.exe / Windows SDK 缺失 | 检查 C++ Build Tools 工作负载和 Windows SDK，使用 MSVC 工具链 |
| libsodium-sys 编译或链接失败 | 阅读第一条构建错误；手动库必须与 Rust 的 x64 / MSVC 和 Debug/Release 链接需求匹配，不能混用 MinGW 库 |
| failed to connect to Postgres | 检查 Docker 已运行、postgres 服务健康、5432 可达、DATABASE_URL 已在当前终端设置 |
| 注册失败 / 登录失败 | 先检查 healthz，再检查模式、账号密码、服务端终端错误；注册可能已成功而后续连接/保存失败，此时尝试 Login |
| 提示通过 Electron 桌面使用 | 切换到根目录 `npm run dev` 打开的桌面窗口 |
| 等待 frontend dev server / 1420 被占用 | 检查 Vite 输出，关闭自己先前的预览进程；Vite 固定使用 127.0.0.1:1420 |
| 3000 被占用 | `Get-NetTCPConnection -LocalPort 3000 -State Listen` 查看 OwningProcess，再用 `Get-Process -Id <PID>` 确认；不要盲目结束未知进程 |
| 白屏 / 无法启动桌面服务 | 检查开发终端的构建错误或启动错误框；安装版确认 resources/desktop 中存在 Rust exe，重新安装完整程序 |
| 桌面服务异常退出 | 应用提示后退出；重新启动恢复本地会话，不自动重发结果未确定的操作 |
| 消息未到达 | 确认双方用同一服务端、互加联系人、对方在线或正在补投递；等待数秒，记录消息状态及两端错误 |
| [signature invalid] / [decryption failed] / [encrypted] | 记录是否曾 Logout、换用户、重置数据或新增设备；不要把该占位符当作消息正文或忽略 |
| Storage Manager 一直 Loading | 查看开发者工具和桌面错误提示，当前读取失败主要写控制台 |
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
运行方式：npm run dev / win-unpacked / 安装包
Node / Rust / Electron 版本：
用例编号：
双方是否独立 Windows 数据环境：
操作步骤：
预期结果：
实际结果和出现时间：
客户端错误 / 服务端日志（去除密码、令牌和密钥）：
截图：
是否能稳定复现：
```

代码定位：界面在 `ui/src/components/`，会话恢复在 `ui/src/App.tsx`，原生桥接在 `ui/src/hooks/useDesktop.ts`、`electron/` 与 `desktop/src/commands/`，客户端核心在 `core/src/`，服务端启动配置在 `server/src/main.rs`、`server/src/config.rs`。后续完成一个任务后，先记录验证结果，再单独提交该任务涉及的文件，避免把其他未完成改动混入提交。

2026-09-09 注册增强：新增可重复邀请码的服务端校验、Windows 表单确认密码和逐行提示灯。`npm run build --prefix ui`、`cargo check --offline --workspace` 均通过；`cargo test --offline -p liteseal-server -p liteseal-core -p liteseal-shared` 共 60 项测试通过，含 HTTP 邀请码校验与拒绝绕过测试。按用户要求未执行界面交互测试；未执行 Windows 实机注册或真实 PostgreSQL 的多账号注册联调。


2026-09-09 Electron 迁移核查：已替换桌面外壳及全部 26 个命令，保留 Rust 核心和既有数据路径。`npm run build`、`cargo check --offline --workspace` 通过；Node 桥接及主进程测试 11 项、Rust workspace 测试 63 项通过，共 74 项。测试包括真实子进程的密码学和数据库调用、模拟 HTTP 端点、WebSocket 连接/发送/状态落库，以及分帧、超时、错误和 EOF 退出；主进程模拟测试验证 IPC 来源、导航限制和资源 CSP。另通过 electron-builder 在 Linux 生成未安装目录并检查 ASAR 页面/preload 与 Rust 资源，Windows 图标转换检查通过。已配置 Windows CI 的编译、DPAPI 测试及 NSIS 安装包资源验证，但尚未在 Windows 执行。按要求未进行任何界面交互测试，也未进行真实 PostgreSQL 双账号联调。


2026-09-11 P0 开发更新（本轮不执行测试）：完成离线写入失败反馈、心跳和串行自动重连、会话失效分类、按联系人草稿、持久化密文重试、普通退出保留密钥和游标分页。服务端现在先保存再投递，客户端落库后 ACK；queued 表示已保存等待设备确认，received 表示目标设备已保存，不表示已读。未确认消息不再按离线时长自动删除。新增 outgoing_payloads / outgoing_delivery 本地表由启动初始化，桌面接口现为 29 个。2026-09-13 已实现 V2 按收件设备完整性链，待验收。所有本轮验证仅为构建/编译检查，先前自动化通过记录不代表本轮修改已经回归。


### V2 消息链升级（2026-09-13）

客户端与服务端必须统一部署新版；保留本机数据库和密钥，旧历史继续读取。建议在维护窗口先停止旧客户端、备份数据库、升级服务端后再启动新版客户端，不将新旧版本混用作为支持场景。

服务端启动为 offline_messages 增加 chain_version（旧记录默认为 0）；本地启动新增 outgoing_chains 和 incoming_chain_versions。新版发送使用 send_v2，按收件设备分别记录序号与前序哈希，服务端以 message_v2 转发。旧队列和旧重试载荷仍按旧版本处理。新增设备从独立链起点接收新消息，不因此获得旧历史。

乱序消息先保存并标记异常，前序补齐后重新校验并更新当前界面。内容或元数据冲突不会当作正常重复消息确认。服务端读取待投递队列失败时断开连接，以便客户端重连重试。

本轮未运行自动化测试或界面交互测试；旧数据库升级、多设备连续消息、乱序补收、ACK 丢失及 Windows 实机行为仍需后续验收。


### P1 会话列表（2026-09-13）

聊天标签显示最近消息摘要、时间及未读数，并按最近消息时间排序；联系人标签继续显示信任状态。会话行支持 Enter/空格选择。列表约每 2 秒刷新本地数据，离线也能使用；解密或验证失败显示占位提示。

本机已读状态重启后保留。仅打开聊天且窗口可见并获得焦点时，已加载的收到消息才标为已读；更早的未加载消息需加载历史后消除未读。切换联系人详情、最小化或失去焦点时不自动清零。不发送对方已读回执。旧版本没有已读记录，升级后旧收到消息初始计入未读。

桌面业务接口新增 2 个，总计 31 个。本轮只完成编译/构建检查，未执行测试与界面验收。


### P1 会话整理（2026-09-13）

聊天行支持置顶/取消置顶、归档/移回聊天；“已归档”按钮切换归档列表。归档仍接收消息并累计未读，不自动回到普通聊天列表。置顶在当前列表内优先排序。

草稿自动加密保存到本机，列表显示“草稿”提示，重启或普通退出后同账号登录可恢复。失败发送的原消息编号一同保留。状态栏显示保存进度，失败可点“重试”；恢复失败时暂停编辑，防止覆盖旧草稿。未保存时常规关闭会被阻止，请完成保存后再次关闭；强制结束进程不保证保留最后尚未写入的内容。

本轮增加 2 个业务接口，总计 33 个。编译/构建通过；按要求未运行测试，上述 Windows 恢复与关闭行为仍待实机验收。


### P1 引用、复制与转发（2026-09-13）

消息下方新增“复制”“回复”“转发”。复制只复制正文；回复将最多 500 字符的原文快照加入当前草稿，可在发送前移除。收到的引用可点击定位已加载原消息，未加载时提示先加载更早消息。

转发选择联系人后生成该会话的加密草稿，需要再点发送；目标已有草稿时拒绝覆盖。转发来源为转发者提供的信息。引用与转发标记会在重启恢复草稿时保留，原消息进入失败重试状态后不能修改标记。

旧纯文本历史继续读取。当前只完成 D-03 的引用、复制与转发，编辑、删除和撤回尚未提供。业务 API 总计 34 个。本轮通过前端/Electron 构建，未执行自动化或界面测试。
