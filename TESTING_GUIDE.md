# LiteSeal 开发测试指南

你是开发者，代码已写好，现在要验证功能是否正常。

---

## 快速启动（3步）

### 第 1 步：安装前端依赖（仅首次）

```bash
cd ui && npm install
```

### 第 2 步：启动服务器

打开终端 A：

```bash
cd server && cargo run
```

看到 `Server listening on 0.0.0.0:3000` 表示成功。**保持这个终端运行。**

### 第 3 步：启动客户端

打开终端 B：

```bash
cd src-tauri && cargo tauri dev
```

首次会编译几分钟，之后会自动打开 LiteSeal 窗口。

---

## 验证功能

### 验证注册

1. 在登录界面输入用户名（如 `alice`）
2. 服务器地址填 `http://localhost:3000`
3. 点击注册
4. **成功标志**：跳转到聊天界面，终端 A 显示注册日志

### 验证发送消息

1. 在聊天界面输入任意消息，点击发送
2. **成功标志**：消息出现在聊天记录中，终端 A 显示 `Relaying message` 日志

### 验证双人聊天（端到端加密）

需要同时运行两个客户端实例：

```bash
# 终端 B - 用户 Alice
cd src-tauri && cargo tauri dev

# 终端 C - 用户 Bob（新终端窗口）
cd src-tauri && cargo tauri dev
```

两个窗口分别注册 `alice` 和 `bob`，然后互相发消息。

**成功标志**：双方都能收到对方的消息，服务器终端只显示密文中继。

---

## 运行单元测试

```bash
# 全部测试（27个）
cargo test --workspace

# 只测加密模块
cargo test -p liteseal-shared

# 只测数据库
cargo test -p liteseal-app
```

全部 `ok` 即通过。

---

## 常见问题

### 编译报错：找不到 libsodium

Windows 需要安装 libsodium：

```bash
# 方法1：用 vcpkg
vcpkg install libsodium

# 方法2：手动下载
# 从 https://download.libsodium.org/libsodium/releases/ 下载
# 解压后设置环境变量：
set SODIUM_LIB_DIR=C:\path\to\libsodium\lib
set SODIUM_INCLUDE_DIR=C:\path\to\libsodium\include
```

### Tauri 启动失败：WebView2 错误

下载安装：https://developer.microsoft.com/en-us/microsoft-edge/webview2/

### 端口 3000 被占用

```bash
# 找到占用进程
netstat -ano | findstr :3000

# 杀掉进程
taskkill /PID <进程ID> /F
```

### 前端白屏或报错

```bash
cd ui
rm -rf node_modules
npm install
```

### cargo tauri dev 卡住不动

检查终端 A 的服务器是否在运行。如果没启动，客户端无法连接。

---

## 调试技巧

### 查看详细日志

```bash
# 服务器
RUST_LOG=debug cargo run -p liteseal-server

# 客户端
RUST_LOG=debug cargo tauri dev
```

### 检查数据库内容

数据库文件位置：`%LOCALAPPDATA%\liteseal\data.db`

用 SQLite 工具打开查看：

```bash
sqlite3 "%LOCALAPPDATA%\liteseal\data.db" ".tables"
```

### 验证服务器只转发密文

在 `server/src/relay/handlers.rs` 的消息转发处加日志：

```rust
tracing::info!("Relaying: {:?}", &msg.ciphertext[..8.min(msg.ciphertext.len())]);
```

重启服务器，发消息后在终端 A 看到的是字节数组，不是明文，说明加密生效。

---

## 代码改了之后怎么测

| 改了什么 | 怎么验证 |
|---------|---------|
| `shared/src/crypto.rs` | `cargo test -p liteseal-shared` |
| `src-tauri/src/db/` | `cargo test -p liteseal-app` |
| `server/src/` | 重启服务器（终端 A Ctrl+C 再 `cargo run`） |
| `src-tauri/src/commands/` | 重启客户端（终端 B Ctrl+C 再 `cargo tauri dev`） |
| `ui/src/` | Vite 热更新，无需重启，刷新窗口即可 |
| `Cargo.toml` 依赖变更 | 重启对应服务 |
