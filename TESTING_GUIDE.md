# LiteSeal 体验与测试指南

本指南将帮助你从零开始搭建并体验 LiteSeal 技术验证Demo。

---

## 一、环境准备

### 1.1 必需工具

| 工具 | 版本要求 | 说明 |
|------|----------|------|
| Rust | stable (1.70+) | 安装：https://rustup.rs |
| Node.js | >= 18 | 安装：https://nodejs.org |
| npm | 随 Node.js | 包管理器 |
| Git | 任意版本 | 版本控制 |

### 1.2 验证安装

打开终端，运行以下命令确认安装成功：

```bash
rustc --version
cargo --version
node --version
npm --version
```

### 1.3 Windows 额外依赖

Tauri 在 Windows 上需要以下依赖：

1. **Microsoft Visual Studio C++ Build Tools**
   - 下载：https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - 安装时选择"使用 C++ 的桌面开发"

2. **WebView2**（Windows 10/11 通常已预装）
   - 下载：https://developer.microsoft.com/en-us/microsoft-edge/webview2/

---

## 二、项目搭建

### 2.1 克隆项目（如已有代码可跳过）

```bash
cd D:\Coding
git clone <your-repo-url> LiteSeal
cd LiteSeal
```

### 2.2 安装前端依赖

```bash
cd ui
npm install
cd ..
```

### 2.3 验证 Rust 工作空间

```bash
cargo check --workspace
```

预期输出：编译成功，可能有一些警告但无错误。

---

## 三、启动服务端

### 3.1 启动中继服务器

在**第一个终端窗口**中运行：

```bash
cd server
cargo run
```

预期输出：
```
INFO Server listening on 0.0.0.0:3000
```

服务器现在运行在 `http://localhost:3000`。

### 3.2 验证服务器运行

在**第二个终端窗口**中测试：

```bash
# 测试注册接口
curl -X POST http://localhost:3000/register -H "Content-Type: application/json" -d "{\"username\":\"testuser\"}"
```

预期输出（JSON格式）：
```json
{"user_id":"<uuid>","token":"<uuid>"}
```

---

## 四、启动客户端

### 4.1 启动 Tauri 开发模式

在**第三个终端窗口**中运行：

```bash
cd src-tauri
cargo tauri dev
```

首次启动会：
1. 编译 Rust 代码（可能需要几分钟）
2. 启动 Vite 开发服务器
3. 打开 LiteSeal 应用窗口

### 4.2 应用界面

启动后你会看到：
- **登录界面**：输入用户名和服务器地址
- **聊天界面**：发送和接收消息
- **联系人列表**：侧边栏显示联系人

---

## 五、功能体验

### 5.1 注册新用户

1. 在登录界面输入用户名（如 `alice`）
2. 服务器地址保持 `http://localhost:3000`
3. 点击"注册"按钮
4. 注册成功后自动进入聊天界面

### 5.2 测试发送消息

1. 在聊天界面输入消息
2. 点击"发送"或按 Enter
3. 消息会通过服务器中继

### 5.3 双用户测试（完整流程）

要体验完整的端到端加密聊天，需要**两个客户端实例**：

**步骤 1：启动两个客户端**

```bash
# 终端 3 - 用户 Alice
cd src-tauri
cargo tauri dev

# 终端 4 - 用户 Bob（新终端窗口）
cd src-tauri
cargo tauri dev
```

**步骤 2：分别注册**

- Alice：用户名 `alice`，服务器 `http://localhost:3000`
- Bob：用户名 `bob`，服务器 `http://localhost:3000`

**步骤 3：互相发送消息**

- Alice 向 Bob 发送消息
- Bob 向 Alice 发送消息
- 观察消息是否正常中继

---

## 六、运行测试

### 6.1 运行所有测试

```bash
cargo test --workspace
```

### 6.2 运行加密模块测试

```bash
cargo test -p liteseal-shared
```

预期输出：
```
running 27 tests
test test_keypair_generation ... ok
test test_encrypt_decrypt ... ok
test test_sign_verify ... ok
...
test result: ok. 27 passed; 0 failed
```

### 6.3 运行数据库测试

```bash
cargo test -p liteseal-app
```

### 6.4 查看测试覆盖率

```bash
# 安装 cargo-tarpaulin（可选）
cargo install cargo-tarpaulin

# 生成覆盖率报告
cargo tarpaulin -p liteseal-shared
```

---

## 七、技术验证要点

### 7.1 验证端到端加密

**测试方法：**

1. 查看服务器日志，确认只传输密文
2. 在 `server/src/relay/handlers.rs` 中添加日志：
   ```rust
   tracing::info!("Relaying ciphertext: {:?}", &msg.ciphertext[..8]);
   ```
3. 确认服务器无法解密消息内容

### 7.2 验证本地加密存储

**测试方法：**

1. 运行数据库测试：
   ```bash
   cargo test -p liteseal-app
   ```
2. 检查 SQLite 数据库文件（如存在）：
   ```bash
   # 数据库位置（Windows）
   %APPDATA%\com.liteseal.app\liteseal.db
   ```

### 7.3 验证 WebSocket 通信

**测试方法：**

1. 使用 WebSocket 测试工具（如 Postman）连接 `ws://localhost:3000/ws`
2. 发送认证消息：
   ```json
   {"type": "auth", "user_id": "test", "token": "test"}
   ```
3. 观察服务器响应

---

## 八、代码结构说明

### 8.1 客户端核心模块

```
src-tauri/src/
├── main.rs           # Tauri 应用入口
├── lib.rs            # AppState 定义
├── commands/
│   ├── auth.rs       # 认证命令（注册、连接）
│   └── chat.rs       # 聊天命令（发送、接收）
├── db/
│   ├── models.rs     # 数据模型
│   └── repository.rs # 数据库操作
└── network/
    └── websocket.rs  # WebSocket 客户端
```

### 8.2 服务端模块

```
server/src/
├── main.rs           # 服务器入口
├── state.rs          # 应用状态（连接管理）
├── auth/
│   └── handlers.rs   # 注册接口
└── relay/
    └── handlers.rs   # WebSocket 消息中继
```

### 8.3 共享库

```
shared/src/
├── lib.rs            # 模块导出
├── crypto.rs         # 加密函数（密钥生成、加解密、签名）
└── types.rs          # 共享类型定义
```

---

## 九、常见问题

### Q1: 编译失败，提示找不到 libsodium

**解决方案：**

Windows 上需要安装 libsodium：

```bash
# 使用 vcpkg
vcpkg install libsodium

# 或设置环境变量
set SODIUM_LIB_DIR=C:\path\to\libsodium\lib
set SODIUM_INCLUDE_DIR=C:\path\to\libsodium\include
```

### Q2: Tauri 启动失败，提示 WebView2 错误

**解决方案：**

下载并安装 WebView2 Runtime：
https://developer.microsoft.com/en-us/microsoft-edge/webview2/

### Q3: 服务器启动失败，端口被占用

**解决方案：**

```bash
# 查找占用端口的进程
netstat -ano | findstr :3000

# 终止进程
taskkill /PID <进程ID> /F

# 或修改服务器端口（server/src/main.rs:20）
let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
```

### Q4: 前端启动失败

**解决方案：**

```bash
cd ui
rm -rf node_modules package-lock.json
npm install
```

---

## 十、开发者调试技巧

### 10.1 查看详细日志

```bash
# 服务器日志级别
RUST_LOG=debug cargo run -p liteseal-server

# 客户端日志
RUST_LOG=debug cargo tauri dev
```

### 10.2 使用 VSCode 调试

1. 安装扩展：rust-analyzer、CodeLLDB
2. 创建 `.vscode/launch.json`：
   ```json
   {
     "version": "0.2.0",
     "configurations": [
       {
         "type": "lldb",
         "request": "launch",
         "name": "Debug Tauri",
         "cargo": {
           "args": ["build", "--manifest-path=src-tauri/Cargo.toml"]
         },
         "program": "${workspaceFolder}/src-tauri/target/debug/liteseal-app"
       }
     ]
   }
   ```

### 10.3 测试加密性能

```bash
# 运行加密基准测试
cargo bench -p liteseal-shared

# 或手动测试
cargo test -p liteseal-shared test_large_message_encryption -- --nocapture
```

---

## 十一、下一步探索

完成基础体验后，可以尝试：

1. **阅读源码**：从 `shared/src/crypto.rs` 开始理解加密实现
2. **修改协议**：在 `server/src/relay/handlers.rs` 中添加新消息类型
3. **扩展功能**：实现文件传输、群聊等
4. **性能优化**：使用 `cargo flamegraph` 分析热点
5. **安全审计**：检查加密实现是否符合最佳实践

---

## 十二、反馈与贡献

如遇到问题或有改进建议：

1. 查看 `plan-book.md` 了解项目规划
2. 在 `docs/compose/specs/` 中查看设计文档
3. 提交 Issue 或 Pull Request

---

**祝你体验愉快！** 🎉
