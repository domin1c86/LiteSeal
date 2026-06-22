# LiteSeal 轻密

一款面向 Windows 与 Android 的安全聊天软件。核心特点：端到端加密、本地加密存储、媒体按需下载、空间占用透明可控。

## 技术栈

| 层 | 技术 |
|---|---|
| 客户端 UI | React 18 + TypeScript + Vite 5 |
| 客户端框架 | Tauri 1 |
| 客户端核心 | Rust (tokio, rusqlite, reqwest) |
| 加密 | libsodium |
| 服务端 | Rust + Axum (WebSocket 中继) |
| 共享库 | Rust (`liteseal-shared`)，客户端与服务端共用协议与加密逻辑 |

## 项目结构

```
LiteSeal/
├── src-tauri/       # Tauri 客户端应用 (Rust)
├── ui/              # 前端界面 (React + TypeScript)
├── server/          # 加密中继服务器 (Axum)
├── shared/          # 共享协议与加密库
└── Cargo.toml       # Rust workspace 根
```

## 快速开始

### 环境要求

- Rust (nightly/stable)
- Node.js >= 18
- npm

### 安装依赖

```bash
# 前端依赖
cd ui && npm install

# Rust 依赖会在首次构建时自动拉取
```

### 开发模式

```bash
# 启动客户端（同时启动 Vite dev server 和 Tauri）
cd src-tauri && cargo tauri dev

# 启动服务端
cd server && cargo run
```

### 构建

```bash
cd ui && npm run build
cd src-tauri && cargo tauri build
```

## 当前状态

项目处于早期技术验证阶段，正在构建核心基础架构。
