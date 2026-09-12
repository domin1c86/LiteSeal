# LiteSeal 轻密

面向 Windows 与 Android 的聊天软件，当前优先完善 Windows。桌面架构为 **Electron + React + Rust 子进程**，移动端继续复用 Rust 核心。

完整入口、环境配置、邀请码、功能清单及手动测试用例见 [Windows 开发与测试指南](WINDOWS_TESTING_GUIDE.md)。桥接协议及迁移说明见 [Electron 架构说明](ELECTRON_ARCHITECTURE.md)。后续缺项、优先级和完成标准见 [开发清单](DEVELOPMENT_BACKLOG.md)。

## 项目结构

| 目录 | 职责 |
| --- | --- |
| `electron/` | 主进程、preload、类型化桌面接口、stdio 桥接和测试 |
| `desktop/` | `liteseal-desktop` Rust 可执行程序，分发桌面命令 |
| `ui/` | React 18、TypeScript、Vite 8 页面 |
| `core/` | SQLite、会话、联系人、聊天、HTTP/WebSocket、Windows DPAPI |
| `shared/` | libsodium 加密与共享协议 |
| `server/` | Axum 服务端、PostgreSQL 账号/设备/离线密文 |
| `mobile/` | React Native 移动端及 Rust FFI 接入 |
| `scripts/` | 开发启动、构建和安装包验证 |

## Windows 快速开始

开发需要 Node.js 24+、Rust stable x64 MSVC、C++ Build Tools、Windows SDK 和 libsodium。客户端运行不依赖 WebView2。所有命令在仓库根目录执行：

```powershell
npm ci
# 按 Windows 指南另开终端启动数据库、配置环境变量并运行服务端
npm run dev
```

首次注册需要服务端配置的有效邀请码；密码至少 8 字符，确认密码需一致，各行有校验提示灯。现有功能还包括会话恢复、联系人、指纹信任、加密单聊、本地历史、存储统计和清理。

```powershell
npm run build       # UI + Electron + Rust release
npm test            # 桥接自动化 + Rust workspace 测试，不打开界面
npm run dist:win     # Windows x64 NSIS 安装包，输出到 release/
```

`npm run dev --prefix ui` 只提供浏览器预览，无法执行桌面业务。安装包自带 Electron 和 Rust 程序，但不包含服务端或 PostgreSQL。

当前 Linux 环境的编译与自动化结果不能替代 Windows 安装、DPAPI 和真实双人聊天验收；具体记录见 Windows 指南。
