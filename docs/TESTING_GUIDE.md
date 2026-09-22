# 测试入口

Windows 桌面开发、功能清单和完整手动用例统一维护在 [WINDOWS_TESTING_GUIDE.md](WINDOWS_TESTING_GUIDE.md)。Electron 桥接协议、数据兼容和进程生命周期见 [ELECTRON_ARCHITECTURE.md](ELECTRON_ARCHITECTURE.md)。

在仓库根目录执行：

```powershell
npm ci
npm run dev
```

完整业务测试需要另行启动服务端与 PostgreSQL，并配置测试邀请码；浏览器预览不能代替 Electron 桌面应用。

自动化检查：

```powershell
cargo check --locked --workspace
npm test
npm run build
```

Windows x64 打包：`npm run dist:win`，产物在 `release/`。双人测试使用两台机器或独立 Windows 用户环境。

本次迁移按用户要求不执行界面交互测试，手动用例保持“未执行”。
