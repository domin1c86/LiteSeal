# 下一批计划：数据库验收与群聊收尾

目标：完成隔离数据库测试入口、真实服务集成回归、群界面回归及文档同步。每个完整改动验证后独立提交，不推送。

| 步骤 | 交付 | 状态 |
| --- | --- | --- |
| 1 | 专用 PostgreSQL 检查、迁移及串行 ignored 测试入口，脱敏报告 | 已实现；缺失/不可达路径已验证 |
| 2 | 执行全部真实数据库测试并修复 | 待执行：未配置测试库 |
| 3 | 三个隔离 Rust 桌面进程与真实服务的集成回归 | 已编写；真实运行待专用库 |
| 4 | 群静音、邀请、清理、草稿及生命周期界面回归 | 已完成：8 组用例在宽窄窗口通过 |
| 5 | 同步群设计、T16–T20 验收模板和实际结果 | 已完成 |

验证：npm test、npm run build、cargo fmt --all -- --check、Clippy（全 workspace/all-targets，拒绝警告）、核心 ffi 编译。真实数据库通过专用入口运行，跳过不计作通过。同机真实服务集成、模拟接口界面与双机/系统场景分别记录。

约束：只使用 LITESEAL_TEST_DATABASE_URL 明确指定的专用库，不回退业务配置；不自动安装或启动 Docker/PostgreSQL；不处理真实用户数据，不执行安装包、签名、部署或双机验收。保留现有未跟踪文件，不纳入提交。提交只使用 completed/fixed/time，时间为提交当时 UTC+8。

后续：T21 群协作 → T22 备份与 T23 多设备设计。本批不增加这些协议，也不提前勾选 T20。

## 本批实际结果（2026-09-30）

| 验证 | 结果 |
| --- | --- |
| npm test | 15 项 Electron/Node、127 项 Rust 通过；18 项 PostgreSQL ignored |
| npm run build | 通过；保留既有 LNK4098/LNK4099 警告 |
| cargo fmt --all -- --check | 通过 |
| cargo clippy --locked --workspace --all-targets -- -D warnings | 通过 |
| cargo check --locked -p liteseal-core --features ffi | 通过 |
| npm run test:groups:ui | 1280×900 与 390×844 各 8 组通过，截图已核对 |
| npm run test:database | 未执行数据库用例：配置缺失；缺失/不可达及脱敏路径已验证 |
| npm run test:groups:integration | 真实链路未执行：配置缺失；语法及入口失败路径已验证 |

本批源代码与测试工具已交付，步骤 2 和步骤 3 的真实执行仍受环境阻塞。不得将此计划标为全部验收完成。准备专用库后按数据库说明运行两个入口，先修复实际失败，再继续系统/双机验收。T20 保持未勾选。

已提交：`cd008ce` 数据库入口与计划；`1892691` 三客户端集成脚本；`c448753` 群界面回归；`884f69b` 集成队列参数及超时修正。文档汇总随后单独提交。未推送，原有未跟踪文件未纳入提交。
