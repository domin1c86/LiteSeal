# 长期群测试

`npm run test:groups:soak` 默认在标记专用 PostgreSQL 中运行 24 小时：10 个合成账号、10 个群，每账号参加全部 10 个群。`node scripts/test-group-soak.mjs --smoke` 只运行六轮，明确记录 mode=smoke。

每轮发消息并调用真实 `process_groups` 轮转补收，检查每个编号恰好出现一次及任务归零。周期注入请求不可达、成功提交响应丢失、进程重启和移除/重新加入隔离；每 20 分钟刷新令牌，短测第二轮验证刷新。报告包含阶段、故障、补收耗时、队列和测试进程内存/CPU，不保存正文、密码、令牌或私钥。运行时长使用单调时钟；实际休眠/停机等间断仍需结合采样间隔解释。

```powershell
./scripts/run-isolated-validation.ps1             # 数据库及三客户端（含 T22）
./scripts/run-isolated-validation.ps1 -SoakSmoke  # 六轮短测
./scripts/run-isolated-validation.ps1 -StartSoak  # 隐藏后台启动 24h，返回 PID/日志
```

入口只在已存在的 `liteseal-postgres-1` 创建随机测试角色及带标记的新库，凭据仅在进程环境。不会启动/重置/删除 Docker、业务库或卷，也不把口令写到报告或命令行；结束恢复调用进程环境，测试库保留。

长期进程使用临时目录中的可执行文件副本，不锁住 `target/debug` 构建文件。结束只清理本轮进程和临时客户端数据。查看 `target/test-results/group-soak-<时间>.json` 的最终 status、mode、actual_seconds 和 samples；后台 started、running 或 smoke=passed 都不代表 24 小时通过。本机 Rust 回归也不替代系统通知/托盘、锁屏、双机和独立审查。
