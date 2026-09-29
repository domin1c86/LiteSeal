# 专用 PostgreSQL 验收

`npm run test:database` 只读取进程环境中的 `LITESEAL_TEST_DATABASE_URL`，不加载 .env，也不回退到 DATABASE_URL。缺失环境返回非零，报告为 not_executed。入口先编译服务端，再以 `--test-database-check --migrate` 校验连接和隔离标记，通过后使用正常迁移逻辑；依次单独运行所有 ignored 服务端用例。脱敏结果位于 `target/test-results/database.json`，包含提交、数据库版本、用例名及通过/失败/跳过数量。原始异常不输出、不保存；失败后需在隔离环境针对用例诊断，分享日志前检查敏感数据。

## 手工准备

使用已启动的本机 PostgreSQL，通过管理员连接创建独立角色与库（密码自行生成，不使用真实账号）：

```sql
CREATE ROLE liteseal_test_runner LOGIN PASSWORD '<随机测试密码>';
CREATE DATABASE liteseal_test_suite OWNER liteseal_test_runner;
COMMENT ON DATABASE liteseal_test_suite IS 'liteseal-dedicated-test-v1';
```

库名必须以 `liteseal_test_` 开头，仅含小写字母、数字和下划线，且数据库 COMMENT 必须完全匹配以上标记。不要在现有业务库添加此标记。角色仅授予该测试库权限；测试会执行迁移并保留合成账号及消息，建议每轮使用新建的专用库。

PowerShell 中设置 `LITESEAL_TEST_DATABASE_URL` 为该角色的 PostgreSQL URL（特殊字符需 URL 编码），然后执行：

```powershell
npm run test:database
```

脚本不会安装/启动 Docker 或 PostgreSQL，也不创建、删除或重置数据库。仓库历史的直接 cargo ignored 命令没有此入口的隔离门禁，应优先使用新入口。数据库检测 CLI 不启动 HTTP 服务，不读取业务配置，错误仅输出固定阶段信息。

## 三客户端真实服务回归

`npm run test:groups:integration` 复用同一测试库检查，启动真实 Rust 服务与三个隔离 Rust 桌面进程。随机端口、一次性邀请码和临时 DPAPI/SQLite 文件均由脚本创建；结束只停止本轮进程并清理临时客户端文件，不删除数据库。合成账号保留在专用库，下一轮使用新的随机账号。

本机透明 HTTP 代理只注入 ACK 失败及一次旧信封重放，其余请求转发真实服务。覆盖邀请撤销/接受、三方收发、离线重启、ACK 补交、隐藏去重、静音/草稿持久化、移除和重新加入。结果保存在 `target/test-results/group-integration.json`；失败只报告阶段，不记录消息、密钥、令牌或服务器原始错误。该命令需要 Windows，不代表真实双机/系统通知验收。

## 本批实际运行（2026-09-30）

已按授权启动项目容器并建立独立测试角色/数据库；PostgreSQL 16.14 的全部 20 项用例通过。三进程入口已扩展 T21 的提及重试、置顶阶段隔离、改票/关闭与重新加入资格回归。当前服务端迁移为 12。

集成服务直接绑定本机随机端口，由实际监听日志发现端口；测试子进程固定 `RUST_LOG=liteseal_server=info`，不依赖宿主日志级别。就绪探测最长 30 秒；失败报告保留退出/启动错误代码，不输出原始服务错误。两类数据库报告同时保存按时间命名的副本，失败不会被下一次覆盖。既有业务库与数据卷未改动，测试库和容器保留，进程内临时凭据不写入仓库。
