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
