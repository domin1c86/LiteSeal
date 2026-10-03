# Each run creates an ephemeral, explicitly marked test database. Credentials
# live only in this process and are removed with the database in finally.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$operationSuffix = [guid]::NewGuid().ToString('N')
$operationRole = 'liteseal_test_' + $operationSuffix
$operationPassword = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
$operationDatabase = 'liteseal_test_ops_' + $operationSuffix
$previousOperationUrl = $env:LITESEAL_TEST_DATABASE_URL
$operationCreated = $false
$operationCode = 2
try {
    "CREATE ROLE $operationRole LOGIN PASSWORD '$operationPassword'; CREATE DATABASE $operationDatabase OWNER $operationRole; COMMENT ON DATABASE $operationDatabase IS 'liteseal-dedicated-test-v1';" | docker exec -i liteseal-postgres-1 psql -U liteseal -d postgres -v ON_ERROR_STOP=1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '隔离操作测试库创建失败；不输出凭据。' }
    $operationCreated = $true
    $env:LITESEAL_TEST_DATABASE_URL = "postgres://$($operationRole):$($operationPassword)@127.0.0.1:5432/$operationDatabase"
    node --input-type=module -e "import {runSuite} from './scripts/test-database.mjs'; import {mkdirSync,writeFileSync} from 'node:fs'; const r=runSuite(process.env,undefined,'trusted_device_tests::direct_message_tests::operation_tests::'); r.scope='synthetic isolated PostgreSQL/HTTP and native Windows stores, no GUI or real profiles'; mkdirSync('target/test-results',{recursive:true}); const p='target/test-results/direct-operations-'+r.at.replace(/[:.]/g,'-')+'.json'; writeFileSync(p,JSON.stringify(r,null,2)); console.log(JSON.stringify(r,null,2)); console.log(p); process.exitCode=r.status==='passed'?0:2;"
    $operationCode = $LASTEXITCODE
} finally {
    $env:LITESEAL_TEST_DATABASE_URL = $previousOperationUrl
    # Names contain only our fixed prefix and generated hexadecimal suffix.
    "DROP DATABASE IF EXISTS $operationDatabase WITH (FORCE); DROP ROLE IF EXISTS $operationRole;" | docker exec -i liteseal-postgres-1 psql -U liteseal -d postgres -v ON_ERROR_STOP=1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '本轮隔离库或临时角色清理失败，需要处理；不输出凭据。' }
    Write-Output '本轮隔离数据库与临时登录角色已删除。'
    $operationPassword = $null
}
exit $operationCode
