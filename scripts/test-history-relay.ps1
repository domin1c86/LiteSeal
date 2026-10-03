# Each run creates an ephemeral, explicitly marked test database. Credentials
# live only in this process and are removed with the database in finally.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$historySuffix = [guid]::NewGuid().ToString('N')
$historyRole = 'liteseal_test_' + $historySuffix
$historyPassword = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
$historyDatabase = 'liteseal_test_history_' + $historySuffix
$previousHistoryUrl = $env:LITESEAL_TEST_DATABASE_URL
$historyCreated = $false
$historyCode = 2
try {
    "CREATE ROLE $historyRole LOGIN PASSWORD '$historyPassword'; CREATE DATABASE $historyDatabase OWNER $historyRole; COMMENT ON DATABASE $historyDatabase IS 'liteseal-dedicated-test-v1';" | docker exec -i liteseal-postgres-1 psql -U liteseal -d postgres -v ON_ERROR_STOP=1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '隔离历史迁移测试库创建失败；不输出凭据。' }
    $historyCreated = $true
    $env:LITESEAL_TEST_DATABASE_URL = "postgres://$($historyRole):$($historyPassword)@127.0.0.1:5432/$historyDatabase"
    node scripts/test-history-relay.mjs
    $historyCode = $LASTEXITCODE
} finally {
    $env:LITESEAL_TEST_DATABASE_URL = $previousHistoryUrl
    # Names contain only our fixed prefix and generated hexadecimal suffix.
    "DROP DATABASE IF EXISTS $historyDatabase WITH (FORCE); DROP ROLE IF EXISTS $historyRole;" | docker exec -i liteseal-postgres-1 psql -U liteseal -d postgres -v ON_ERROR_STOP=1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '本轮隔离库或临时角色清理失败，需要处理；不输出凭据。' }
    Write-Output '本轮隔离数据库与临时登录角色已删除。'
    $historyPassword = $null
}
exit $historyCode
