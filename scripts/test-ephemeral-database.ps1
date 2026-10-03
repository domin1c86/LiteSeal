# Full short regression in a fresh, marked DB. No business data is queried.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$suiteSuffix = [guid]::NewGuid().ToString('N')
$suiteRole = 'liteseal_test_' + $suiteSuffix
$suitePassword = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
$suiteDatabase = 'liteseal_test_regression_' + $suiteSuffix
$previousSuiteUrl = $env:LITESEAL_TEST_DATABASE_URL
$suiteCode = 2
try {
    "CREATE ROLE $suiteRole LOGIN PASSWORD '$suitePassword'; CREATE DATABASE $suiteDatabase OWNER $suiteRole; COMMENT ON DATABASE $suiteDatabase IS 'liteseal-dedicated-test-v1';" | docker exec -i liteseal-postgres-1 psql -U liteseal -d postgres -v ON_ERROR_STOP=1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '隔离回归测试库创建失败；不输出凭据。' }
    $env:LITESEAL_TEST_DATABASE_URL = "postgres://$($suiteRole):$($suitePassword)@127.0.0.1:5432/$suiteDatabase"
    node scripts/test-database.mjs
    $suiteCode = $LASTEXITCODE
} finally {
    $env:LITESEAL_TEST_DATABASE_URL = $previousSuiteUrl
    "DROP DATABASE IF EXISTS $suiteDatabase WITH (FORCE); DROP ROLE IF EXISTS $suiteRole;" | docker exec -i liteseal-postgres-1 psql -U liteseal -d postgres -v ON_ERROR_STOP=1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '本轮隔离库或临时角色清理失败；不输出凭据。' }
    Write-Output '本轮隔离数据库与临时登录角色已删除。'
    $suitePassword = $null
}
exit $suiteCode
