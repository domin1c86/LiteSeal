param([switch]$GroupsOnly, [switch]$SoakSmoke, [switch]$StartSoak)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$validationSuffix = [guid]::NewGuid().ToString('N')
$validationRole = 'liteseal_test_' + $validationSuffix
$validationPassword = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
$validationDatabase = 'liteseal_test_t22_' + $validationSuffix
$validationSql = "CREATE ROLE $validationRole LOGIN PASSWORD '$validationPassword'; CREATE DATABASE $validationDatabase OWNER $validationRole; COMMENT ON DATABASE $validationDatabase IS 'liteseal-dedicated-test-v1';"
$validationOutput = $validationSql | docker exec -i liteseal-postgres-1 psql -U liteseal -d postgres -v ON_ERROR_STOP=1 2>&1
if ($LASTEXITCODE -ne 0) { throw '独立测试角色/数据库准备失败；未保存或输出凭据。' }
$previousTestUrl = $env:LITESEAL_TEST_DATABASE_URL
try {
    $env:LITESEAL_TEST_DATABASE_URL = "postgres://$($validationRole):$($validationPassword)@127.0.0.1:5432/$validationDatabase"
    if ($StartSoak) {
        $validationNode = (Get-Command node).Source
        $validationStdout = Join-Path (Get-Location) ('target/test-results/soak-launch-' + $validationSuffix + '.stdout.txt')
        $validationStderr = Join-Path (Get-Location) ('target/test-results/soak-launch-' + $validationSuffix + '.stderr.txt')
        New-Item -ItemType Directory -Force -Path target/test-results | Out-Null
        $validationProcess = Start-Process -FilePath $validationNode -ArgumentList 'scripts/test-group-soak.mjs' -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru -RedirectStandardOutput $validationStdout -RedirectStandardError $validationStderr
        [PSCustomObject]@{ Status='started'; ProcessId=$validationProcess.Id; Mode='24h'; Database=$validationDatabase; Stdout=$validationStdout } | ConvertTo-Json
    } elseif ($SoakSmoke) {
        node scripts/test-group-soak.mjs --smoke
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } else {
        if (!$GroupsOnly) { node scripts/test-database.mjs; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
        node scripts/test-group-integration.mjs
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
} finally { $env:LITESEAL_TEST_DATABASE_URL = $previousTestUrl }
