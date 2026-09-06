$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path $workspace ("target/beta-gate-test-" + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $fixture
$trace = Join-Path $fixture 'commands.txt'
$originalPath = $env:PATH
$originalDatabase = $env:LITESEAL_TEST_DATABASE_URL
$originalTrace = $env:LITESEAL_GATE_TEST_TRACE
$originalFailure = $env:LITESEAL_GATE_TEST_FAIL
$shell = (Get-Process -Id $PID).Path
$gate = Join-Path $PSScriptRoot 'check-windows-beta.ps1'

try {
    foreach ($command in @('cargo', 'npm')) {
        $stub = "@echo off`r`necho $command %*>> `"%LITESEAL_GATE_TEST_TRACE%`"`r`nif `"%LITESEAL_GATE_TEST_FAIL%`"==`"1`" exit /b 23`r`nexit /b 0`r`n"
        Set-Content -LiteralPath (Join-Path $fixture "$command.cmd") -Value $stub -Encoding ASCII
    }
    $env:PATH = "$fixture;$originalPath"
    $env:LITESEAL_GATE_TEST_TRACE = $trace

    $env:LITESEAL_TEST_DATABASE_URL = ''
    $null = & $shell -NoProfile -File $gate 2>&1
    if ($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath $trace)) {
        throw 'Missing Postgres configuration did not stop the gate before commands ran.'
    }

    # No database is contacted: both executables are isolated local stubs.
    $env:LITESEAL_TEST_DATABASE_URL = 'postgres://unused/unused'
    $env:LITESEAL_GATE_TEST_FAIL = '1'
    $null = & $shell -NoProfile -File $gate 2>&1
    if ($LASTEXITCODE -eq 0) { throw 'Native command failure did not fail the gate.' }
    $commands = @(Get-Content -LiteralPath $trace)
    if ($commands.Count -ne 1 -or $commands[0] -ne 'cargo fmt --all -- --check') {
        throw 'Gate continued running after its first failed command.'
    }

    Remove-Item -LiteralPath $trace
    $env:LITESEAL_GATE_TEST_FAIL = '0'
    $null = & $shell -NoProfile -File $gate 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Successful commands did not pass the gate.' }
    $commands = @(Get-Content -LiteralPath $trace)
    if ($commands.Count -ne 9 -or $commands -notcontains 'cargo test -p liteseal-server -- --ignored') {
        throw 'Gate omitted a required check, including explicit Postgres tests.'
    }
    Write-Output 'Beta gate regressions passed: missing database, native failure, complete success path.'
}
finally {
    $env:PATH = $originalPath
    $env:LITESEAL_TEST_DATABASE_URL = $originalDatabase
    $env:LITESEAL_GATE_TEST_TRACE = $originalTrace
    $env:LITESEAL_GATE_TEST_FAIL = $originalFailure
    # Remove only the files created by this fixture; no recursive deletion.
    foreach ($name in @('cargo.cmd', 'npm.cmd', 'commands.txt')) {
        $path = Join-Path $fixture $name
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
    }
    Remove-Item -LiteralPath $fixture
}
