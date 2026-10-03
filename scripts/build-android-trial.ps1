#requires -Version 7.0
param(
    [ValidateSet('x86_64', 'arm64-v8a')]
    [string]$Architecture = 'x86_64',
    [switch]$WithInstrumentation
)
$ErrorActionPreference = 'Stop'
$trialRoot = Split-Path -Parent $PSScriptRoot
$trialArchive = Join-Path $trialRoot "mobile/modules/react-native-liteseal/android/src/main/jniLibs/$Architecture/libliteseal_core.a"
if (-not (Test-Path -LiteralPath $trialArchive -PathType Leaf)) {
    throw 'Build and copy the matching Android native Rust archive first; no replacement identity or credentials are created.'
}
if (-not $env:JAVA_HOME -or -not $env:ANDROID_HOME) {
    throw 'Set JAVA_HOME and ANDROID_HOME to the installed JDK and SDK; this script does not install SDK packages or accept licenses.'
}
$trialOutput = Join-Path $trialRoot 'target/test-results'
New-Item -ItemType Directory -Path $trialOutput -Force | Out-Null
$trialStamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$trialLog = Join-Path $trialOutput "android-isolated-$Architecture-$trialStamp.log"
$trialResult = Join-Path $trialOutput "android-isolated-$Architecture-$trialStamp.json"
$trialPrior = @{}
foreach ($entry in @('ANDROID_USER_HOME', 'GRADLE_USER_HOME', 'CMAKE_BUILD_PARALLEL_LEVEL')) {
    $trialPrior[$entry] = [Environment]::GetEnvironmentVariable($entry)
}
$trialStart = [DateTime]::UtcNow
$trialCode = 2
$trialSigningPath = [IO.Path]::GetFullPath((Join-Path $trialRoot 'target/android-user/debug.keystore'))
$trialSigningExisted = Test-Path -LiteralPath $trialSigningPath
$trialTasks = @(':app:assembleIsolatedTrial')
if ($WithInstrumentation) { $trialTasks += ':react-native-liteseal:assembleDebugAndroidTest' }
Push-Location (Join-Path $trialRoot 'mobile/android')
try {
    $env:ANDROID_USER_HOME = Join-Path $trialRoot 'target/android-user'
    $env:GRADLE_USER_HOME = Join-Path $trialRoot 'target/gradle-mobile'
    $env:CMAKE_BUILD_PARALLEL_LEVEL = '2'
    & ./gradlew.bat @trialTasks --no-daemon --max-workers=2 '-Pkotlin.compiler.execution.strategy=in-process' "-PreactNativeArchitectures=$Architecture" *> $trialLog
    $trialCode = $LASTEXITCODE
} finally {
    Pop-Location
    # Gradle instrumentation may create a scratch debug key. Delete only a key
    # absent before this build, in our exact workspace directory; never read it.
    if (-not $trialSigningExisted -and (Test-Path -LiteralPath $trialSigningPath)) {
        $trialExpected = [IO.Path]::GetFullPath((Join-Path $trialRoot 'target/android-user/debug.keystore'))
        if ($trialSigningPath -ne $trialExpected -or
            (Get-Item -LiteralPath $trialSigningPath).CreationTimeUtc -lt $trialStart) {
            throw 'Scratch signing-key ownership changed; preserve it for review.'
        }
        Remove-Item -LiteralPath $trialSigningPath
    }
    foreach ($entry in $trialPrior.Keys) {
        [Environment]::SetEnvironmentVariable($entry, $trialPrior[$entry])
    }
    [ordered]@{
        started_utc = $trialStart.ToString('o')
        finished_utc = [DateTime]::UtcNow.ToString('o')
        exit_code = $trialCode
        architecture = $Architecture
        instrumentation_requested = [bool]$WithInstrumentation
        instrumentation_build_passed = [bool]$WithInstrumentation -and $trialCode -eq 0
        scope = 'Debug-signed isolated application with embedded JS; build only, no installation or publication'
        log = $trialLog
    } | ConvertTo-Json | Set-Content -Encoding utf8 $trialResult
    Write-Output $trialResult
}
exit $trialCode
