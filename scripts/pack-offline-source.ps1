#requires -Version 7.0
# Source-only checkpoint. No .git, local credentials, caches or user data.
$ErrorActionPreference = 'Stop'
$sourceRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$snapshotStamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$snapshotDir = Join-Path $sourceRoot "target/test-results/offline-source-$snapshotStamp"
New-Item -ItemType Directory -Path $snapshotDir | Out-Null
$snapshotZip = Join-Path $snapshotDir "LiteSeal-source-$snapshotStamp.zip"
Push-Location $sourceRoot
try {
    $sourcePaths = @(git -c core.quotepath=false ls-files --cached --others --exclude-standard | Sort-Object -Unique)
    if ($LASTEXITCODE -ne 0) { throw 'Source inventory failed.' }
    $excludedPaths = @()
    $manifestFiles = @()
    foreach ($relative in $sourcePaths) {
        if ($relative -match '(^|/)(\.git|\.agents|\.codex|\.aws|node_modules|target|build|dist|\.gradle|\.cxx)(/|$)' -or
            $relative -match '(?i)(\.keystore|\.jks|\.p12|\.pfx|\.pem|\.key|\.sqlite|\.sqlite3|\.db|\.db-wal|\.db-shm)$' -or
            $relative -match '(^|/)\.env($|\.(?!example$))' -or
            $relative -match '^src-tauri/' -or $relative -in @('deisgn-preview.html','mobile-deisgn-preview.html')) {
            $excludedPaths += $relative
            continue
        }
        $absolute = [IO.Path]::GetFullPath((Join-Path $sourceRoot $relative))
        if (-not $absolute.StartsWith($sourceRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Source path escaped workspace.' }
        if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) { continue }
        $item = Get-Item -LiteralPath $absolute
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing linked source path.' }
        if ($item.Length -gt 16MB) { throw "Unexpected large source file: $relative" }
        $manifestFiles += [ordered]@{path=$relative;size=$item.Length;sha256=(Get-FileHash -LiteralPath $absolute -Algorithm SHA256).Hash}
    }
    $snapshotManifest = Join-Path $snapshotDir 'manifest.json'
    [ordered]@{
        at=[DateTime]::UtcNow.ToString('o');head=(git rev-parse HEAD);branch=(git branch --show-current)
        scope='Full current required source plus uncommitted patch; no credentials, user data or build artifacts'
        files=$manifestFiles;excluded=$excludedPaths
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $snapshotManifest -Encoding utf8
    git -c core.quotepath=false status --porcelain=v1 | Set-Content -LiteralPath (Join-Path $snapshotDir 'git-status.txt') -Encoding utf8
    # Patch exclusions mirror credential/runtime exclusions, including any
    # future tracked credential change. Never read signing key bytes.
    git diff --binary --no-ext-diff "--output=$(Join-Path $snapshotDir 'uncommitted.patch')" -- . ':!*.keystore' ':!*.jks' ':!*.p12' ':!*.pfx' ':!*.pem' ':!*.key' ':!*.db' ':!*.sqlite*' ':!.env' ':!.env.*' ':!src-tauri/**' ':!deisgn-preview.html' ':!mobile-deisgn-preview.html' 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Uncommitted patch creation failed.' }
    Add-Type -AssemblyName System.IO.Compression
    $zip = [IO.Compression.ZipFile]::Open($snapshotZip, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($entry in $manifestFiles) {
            $absolute = Join-Path $sourceRoot $entry.path
            if ((Get-FileHash -LiteralPath $absolute -Algorithm SHA256).Hash -ne $entry.sha256) { throw 'Concurrent source change; discard this snapshot and retry.' }
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$absolute,$entry.path,[IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
        foreach ($name in @('manifest.json','git-status.txt','uncommitted.patch')) {
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,(Join-Path $snapshotDir $name),"_handoff/$name",[IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    } finally { $zip.Dispose() }
    foreach ($entry in $manifestFiles) {
        if ((Get-FileHash -LiteralPath (Join-Path $sourceRoot $entry.path) -Algorithm SHA256).Hash -ne $entry.sha256) { throw 'Concurrent source change; snapshot is not a coherent handoff.' }
    }
    [ordered]@{file=$snapshotZip;bytes=(Get-Item -LiteralPath $snapshotZip).Length;sha256=(Get-FileHash -LiteralPath $snapshotZip -Algorithm SHA256).Hash;source_files=$manifestFiles.Count;excluded_files=$excludedPaths.Count;manifest=$snapshotManifest} |
        ConvertTo-Json | Tee-Object -FilePath (Join-Path $snapshotDir 'package-result.json')
} finally { Pop-Location }
