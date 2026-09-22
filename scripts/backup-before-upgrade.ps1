param([Parameter(Mandatory=$true)][string]$Destination)
$ErrorActionPreference = 'Stop'
if (Get-Process -Name 'LiteSeal','liteseal-desktop','electron' -ErrorAction SilentlyContinue) {
    throw '请先完全退出 LiteSeal 和开发版 Electron，再制作一致的数据快照。'
}
$target = [IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $target) { throw '请选择尚不存在的新快照目录，避免覆盖已有备份。' }
$sources = @(
    (Join-Path $env:APPDATA 'liteseal'),
    (Join-Path $env:LOCALAPPDATA 'liteseal')
) | Select-Object -Unique
foreach ($source in $sources) {
    $absolute = [IO.Path]::GetFullPath($source).TrimEnd('\')
    if ($target.Equals($absolute,[StringComparison]::OrdinalIgnoreCase) -or $target.StartsWith($absolute+'\',[StringComparison]::OrdinalIgnoreCase)) { throw '快照目录不能放在应用数据目录内。' }
}
New-Item -ItemType Directory -Path $target | Out-Null
$entries = @()
$index = 0
foreach ($source in $sources) {
    $index++
    if (!(Test-Path -LiteralPath $source)) { continue }
    $copy = Join-Path $target "data-$index"
    Copy-Item -LiteralPath $source -Destination $copy -Recurse
    foreach ($file in Get-ChildItem -LiteralPath $copy -Recurse -File) {
        $relative = $file.FullName.Substring($copy.Length).TrimStart('\')
        $original = Join-Path $source $relative
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        if ($hash -ne (Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash) { throw "快照校验失败：$relative" }
        $entries += [PSCustomObject]@{SourceRoot=$source; SnapshotRoot="data-$index"; RelativePath=$relative; SHA256=$hash}
    }
}
$entries | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $target 'manifest.json') -Encoding UTF8
Write-Output '数据快照与 SHA256 清单已写入；仅适用于原 Windows 身份恢复，不代表支持换机登录。请妥善保管快照。'
