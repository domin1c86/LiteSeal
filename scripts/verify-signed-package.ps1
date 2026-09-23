$ErrorActionPreference = 'Stop'
$version = (Get-Content -LiteralPath 'package.json' -Raw | ConvertFrom-Json).version
$files = @(
    "release/LiteSeal Setup $version.exe",
    'release/win-unpacked/LiteSeal.exe',
    'release/win-unpacked/resources/desktop/liteseal-desktop.exe'
)
$thumbprints = @()
foreach ($relative in $files) {
    $file = (Resolve-Path -LiteralPath $relative).Path
    $signature = Get-AuthenticodeSignature -LiteralPath $file
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
        throw "Signature verification failed: $relative ($($signature.Status))"
    }
    $thumbprints += $signature.SignerCertificate.Thumbprint
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    Write-Output "$relative  SHA256=$hash  Signature=Valid"
}
if (@($thumbprints | Select-Object -Unique).Count -ne 1) {
    throw 'The installer, app, and Rust sidecar have different signing certificates'
}
Write-Output 'Windows signed package verified'
