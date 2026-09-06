$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param([scriptblock]$Command)
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Beta check failed (exit $LASTEXITCODE): $Command"
    }
}

if ([string]::IsNullOrWhiteSpace($env:LITESEAL_TEST_DATABASE_URL)) {
    throw "LITESEAL_TEST_DATABASE_URL must point to a dedicated test Postgres database. A beta gate cannot skip integration tests."
}

$workspace = Split-Path -Parent $PSScriptRoot
Push-Location $workspace
try {
    Invoke-Checked { cargo fmt --all -- --check }
    Invoke-Checked { cargo clippy --workspace --all-targets -- -D warnings }
    Invoke-Checked { cargo test --workspace }
    Invoke-Checked { cargo test -p liteseal-server -- --ignored }

    Push-Location (Join-Path $workspace "ui")
    try {
        Invoke-Checked { npm exec tsc -- --noEmit }
        Invoke-Checked { npm run build }
        Invoke-Checked { npm audit --omit=dev --audit-level=high }
    }
    finally {
        Pop-Location
    }

    Invoke-Checked { cargo audit `
        --ignore RUSTSEC-2026-0194 `
        --ignore RUSTSEC-2026-0195 `
        --ignore RUSTSEC-2023-0071 }

    Push-Location (Join-Path $workspace "src-tauri")
    try {
        Invoke-Checked { cargo tauri build --no-bundle }
    }
    finally {
        Pop-Location
    }
}
finally {
    Pop-Location
}
