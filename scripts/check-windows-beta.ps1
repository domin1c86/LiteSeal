$ErrorActionPreference = "Stop"

$workspace = Split-Path -Parent $PSScriptRoot
Push-Location $workspace
try {
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace

    Push-Location (Join-Path $workspace "ui")
    try {
        npm exec tsc -- --noEmit
        npm run build
        npm audit --omit=dev --audit-level=high
    }
    finally {
        Pop-Location
    }

    cargo audit `
        --ignore RUSTSEC-2026-0194 `
        --ignore RUSTSEC-2026-0195 `
        --ignore RUSTSEC-2023-0071

    Push-Location (Join-Path $workspace "src-tauri")
    try {
        cargo tauri build --no-bundle
    }
    finally {
        Pop-Location
    }
}
finally {
    Pop-Location
}
