# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

LiteSeal (轻密) is an end-to-end encrypted chat app for Windows (Tauri desktop) and Android (React Native), with a Rust relay server. `AGENTS.md` holds the full Chinese-language agent brief (protocol invariants, security boundaries, Android/UniFFI workflow, known gaps) — read it before non-trivial work; this file is the quick orientation.

`README.md` is stale in places (it says Tauri 1 / Vite 5; the code is Tauri 2 / Vite 8, and the `core/` crate is not mentioned). Trust the source, not the README.

## Commands

Run from the repo root. Shell is PowerShell.

```powershell
npm ci --prefix ui                 # desktop frontend deps (locked)
cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run build --prefix ui          # tsc + vite build
```

Scoped tests — pick by what you touched:

```powershell
cargo test -p liteseal-shared      # crypto + protocol
cargo test -p liteseal-core        # client, db, network
cargo test -p liteseal-server      # auth, relay, http
cargo test -p liteseal-app         # Tauri session/IPC
cargo test -p liteseal-core --test db_test       # one test file
cargo test -p liteseal-server <name-substring>   # one test by name filter
```

Postgres integration tests are `#[ignore]` by default. They require `LITESEAL_TEST_DATABASE_URL` pointing at a dedicated test database, then:

```powershell
cargo test -p liteseal-server -- --ignored
cargo test --workspace -- --include-ignored
```

A skipped ignored test is not a pass.

Running the apps:

```powershell
Push-Location src-tauri; cargo tauri dev; Pop-Location          # starts Vite (localhost:1420) too
Push-Location src-tauri; cargo tauri build --no-bundle; Pop-Location
cargo run -p liteseal-server                                     # needs env vars set in-process; .env is NOT auto-loaded
```

Mobile:

```powershell
npm ci --prefix mobile
npm test --prefix mobile -- --runInBand
npm run lint --prefix mobile
cargo check -p liteseal-core --features ffi     # after editing core/src/ffi.rs
```

Release gate: `scripts/check-windows-beta.ps1` chains fmt, clippy, workspace tests, ignored Postgres tests, `tsc --noEmit`, ui build, `npm audit`, `cargo audit` (with documented RUSTSEC exceptions), and `cargo tauri build --no-bundle`; it fails fast and refuses to run without `LITESEAL_TEST_DATABASE_URL`. `scripts/test-windows-beta-gate.ps1` tests that the gate actually blocks failures.

## Architecture

Cargo workspace: `shared`, `core`, `src-tauri`, `server`. Plus two JS trees: `ui/` (desktop React) and `mobile/` (React Native).

**`shared/` (`liteseal-shared`)** — the single source of truth for crypto and wire format, linked by both client and server. `src/crypto.rs` wraps libsodium (signature verification goes through `verify_with_public_key()`); `src/protocol.rs` defines `ClientMessage`/`ServerMessage` as `#[serde(tag = "type")]` enums and `SignedEnvelopeV2`. Never reimplement either side's crypto elsewhere.

**`core/` (`liteseal-core`)** — all shared business logic for desktop *and* mobile: `client.rs` (`LitesealClient`: session state, encrypt/decrypt, secure message polling), `db/` (rusqlite SQLite + migrations + repository), `network/websocket.rs`, `api.rs` (HTTP), `keystore.rs`, `secret_store.rs` (platform credential storage; Windows DPAPI is implemented, other platforms are limited), `ffi.rs` (optional UniFFI surface behind the `ffi` feature). New logic belongs here, not duplicated in the shells.

**`src-tauri/` (`liteseal-app`)** — thin Tauri 2 desktop shell. `commands/{auth,chat,contacts,keystore,storage}.rs` are the IPC surface; `lib.rs` owns `AppState`, session lifecycle, and per-account data directories keyed by a hash of the normalized server origin + user id (see `normalized_origin`/`profile_dir`). Preserve that isolation when touching login or migrations.

**`server/` (`liteseal-server`)** — Axum HTTP + WebSocket relay. Routes in `main.rs::build_router`: `/auth/*` (register, login, refresh, logout, logout_all), `/users/*` key and search endpoints, `/ws`. `relay/` validates, forwards, and ACKs ciphertext; `db.rs` is Postgres with embedded schema/migration SQL (the server is *not* a stateless in-memory relay); `state.rs` holds DashMap connection and rate-limit state. Tests live in-crate as `http_tests.rs` / `relay_tests.rs`.

**`ui/`** — desktop frontend is `ui/`, not a root `src/`. Tauri serves `../ui/dist` and runs `npm run dev/build --prefix ui` as its hooks.

### Boundaries that matter

- The WebView never receives access tokens, refresh tokens, or private keys, and raw crypto/key-export IPC is not exposed. Rust owns sessions, crypto, verification, storage, and acking.
- Current wire path is `send_v2` / `message_v2` / `ack_v2`. The server rejects new v1 sends; legacy stored messages keep an explicit legacy verification state and must not be relabeled as v2-verified. Old docs showing a plain `send` are wrong.
- `SignedEnvelopeV2::signing_bytes()` is a deterministic domain-separated encoding over identity, routing, ordering, time, message type, and ciphertext. Changing envelope fields means updating signing, client handling, server validation, and protocol tests together.
- WebSocket first frame authenticates with `user_id` + `token` + `device_id`. ACKs must bind to the authenticated device and be sent only after the client has processed and persisted the message.
- `LitesealClient` uses `std::sync::Mutex` for the sync DB and `tokio::sync::Mutex` for WebSocket state — never hold the sync lock across an `.await`.
- The local SQLite database is bundled rusqlite without SQLCipher: it is **not** an encrypted database. DPAPI credential protection is a separate, Windows-only layer.

### Server config

`DATABASE_URL` and `LITESEAL_CORS_ALLOW_ORIGIN` are required; wildcard CORS and default `postgres:postgres` credentials are rejected. `LITESEAL_BIND` defaults to `0.0.0.0:3000`. `LITESEAL_BOOTSTRAP_INVITE_CODE` seeds an invite. See `.env.example` and `docker-compose.yml` — note the `postgres` hostname there is Docker-internal and Compose does not publish the DB port to the host.

## Commits

Per the global instruction: commit after each completed, verified change, with only `completed:` bullets (tab-indented) and a `time: MM-DD HH:mm` line — no attribution trailers, in this repo specifically (`AGENTS.md` repeats this). Ask before `git push`.

## Status sources

`BETA_READINESS.md` lists the outstanding Windows beta acceptance gates (device-replacement history drain, device key history, unknown-sender flow, end-to-end acceptance, installer verification); `TESTING_GUIDE.md` covers Postgres and two-machine validation; `SECURITY.md` records dependency-audit exceptions and their review deadlines. Verify against current source before reporting — past green runs are not this run's result.
