# AGENTS.md

## Commands (repository root)

```bash
npm ci
npm run dev              # Rust sidecar + Vite + Electron
npm run build            # UI + Electron + Rust release
npm test                 # Node bridge tests + Rust workspace tests, no GUI
npm run dist:win         # Windows x64 NSIS, release/
cargo check --locked --workspace
cargo test -p liteseal-core --test db_test
cargo run -p liteseal-server
```

## Architecture and conventions

- `ui/`: React frontend; `useDesktop` calls typed `window.desktop` methods.
- `electron/`: main process, isolated preload, typed contracts, private stdio bridge.
- `desktop/`: `liteseal-desktop` Rust executable, serde command dispatch, one shared client.
- `core/`: SQLite repository, HTTP/WebSocket, contact and chat logic, Windows DPAPI; shared with mobile FFI.
- `shared/`: crypto and wire protocol source of truth.
- `server/`: Axum + PostgreSQL accounts, sessions, devices and offline ciphertext; env variables are not auto-loaded from .env.
- `mobile/`: React Native and Rust FFI; separate npm lockfile.
- Add Rust integration tests under each crate's `tests/`; Electron bridge tests under `electron/tests/`.
- Root package-lock and Cargo.lock are tracked. Install desktop and UI dependencies using root npm workspace.
- Node 24+, Rust stable Windows x64 MSVC, C++ Build Tools and libsodium are development prerequisites. Installed apps bundle Chromium; no WebView2 required.
- libsodium-sys 0.2.7 rejects SODIUM_STATIC. For a manually supplied static Windows library set SODIUM_LIB_DIR, leaving SODIUM_SHARED and SODIUM_USE_PKG_CONFIG unset.
- Preserve `%APPDATA%/liteseal/data.db` and `%LOCALAPPDATA%/liteseal/keystore.bin`. Do not touch real user data during tests. Non-Windows secret storage remains unsupported.
- Keep blocking SQLite mutexes out of await scopes. Async WebSocket handles use Tokio mutexes.
- IPC exposes only business commands. Never expose raw ipcRenderer, generic filesystem/shell operations or secret-bearing logs to pages.
- Secret keys never cross the Electron bridge: the sidecar keeps the identity (`AppState::identity`), returns only public keys and session fields, and performs encrypt/decrypt/sign itself. Tests pass `--keystore-path` so the real keystore is never touched.
- Protocol details: `shared/src/protocol.rs` (server wire), `desktop/src/protocol.rs` (stdio), `electron/contracts.ts` (TypeScript).
- New messages travel as `send_v2` / `message_v2` / `ack_v2` carrying `SignedEnvelopeV2`. Its `signing_bytes()` covers identity, routing, ordering, time, type and ciphertext; changing envelope fields means updating signing, client handling, relay validation and protocol tests together. Rust signs outgoing envelopes and verifies incoming ones before storage; ACK only after local persistence.
- The relay keeps durable receipts (`beta_receipts`) after ACK deletes ciphertext; message operations find originals through them. Beta accounts are bound to one device: login without the original device and key, device registration and key rotation are refused.
- `/users/*` lookups require a bearer token. Keep `verify_with_public_key()` rejecting non-64-byte signatures.
- Current instructions prioritize Windows. Do not run UI interaction tests when the user has excluded them. Commit after completing each requested task.

See WINDOWS_TESTING_GUIDE.md for startup and manual acceptance; ELECTRON_ARCHITECTURE.md for lifecycle, compatibility and bridge details.
