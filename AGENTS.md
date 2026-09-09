# AGENTS.md

## Quick Reference

### Build & Test Commands

```bash
# Check whole workspace compiles
cargo check --workspace

# Run all tests (27 tests across shared + src-tauri)
cargo test --workspace

# Run only shared crypto tests
cargo test -p liteseal-shared

# Run only database tests
cargo test -p liteseal-app

# Start relay server (port 3000)
cargo run -p liteseal-server

# Start Tauri client (auto-starts Vite dev server)
cd src-tauri && cargo tauri dev

# Install frontend deps (run once)
cd ui && npm install
```

### Architecture

```
LiteSeal/                   # Cargo workspace root
├── shared/                 # liteseal-shared: crypto + protocol types
│   ├── src/crypto.rs       # libsodium wrappers (generate_keypair, encrypt, decrypt, sign, verify)
│   ├── src/types.rs        # User, Device, Message, Conversation structs
│   └── tests/              # crate-level integration tests (not unit tests)
├── src-tauri/              # liteseal-app: Tauri desktop client
│   ├── src/commands/       # Tauri IPC commands (auth.rs, chat.rs)
│   ├── src/db/             # SQLite repository (rusqlite, NOT sqlcipher)
│   ├── src/network/        # WebSocket client
│   └── tests/db_test.rs    # database tests
├── server/                 # liteseal-server: Axum WebSocket relay
│   └── src/                # auth + relay handlers, in-memory state only
└── ui/                     # React + Vite frontend (NOT at root src/)
```

### Key Conventions

- **Frontend lives in `ui/`**, not `src/`. Tauri config references `../ui/dist`.
- **Tests are crate-level integration tests** in `shared/tests/` and `src-tauri/tests/`, not alongside source files.
- **`shared/src/crypto.rs` is the single source of truth** for all encryption. Both client and server depend on it.
- **Server is stateless** — no database, in-memory DashMap only. Messages are forwarded, not persisted.
- **Database uses plain SQLite** (rusqlite `bundled` feature), not SQLCipher. This is a known gap.

### Dependencies & Quirks

- **libsodium-sys** requires libsodium installed on the system. On Windows, set `SODIUM_LIB_DIR` or use vcpkg.
- **Tauri requires WebView2** on Windows (usually pre-installed on Win10/11).
- **`cargo tauri dev`** must run from `src-tauri/` directory — it invokes `cd ../ui && npm run dev` automatically.
- **`AppState` uses split mutexes**: `std::sync::Mutex` for blocking DB, `tokio::sync::Mutex` for async WebSocket client.

### WebSocket Protocol

Client and server use tagged JSON enums with `#[serde(tag = "type")]`:

```json
{"type": "auth", "user_id": "...", "token": "..."}
{"type": "send", "to": "...", "conversation_id": "...", "sender_seq": 1, "ciphertext": [...]}
{"type": "message", "from": "...", "conversation_id": "...", "sender_seq": 1, "ciphertext": [...]}
```

### Current Gaps (known, don't re-report)

- No SQLCipher integration — database is unencrypted at rest
- `verify()` accepts secret_key instead of public_key (use `verify_with_public_key()` for public key verification)
- No server-side message persistence
- Login flow is actually registration (no password field)
