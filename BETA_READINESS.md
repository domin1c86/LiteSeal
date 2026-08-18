# Windows beta readiness

Last updated: 2026-08-19

## Current assessment

LiteSeal is approximately **70% ready** for a controlled Windows beta. Do not
distribute it to real users yet. The protocol, relay authorization, desktop
credential boundary, account isolation, dependency lock, and release build are
implemented, but the acceptance and soak gates below are still blocking.

## Completed security work

- Protocol v2 signs every identity, routing, ordering, timestamp, type, and
  ciphertext field with deterministic domain-separated encoding.
- New v1 sends are rejected. Existing v1 messages retain an explicit
  `legacy_ciphertext_verified`/`legacy_unverified` state and are never promoted
  to v2 authenticity.
- ACKs are bound to the authenticated device and are emitted only after local
  processing and durable insert. Invalid permanent payloads are quarantined;
  missing contact keys remain unacknowledged for later reconciliation.
- WebSocket authentication is first-frame-only. Sender/recipient device
  ownership, canonical conversations, signatures, UUIDs, sequence shape, and
  field sizes are validated before relay.
- Connection queues are bounded at 128. Offline queues are atomically capped at
  1,000 messages or 10 MiB per device. Connection generations prevent a stale
  disconnect from deleting a replacement connection.
- Invitation registration and refresh rotation are atomic Postgres
  transactions. Invite codes are hashed, expiring, and single-use. New-device
  login requires explicit replacement confirmation.
- Lookup endpoints require Bearer authentication. Authentication, search, and
  message operations use account/IP rate limits. Invalid CORS/database config
  fails closed.
- React/WebView no longer receives credentials or private keys and no longer
  exposes raw encryption/signing/key-store IPC. Rust owns session restoration,
  refresh, encryption, verification, decryption, persistence, ACK, and logout.
- Accounts use separate `SHA-256(server origin || user id)` profile directories,
  databases, and DPAPI stores. Legacy database migration validates a temporary
  copy and retains a timestamped backup before atomic activation.
- Tauri CSP denies external scripts, objects, frames, and network connections;
  only application assets, IPC, and the current inline-style exception remain.
- `Cargo.lock` is committed. Directly fixable `anyhow` and `event-listener`
  advisories are upgraded; temporary target-reachability exceptions are
  documented in `SECURITY.md` with a 2026-09-30 review date.

## Verified gates

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace` — 70 tests passed
- Real Postgres concurrency test for invitation consumption, registration
  rollback, and refresh-token replay
- `npm exec tsc -- --noEmit`
- `npm run build`
- `cargo tauri build --no-bundle` — produced `target/release/liteseal-app.exe`

## Remaining beta blockers

1. Implement `legacy_draining` device state. Replacement currently revokes the
   old device immediately, so it cannot drain its already-queued v1 messages.
2. Add client device-key history and an explicit unknown-sender message-request
   flow. The current single pinned contact key safely blocks on change but does
   not provide historical per-device reconciliation or a request inbox.
3. Add black-box WebSocket/HTTP integration tests against real Postgres for
   authenticated ACK isolation, forged recipient devices, online/offline
   delivery, reconnect generations, slow consumers, and quota boundaries.
4. Add automated Tauri UI coverage for restore/offline, replacement confirmation,
   key changes, legacy labels, quarantine, and logout revocation. The local
   in-app-browser harness could not initialize because its plugin dependency was
   rejected outside the configured trusted path.
5. Produce the signed installer twice in clean environments and compare inputs
   and artifact hashes. The current check validates the Release executable, not
   installer signing or clean-room reproducibility.
6. Perform the two-Windows-device acceptance matrix and then a continuous
   72-hour soak with zero message loss, cross-account leakage, unauthorized
   delivery, or P0/P1 defects.

Estimated remaining effort: **5–8 engineering days plus the 3-day soak**.

## Required acceptance sequence

1. Close blockers 1–4 and rerun all automated gates.
2. Deploy with unique Postgres credentials, one-time invite codes, HTTPS/WSS,
   private Postgres networking, readiness monitoring, and backups.
3. Run registration, online/offline v2 messaging, v1 upgrade migration, device
   replacement, account switching, and logout/logout-all on two Windows PCs.
4. Build and hash the installer twice from the committed lockfile.
5. Start the 72-hour soak only after all earlier steps pass.
