# Discable — Remaining Action Items

## Completed Work Reference

All of the following are fully implemented and tested:

- **Phase 1**: Security audit fixes (offline timestamps, queue limits, batched deletion)
- **Phase 2**: DM Voice Calls (WebRTC P2P, ringtone/ringback, 30s auto-reject)
- **Phase 3**: Channel Voice Chat (server-relayed, Opus 24kbps VBR, join/leave, disconnect cleanup)
- **Phase A**: Dependency security audit (sqlx 0.7 -> 0.8, subtle constant-time comparison)
- **Phase B**: Server hardening (connection limits, rate limiting, CORS, graceful shutdown, WAL checkpoint)
- **Phase C**: Client reliability (auto-reconnect, DB migrations V1-V3, bounded buffers, sender key rotation)
- **DM Screen Share**: Peer-to-peer via WebRTC, renegotiation-based
- **Channel Screen Share**: Server-relayed, encrypted VP8/WebM with quality presets (360p/720p/1080p at 15fps)
- **6-Step Security Sweep**: Zeroization, error sanitization, rustls-tls, pre-key replenishment, DH persistence fix, RPi optimization
- **DM Ratchet Bug Fix**: V3 migration clears corrupt sessions, `load()` validates DH key consistency
- **Two-Tier Server Design**: Architecture document at `docs/DESIGN_TWO_TIER.md`

**Build status**: `cargo check --workspace` 0 errors, `cargo test -p securecomm-shared` 90/90 pass, `vite build` passes.

---

## High Priority

### Wire Up `lock_profile()` Tauri Command + UI

**Status**: Rust implementation complete (`client/src-tauri/src/state.rs:104`), NOT exposed as a Tauri command yet.

**What to do**:
1. Add `#[tauri::command] async fn lock_profile(state: State<'_, AppState>)` in `commands.rs`
2. Register in Tauri's `invoke_handler`
3. Add a "Lock" button in the UI (Sidebar or settings area)
4. On lock: call `lock_profile()`, disconnect WebSocket, navigate to Login screen
5. On unlock: re-derive `db_key` from password, reload identity, reconnect

### Replace Hardcoded Google STUN with Server-Provided ICE Config

**Status**: Google STUN hardcoded at `client/src/lib/voice.ts:26-31`. Design for server-provided ICE is in `docs/DESIGN_TWO_TIER.md` Section 5.

**What to do**:
1. Add `SC_ICE_STUN_URL` and `SC_ICE_TURN_URL` + `SC_ICE_TURN_SECRET` env vars to `server/src/config.rs`
2. Add `handle_get_ice_config` handler in `server/src/websocket.rs`
3. Implement HMAC-SHA1 TURN credential generation (if `SC_ICE_TURN_SECRET` is set)
4. Add `get_ice_config` Tauri command on client
5. Client fetches ICE config after auth, caches with TTL
6. Remove hardcoded `ICE_SERVERS` from `voice.ts`, use server-provided config
7. Update `channelVoice.ts` if it also uses hardcoded STUN

---

## Medium Priority

### Proper TLS Termination

**Status**: `server/src/main.rs:82` has a TODO comment. TLS is configured but the HTTP fallback is used even when TLS certs are provided.

**What to do**: Use `axum-server` with the rustls TLS acceptor for actual HTTPS/WSS termination, or document that a reverse proxy (Caddy/Nginx) should handle TLS.

### RPi Cross-Compile Documentation

**Status**: `Cargo.toml` has `release-small` profile and jemalloc for Linux, but no cross-compilation instructions.

**What to do**: Document `cross` toolchain setup for `aarch64-unknown-linux-gnu`, add to `docs/DEPLOYMENT.md`.

### Clean Up Deprecated `save_with_key()`

**Status**: `shared/src/ratchet.rs` — `save_with_key()` is marked deprecated but still exists. `save()` is now correct (stores real DH private bytes).

**What to do**: Remove `save_with_key()` entirely. Grep all call sites (there should be none left). Run tests to confirm.

### Database Abstraction (Phase 1 of Two-Tier)

**Status**: Designed in `docs/DESIGN_TWO_TIER.md` Section 3.

**What to do**: Extract `server/src/database.rs` into `server/src/db/mod.rs` + `server/src/db/sqlite.rs` with `DatabaseBackend` trait. Update `ServerState` to use `Arc<dyn DatabaseBackend>`.

---

## Low Priority

### Use `OsRng` for Challenge Nonce

**Status**: `server/src/websocket.rs:230-233` uses `rand::thread_rng()` for the auth challenge nonce. `OsRng` is cryptographically preferable.

**What to do**: Replace `rand::thread_rng().fill_bytes(&mut nonce)` with `rand::rngs::OsRng.fill_bytes(&mut nonce)`.

### Channel Access Control

**Status**: Anyone can join any channel by ID. Auto-creates channel if it doesn't exist (`server/src/websocket.rs:631-645`).

**What to do**: Design decision pending. Options:
- Invite-only channels (creator generates invite tokens)
- Password-protected channels (shared secret)
- Public/private flag on channel creation
- This intersects with the managed server's public channel directory (see `docs/DESIGN_TWO_TIER.md` Section 6.2)

### Pre-Existing Warnings Cleanup

5 compiler warnings that have been accepted but could be cleaned up:
- `shared/src/sss.rs:7` — unused `Zeroize`/`ZeroizeOnDrop` imports
- `server/src/auth.rs:3` — unused `Verifier` import
- `server/src/database.rs:364` — unused `update_last_seen` function
- `server/src/tls.rs:90` — unused `generate_self_signed_cert`
- `client/src-tauri/src/db.rs:516` — `SenderKeyRow.channel_id` field never read

---

## STUN/TURN Architecture Reference

### STUN (Session Traversal Utilities for NAT)

- Lightweight protocol for NAT type discovery and public IP/port mapping
- Client sends a binding request to STUN server, gets back its public address
- Used by WebRTC ICE to gather `srflx` (server reflexive) candidates
- Works for ~85-90% of NAT configurations
- Google provides free public STUN servers, but this leaks IP to Google
- Self-hosted STUN is trivial (coturn handles it)

### TURN (Traversal Using Relays around NAT)

- Relay fallback for symmetric NATs where STUN fails (~10-15% of connections)
- All media flows through the TURN server (relay candidates)
- Resource-intensive: bandwidth + CPU for every relayed stream
- Requires authentication to prevent abuse
- coturn's `use-auth-secret` mode: shared secret between TURN server and application server, time-limited HMAC-SHA1 credentials

### Recommended Deployment

**Self-hosted (community)**:
1. Install coturn alongside the Discable server
2. Configure `use-auth-secret` with a shared secret
3. Set `SC_ICE_TURN_URL` and `SC_ICE_TURN_SECRET` in Discable's env
4. Discable server generates time-limited credentials per user session

**Managed**:
1. Deploy coturn cluster (one per geographic region for latency)
2. Discable managed server generates HMAC credentials internally
3. Client receives credentials after auth, refreshes on TTL expiry
