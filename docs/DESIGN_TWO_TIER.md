# Mobium Two-Tier Server Architecture

## 1. Vision & Principles

Mobium evolves from a single self-hosted server into two deployment tiers sharing one codebase:

### Community Server (Self-Hosted)

- **Audience**: Privacy-focused individuals, small friend groups, families
- **Hosted by**: The end user, on their own hardware (RPi, VPS, homelab)
- **Philosophy**: Lightweight, minimal dependencies, easy to deploy
- **Features**: Core messaging, voice, screen share, channel management
- **Database**: SQLite (single-file, zero config)
- **Scale target**: ~50-200 concurrent users per instance
- **ICE/TURN**: User chooses — self-hosted coturn, Google STUN, or opt-in to managed TURN service

### Managed Server ("Mobium Cloud")

- **Audience**: Larger communities, public channels, friends-of-friends discovery
- **Hosted by**: Mobium (the company/project)
- **Philosophy**: Full-featured encrypted communication platform with zero-knowledge encryption
- **Features**: Everything in Community + account system, user discovery, public channels, moderation tools, managed STUN/TURN
- **Database**: PostgreSQL (concurrent writes, horizontal scaling readiness)
- **Scale target**: Start single-instance, design for eventual horizontal scaling
- **ICE/TURN**: Managed coturn cluster with time-limited HMAC credentials

### Shared Principles (Both Tiers)

- Zero-knowledge: server NEVER sees plaintext content
- Same WebSocket protocol and MessagePack encoding
- Same cryptographic primitives (X3DH, Double Ratchet, Sender Keys)
- Same client app connects to either server type
- Ed25519 public key is the fundamental identity in both tiers

---

## 2. Codebase Strategy

### Single Codebase with Cargo Features

Both server tiers share one Rust crate (`server/`) with compile-time feature flags:

```toml
# server/Cargo.toml
[features]
default = ["community"]
community = ["dep:sqlx-sqlite"]
managed = ["dep:sqlx-postgres", "dep:redis", "dep:lettre"]
```

**Rationale** (vs separate binaries):
- WebSocket protocol evolves in lockstep — one change, both tiers get it
- Shared crypto relay logic is identical (voice_data, screen_data, sender_key_distribution)
- Bug fixes and security patches apply to both automatically
- Reduces maintenance burden significantly
- Feature flags have zero runtime cost for unused code paths

### Module Structure

```
server/src/
  main.rs                  # Entry point (shared)
  config.rs                # ServerConfig (extended with tier-specific fields)
  routing.rs               # HTTP router (shared core + feature-gated routes)
  websocket.rs             # WS protocol handler (shared)
  auth.rs                  # Challenge-response auth (shared)
  tls.rs                   # TLS configuration (shared)
  
  # Database abstraction layer (NEW)
  db/
    mod.rs                 # DatabaseBackend trait definition
    sqlite.rs              # SQLite implementation (community)
    postgres.rs            # PostgreSQL implementation (managed, feature-gated)
  
  # Managed-only modules (feature-gated behind "managed")
  managed/
    mod.rs
    accounts.rs            # User registration, profiles, friend requests
    discovery.rs           # Username search, public channel directory
    moderation.rs          # Ban, mute, audit log, report handling
    ice_service.rs         # TURN credential generation (HMAC-based)
    
  # Community has no additional modules — it's the default/minimal build
```

### Build Commands

```bash
# Community server (default — what users compile today)
cargo build --release -p mobium-server

# Managed server (with all managed-tier features)
cargo build --release -p mobium-server --features managed --no-default-features
```

---

## 3. Database Abstraction

### Current State

The server uses raw `sqlx` queries against SQLite in `database.rs` (~708 lines, 20+ functions). All queries are SQLite-specific string literals.

### Proposed: `DatabaseBackend` Trait

Introduce an async trait that abstracts every database operation:

```rust
// server/src/db/mod.rs

#[cfg(feature = "community")]
pub mod sqlite;
#[cfg(feature = "managed")]
pub mod postgres;

use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait DatabaseBackend: Send + Sync + 'static {
    // ── Users ────────────────────────────────────────────────────
    async fn store_user(
        &self, pubkey: &[u8], x25519_pub: Option<&[u8]>,
        encrypted_prekeys: Option<&[u8]>,
    ) -> Result<()>;
    
    async fn update_last_seen(&self, pubkey: &[u8]) -> Result<()>;
    
    // ── Pre-keys (X3DH) ─────────────────────────────────────────
    async fn store_prekey_bundle(
        &self, user_pubkey: &[u8], identity_x25519_pub: &[u8],
        signed_prekey: &[u8], signed_prekey_sig: &[u8],
        one_time_prekeys: &[u8],
    ) -> Result<()>;
    
    async fn get_and_consume_prekey_bundle(
        &self, user_pubkey: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<usize>)>>;
    
    async fn count_one_time_prekeys(&self, user_pubkey: &[u8]) -> Result<usize>;
    
    // ── Offline messages ─────────────────────────────────────────
    async fn store_offline_message(
        &self, recipient: &[u8], sender: &[u8], payload: &[u8],
    ) -> Result<i64>;
    
    async fn get_offline_messages(
        &self, recipient: &[u8], limit: i64,
    ) -> Result<Vec<(i64, Vec<u8>, Vec<u8>, i64)>>;
    
    async fn delete_offline_messages(&self, ids: &[i64]) -> Result<()>;
    async fn count_offline_messages(&self, recipient: &[u8]) -> Result<i64>;
    
    // ── Channels ─────────────────────────────────────────────────
    async fn create_channel(
        &self, channel_id: &[u8], encrypted_metadata: &[u8],
        creator_pubkey: &[u8],
    ) -> Result<()>;
    
    async fn channel_exists(&self, channel_id: &[u8]) -> Result<bool>;
    async fn add_channel_member(&self, channel_id: &[u8], user_pubkey: &[u8]) -> Result<()>;
    async fn remove_channel_member(&self, channel_id: &[u8], user_pubkey: &[u8]) -> Result<()>;
    async fn is_channel_member(&self, channel_id: &[u8], user_pubkey: &[u8]) -> Result<bool>;
    async fn get_channel_members(&self, channel_id: &[u8]) -> Result<Vec<Vec<u8>>>;
    
    async fn get_channel_members_with_keys(
        &self, channel_id: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;
    
    // ── Channel messages ─────────────────────────────────────────
    async fn store_channel_message(
        &self, channel_id: &[u8], sender: &[u8],
        payload: &[u8], bucket_size: i64,
    ) -> Result<i64>;
    
    async fn get_channel_history(
        &self, channel_id: &[u8], user_pubkey: &[u8],
        after_timestamp: i64, limit: i64,
    ) -> Result<Vec<(i64, Vec<u8>, Vec<u8>, i64, i64)>>;
    
    // ── Sender keys ──────────────────────────────────────────────
    async fn store_sender_key_distribution(
        &self, channel_id: &[u8], sender: &[u8], recipient: &[u8],
        sender_x25519_pub: &[u8], encrypted_dist: &[u8],
    ) -> Result<()>;
    
    async fn get_sender_keys_for_recipient(
        &self, channel_id: &[u8], recipient: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>>;
    
    // ── TTL cleanup ──────────────────────────────────────────────
    async fn purge_expired_messages(&self, ttl_seconds: i64) -> Result<u64>;
    async fn purge_expired_offline_messages(&self, ttl_seconds: i64) -> Result<u64>;
}
```

### Migration Path

1. Extract current `database.rs` functions into `db/sqlite.rs` implementing the trait
2. Update `ServerState` to hold `Arc<dyn DatabaseBackend>` instead of `Pool<Sqlite>`
3. Update all handler functions to call `state.db.method()` instead of `database::method(&state.db_pool, ...)`
4. Implement `db/postgres.rs` behind the `managed` feature flag
5. The PostgreSQL implementation uses the same table schema but with PostgreSQL syntax (`$1` params, `SERIAL` vs `AUTOINCREMENT`, `BYTEA` vs `BLOB`, etc.)

### PostgreSQL Schema Differences

| SQLite | PostgreSQL |
|--------|-----------|
| `BLOB` | `BYTEA` |
| `INTEGER PRIMARY KEY AUTOINCREMENT` | `SERIAL PRIMARY KEY` or `BIGSERIAL` |
| `strftime('%s', 'now')` | `EXTRACT(EPOCH FROM NOW())::BIGINT` |
| `?1, ?2` parameter binding | `$1, $2` parameter binding |
| WAL checkpoint on shutdown | Not needed (MVCC) |
| 5 connections max | Connection pool sized to workload |

---

## 4. Identity Model (Design Decision Pending)

The current system uses Ed25519 public keys as the sole identity. For the managed server, there are two viable approaches. **This decision should be finalized before implementation.**

### Option A: Crypto-Only Identity (Attach Username)

- Ed25519 key remains THE identity (same as today)
- Users optionally register a username that maps to their public key
- Username is a convenience layer for discovery, not an auth mechanism
- No email, no password — the Ed25519 key is the only credential
- Server stores: `(username, ed25519_pubkey, registered_at)`
- **Pro**: Simpler, consistent with zero-knowledge philosophy, no PII stored
- **Con**: No account recovery if key is lost (same as today), username squatting risk

### Option B: Traditional Accounts Linked to Crypto Keys

- Users create an account with email + password (or passkey)
- Account is linked to their Ed25519 key on first login
- Server can verify account ownership via email for recovery flows
- **Pro**: Familiar UX, enables account recovery, reduces key loss risk
- **Con**: Server stores PII (email), more complex, moves away from zero-knowledge purity
- **Mitigation**: Email could be stored as a one-way hash (for dedup) + encrypted blob (for recovery emails only)

### Recommendation

Option A is more aligned with Mobium's zero-knowledge identity. Phone-number-based messengers chose phone numbers because they needed a social graph bootstrap mechanism — Mobium could use invite links or QR codes instead. The username-to-pubkey mapping can be made auditable (signed by the user's key).

---

## 5. ICE Configuration Service

### Problem

The client currently hardcodes Google STUN servers (`client/src/lib/voice.ts:26-31`). This:
- Leaks user IP addresses to Google
- Doesn't work behind symmetric NATs (no TURN fallback)
- Can't be customized per deployment

### Solution: Server-Provided ICE Configuration

After authentication, the client requests ICE configuration from the server. The server responds based on its tier and config.

#### New Protocol Messages

```
Client → Server:  { "type": "get_ice_config" }

Server → Client:  {
    "type": "ice_config",
    "ice_servers": [
        { "urls": "stun:stun.example.com:3478" },
        {
            "urls": "turn:turn.example.com:3478",
            "username": "1700000000:user123",
            "credential": "hmac-sha1-signature"
        }
    ],
    "ttl": 86400
}
```

#### Community Server Configuration

New env vars:

```bash
# Option 1: Self-hosted coturn (recommended)
SC_ICE_STUN_URL=stun:my-server.example.com:3478
SC_ICE_TURN_URL=turn:my-server.example.com:3478
SC_ICE_TURN_SECRET=shared-secret-with-coturn

# Option 2: Google STUN only (no TURN, ~85-90% success rate)
SC_ICE_STUN_URL=stun:stun.l.google.com:19302

# Option 3: Use Mobium managed TURN (when available)
SC_ICE_MANAGED_TURN=true
SC_ICE_MANAGED_API_KEY=your-api-key
```

The community server reads these env vars and returns a static ICE configuration. If `SC_ICE_TURN_SECRET` is set, it generates time-limited HMAC-SHA1 credentials for coturn's `use-auth-secret` mode:

```
username = "{expiry_timestamp}:{user_identifier}"
credential = HMAC-SHA1(shared_secret, username)
```

Credentials expire after `ttl` seconds (default 86400 = 24h). The client re-requests when TTL expires.

#### Managed Server

The managed server runs its own coturn cluster. Credential generation is identical (HMAC-SHA1) but uses internal infrastructure:

```rust
// server/src/managed/ice_service.rs
pub fn generate_turn_credentials(
    shared_secret: &[u8],
    user_id: &str,
    ttl_seconds: u64,
) -> (String, String) {
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap()
        .as_secs() + ttl_seconds;
    let username = format!("{}:{}", expiry, user_id);
    let credential = hmac_sha1(shared_secret, username.as_bytes());
    (username, base64::encode(credential))
}
```

#### Client Changes

```typescript
// voice.ts — replace hardcoded ICE_SERVERS
let iceConfig: RTCConfiguration = { iceServers: [] };

export async function refreshIceConfig(): Promise<void> {
    const config = await invoke('get_ice_config');
    iceConfig = {
        iceServers: config.ice_servers.map(s => ({
            urls: s.urls,
            username: s.username,
            credential: s.credential,
        }))
    };
}

// Called after auth_success, and periodically based on TTL
// Used by both voice.ts (DM WebRTC) and channelVoice.ts
```

#### coturn Deployment Reference

For community server operators who want self-hosted TURN:

```bash
# /etc/turnserver.conf
listening-port=3478
tls-listening-port=5349
fingerprint
use-auth-secret
static-auth-secret=YOUR_SHARED_SECRET  # same as SC_ICE_TURN_SECRET
realm=your-domain.com
cert=/etc/letsencrypt/live/your-domain.com/fullchain.pem
pkey=/etc/letsencrypt/live/your-domain.com/privkey.pem
no-cli
```

```yaml
# docker-compose addition
services:
  coturn:
    image: coturn/coturn:latest
    network_mode: host
    volumes:
      - ./turnserver.conf:/etc/turnserver.conf:ro
      - ./certs:/etc/letsencrypt:ro
    restart: unless-stopped
```

---

## 6. Managed Server: New Features

### 6.1 Account System

**Note**: See Section 4 for the pending identity model decision. The account system design depends on which option is chosen.

Regardless of identity model, the managed server needs:

- **Username reservation**: Map human-readable names to Ed25519 pubkeys
- **Profile data**: Encrypted display name, avatar (stored as opaque blobs — server can't read them)
- **Friend list**: Bidirectional pubkey relationships (stored server-side for discovery)
- **Block list**: Per-user, enforced at the routing layer

#### New Database Tables (Managed Only)

```sql
-- Username → pubkey mapping
CREATE TABLE accounts (
    username VARCHAR(32) PRIMARY KEY,
    ed25519_pubkey BYTEA UNIQUE NOT NULL,
    encrypted_profile BYTEA,          -- client-encrypted display name, avatar
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
);

-- Friend relationships
CREATE TABLE friends (
    user_a BYTEA NOT NULL,
    user_b BYTEA NOT NULL,
    status VARCHAR(16) NOT NULL,       -- 'pending', 'accepted', 'blocked'
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
    PRIMARY KEY (user_a, user_b)
);

-- Public channel directory
CREATE TABLE public_channels (
    channel_id BYTEA PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    owner_pubkey BYTEA NOT NULL,
    member_count INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
    FOREIGN KEY (channel_id) REFERENCES channels(id)
);
```

### 6.2 User Discovery

New WebSocket message types (managed only):

```
search_users      → { query: string }         → { users: [{username, pubkey}] }
send_friend_req   → { target_pubkey: bytes }   → ack
accept_friend_req → { from_pubkey: bytes }      → ack
list_friends       → {}                          → { friends: [{pubkey, username, online}] }
```

### 6.3 Public Channel Directory

```
list_public_channels → { page, limit }         → { channels: [{id, name, desc, members}] }
create_public_channel → { name, desc }          → { channel_id }
```

### 6.4 Moderation Tools

Admin/moderator capabilities for the managed instance:

- **User bans**: Temporary or permanent, by pubkey
- **Channel moderation**: Mute users, delete messages (server deletes encrypted blobs by ID — can't read content)
- **Audit log**: Timestamped record of moderation actions
- **Report system**: Users flag content (by message ID), moderators review
- **Rate limiting per account**: Stricter than per-connection, tracks across reconnects

New WebSocket messages:
```
ban_user          → { target_pubkey, duration, reason }
mute_user         → { target_pubkey, channel_id, duration }
delete_message    → { channel_id, message_id }
report_message    → { channel_id, message_id, reason }
get_reports       → { page, limit }  (admin only)
```

#### Moderation Database Tables

```sql
CREATE TABLE bans (
    user_pubkey BYTEA NOT NULL,
    banned_by BYTEA NOT NULL,
    reason TEXT,
    expires_at BIGINT,                -- NULL = permanent
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
    PRIMARY KEY (user_pubkey)
);

CREATE TABLE mutes (
    user_pubkey BYTEA NOT NULL,
    channel_id BYTEA NOT NULL,
    muted_by BYTEA NOT NULL,
    expires_at BIGINT,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
    PRIMARY KEY (user_pubkey, channel_id)
);

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    actor_pubkey BYTEA NOT NULL,
    action VARCHAR(50) NOT NULL,
    target_pubkey BYTEA,
    target_channel BYTEA,
    details JSONB,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
);

CREATE TABLE reports (
    id BIGSERIAL PRIMARY KEY,
    reporter_pubkey BYTEA NOT NULL,
    channel_id BYTEA NOT NULL,
    message_id BIGINT NOT NULL,
    reason TEXT,
    status VARCHAR(16) NOT NULL DEFAULT 'open',   -- open, reviewed, dismissed
    reviewed_by BYTEA,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
);
```

---

## 7. Horizontal Scaling (Future — Design Now, Build Later)

### What Works Today (Single Instance)

All real-time state lives in-memory on one process:
- `connections: DashMap<Vec<u8>, mpsc::Sender>` — active WebSocket connections
- `voice_channels: DashMap<Vec<u8>, HashSet<Vec<u8>>>` — voice participants
- `ip_connections: DashMap<IpAddr, AtomicUsize>` — per-IP tracking

This is fast and simple. For the community server, this is sufficient forever.

### What Breaks with Multiple Instances

If user A is connected to instance 1 and user B to instance 2:
- DM routing fails (instance 1 doesn't have B's sender channel)
- Voice data relay fails (participants may be on different instances)
- Channel message fanout misses offline-to-this-instance members

### Proposed Solution: Redis Pub/Sub

```
                    ┌──────────────┐
                    │   Redis      │
                    │  Pub/Sub     │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴─────┐ ┌───┴────┐ ┌────┴─────┐
        │ Instance 1 │ │ Inst 2 │ │ Inst 3  │
        │ (users A,C)│ │ (B,D)  │ │ (E,F)   │
        └────────────┘ └────────┘ └──────────┘
```

**Connection registry**: Each instance publishes its user set to Redis. When routing a message, check local connections first, then publish to the Redis channel for the target user.

**Voice channels**: Use sticky sessions — all participants in one voice channel connect to the same instance (via a Redis-backed assignment table). If an instance goes down, participants reconnect and get reassigned.

**Channel messages**: Fanout via Redis pub/sub channel per text channel. Each instance subscribes to channels that its connected users belong to.

### Implementation Phases

This is NOT built in the first version. The architecture just needs to not preclude it:

1. **Phase 1** (now): Abstract `ServerState.connections` behind a trait so it can be swapped for a Redis-backed implementation later
2. **Phase 2** (later): Add Redis pub/sub for cross-instance message routing
3. **Phase 3** (later): Sticky session assignment for voice channels
4. **Phase 4** (much later): Kubernetes deployment with auto-scaling

### Key Design Constraint

The `DatabaseBackend` trait already isolates the persistence layer. For horizontal scaling, we additionally need a `ConnectionRegistry` trait:

```rust
#[async_trait]
pub trait ConnectionRegistry: Send + Sync + 'static {
    /// Register a local connection
    async fn register(&self, pubkey: &[u8], tx: mpsc::Sender<Vec<u8>>);
    /// Unregister a connection
    async fn unregister(&self, pubkey: &[u8]);
    /// Send to a user (local or remote)
    async fn send_to(&self, pubkey: &[u8], data: Vec<u8>) -> bool;
    /// Check if a user is connected (anywhere)
    async fn is_connected(&self, pubkey: &[u8]) -> bool;
}
```

The current `DashMap<Vec<u8>, mpsc::Sender>` becomes a `LocalConnectionRegistry` implementing this trait. The Redis-backed version wraps it and falls back to pub/sub for non-local users.

---

## 8. Client Changes

### Server Capability Discovery

The `/info` endpoint is extended to advertise the server type and available features:

```json
{
    "name": "Mobium Server",
    "protocol_version": 2,
    "server_type": "community",
    "capabilities": [
        "dm", "channels", "voice_dm", "voice_channel",
        "screen_share", "ice_config"
    ]
}
```

For managed:
```json
{
    "name": "Mobium Cloud",
    "protocol_version": 2,
    "server_type": "managed",
    "capabilities": [
        "dm", "channels", "voice_dm", "voice_channel",
        "screen_share", "ice_config",
        "accounts", "discovery", "public_channels", "moderation"
    ]
}
```

### Client UI Adaptation

The Svelte frontend checks capabilities after connecting:

```typescript
// After auth_success, fetch server info
const info = await invoke('get_server_info');

// Show/hide UI elements based on capabilities
const hasDiscovery = info.capabilities.includes('discovery');
const hasPublicChannels = info.capabilities.includes('public_channels');
```

- **Community**: Hide "Find Users", "Browse Public Channels" — users share channel IDs / invite links manually
- **Managed**: Show full discovery UI, friend requests, public channel browser

### ICE Config Integration

Remove hardcoded Google STUN from `voice.ts:26-31` and `channelVoice.ts` (if present). Replace with:

```typescript
import { invoke } from '@tauri-apps/api/core';

let cachedIceConfig: RTCConfiguration | null = null;
let iceConfigExpiry = 0;

export async function getIceConfig(): Promise<RTCConfiguration> {
    if (cachedIceConfig && Date.now() < iceConfigExpiry) {
        return cachedIceConfig;
    }
    const config = await invoke('get_ice_config');
    cachedIceConfig = { iceServers: config.ice_servers };
    iceConfigExpiry = Date.now() + (config.ttl * 1000);
    return cachedIceConfig;
}
```

Both `voice.ts` (DM WebRTC) and `channelVoice.ts` use `getIceConfig()` when creating `RTCPeerConnection`.

---

## 9. Migration Path

### Phase 1: Foundation (Implement First)

**Goal**: Refactor for extensibility without changing behavior.

1. **Database abstraction**: Extract `database.rs` into `db/mod.rs` + `db/sqlite.rs` trait implementation
2. **ICE config service**: Add `get_ice_config` message handler, new env vars, remove hardcoded Google STUN from client
3. **Server info extension**: Add `server_type` and `capabilities` to `/info` endpoint
4. **Connection registry trait**: Abstract `ServerState.connections` behind a trait (local DashMap implementation)
5. **Wire up `lock_profile()`**: Expose as Tauri command with UI button (already implemented in Rust)

**Estimated effort**: Medium. Mostly refactoring, no new features.

### Phase 2: PostgreSQL Backend

**Goal**: Managed server can use PostgreSQL.

1. Add `sqlx` PostgreSQL feature and implement `db/postgres.rs`
2. Write PostgreSQL migration scripts
3. Add `managed` feature flag to `Cargo.toml`
4. Integration test both backends against the same test suite

**Estimated effort**: Medium. SQL translation + testing.

### Phase 3: Account System & Discovery

**Goal**: Managed server supports user accounts and friend discovery.

1. Account registration (username claim)
2. Friend request/accept flow
3. User search
4. Public channel directory
5. Client UI for discovery features (conditional on capabilities)

**Estimated effort**: Large. New protocol messages, new UI components.

### Phase 4: Moderation

**Goal**: Managed server has admin/moderator tools.

1. Ban/mute system with expiry
2. Message deletion (by ID)
3. Report system
4. Audit log
5. Admin dashboard (web UI or in-app)

**Estimated effort**: Large. Requires role/permission system design.

### Phase 5: Horizontal Scaling

**Goal**: Managed server runs multiple instances behind a load balancer.

1. Redis pub/sub for cross-instance messaging
2. Redis-backed connection registry
3. Sticky sessions for voice channels
4. Health check + auto-scaling configuration

**Estimated effort**: Very large. Distributed systems complexity.

---

## 10. Configuration Reference

### Community Server (Current + New)

```bash
# ── Existing ──────────────────────────────────────────────
SC_HOST=0.0.0.0
SC_PORT=8443
SC_DATABASE_URL=sqlite://./data/mobium.db
SC_TLS_CERT=/path/to/cert.pem
SC_TLS_KEY=/path/to/key.pem
SC_REQUIRE_TLS=true
SC_MAX_CONNECTIONS=2000
SC_MAX_CONNECTIONS_PER_IP=10
SC_WS_PING_INTERVAL=30
SC_MAX_OFFLINE_MESSAGES=1000
SC_MAX_MESSAGE_SIZE=1048576
SC_MESSAGE_TTL=604800
SC_AUTH_TIMEOUT=10
SC_CORS_ORIGINS=
SC_ADMIN_TOKEN=

# ── New: ICE Configuration ────────────────────────────────
SC_ICE_STUN_URL=stun:stun.l.google.com:19302
SC_ICE_TURN_URL=                               # empty = no TURN
SC_ICE_TURN_SECRET=                             # coturn shared secret
SC_ICE_TTL=86400                                # credential lifetime (seconds)
```

### Managed Server (Additional)

```bash
# ── Database (PostgreSQL) ─────────────────────────────────
SC_DATABASE_URL=postgres://user:pass@localhost/mobium

# ── Redis (for horizontal scaling, optional at first) ─────
SC_REDIS_URL=redis://localhost:6379

# ── Account System ────────────────────────────────────────
SC_REGISTRATION_ENABLED=true
SC_MAX_USERNAME_LENGTH=32
SC_USERNAME_MIN_LENGTH=3

# ── Moderation ────────────────────────────────────────────
SC_MODERATOR_PUBKEYS=hex1,hex2,hex3            # comma-separated Ed25519 pubkeys

# ── Managed TURN ──────────────────────────────────────────
SC_ICE_TURN_URL=turn:turn.mobium.io:3478
SC_ICE_TURN_SECRET=managed-coturn-shared-secret
SC_ICE_STUN_URL=stun:stun.mobium.io:3478
```

---

## 11. Open Questions

These should be resolved before or during implementation:

1. **Identity model**: Option A (crypto-only + username) vs Option B (traditional accounts). See Section 4.
2. **Channel access control**: Currently anyone can join any channel by ID. Should community server add invite-only channels? Should this be a shared feature or managed-only?
3. **Federation**: Should community servers be able to federate with each other or with the managed server? (Significantly increases complexity — probably not for v1.)
4. **Monetization**: If the managed server has operational costs, how is it funded? Free tier + paid features? Donations? This affects feature partitioning between tiers.
5. **Data portability**: Can a user export their data from managed and import into a self-hosted community server? The zero-knowledge design makes this mostly about channel membership and contact lists (messages are client-side).
6. **Protocol versioning**: When the managed server adds new message types, how do older community servers handle unknown types? Currently `handle_binary_message` returns an error for unknown types. Should unknown types be silently ignored instead?
