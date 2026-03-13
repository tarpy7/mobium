# Bonchi Mesh Architecture — Design Document

> Built on Mobium. Decentralized by design.

## Vision

Transform Bonchi from a single-server encrypted messenger into a **federated mesh social platform** where:

- **Users own their data** — stored encrypted on their devices and replicated across the mesh
- **No single point of failure** — the network works without any one server
- **Discovery is distributed** — find people and content through the mesh, not a central directory
- **Servers are optional peers** — anyone can run one, they sync with each other, and the network grows organically
- **Everything stays E2E encrypted** — the mesh routes and stores ciphertext, never plaintext

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        BONCHI MESH                              │
│                                                                 │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐              │
│   │ Superpeer │────│ Superpeer │────│ Superpeer │              │
│   │ (thin)    │     │ (thin)    │     │ (thin)    │              │
│   └────┬─────┘     └────┬─────┘     └─────┬────┘              │
│        │                 │                  │                    │
│   ┌────┴────┐      ┌────┴────┐       ┌────┴────┐              │
│   │ Client  │      │ Client  │       │ Client  │              │
│   │ (full   │      │ (full   │       │ (full   │              │
│   │  peer)  │──────│  peer)  │───────│  peer)  │              │
│   └─────────┘      └─────────┘       └─────────┘              │
│                                                                 │
│   Every client is a peer. Superpeers are just peers with        │
│   stable addresses that help with NAT traversal & bootstrap.    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Layer Model

### Layer 0: Identity (already built)
- Ed25519 keypairs for identity
- X25519 for key exchange (X3DH + Double Ratchet)
- Identity = public key. No registration, no email, no phone.

### Layer 1: Mesh Transport
The foundation — how peers find and talk to each other.

**Peer Discovery:**
```
1. Client starts → connects to known superpeer(s) via WebSocket
2. Superpeer returns a peer list (pubkey + address + capabilities)
3. Client attempts direct connections to nearby peers (WebRTC or QUIC)
4. Falls back to superpeer relay if direct connection fails
5. Peers share their peer lists with each other (gossip protocol)
```

**Transport Options (in order of preference):**
| Transport | When | Why |
|-----------|------|-----|
| QUIC (direct) | Both peers have public IPs | Fastest, multiplexed, encrypted in transit |
| WebRTC | NAT traversal needed | ICE/STUN handles NAT, works in browsers |
| WebSocket relay | Fallback | Through superpeer, always works |
| Tor (.onion) | Privacy mode | Already partially built (Arti) |

**Peer Table (DHT):**
Every peer maintains a routing table (Kademlia-style):
```rust
struct PeerEntry {
    pubkey: Ed25519PublicKey,     // Peer identity
    addresses: Vec<Multiaddr>,    // How to reach them
    capabilities: Capabilities,   // What they offer
    last_seen: Timestamp,
    reputation: f32,              // Trust score (0.0 - 1.0)
}
```

### Layer 2: Distributed Storage (Encrypted Object Store)

All content is stored as **encrypted blobs** with content-addressed hashes.

**Data Model:**
```rust
struct MeshObject {
    id: Blake3Hash,              // Content-addressed (hash of encrypted_data)
    encrypted_data: Vec<u8>,     // E2E encrypted payload
    author: Ed25519PublicKey,    // Who created it (signed)
    signature: Ed25519Signature, // Proves authorship
    timestamp: u64,              // Logical clock
    ttl: Option<Duration>,       // Auto-expire (ephemeral messages)
    replication: ReplicationPolicy,
    object_type: ObjectType,     // Post, Message, Profile, Media, etc.
}

enum ReplicationPolicy {
    Pin,          // Keep forever, replicate to N peers
    Cache,        // Keep if space allows, garbage collect oldest first
    Ephemeral,    // Delete after TTL expires
    LocalOnly,    // Never replicate (drafts, private notes)
}

enum ObjectType {
    DirectMessage,    // 1:1 encrypted (Double Ratchet)
    ChannelMessage,   // Group encrypted (Sender Keys)
    Post,             // Public or followers-only
    Profile,          // User profile data
    Media,            // Images, files, voice notes
    Reaction,         // Likes, emoji reactions
    Follow,           // Social graph edge
    ChannelMeta,      // Channel description, rules, settings
}
```

**Storage Strategy:**
- Each peer stores objects they've created + objects they're subscribed to
- Popular objects get replicated more (demand-based)
- Superpeers cache more aggressively (they have more storage/bandwidth)
- Clients set their own storage budget (e.g., "use up to 2GB for mesh cache")

**Retrieval:**
```
1. Client wants object with hash X
2. Check local store → found? done.
3. Ask connected peers → anyone have X?
4. Walk DHT → find peer closest to X's hash
5. Retrieve, verify signature, decrypt, cache locally
```

### Layer 3: Social Graph (Encrypted, Local-First)

The social layer — follows, feeds, profiles — built on top of the mesh.

**Follows:**
- Stored as signed `Follow` objects on the mesh
- Your follow list is encrypted (only you can see who you follow)
- When you follow someone, your client subscribes to their objects in the mesh
- Their content gets replicated to your local store automatically

**Profiles:**
- A signed, encrypted `Profile` object published to the mesh
- Public portion (username, bio, avatar hash) readable by anyone
- Private portion (settings, blocked users) encrypted to self only
- Profile updates are new versions — peers keep latest

**Feed:**
```
Your feed = merge(
    objects from people you follow,
    channel messages from joined channels,
    DMs addressed to you,
) sorted by timestamp, deduplicated by hash
```

No algorithmic ranking. Chronological. You see what you subscribe to.

**Posts:**
```rust
struct Post {
    content: EncryptedContent,    // Text, media references
    visibility: Visibility,
    reply_to: Option<Blake3Hash>, // Thread support
    mentions: Vec<Ed25519PublicKey>,
}

enum Visibility {
    Public,              // Anyone on the mesh can read
    FollowersOnly,       // Encrypted to current follower set
    MutualOnly,          // Encrypted to mutual follows only
    Custom(Vec<Ed25519PublicKey>), // Specific recipients
}
```

### Layer 4: Federation (Server-to-Server Sync)

Superpeers (and any self-hosted servers) can federate.

**Federation Protocol:**
```
Server A                          Server B
    │                                 │
    │──── federation_hello ──────────>│  (exchange pubkeys, capabilities)
    │<─── federation_hello ───────────│
    │                                 │
    │──── sync_request ──────────────>│  (I want objects matching filter X)
    │<─── sync_response ─────────────│  (here are hashes I have)
    │                                 │
    │──── object_request ────────────>│  (send me objects A, B, C)
    │<─── object_data ───────────────│  (encrypted blobs)
    │                                 │
    │<─── push_notification ─────────│  (new object for your users)
    │                                 │
```

**What syncs:**
- Channel messages (for channels with members on both servers)
- Public posts (for followed users across servers)
- Prekey bundles (so users on different servers can DM)
- Peer discovery info (share routing tables)

**What doesn't sync:**
- Private DMs (point-to-point, never stored on servers)
- Local-only data (friend lists, settings, drafts)
- Anything without a valid signature

**Trust Model:**
```rust
struct FederationPeer {
    pubkey: Ed25519PublicKey,
    server_url: String,
    trust_level: TrustLevel,
    last_sync: Timestamp,
    shared_channels: Vec<ChannelId>,
}

enum TrustLevel {
    Untrusted,    // New peer, rate limited, no relay
    Verified,     // Admin manually approved
    Trusted,      // Long-standing, good reputation
    Blocked,      // Explicitly blocked (spam, abuse)
}
```

---

## Migration Path (Current → Mesh)

### Phase 1: Federation (2-3 weeks)
**Goal:** Servers can talk to each other. Users on Server A can join channels on Server B.

1. Add `federation` module to server
   - Server-to-server WebSocket connections
   - Mutual authentication (Ed25519 challenge)
   - `federation_peers` table in SQLite
2. Implement channel federation
   - Server relays channel messages to federated peers
   - Member lists sync across servers
   - Prekey bundles shared for cross-server DMs
3. Add federation config
   - `[federation]` section in server config
   - Allowlist/blocklist for peer servers
   - Sync interval, bandwidth limits

**Database additions:**
```sql
CREATE TABLE federation_peers (
    pubkey BLOB PRIMARY KEY,
    server_url TEXT NOT NULL,
    trust_level TEXT NOT NULL DEFAULT 'untrusted',
    last_sync INTEGER,
    added_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE federation_channels (
    channel_id BLOB NOT NULL,
    peer_pubkey BLOB NOT NULL,
    PRIMARY KEY (channel_id, peer_pubkey)
);
```

### Phase 2: Mesh Storage (3-4 weeks)
**Goal:** Content-addressed encrypted object store. Clients can store/retrieve from mesh.

1. Add `mesh` crate to workspace
   - `MeshObject` type with signing + verification
   - Blake3 content addressing
   - Local object store (SQLite or sled)
2. Implement object replication
   - Push: when you create an object, push to connected peers
   - Pull: when you need an object, ask peers for it
   - Garbage collection based on `ReplicationPolicy`
3. Migrate messages to mesh objects
   - Channel messages become `MeshObject::ChannelMessage`
   - DMs stay point-to-point but offline messages become mesh objects
   - Old `channel_messages` table feeds into mesh store

### Phase 3: DHT & Peer Discovery (2-3 weeks)
**Goal:** Clients can find each other without a central server.

1. Implement Kademlia DHT
   - Peer routing table
   - `FIND_NODE`, `FIND_VALUE`, `STORE` RPCs
   - Bootstrap from superpeer list
2. Username → pubkey resolution via DHT
   - Register `username → pubkey` mapping in DHT
   - Clients query DHT instead of server directory
3. NAT traversal
   - STUN/TURN through superpeers
   - ICE candidate exchange via mesh
   - Hole punching for direct connections

### Phase 4: Social Layer (2-3 weeks)
**Goal:** Posts, follows, feeds, profiles on the mesh.

1. `Post` object type with visibility controls
2. `Follow` / `Unfollow` objects (encrypted)
3. Feed aggregation (client-side merge of subscribed content)
4. Profile objects (public bio + encrypted private data)
5. Reactions (lightweight mesh objects referencing parent hash)
6. Thread/reply support (objects referencing parent hash)

### Phase 5: Superpeer Optimization (1-2 weeks)
**Goal:** Make superpeers thin and efficient.

1. Superpeer mode flag in server config (`role = "superpeer"`)
2. Aggressive caching for popular content
3. Relay service for NAT-blocked peers
4. Bootstrap endpoint (`GET /bootstrap` returns peer list)
5. Bandwidth/storage quotas per peer
6. Reputation system (peers that serve content reliably get higher scores)

---

## What Stays the Same

| Component | Status |
|-----------|--------|
| E2E encryption (X3DH + Double Ratchet) | ✅ Unchanged |
| Sender Keys for groups | ✅ Unchanged |
| Ed25519 identity | ✅ Unchanged |
| WebRTC voice/screen/files | ✅ Unchanged |
| Tauri + Svelte client | ✅ Unchanged |
| Channel system (rooms, roles, bans) | ✅ Migrated to mesh objects |
| NSFW filter, age gate | ✅ Unchanged |
| Tor integration | ✅ Enhanced (mesh over Tor) |

## What Changes

| Component | Before | After |
|-----------|--------|-------|
| Storage | Single SQLite on one server | Distributed encrypted objects across mesh |
| Discovery | Server username directory | DHT + superpeer bootstrap |
| Message routing | Server relays all | Direct peer-to-peer, server relay as fallback |
| Architecture | Client → Server | Client ↔ Client (mesh), Superpeer assists |
| Server role | Central authority | Optional federated peer |
| Social features | Channels + DMs only | Posts, follows, feeds, profiles |

---

## Security Considerations

**Metadata leakage in mesh:**
- DHT queries reveal what content you're looking for
- Mitigation: Query through Tor, use cover traffic, batch queries

**Sybil attacks:**
- Attacker floods DHT with malicious peers
- Mitigation: Proof-of-work for peer registration, reputation system, superpeer vouching

**Spam:**
- Open mesh means anyone can publish objects
- Mitigation: Rate limiting per pubkey, client-side filtering, reputation-gated relay

**Eclipse attacks:**
- Attacker surrounds a peer with malicious nodes
- Mitigation: Maintain connections to diverse peers, pin superpeer connections

**Storage abuse:**
- Someone publishes 10TB of encrypted garbage
- Mitigation: Per-pubkey storage quotas, reputation-based allocation, peers choose what to cache

---

## Superpeer Economics

Superpeers cost money to run. Options for sustainability:

1. **Donation-based** — Run by community members, funded by tips
2. **Storage-for-access** — You contribute storage/bandwidth, you get priority relay
3. **Lightning micropayments** — Pay-per-relay via BTCPay (already planned)
4. **Self-host incentive** — Running a superpeer earns reputation, unlocks features

---

## Tech Stack Additions

| Component | Library/Tool | Why |
|-----------|-------------|-----|
| DHT | `libp2p` or custom Kademlia | Proven P2P networking stack |
| Content addressing | `blake3` | Fast, secure hashing |
| Object serialization | `rmp-serde` (already using) | Compact binary format |
| Peer transport | `quinn` (QUIC) | Multiplexed, encrypted, NAT-friendly |
| Local mesh store | `sled` or SQLite | Embedded, concurrent, crash-safe |

---

## First Commit: Federation Scaffolding

The first concrete step — add to the existing server:

```
server/src/
├── federation/
│   ├── mod.rs          // Federation manager
│   ├── protocol.rs     // Message types (hello, sync, push)
│   ├── sync.rs         // Object sync logic
│   └── peers.rs        // Peer management + trust
├── mesh/
│   ├── mod.rs          // Mesh object types
│   ├── store.rs        // Local object store
│   └── replication.rs  // Push/pull replication
```

This is additive — nothing breaks. The current WebSocket protocol keeps working.
Federation is opt-in via config. Mesh storage runs alongside existing SQLite tables.
