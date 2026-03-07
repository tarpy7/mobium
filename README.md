# Mobium

> ⚠️ **ALPHA SOFTWARE** — Mobium has not undergone a formal security audit. It may contain vulnerabilities. Do not rely on it for life-or-death communications until a stable release has been published and independently audited. Use at your own risk.

**Zero-knowledge encrypted messaging, voice, and file sharing — with Tor integration for network-level anonymity.**

The server is blind by design — it routes encrypted blobs and nothing more. Pair with Tor to hide *who* is talking, not just *what* they're saying. Self-host on a Raspberry Pi or connect to a managed instance.

## What is this?

Mobium is a communication platform where every message, voice call, and file transfer is end-to-end encrypted using proven cryptographic primitives. The server mathematically cannot decrypt your content.

**Most encrypted messengers protect message content but leak metadata** — who you talk to, when, and from where. Mobium is designed from the ground up to minimize metadata exposure, and with built-in Tor support, your IP address and network location stay hidden from the server and observers.

**Server:** Rust (Axum) · SQLite · ~9MB RAM  
**Client:** Tauri v2 · Svelte 5 · TypeScript  
**Crypto:** Ed25519 · X3DH · Double Ratchet · Sender Keys · AES-256-GCM

## Features

- **Encrypted DMs** — X3DH key exchange + Double Ratchet with forward secrecy. Messages are encrypted client-side and relayed as opaque blobs through the server (store-and-forward for offline delivery)
- **Group DMs** — Ad-hoc encrypted group conversations without creating a persistent channel
- **Channels** — Persistent group spaces with Sender Keys and bucket padding (server can't see message sizes)
- **Voice Calls** — P2P WebRTC mesh for ≤4 participants (audio never touches the server); encrypted Opus relay through the server for 5–40 participants. Channels are capped at 40 callers
- **Screen Sharing** — P2P in DMs, encrypted server-relay in channels (360p–1080p)
- **File Transfer** — P2P via WebRTC data channels in DMs (server never sees file data). Client-side NSFW filter scans images/video locally before sending. Channel/group file sharing is not yet supported
- **Private Channels** — Invite tokens with use limits and expiry
- **Content Safety** — NSFW filter (NSFWJS) runs entirely on-device. Fail-closed: if the model fails to load, all image/video transfers are blocked. No data leaves your device
- **Age Gate** — Users under 13 cannot create accounts. Verification is purely client-side; nothing is stored or sent to the server
- **Profile Lock** — Zeroize all crypto material from RAM on demand
- **No Accounts** — Ed25519 public key = identity, BIP39 mnemonic recovery. No email, no phone number
- **Tor Integration** — Route all traffic through Tor via embedded Arti client; hide your IP from the server and network observers
- **Self-Hostable** — Single binary, SQLite, ~9MB RAM, runs on a Raspberry Pi
- **Onion Service Ready** — Run the server as a Tor hidden service for full anonymity on both ends

## Quick Start

### Server

```bash
git clone https://github.com/tarpy7/mobium
cd mobium
cargo build --release -p mobium-server
cp .env.example .env
mkdir -p data
./target/release/mobium-server
```

Server listens on `ws://0.0.0.0:8443/ws` by default.

### Client

```bash
cd client
npm install
npm run tauri dev    # development
npm run tauri build  # production
```

Pre-built binaries: [Releases](https://github.com/tarpy7/mobium/releases)

## Architecture

```
┌──────────────┐                    ┌──────────────┐
│   Client A   │◄──── WebRTC P2P ──►│   Client B   │
│  (Tauri/Svelte)│  (DM voice/files) │  (Tauri/Svelte)│
└──────┬───────┘   (≤4 group voice)  └──────┬───────┘
       │                                    │
       │ WSS (encrypted blobs)              │
       │ [optional: via Tor circuit]        │
       └──────────────┬────────────────────┘
                      ▼
              ┌───────────────┐
              │  Mobium Server │  ← can run as .onion
              │  (Rust/Axum)   │
              │  SQLite DB     │
              └───────────────┘

  Through server (encrypted):     P2P (never touches server):
  • DM & channel messages         • DM voice calls
  • Prekey bundles                 • DM screen sharing
  • Channel voice (5-40 users)    • DM file transfers
  • Channel screen sharing        • Small group voice (≤4)
  • Offline message delivery

  Server sees: pubkeys, encrypted blobs, timestamps.
  Server CANNOT see: message content, files, voice
  audio, channel names, nicknames, age, identity.
  With Tor: server also cannot see client IP addresses.
```

## Tor Integration

Mobium is built for anonymity. While E2E encryption protects *what* you say, Tor protects *who* you are.

### Client-Side (Arti)

Mobium uses [Arti](https://gitlab.torproject.org/tpo/core/arti) — Tor's official Rust implementation — to route WebSocket connections through the Tor network. No separate Tor daemon needed; it's embedded in the client.

- **Your IP is hidden** from the Mobium server and network observers
- **No extra setup** — toggle Tor mode in settings, Arti handles circuit management
- **Bootstraps in seconds** — Arti is lightweight and fast

### Server-Side (Onion Service)

Run your Mobium server as a Tor hidden service for full bidirectional anonymity:

```bash
# Install Tor
sudo apt install tor

# Add to /etc/tor/torrc:
HiddenServiceDir /var/lib/tor/mobium/
HiddenServicePort 443 127.0.0.1:8443

# Restart Tor and get your .onion address
sudo systemctl restart tor
cat /var/lib/tor/mobium/hostname
```

Your server is now reachable at `xxxxx.onion` — no public IP, no DNS, no exposure.

### Privacy Layers

| Layer | What's Protected | How |
|-------|-----------------|-----|
| **E2E Encryption** | Message content, files, voice | X3DH + Double Ratchet + AES-256-GCM |
| **Bucket Padding** | Message sizes | Fixed-size buckets hide content length |
| **Tor (Client)** | Client IP + location | Traffic routed through 3-hop circuits |
| **Tor (Server)** | Server IP + location | Reachable only via .onion address |
| **No Accounts** | Real identity | Ed25519 pubkey = identity, no email/phone |

## Cryptography

| Layer | Primitive |
|-------|-----------|
| Identity | Ed25519 signing + X25519 encryption |
| Key Exchange | X3DH (Extended Triple Diffie-Hellman) |
| DM Encryption | Double Ratchet (forward secrecy) |
| Group Encryption | Sender Keys |
| Symmetric | AES-256-GCM |
| KDF | Argon2id (password) · HKDF-SHA256 (keys) |
| Message Padding | Bucket padding (hides message sizes) |
| Recovery | BIP39 24-word mnemonic |
| RNG | OS entropy via OsRng |

Full crypto documentation: [docs/CRYPTO.md](docs/CRYPTO.md)

## Configuration

Copy `.env.example` to `.env` and configure:

| Variable | Default | Description |
|----------|---------|-------------|
| `SC_HOST` | `0.0.0.0` | Bind address |
| `SC_PORT` | `8443` | Listen port |
| `SC_DATABASE_URL` | `sqlite://./data/mobium.db` | Database path |
| `SC_TLS_CERT` | — | TLS certificate path |
| `SC_TLS_KEY` | — | TLS private key path |
| `SC_MAX_CONNECTIONS` | `2000` | Max WebSocket connections |
| `SC_MAX_CONNECTIONS_PER_IP` | `10` | Per-IP connection limit |
| `SC_ICE_STUN_URL` | — | STUN server for NAT traversal |
| `SC_ICE_TURN_URL` | — | TURN relay server |
| `SC_ICE_TURN_SECRET` | — | TURN HMAC shared secret |
| `SC_ADMIN_TOKEN` | — | Bearer token for /admin endpoints |

## Security

- All crypto operations use `OsRng` (OS entropy)
- Message rate limiting: 1 per 0.3 seconds per user (server + client enforced)
- Connection rate limiting and per-IP limits
- Voice channel cap: 40 participants max
- Ed25519 challenge-response authentication
- Constant-time signature verification via `subtle`
- Memory zeroization on profile lock (`zeroize` crate)
- Sender key rotation on member departure (forward secrecy)
- CSP: no external CDN loads, frame-src/object-src blocked
- WebRTC ICE candidate filtering: private/local IPs stripped before peer exchange
- Input validation on all client→server commands (pubkeys, names, messages)
- Client-side NSFW filter (fail-closed)
- No plaintext ever stored server-side

## Project Structure

```
mobium/
├── server/          # Rust server (Axum + SQLite)
│   └── src/
│       ├── main.rs
│       ├── websocket.rs    # WS protocol handler
│       ├── database.rs     # SQLite operations
│       ├── db/             # Database abstraction trait
│       ├── config.rs       # Environment config
│       ├── auth.rs         # Challenge-response auth
│       └── tls.rs          # TLS configuration
├── client/          # Tauri v2 + Svelte 5 client
│   ├── src/         # Svelte frontend
│   └── src-tauri/   # Rust backend
│       └── src/
│           ├── commands.rs  # Tauri commands
│           ├── websocket.rs # WS client
│           ├── crypto.rs    # Key storage
│           ├── db.rs        # Client database
│           └── state.rs     # App state + lock_profile
├── shared/          # Shared crypto library
│   └── src/
│       ├── x3dh.rs         # X3DH key exchange
│       ├── ratchet.rs      # Double Ratchet
│       ├── sender_keys.rs  # Group encryption
│       ├── recovery.rs     # BIP39 mnemonic
│       ├── padding.rs      # Bucket padding
│       └── sss.rs          # Shamir's Secret Sharing
├── website/         # Landing page
├── scripts/         # Monitoring & security tools
└── docs/            # Architecture & crypto docs
```

## Status

**Alpha** — under active development. The cryptographic primitives (X3DH, Double Ratchet, AES-256-GCM) are well-established, but Mobium's implementation has not been formally audited. Use for experimentation and development. Do not depend on it for sensitive communications until a stable release and independent audit.

## License

Source Available — Personal Use. See [LICENSE](LICENSE) for full terms.

- ✅ Personal use, self-hosting, private communities
- ✅ Modify and learn from the code
- ❌ Commercial use without permission
- ❌ Competing products or services
- ❌ Surveillance or privacy-undermining purposes

For commercial licensing, contact the maintainers.
