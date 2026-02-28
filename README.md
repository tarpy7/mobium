# Mobium

**Zero-knowledge encrypted messaging, voice, and file sharing.**

The server is blind by design — it routes encrypted blobs and nothing more. Self-host on a Raspberry Pi or connect to a managed instance.

## What is this?

Mobium is a Discord-like communication platform where every message, voice call, and file transfer is end-to-end encrypted using the Signal Protocol. The server mathematically cannot decrypt your content.

**Server:** Rust (Axum) · SQLite · ~9MB RAM  
**Client:** Tauri v2 · Svelte 5 · TypeScript  
**Crypto:** Ed25519 · X3DH · Double Ratchet · Sender Keys · AES-256-GCM

## Features

- **Encrypted DMs** — Signal Double Ratchet with forward secrecy
- **Group Channels** — Sender Keys with bucket padding (server can't see message sizes)
- **Voice Calls** — P2P WebRTC (DMs) / AES-256-GCM encrypted relay (channels)
- **Screen Sharing** — P2P or encrypted server-relay, 360p–1080p
- **P2P File Transfer** — WebRTC data channels, server never sees file data
- **Private Channels** — Invite tokens with use limits and expiry
- **Profile Lock** — Zeroize all crypto material from RAM on demand
- **No Accounts** — Ed25519 public key = identity, BIP39 mnemonic recovery
- **Self-Hostable** — Single binary, SQLite, runs on a Raspberry Pi

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
│  (Tauri/Svelte)│    (voice/files)  │  (Tauri/Svelte)│
└──────┬───────┘                    └──────┬───────┘
       │ WSS (encrypted blobs)             │
       └──────────────┬───────────────────┘
                      ▼
              ┌───────────────┐
              │  Mobium Server │
              │  (Rust/Axum)   │
              │  SQLite DB     │
              └───────────────┘
              Server sees: pubkeys,
              encrypted blobs, timestamps.
              Server CANNOT see: message
              content, files, voice audio,
              channel names, nicknames.
```

## Cryptography

| Layer | Primitive |
|-------|-----------|
| Identity | Ed25519 signing + X25519 encryption |
| Key Exchange | X3DH (Extended Triple Diffie-Hellman) |
| DM Encryption | Double Ratchet (forward secrecy) |
| Group Encryption | Signal Sender Keys |
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
- Connection rate limiting and per-IP limits
- Ed25519 challenge-response authentication
- Constant-time signature verification via `subtle`
- Memory zeroization on profile lock (`zeroize` crate)
- Sender key rotation on member departure (forward secrecy)
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

## License

MIT / Apache-2.0
