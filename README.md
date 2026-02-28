# Mobium

A zero-knowledge encrypted messaging platform. Self-host your own server or connect to a managed instance -- the server never sees your messages, keys, or content.

## What It Does

- **End-to-end encrypted DMs** using the Signal Protocol (X3DH + Double Ratchet)
- **Encrypted group channels** using Signal Sender Keys with bucket padding for size masking
- **DM voice calls** -- peer-to-peer WebRTC with DTLS-SRTP, no audio touches the server
- **Channel voice chat** -- server-relayed Opus audio, encrypted with AES-256-GCM derived from Sender Keys
- **Screen sharing** -- peer-to-peer in DMs (WebRTC), encrypted server-relay in channels (VP8/WebM)
- **Offline message queue** -- encrypted blobs stored on server until recipient reconnects
- **Multi-profile support** -- independent identities per profile
- **BIP39 recovery** -- 24-word mnemonic is the only way to restore your identity
- **Self-hosted** -- runs on a Raspberry Pi 5 or any Linux/macOS/Windows machine

The server stores and routes encrypted blobs. It cannot decrypt anything. There are no accounts, no emails, no phone numbers. Your Ed25519 public key is your identity.

---

## Self-Hosting Quickstart

### Prerequisites

- [Rust](https://rustup.rs/) 1.75+ (for building from source)
- **OR** [Docker](https://docs.docker.com/get-docker/) (for container deployment)

### Option A: Docker (Recommended)

```bash
git clone https://github.com/anomalyco/Mobium.git
cd Mobium

# Create data directory
mkdir -p data

# Copy and review config
cp .env.example .env

# Start the server (no TLS -- use a reverse proxy for production)
docker-compose up -d

# Verify
curl http://localhost:8443/health
# → OK
```

The server is now running at `ws://localhost:8443/ws`. Point the Mobium client at your server's IP/domain.

### Option B: Build from Source

```bash
git clone https://github.com/anomalyco/Mobium.git
cd Mobium

# Build the server (release mode, optimized)
cargo build --release -p mobium-server

# Create data directory
mkdir -p data

# Copy and review config
cp .env.example .env

# Run (reads .env automatically)
./target/release/mobium-server
```

### Option C: Raspberry Pi 5

```bash
# On the Pi (64-bit Raspberry Pi OS)
sudo apt install -y build-essential pkg-config libssl-dev libsqlite3-dev

git clone https://github.com/anomalyco/Mobium.git
cd Mobium

# Build with size optimization (strip + LTO)
cargo build --profile release-small -p mobium-server

# Run
mkdir -p data
cp .env.example .env
./target/release-small/mobium-server
```

The server uses jemalloc on Linux automatically for reduced memory fragmentation.

### TLS Setup

For production, put a reverse proxy in front of the server:

**Caddy** (automatic HTTPS):
```
your-domain.com {
    reverse_proxy localhost:8443
}
```

**Or** provide certs directly:
```bash
# In .env
SC_TLS_CERT=/path/to/cert.pem
SC_TLS_KEY=/path/to/key.pem
SC_REQUIRE_TLS=true
```

### Connecting Clients

Once the server is running, [build the client](#client-quickstart) and connect:

1. Launch the Mobium client and create a new identity
2. **Write down your 24-word recovery phrase** -- there is no other way to recover your identity
3. Enter your server URL (e.g., `wss://your-domain.com` or `ws://192.168.1.50:8443`)
4. The client authenticates via Ed25519 challenge-response -- no passwords sent to the server

See the [Client Quickstart](#client-quickstart) below for full setup instructions including platform-specific dependencies.

---

## Client Quickstart

The Mobium client is a native desktop app built with Tauri v2 (Rust backend) and Svelte 5 (frontend). It runs on Windows, macOS, and Linux.

### Prerequisites

Install these before building:

- [Rust](https://rustup.rs/) 1.75+
- [Node.js](https://nodejs.org/) 18+
- Platform-specific Tauri v2 dependencies:

**Windows:**
- [Microsoft Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (install "Desktop development with C++")
- [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) (pre-installed on Windows 10/11)

**macOS:**
```bash
xcode-select --install
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install -y libwebkit2gtk-4.1-dev build-essential curl wget \
  file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev \
  libsqlite3-dev pkg-config
```

**Linux (Fedora):**
```bash
sudo dnf install webkit2gtk4.1-devel openssl-devel curl wget file \
  libxdo-devel libappindicator-gtk3-devel librsvg2-devel sqlite-devel
```

**Linux (Arch):**
```bash
sudo pacman -S webkit2gtk-4.1 base-devel curl wget file openssl \
  appmenu-gtk-module libappindicator-gtk3 librsvg sqlite
```

### Build and Run (Development)

```bash
cd client
npm install
npm run tauri dev
```

This starts the Vite dev server with hot-reload and opens the Mobium window. The Rust backend recompiles automatically when you change `.rs` files.

### Build for Production

```bash
cd client
npm install
npm run tauri build
```

This produces native installers in `client/src-tauri/target/release/bundle/`:

| Platform | Output |
|----------|--------|
| **Windows** | `.msi` installer and `.exe` in `bundle/msi/` and `bundle/nsis/` |
| **macOS** | `.dmg` and `.app` bundle in `bundle/dmg/` and `bundle/macos/` |
| **Linux** | `.deb` and `.AppImage` in `bundle/deb/` and `bundle/appimage/` |

### First Launch Walkthrough

1. **Profile selection** -- If this is your first time, you'll be prompted to create a profile. Each profile has its own identity and data, stored in your OS data directory (`%APPDATA%/Mobium` on Windows, `~/.local/share/Mobium` on Linux, `~/Library/Application Support/Mobium` on macOS). You can override the location with the `MOBIUM_DATA_DIR` environment variable.

2. **Create or import identity** -- Choose "Create New Identity" to generate a fresh Ed25519 keypair, or "Import from Recovery Phrase" if you have an existing 24-word BIP39 mnemonic.

3. **Set a password** -- This password encrypts your identity key on disk using Argon2id. It never leaves your machine. Minimum 12 characters.

4. **Back up your recovery phrase** -- You'll see a 24-word BIP39 mnemonic. **Write it down on paper and store it securely.** This is the only way to recover your identity if you lose your password or device. The server cannot help you.

5. **Connect to a server** -- Click the connection button in the sidebar and enter your server URL:
   - Local dev server: `ws://localhost:8443`
   - LAN server: `ws://192.168.1.50:8443`
   - Production with TLS: `wss://your-domain.com`
   - Just a hostname works too: `your-domain.com` (auto-prefixes `wss://`)

   The client authenticates automatically using Ed25519 challenge-response. No passwords are sent to the server.

6. **Start messaging** -- Create a channel or start a DM by entering a contact's public key. Set nicknames for your contacts so you don't have to remember hex strings.

### Client Configuration

The client has minimal configuration. Most settings are managed through the UI.

| Setting | How to Configure |
|---------|-----------------|
| Data directory | `MOBIUM_DATA_DIR` env var (default: OS app data) |
| Server URL | Entered in the connection modal, remembered across sessions |
| Nicknames | Set per-contact in the UI, stored in local encrypted DB |
| Profiles | Created/selected in the profile picker on launch |

### Subsequent Launches

On future launches, the client:
1. Auto-selects your profile if you only have one
2. Prompts for your password to unlock your identity
3. Auto-reconnects to the last server you connected to
4. Resumes all channel memberships and DM sessions

---

## Configuration

All server configuration is via environment variables (or `.env` file). See `.env.example` for the full list.

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SC_HOST` | `0.0.0.0` | Bind address |
| `SC_PORT` | `8443` | Listen port |
| `SC_DATABASE_URL` | `sqlite://./data/mobium.db` | SQLite database path |
| `SC_REQUIRE_TLS` | `true` | Reject connections without TLS |
| `SC_TLS_CERT` | *(none)* | Path to TLS certificate |
| `SC_TLS_KEY` | *(none)* | Path to TLS private key |

### Limits & Tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `SC_MAX_CONNECTIONS` | `2000` | Max total WebSocket connections (0 = unlimited) |
| `SC_MAX_CONNECTIONS_PER_IP` | `10` | Max connections per IP (0 = unlimited) |
| `SC_MAX_MESSAGE_SIZE` | `1048576` | Max message size in bytes (1MB) |
| `SC_MAX_OFFLINE_MESSAGES` | `1000` | Offline message queue limit per user |
| `SC_MESSAGE_TTL` | `604800` | Message expiry in seconds (default: 7 days) |
| `SC_WS_PING_INTERVAL` | `30` | WebSocket keepalive ping interval (seconds) |
| `SC_AUTH_TIMEOUT` | `10` | Seconds before unauthenticated connections are dropped |

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `SC_CORS_ORIGINS` | *(none)* | Comma-separated allowed CORS origins (empty = permissive) |
| `SC_ADMIN_TOKEN` | *(none)* | Bearer token for `/admin/stats` endpoint |

### ICE/TURN (Voice & Screen Share)

| Variable | Default | Description |
|----------|---------|-------------|
| `SC_ICE_STUN_URL` | *(none)* | STUN server URL (e.g., `stun:stun.l.google.com:19302`) |
| `SC_ICE_TURN_URL` | *(none)* | TURN server URL (e.g., `turn:turn.example.com:3478`) |
| `SC_ICE_TURN_SECRET` | *(none)* | Shared secret for coturn `use-auth-secret` credential generation |
| `SC_ICE_TTL` | `86400` | TURN credential lifetime in seconds |

---

## Architecture

```
Client A                          Server                        Client B
   |                                |                               |
   |-- Encrypt (Double Ratchet) --> |                               |
   |                                |-- Forward encrypted blob ---> |
   |                                |                               |-- Decrypt
   |                                |                               |
   |           Server sees: encrypted blobs, public keys only       |
   |           Server CANNOT: decrypt, read content, recover keys   |
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| **Server** | Rust, Axum, SQLite (sqlx), WebSocket + MessagePack, rustls TLS 1.3 |
| **Client backend** | Rust (Tauri v2), SQLite (encrypted), Ed25519/X25519 crypto |
| **Client frontend** | Svelte 5, TypeScript, Tailwind CSS |
| **Voice codec** | Opus 24kbps VBR via `@evan/wasm` (WASM, inline binary) |
| **DM voice** | WebRTC peer-to-peer (DTLS-SRTP) |
| **Channel voice** | Server-relayed encrypted Opus frames |
| **Screen share (DM)** | WebRTC peer-to-peer |
| **Screen share (channel)** | Server-relayed encrypted VP8/WebM (MediaRecorder + MediaSource) |

### Cryptography

| Purpose | Algorithm |
|---------|-----------|
| Identity signing | Ed25519 |
| Key agreement | X25519 ECDH |
| Symmetric encryption | AES-256-GCM |
| DM forward secrecy | Signal Double Ratchet |
| Group encryption | Signal Sender Keys (HMAC-SHA256 chain + AES-256-GCM) |
| Voice encryption | AES-256-GCM with stable keys derived from Sender Key seed |
| Key derivation | Argon2id (passwords), HMAC-SHA256 (chain/voice keys) |
| Size masking | Bucket padding (14 buckets, 512B to 4MB) |
| Recovery | BIP39 24-word mnemonic |

### Project Structure

```
Mobium/
  shared/                  Rust crypto library (X3DH, Double Ratchet, Sender Keys)
  server/                  Axum WebSocket server (SQLite, message routing, voice relay)
  client/
    src-tauri/             Tauri v2 Rust backend (state, commands, WS client, local DB)
    src/lib/
      voice.ts             DM WebRTC voice calls
      channelVoice.ts      Channel voice (Opus codec)
      channelScreen.ts     Channel screen share
      stores/index.ts      Svelte stores
      components/          Svelte UI components
  docs/
    ARCHITECTURE.md        System architecture detail
    CRYPTO.md              Cryptographic protocol documentation
    DEPLOYMENT.md          Deployment guide (RPi, VPS, Docker, K8s)
    DESIGN_TWO_TIER.md     Two-tier server architecture design
    TODO.md                Remaining action items
```

---

## Security Model

**The server is zero-knowledge by design.** It routes encrypted blobs between clients and stores them for offline delivery. It never possesses decryption keys.

### What the Server Sees

- Ed25519 public keys (identity)
- X25519 public keys (key agreement)
- Encrypted message blobs (opaque ciphertext)
- Connection metadata (IP, online/offline status)
- Channel membership (which pubkeys are in which channels)

### What the Server Cannot Do

- Decrypt any message, voice frame, or screen share chunk
- Access private keys
- Recover accounts (only BIP39 mnemonic can restore identity)
- Read display names or nicknames (encrypted client-side)
- Determine message content or size (bucket padding)

### Hardening Measures

- Connection limits (global + per-IP) to prevent resource exhaustion
- Rate limiting (30 msg/s general, 150 burst / 80/s for voice+screen)
- Auth timeout (10s default) to drop idle unauthenticated connections
- Error sanitization (generic errors to client, full detail in server logs only)
- Constant-time admin token comparison (prevents timing attacks)
- Graceful shutdown with SQLite WAL checkpoint
- Pre-key replenishment (auto-generates OTPKs when server count drops below 5)
- Sender key rotation on member leave (forward secrecy for channels)
- Zeroization of key material on profile lock (`lock_profile()` wipes all secrets from memory)

---

## WebSocket Protocol

Binary MessagePack-encoded messages over WebSocket. The server speaks 18 message types:

### Authentication
```
Server → Client:  { type: "auth_challenge", nonce: bytes }
Client → Server:  { type: "auth", pubkey: bytes, signature: bytes, x25519_pub: bytes }
Server → Client:  { type: "auth_success", offline_count: int }
```

### Direct Messages
```
Client → Server:  { type: "message", recipient: bytes, payload: bytes }
Server → Client:  { type: "message", sender: bytes, payload: bytes }
```

### Channels
```
create_channel, join_channel, leave_channel, channel_message,
get_history, get_members, sender_key_distribution
```

### Voice & Screen Share
```
voice_signal (DM WebRTC signaling), join_voice, leave_voice,
voice_data (channel audio frames), screen_data (channel screen frames)
```

### Key Management
```
publish_prekeys, get_prekey_bundle, get_prekey_count
```

---

## Running Tests

```bash
# Shared crypto library (90 tests: unit, crypto, edge cases, protocol)
cargo test -p mobium-shared

# Server
cargo test -p mobium-server

# All workspace crates
cargo test --workspace

# Type-check workspace (0 errors)
cargo check --workspace

# Frontend type check
cd client && npm run check
```

---

## Roadmap

### Completed

- [x] E2E encrypted DMs (Signal Double Ratchet)
- [x] Group channels (Sender Keys, bucket padding, member management)
- [x] DM voice calls (WebRTC P2P, ringtone/ringback, 30s auto-reject)
- [x] Channel voice chat (server-relayed Opus, encrypted)
- [x] DM screen sharing (WebRTC P2P)
- [x] Channel screen sharing (encrypted VP8/WebM, quality presets)
- [x] Security audit (zeroization, error sanitization, rustls, pre-key replenishment)
- [x] Server hardening (connection limits, rate limiting, CORS, graceful shutdown)
- [x] Client reliability (auto-reconnect, DB migrations, bounded buffers, sender key rotation)
- [x] RPi optimization (jemalloc, strip binaries, release-small profile)

### In Progress

- [ ] Server-provided ICE configuration (replace hardcoded Google STUN)
- [ ] Profile lock UI (Rust implementation complete, needs Tauri command + UI)
- [ ] Two-tier server architecture ([design document](docs/DESIGN_TWO_TIER.md))

### Planned

- [ ] Database abstraction layer (trait-based, prep for PostgreSQL)
- [ ] PostgreSQL backend for managed server
- [ ] Account system and user discovery (managed server)
- [ ] Moderation tools (managed server)
- [ ] File sharing with client-side encryption
- [ ] Channel access control (invite-only / private channels)
- [ ] Proper TLS termination in server binary
- [ ] Tor integration via Arti

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for crypto changes
5. Submit a pull request

### Commit Prefixes

- `feat:` New feature
- `fix:` Bug fix
- `sec:` Security-related change
- `docs:` Documentation
- `test:` Tests
- `refactor:` Code restructuring

---

## License

MIT OR Apache-2.0

## Resources

- [Signal Protocol](https://signal.org/docs/)
- [Tauri v2](https://v2.tauri.app/)
- [Axum](https://github.com/tokio-rs/axum)
- [coturn TURN Server](https://github.com/coturn/coturn)
