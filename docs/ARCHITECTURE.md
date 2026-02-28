# Mobium Architecture

## Overview

Mobium is a mathematically secure, self-hosted Discord alternative with zero-knowledge architecture. The server cannot decrypt any communications, and no account recovery is possible without the user's BIP39 mnemonic phrase.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT (Tauri)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ SvelteKit UI │  │  Rust Core   │  │  SQLite DB   │      │
│  │              │  │  (Crypto)    │  │              │      │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘      │
│         │                 │                                  │
│         └────────┬────────┘                                  │
│                  │                                           │
│            WebSocket (WSS)                                   │
└──────────────────┼──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                      SERVER (Axum)                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   WebSocket  │  │   Message    │  │   SQLite     │      │
│  │   Handler    │  │   Router     │  │   (Metadata) │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  • Zero knowledge of plaintext                               │
│  • Opaque blob storage only                                  │
│  • TLS 1.3 mandatory                                         │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Client

**Tauri v2 Application**
- **Frontend**: SvelteKit + TypeScript with strict mode
- **Backend**: Rust with shared crypto library
- **Database**: Encrypted SQLite for local storage
- **Bundle**: <50MB target size

**Key Features**:
- Identity key generation and secure storage (OS keychain or encrypted file)
- BIP39 mnemonic for recovery
- Double Ratchet encryption for DM messages
- Sender Key encryption for channel messages (with bucket padding)
- X3DH key exchange for initial DM handshake
- WebRTC peer-to-peer voice calling for DMs (ringtone, ringback, 30s timeout)
- Server-relayed channel voice chat (Opus 48kbps, stable voice key encryption)
- Multi-profile support with independent identities
- Nickname system for contacts
- WebSocket connection with automatic reconnection

### Server

**Axum Web Framework**
- **Language**: Rust with tokio async runtime
- **Protocol**: WebSocket with MessagePack binary encoding
- **Database**: SQLite for metadata and offline message queue
- **TLS**: Rustls with TLS 1.3 mandatory in production

**Key Features**:
- Message routing based on public keys (no decryption)
- Offline message storage (encrypted blobs) with configurable size limits
- Pre-key bundle storage for X3DH
- Channel management (create, join, member lists with X25519 keys)
- Voice signaling relay (WebRTC SDP/ICE for DM calls)
- Voice data relay (encrypted Opus frames for channel voice)
- Voice channel participant tracking with disconnect cleanup
- No access to plaintext or keys

### Shared Library

**Cryptographic Primitives**:
- **Identity**: Ed25519 signing keys
- **Encryption**: X25519 for ECDH, AES-256-GCM for symmetric encryption
- **DM Protocol**: Signal Double Ratchet for forward secrecy
- **Channel Protocol**: Signal Sender Keys (HMAC-SHA256 chain ratchet + AES-256-GCM)
- **Voice Encryption**: Stable AES-256-GCM keys derived from Sender Key seed (never advances text chain)
- **Key Derivation**: Argon2id (passwords), HMAC-SHA256 (chain keys, voice keys)
- **Padding**: Bucket padding (14 size buckets, 512B to 4MB) for size masking
- **Recovery**: BIP39 mnemonics, Shamir's Secret Sharing optional

## Data Flow

### Message Sending

1. **Encrypt**: Client uses Double Ratchet to encrypt message
2. **Send**: Encrypted blob sent via WebSocket to server
3. **Route**: Server checks if recipient is online
   - Online: Forward encrypted blob immediately
   - Offline: Store encrypted blob in queue
4. **Receive**: Recipient client receives blob
5. **Decrypt**: Recipient uses Double Ratchet to decrypt

### Key Exchange (X3DH)

1. **Publish**: Each user publishes pre-key bundle to server
2. **Fetch**: Alice fetches Bob's pre-key bundle
3. **Handshake**: Alice performs X3DH, derives initial root key
4. **Initialize**: Both parties initialize Double Ratchet
5. **Ratchet**: DH ratchet rotates periodically for forward secrecy

## Security Model

### Server Capabilities
✅ **Server Can**:
- Route encrypted messages
- Store encrypted blobs
- Track online/offline status
- Store pre-key bundles (public keys only)

❌ **Server Cannot**:
- Decrypt message content
- Access private keys
- Recover accounts
- Read conversation metadata
- Link messages to content

### Threats Mitigated
- Server compromise: No plaintext access
- Passive network observer: E2E encrypted
- Man-in-the-middle: Identity keys verified via signatures
- Key compromise: Forward secrecy via ratchet

## Deployment

### Minimum Requirements (Pi5)
- **CPU**: ARM64
- **RAM**: 256MB (idle)
- **Storage**: 1GB
- **Network**: TLS 1.3 capable

### Docker Compose
```bash
# Generate certificates
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes

# Start server
docker-compose up -d
```

## Protocol Versions

- **v1**: Initial release with Signal Protocol
- Support for: X3DH, Double Ratchet, offline messages

## Completed Phases

- **Phase 1**: Foundation (E2E DM messaging with Double Ratchet)
- **Phase 2**: Group channels (Sender Keys, bucket padding, member management)
- **Phase 4**: DM Voice calls (WebRTC P2P with DTLS-SRTP)
- **Phase 5**: Channel voice chat (server-relayed, Opus 48kbps, Sender Key encryption)

## Future Enhancements

- Phase 3: File sharing with client-side encryption
- Phase 6: Tor integration via Arti
- Phase 7: Social recovery UI
- Phase 8: Pi5 optimization