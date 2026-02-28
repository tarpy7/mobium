# Cryptographic Protocols

This document details the cryptographic protocols used in Mobium.

## Overview

Mobium implements the X3DH + Double Ratchet protocol with the following primitives:

- **X3DH** (Extended Triple Diffie-Hellman): Initial key agreement
- **Double Ratchet**: Forward secrecy and future secrecy
- **AES-256-GCM**: Symmetric encryption
- **Ed25519**: Digital signatures
- **X25519**: ECDH key agreement
- **Argon2id**: Password-based key derivation

## Identity Keys

Each user has a long-term identity key pair:

```rust
pub struct IdentityKey {
    pub signing: Ed25519KeyPair,      // For authentication
    pub encryption: X25519StaticKey,  // For X3DH
}
```

### Key Storage

Identity keys are encrypted at rest using:
1. **Argon2id** (memory=64MB, iterations=3, parallelism=1) to derive key from password
2. **AES-256-GCM** with random nonce
3. Stored in OS keychain or encrypted file

### Key Recovery

Users backup their identity via **BIP39 mnemonics**:
- 24-word English mnemonic
- 256 bits of entropy
- PBKDF2-HMAC-SHA512 derivation with "mnemonic" salt
- Optional passphrase for additional security

## X3DH Key Agreement

### Pre-Key Bundles

Each user publishes a pre-key bundle containing:

```rust
pub struct PreKeyBundle {
    pub identity_key: Ed25519PublicKey,
    pub signed_pre_key: X25519PublicKey,
    pub signed_pre_key_signature: Ed25519Signature,
    pub one_time_pre_keys: Vec<X25519PublicKey>,
}
```

**Signed Pre-Key**:
- Rotated periodically (e.g., weekly)
- Signed by identity key
- Intermediate-term key

**One-Time Pre-Keys**:
- Consumed on first use
- Provide additional forward secrecy
- Replenished by client

### Handshake Process

**Initiator (Alice)**:
```
DH1 = alice_identity.encryption × bob_bundle.signed_pre_key
DH2 = alice_ephemeral × bob_bundle.identity_key
DH3 = alice_ephemeral × bob_bundle.signed_pre_key
DH4 = alice_ephemeral × bob_one_time_pre_key (if available)

SK = KDF(DH1 || DH2 || DH3 [|| DH4])
AD = alice_identity_key || bob_identity_key
```

**Responder (Bob)**:
```
DH1 = bob_signed_pre_key × alice_identity_key
DH2 = bob_identity.encryption × alice_ephemeral
DH3 = bob_signed_pre_key × alice_ephemeral
DH4 = bob_one_time_pre_key × alice_ephemeral (if available)

SK = KDF(DH1 || DH2 || DH3 [|| DH4])
AD = alice_identity_key || bob_identity_key
```

### Security Properties

- **Authentication**: Mutual authentication via identity keys
- **Forward Secrecy**: One-time pre-keys prevent decryption after compromise
- **Future Secrecy**: Signed pre-key rotation limits exposure window

## Double Ratchet

After X3DH, parties use the Double Ratchet for ongoing communication.

### State

```rust
pub struct DoubleRatchet {
    root_key: [u8; 32],
    send_chain_key: Option<ChainKey>,
    recv_chain_key: Option<ChainKey>,
    our_dh_key: Option<EphemeralSecret>,
    their_dh_key: Option<PublicKey>,
    // Message numbers for out-of-order handling
    send_message_number: u32,
    recv_message_number: u32,
    skipped_keys: Vec<(u32, MessageKey)>,
}
```

### Message Encryption

**Sending**:
```
message_key, next_chain_key = KDF_Message_Key(send_chain_key)
send_chain_key = next_chain_key

ciphertext = AES-256-GCM(plaintext, message_key, associated_data)
```

**Receiving**:
```
If new DH key received:
    Perform DH ratchet step

message_key, next_chain_key = KDF_Message_Key(recv_chain_key)
recv_chain_key = next_chain_key

plaintext = AES-256-GCM_Decrypt(ciphertext, message_key, associated_data)
```

### DH Ratchet

Triggered when receiving a message with a new DH public key:

1. Derive new root key: `KDF_RK(root_key, DH_Output)`
2. Derive new receiving chain key
3. Generate new sending DH key pair
4. Derive new root key with second DH
5. Derive new sending chain key

### KDF Details

**Root Key KDF**:
```
KDF_RK(rk, dh_out) = HKDF-SHA256(dh_out, rk, "Mobium-v1-RootKey")
```

**Chain Key KDF**:
```
KDF_CK(ck) = HMAC-SHA256(ck, 0x01)  // Message key
KDF_CK(ck) = HMAC-SHA256(ck, 0x02)  // Next chain key
```

### Out-of-Order Messages

The ratchet stores up to `max_skip` (default: 1000) skipped message keys:

- Keys indexed by message number
- Old keys purged to prevent memory exhaustion
- Missing messages detected by sequence gaps

## Message Format

### Encrypted Message Structure

```rust
pub struct EncryptedMessage {
    // Header (unencrypted)
    pub header: MessageHeader,
    // Ciphertext
    pub ciphertext: Vec<u8>,
    // Authentication tag
    pub tag: [u8; 16],
}

pub struct MessageHeader {
    pub sender_pubkey: [u8; 32],
    pub message_number: u32,
    pub previous_chain_length: u32,
    pub ephemeral_pubkey: Option<[u8; 32]>,
    pub timestamp: u64,
}
```

### Associated Data

Each message includes authenticated associated data:

```
AD = protocol_version || sender_pubkey || recipient_pubkey || timestamp
```

This binds the ciphertext to:
- Protocol version (prevent downgrade)
- Sender identity (authenticate source)
- Recipient identity (prevent forwarding)
- Timestamp (prevent replay)

## Security Properties

### Forward Secrecy

**Compromised key cannot decrypt past messages**:

- Each message uses unique key from chain
- Chain keys destroyed after use
- DH ratchet rotates keys regularly
- One-time pre-keys provide initial protection

### Future Secrecy

**Compromised key cannot decrypt future messages indefinitely**:

- DH ratchet introduces new entropy
- Each ratchet step creates new key material
- Self-healing within a few message exchanges

### Post-Compromise Security

Even after full compromise (both keys exposed):
- New DH ratchet breaks attacker's chain
- Within N messages, security is restored
- N depends on ratchet frequency

## Implementation Details

### Constant-Time Operations

All cryptographic operations use constant-time implementations:
- `subtle` crate for constant-time comparisons
- `ed25519-dalek` for constant-time signing
- `x25519-dalek` for constant-time DH

### Memory Safety

Sensitive data is cleared from memory:
- `zeroize` crate for secure clearing
- Keys automatically cleared on drop
- Stack variables cleared after use

### Random Number Generation

- OS-provided CSPRNG ( `/dev/urandom`, Windows CryptoAPI, etc.)
- `rand::rngs::OsRng` for all cryptographic randomness
- Never use deterministic random for keys

## Sender Keys (Group / Channel Encryption)

For channel messages, Mobium uses **Sender Keys** instead
of pairwise Double Ratchets. Each group member maintains their own
symmetric ratchet chain. When sending, you advance YOUR chain and encrypt;
all other members hold a copy of your chain key so they can derive the same
message keys.

### Sender Key Distribution

When you join a channel (or rotate), you send a `SenderKeyDistribution` to
every other member, encrypted pairwise with X25519 ECDH so the server
never sees the plaintext chain key.

```
SenderKeyDistribution {
    channel_id,
    sender_pubkey,        // Ed25519 identity
    key_id: u32,          // unique per chain generation
    chain_key: [u8; 32],  // initial seed
    iteration: u32,       // starting step (normally 0)
    voice_key: [u8; 32],  // stable voice encryption key (see below)
}
```

### Chain Ratchet (Text Messages)

Each message advances the chain:

```
message_key  = HMAC-SHA256(chain_key, 0x01 || iteration_BE)
nonce        = HMAC-SHA256(chain_key, 0x02 || iteration_BE)[..12]
chain_key'   = HMAC-SHA256(chain_key, 0x03)
iteration   += 1
```

Wire format for text messages:
```
[4 bytes: key_id (u32 BE)]
[4 bytes: iteration (u32 BE)]
[12 bytes: nonce]
[N bytes: AES-256-GCM(bucket-padded plaintext) + 16-byte tag]
```

Plaintext is bucket-padded before encryption to mask message size.

### Key Rotation

When a member leaves a group, all remaining members call `rotate()` which
generates a fresh random seed and key_id, then re-distributes to all peers.
This provides forward secrecy: the departed member's chain key cannot decrypt
future messages.

### Out-of-Order Decryption

Up to `max_skip` (256) messages may be received out of order. Skipped
message keys are cached and consumed on arrival.

### Properties

- **Forward Secrecy**: compromising a chain key only reveals future messages
  from that sender
- **Efficient**: O(1) encryption per message (vs O(N) for pairwise ratchets)
- **Key Rotation**: member departure triggers re-keying for all senders

## Voice Encryption

### DM Voice Calls (WebRTC)

DM voice calls use peer-to-peer WebRTC with DTLS-SRTP for transport
encryption. The WebRTC signaling (SDP offers/answers, ICE candidates) is
relayed through the server as opaque payloads.

### Channel Voice Chat (Sender Keys)

Channel voice uses server-relayed audio encrypted with **stable voice keys**
derived from the Sender Key chain. Unlike text messages, voice frames do
NOT advance the chain ratchet. This is critical because:

1. Voice sends ~50 frames/sec (180,000 per hour). Advancing the chain would
   cause text receivers not in voice to see iteration gaps exceeding
   `max_skip` (256), permanently breaking text decryption.

2. If a receiver drops >256 consecutive frames (~5 seconds), they would
   lose sync with the sender's chain permanently.

### Stable Voice Key Derivation

A stable voice key is derived ONCE per chain generation:

```
voice_key = HMAC-SHA256(initial_seed, "Mobium-voice-v1" || key_id_BE)
```

This key is included in the `SenderKeyDistribution` so peers receive it
alongside the text chain key. The voice key never changes until the next
key rotation.

### Voice Wire Format

```
[4 bytes: key_id (u32 BE)]
[8 bytes: seq (u64 BE)]         -- monotonic frame counter
[N bytes: AES-256-GCM(opus frame) + 16-byte tag]
```

- **Nonce**: `key_id(4) || seq(8)` = 12 bytes (unique per sender + frame)
- **Overhead**: 12 bytes header + 16 bytes AES-GCM tag = 28 bytes
- **Codec**: Opus 48kbps VBR, 48kHz mono, 20ms frames
- **DTX**: Opus Discontinuous Transmission handles voice activity detection

### Security Properties

- Voice key is AES-256-GCM with unique nonces (key_id + seq)
- Nonce reuse is prevented by monotonically increasing seq numbers
- Key rotation on member departure re-derives the voice key
- Text chain ratchet is completely unaffected by voice traffic

## Protocol Versioning

```rust
pub const PROTOCOL_VERSION: u8 = 1;
```

Version increments when:
- Breaking changes to message format
- New cryptographic primitives
- Security-critical fixes

Backward compatibility within major version.

## References

1. **X3DH + Double Ratchet protocol**: https://signal.org/docs/
2. **X3DH**: https://signal.org/docs/specifications/x3dh/
3. **Double Ratchet**: https://signal.org/docs/specifications/doubleratchet/
4. **Sender Keys**: https://signal.org/docs/specifications/group-v2/
5. **BIP39**: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
6. **X25519**: https://datatracker.ietf.org/doc/html/rfc7748
7. **Ed25519**: https://datatracker.ietf.org/doc/html/rfc8032
8. **Opus**: https://opus-codec.org/