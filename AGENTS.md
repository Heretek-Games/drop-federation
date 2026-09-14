# AGENTS.md — Drop Federation contributor & AI agent guide

**Drop Federation** (`drop-federation`) manages instance identity, friend handshakes, and cross-instance presence for the Drop platform.

---

## 1. Architecture

- **`src/identity.ts`**: Ed25519 key generation and instance descriptor hashing.
- **`src/moderation.ts`**: Peer block list (`BlockedPeer`) and a sliding-window rate limiter for abuse controls.
- **`src/transport.ts`**: Peer dialing — URL normalization, descriptor fetch/verification (`dialPeer`), a relay fallback (`dialPeerViaRelay`) and the direct-then-relay helper (`dialPeerWithRelay`).
- **`src/rotation.ts`**: Key rotation certificates (`buildRotation`/`signRotation`/`verifyRotation`) and chain verification.
- **`src/sharing.ts`**: Opt-in library sharing scopes (`normalizeSharingSettings`) and the visible-game filter (`visibleGames`).
- **`src/signaling.ts`**: WebRTC signaling contract (`parseSignalingMessage`) and a bounded per-target mailbox (`enqueueMessage`).
- **`src/index.ts`**: Plugin entry point implementing `ServerPlugin` with `/descriptor`, `/identity/*` (rotations/rotate), `/friends/*` (request/accept/reject/remove/block/unblock/blocked), `/odp/*`, `/sharing` + `/shared/library`, `/peers` and `/peers/dial` endpoints, and the `federation:presence` WebSocket channel.
- **Capabilities**: `routes`, `storage`, `events`, `network`, `websocket`.

---

## 2. Invariants

- **Key Protection**: `privateKey` must remain exclusively in encrypted/guarded plugin storage and never be surfaced over the network.
- **Cryptographic Verification**: Always verify signatures against remote instance public keys before accepting federated state updates.
