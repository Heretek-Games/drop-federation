# AGENTS.md — Drop Federation contributor & AI agent guide

**Drop Federation** (`drop-federation`) manages instance identity, friend handshakes, and cross-instance presence for the Drop platform.

---

## 1. Architecture

- **`src/identity.ts`**: Ed25519 key generation and instance descriptor hashing.
- **`src/index.ts`**: Plugin entry point implementing `ServerPlugin` with `/descriptor` and `/friends/request` endpoints, and `federation:presence` WebSocket channel.
- **Capabilities**: `routes`, `storage`, `events`, `network`, `websocket`.

---

## 2. Invariants

- **Key Protection**: `privateKey` must remain exclusively in encrypted/guarded plugin storage and never be surfaced over the network.
- **Cryptographic Verification**: Always verify signatures against remote instance public keys before accepting federated state updates.
