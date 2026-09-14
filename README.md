# drop-federation

Friends Federation and Instance Peering plugin for the [Drop](https://github.com/Heretek-Games/drop) game distribution platform.

Maintained by [Heretek Games](https://github.com/Heretek-Games/drop-federation).

## Overview

`drop-federation` brings Syncthing-style decentralized instance peering to Drop:

1. **Cryptographic identity**: Ed25519 keypair, self-certifying instance ID, and Ed25519-signed `GET /descriptor` records ([docs/identity.md](docs/identity.md)).
2. **Cross-instance social**: persisted friend requests with a `pending -> accepted | rejected` lifecycle (`POST /friends/request`, `POST /friends/accept`, `POST /friends/reject`, `GET /friends`).
3. **Presence**: presence records over the `federation:presence` WebSocket channel and persisted, freshness-filtered peer heartbeats (`GET /peers`).
4. **Open Depot Protocol**: signed catalog syndication (`GET /odp/catalog`, `POST /odp/subscribe`) with signature verification, plus cross-instance discovery search (`GET /odp/search`, `GET /odp/discover`).
5. **Moderation & abuse controls**: peer block list (`POST /friends/block`, `/unblock`, `GET /friends/blocked`), immediate revocation (`POST /friends/remove`), and per-instance friend-request rate limiting.

## Status

Implemented: the routes above, signed and tamper-checked descriptors, friend persistence, presence/peer tracking, optional encrypted-at-rest key storage, ODP catalog subscription + provenance-aware discovery search, and moderation/rate limiting. The threat model is documented in [docs/security.md](docs/security.md).

Not implemented yet: peer transport / NAT traversal ([#4](https://github.com/Heretek-Games/drop-federation/issues/4)), direct or group messaging ([#5](https://github.com/Heretek-Games/drop-federation/issues/5)), opt-in library/save sharing ([#6](https://github.com/Heretek-Games/drop-federation/issues/6)), and key rotation. There is no peer-to-peer messaging today.

## Security

- Set `DROP_FEDERATION_KEY_PASSPHRASE` to encrypt the instance private key at rest (AES-256-GCM keyed by scrypt). Without it the key is stored in plaintext and a warning is logged on every boot. See [docs/security.md](docs/security.md).
- Descriptors use Ed25519 rather than the P-384 roadmap spec; rationale and migration path are in [docs/identity.md](docs/identity.md).

Built on the `@droposs/plugin-sdk`.

## Development

```sh
npm ci
npm run build
npm test
npm run typecheck
```
