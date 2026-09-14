# drop-federation

Friends Federation and Instance Peering plugin for the [Drop](https://github.com/Heretek-Games/drop) game distribution platform.

Maintained by [Heretek Games](https://github.com/Heretek-Games/drop-federation).

## Overview

`drop-federation` brings Syncthing-style decentralized instance peering to Drop:

1. **Cryptographic identity**: Ed25519 keypair, self-certifying instance ID, and Ed25519-signed `GET /descriptor` records ([docs/identity.md](docs/identity.md)).
2. **Cross-instance social**: persisted friend requests with a `pending -> accepted | rejected` lifecycle (`POST /friends/request`, `POST /friends/accept`, `POST /friends/reject`, `GET /friends`).
3. **Presence**: presence records over the `federation:presence` WebSocket channel and persisted, freshness-filtered peer heartbeats (`GET /peers`).
4. **Open Depot Protocol**: signed catalog syndication (`GET /odp/catalog`, `POST /odp/subscribe`) with signature verification, cross-instance discovery search (`GET /odp/search`), subscription provenance (`GET /odp/subscriptions`), and revocation (`DELETE /odp/subscriptions/:instanceId`).
5. **Moderation & abuse controls**: peer block list (`POST /friends/block`, `/unblock`, `GET /friends/blocked`), immediate revocation (`POST /friends/remove`), and per-instance friend-request rate limiting.
6. **Peer transport (direct + relay)**: descriptors advertise `endpoints` (`DROP_FEDERATION_ENDPOINTS`); `POST /peers/dial` fetches and cryptographically verifies a peer's signed descriptor before recording it. When direct dialing fails and `DROP_FEDERATION_RELAY_URL` is set, a relay retransmits the descriptor (`GET <relay>/relay/descriptor?target=...`) — the relay can only censor, never forge, because the descriptor is verified end to end.
7. **Key rotation**: `POST /identity/rotate` (operator-only via `DROP_FEDERATION_ADMIN_TOKEN`) mints a new keypair and publishes a signed rotation certificate; `GET /identity/rotations` exposes the verifiable old→new chain so pinned peers can follow the transition.
8. **Opt-in library sharing**: `POST /sharing` (operator-only) sets a sharing scope (`none`/`library`/`games`); `GET /shared/library` returns the currently-shared games and is empty by default or immediately after revocation.

## Status

Implemented: the routes above, signed and tamper-checked descriptors (v2, with advertised endpoints), friend persistence, presence/peer tracking, optional encrypted-at-rest key storage, ODP catalog subscription + provenance-aware discovery search, moderation/rate limiting, direct peer dialing with descriptor verification, operator-driven key rotation with a verifiable chain, and opt-in library sharing scopes with immediate revocation. The threat model is documented in [docs/security.md](docs/security.md).

Not implemented yet: NAT traversal (the direct and relay transport paths exist, but hole-punching does not) ([#4](https://github.com/Heretek-Games/drop-federation/issues/4)), direct or group messaging ([#5](https://github.com/Heretek-Games/drop-federation/issues/5)), and remote save sharing / streaming a shared game (the sharing scopes and shared-library endpoint exist, but content transfer is not wired). There is no peer-to-peer messaging today.

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
