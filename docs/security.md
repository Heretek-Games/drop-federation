# Security notes: instance private key at rest

This document covers how the instance private key is stored, the risk of the
current storage backend, and the concrete mitigation plan. It feeds the broader
threat-model work in
[Heretek-Games/drop-federation#7](https://github.com/Heretek-Games/drop-federation/issues/7).

## The problem

The plugin persists its identity under `instance_identity` via
`ctx.storage` (`src/index.ts`). As of `@droposs/plugin-sdk@0.4.0`, `PluginStorage`
exposes only:

```ts
get<T>(key), set<T>(key, value), delete(key), listKeys(),
getSchemaVersion(), setSchemaVersion(version)
```

There is **no encryption-at-rest, OS keychain, or KMS hook** in the SDK storage
contract. Any historical build that wrote the key with `privateKey` in
plaintext therefore left a usable signing key readable to anything that can
read the storage backend (database dumps, backups, copied data directories).

## Implemented mitigation (this change)

`src/keystore.ts` adds application-level envelope encryption using only
`node:crypto` (no new dependencies):

- AES-256-GCM with a random 16-byte salt and 12-byte IV per secret.
- Key derived with `scrypt` (N=16384 default, 32-byte key) from the operator
  passphrase in `DROP_FEDERATION_KEY_PASSPHRASE`.
- Stored shape: `sealedPrivateKey` (versioned, algorithm/KDF tagged) and
  `protection: "passphrase"`; the plaintext `privateKey` field is absent.

Behavior in `loadOrCreateIdentity` (`src/index.ts`):

1. **New install with passphrase**: the key is sealed before it is ever
   written.
2. **Existing plaintext key + passphrase**: the key is re-sealed in place on
   the first boot after configuring the passphrase. Old plaintext copies may
   still exist in storage snapshots/backups — rotate the key (see below) if the
   storage was ever exposed.
3. **No passphrase**: the plugin logs a prominent warning on every boot
   (nothing is silently plaintext) and keeps working for development.
4. **Sealed key + missing passphrase**: init throws instead of booting with an
   identity that cannot sign descriptors.

The private key is never returned by any route: `GET /descriptor` exposes only
the public key and a signature.

### Operator guidance

- Set a high-entropy passphrase, e.g.
  `DROP_FEDERATION_KEY_PASSPHRASE="$(openssl rand -base64 32)"`, delivered via
  systemd `LoadCredential`/`EnvironmentFile` with `0600`, Docker/K8s secrets,
  or a vault agent — not a committed `.env`.
- Losing the passphrase means losing the ability to sign as this instance.
  Back up the passphrase in a password manager.

## Residual risk & mitigation plan

| Risk | Status | Mitigation |
| --- | --- | --- |
| Storage backend read (backup, dump, host compromise) | Reduced | AES-256-GCM envelope; plaintext migration; warning when unset. |
| Passphrase visible in process env (`/proc/<pid>/environ`) | Accepted | Same-host attacker with process access can already read plugin memory. Request an SDK credential/keyring capability (below). |
| No key rotation / compromise recovery | Open | Tracked in #2/#7: add `POST /identity/rotate`, publish old+new descriptors during handover, rotate scoped peer tokens on rotation. |
| Backups predating encryption retain plaintext | Open (operational) | Rotate the identity after enabling encryption if old backups cannot be purged. |
| Passphrase strength | Operational | Documented high-entropy requirement; consider rejecting passphrases < 16 chars in a follow-up. |
| Malicious peer / descriptor spoofing | Reduced | Self-certifying instance ID + Ed25519 descriptor signature (`verifyDescriptor`), signature verification on ODP subscriptions and friend requests. |
| Resource abuse, relay trust, metadata leakage | Open | Explicitly deferred to #7 (threat model), #4 (relay), #6 (sharing). |

## Requested SDK capability (upstream follow-up)

The clean long-term fix is host-managed secret storage. Proposal for
`@droposs/plugin-sdk`:

```ts
interface PluginSecretStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}
// ctx.secrets, backed by the OS keychain / host KMS.
```

Until that exists, the passphrase envelope above is the no-new-dependency
mitigation and the plaintext fallback is loudly signposted rather than silent.

## Threat model (federation is opt-in)

Federation connects independent, mutually-untrusted instances. Every capability
is explicit and can be revoked; nothing is shared until an operator accepts a
peer.

| Threat | Vector | Mitigation |
| --- | --- | --- |
| **Malicious peer** | A peer sends forged friend requests, catalogs, or presence. | Ed25519 signatures on descriptors, friend requests, and ODP catalogs (`verifyDescriptor`, `verifyFriendRequestSignature`, `verifyCatalogSignature`). Unsigned requests are accepted only with `signatureVerified: false` and a warning. |
| **Descriptor spoofing** | Impersonating another instance. | Self-certifying instance id derived from the public key (`deriveInstanceId`); the descriptor signature is verified against the advertised key. Key pinning supported by `verifyDescriptor`. |
| **Resource abuse / flooding** | Mass friend requests or subscriptions exhausting storage/CPU. | Sliding-window rate limiter per remote instance (`SlidingWindowRateLimiter`, 20 requests/minute by default) plus a block list. |
| **Persistent abuse** | A blocked or revoked peer keeps reconnecting. | `POST /friends/block` persists a block (by instance id and URL) and drops cached peer state; blocked instances are rejected before persistence. |
| **Revocation lag** | A removed friend retains access. | `POST /friends/remove` deletes the request/link and any cached peer record immediately; presence is informational and re-established only by a fresh, authenticated heartbeat. |
| **Relay operators** | A relay observes peer IPs and instance ids. | Relays are opt-in and documented as learning both (issue #4); traffic stays end-to-end encrypted. Relay is a fallback, never required. |
| **Metadata leakage** | Peers learn more than intended about users/games. | Only presence heartbeats and catalog entries are exchanged; library/save sharing is a separate explicit opt-in (#6). Peer-supplied keys are informational and never make trust decisions. |
| **Key compromise** | A leaked private key allows impersonation. | Passphrase-sealed key at rest (AES-256-GCM + scrypt); rotation is tracked in #2. |

### Consent and defaults

- Federation routes are inert until an operator configures the instance and
  accepts a peer; there is no implicit peering.
- Blocks and revocations take effect immediately and survive restarts.
- The rate limiter is in-process, matching the plugin runtime's single-process
  state; a horizontally-scaled deployment should move it to shared storage
  (tracked with the WebSocket-state prerequisite in #5).
