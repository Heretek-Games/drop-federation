# Instance identity & signed descriptors

This document records how `drop-federation` derives instance identity, how the
descriptor is signed, and where the implementation deliberately deviates from
the original roadmap specification in
[Heretek-Games/drop-federation#2](https://github.com/Heretek-Games/drop-federation/issues/2).

## Identity

- Keypair: **Ed25519** (SPKI public PEM, PKCS#8 private PEM), generated
  in-process by `generateInstanceIdentity()` in `src/identity.ts`.
- Instance ID: `sha256(publicKeyPem)` rendered as hex, truncated to the **first
  32 hex characters** (128 bits), implemented in `deriveInstanceId()`.

The instance ID is self-certifying: `verifyDescriptor()` re-derives it from the
public key embedded in the descriptor, so a peer cannot claim someone else's ID
without also presenting a key that hashes to it.

## Descriptor format (version 1)

`GET /descriptor` returns `src/descriptor.ts`'s `InstanceDescriptor` plus a
base64 detached signature:

```json
{
  "instanceId": "5f3a…",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n…",
  "apiVersion": 2,
  "descriptorVersion": 1,
  "timestamp": 1789000000000,
  "signature": "MEUCIQ…"
}
```

The signature covers a deterministic JSON encoding of
`{apiVersion, descriptorVersion, instanceId, publicKey, timestamp}`
(`canonicalizeDescriptor`), signed with the instance's Ed25519 private key.

Verification (`verifyDescriptor`):

1. When a caller-supplied `publicKeyPem` is given, it must equal the public key
   embedded in the descriptor (pinning support).
2. `instanceId` must equal `deriveInstanceId(descriptor.publicKey)`.
3. The signature must verify over the canonical descriptor bytes.

All three checks return `false` instead of throwing on malformed input.

## Deviation from the P-384 spec

The roadmap specifies deriving identity from the existing server **P-384**
certificate (`server/server/internal/clients/ca.ts`) and signing descriptors
with `ssl.rs::sign_nonce`/`verify_nonce` (ECDSA P-384/SHA-384). This plugin
currently uses **Ed25519** instead:

- The plugin runs inside the Node/Nitro server and has no access to the Rust
  `ssl.rs` primitives or the CA store over the plugin API.
- `node:crypto` ships Ed25519 support with no new dependencies, keeping the
  plugin self-contained and testable with the SDK mock harness.
- Signatures are ~64 bytes and verification is constant-time in the runtime.

Consequences:

- Instance IDs do **not** match a certificate fingerprint of the server CA. A
  future migration to the CA keypair requires a descriptor format bump, since
  the algorithm and key encoding change.
- Verifiers must accept `Ed25519` descriptors today; the `descriptorVersion`
  field is the negotiation point for adding P-384 later.

Migration path (tracked under #2):

1. Read the P-384 server certificate/key through a host-provided capability.
2. Introduce `descriptorVersion: 2` with an explicit `algorithm` field
   (`ed25519` | `ecdsa-p384`).
3. Dual-publish both descriptors during a transition window; keep the existing
   `instanceId` for continuity or publish a documented ID migration.

## Compatibility

`GET /descriptor` keeps returning the pre-existing fields
(`instanceId`, `publicKey`, `apiVersion`, `timestamp`) unchanged for consumers
that ignore the new `descriptorVersion` and `signature` fields.
