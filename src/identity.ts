import { createHash, generateKeyPairSync } from "node:crypto";
import {
  KEY_PASSPHRASE_ENV,
  openSecret,
  sealSecret,
  type SealedSecret,
} from "./keystore.js";

export interface InstanceIdentity {
  instanceId: string;
  publicKey: string;
  privateKey?: string;
}

/**
 * The persisted shape. The private key is either sealed with AES-256-GCM
 * (`sealedPrivateKey`) or, when no passphrase is configured, stored as legacy
 * plaintext (`privateKey`) with a loud startup warning. Both are never present
 * at the same time.
 */
export interface StoredInstanceIdentity {
  instanceId: string;
  publicKey: string;
  privateKey?: string;
  sealedPrivateKey?: SealedSecret;
  protection?: "plaintext" | "passphrase";
}

/**
 * Self-certifying instance ID: first 32 hex chars of SHA-256 over the
 * SPKI public key. This is a deliberate deviation from the P-384 certificate
 * fingerprint described in the roadmap; see docs/identity.md.
 */
export function deriveInstanceId(publicKeyPem: string): string {
  return createHash("sha256").update(publicKeyPem).digest("hex").slice(0, 32);
}

export function generateInstanceIdentity(): InstanceIdentity {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  return {
    instanceId: deriveInstanceId(publicKey),
    publicKey,
    privateKey,
  };
}

/**
 * Converts a runtime identity into its persisted form. When a passphrase is
 * configured the private key is sealed and never written in plaintext;
 * otherwise the legacy plaintext field is used (callers must warn).
 */
export function toStoredIdentity(
  identity: InstanceIdentity,
  passphrase?: string,
): StoredInstanceIdentity {
  if (identity.privateKey && passphrase) {
    return {
      instanceId: identity.instanceId,
      publicKey: identity.publicKey,
      sealedPrivateKey: sealSecret(identity.privateKey, passphrase),
      protection: "passphrase",
    };
  }
  return {
    instanceId: identity.instanceId,
    publicKey: identity.publicKey,
    privateKey: identity.privateKey,
    protection: "plaintext",
  };
}

/**
 * Restores a runtime identity from storage. Throws when the stored key is
 * sealed but the operator passphrase is missing, rather than booting with a
 * public-key-only identity that can no longer sign descriptors.
 */
export function fromStoredIdentity(
  stored: StoredInstanceIdentity,
  passphrase?: string,
): InstanceIdentity {
  if (stored.sealedPrivateKey) {
    if (!passphrase) {
      throw new Error(
        `Instance private key is encrypted at rest; set ${KEY_PASSPHRASE_ENV} to unlock it`,
      );
    }
    return {
      instanceId: stored.instanceId,
      publicKey: stored.publicKey,
      privateKey: openSecret(stored.sealedPrivateKey, passphrase),
    };
  }
  return {
    instanceId: stored.instanceId,
    publicKey: stored.publicKey,
    privateKey: stored.privateKey,
  };
}
