/**
 * Signed instance descriptor (#2).
 *
 * `GET /descriptor` publishes a self-describing record (instance id, public
 * key, protocol versions, timestamp) signed with the instance's Ed25519 key.
 * Peers can verify the record offline: the signature binds the payload and the
 * payload's `instanceId` is re-derived from the embedded public key.
 *
 * Algorithm deviation: the roadmap specifies deriving identity from the server
 * P-384 certificate and signing with `ssl.rs::sign_nonce`/`verify_nonce`
 * (ECDSA P-384/SHA-384). This plugin generates an Ed25519 keypair in-process
 * and signs descriptors with it. See docs/identity.md for rationale and the
 * migration path.
 */
import { createPublicKey, sign, verify } from "node:crypto";
import { deriveInstanceId, type InstanceIdentity } from "./identity.js";

export const DESCRIPTOR_FORMAT_VERSION = 2;

export interface InstanceDescriptor {
  instanceId: string;
  publicKey: string;
  apiVersion: number;
  descriptorVersion: number;
  /** Advertised peer-transport base URLs (direct dial candidates). */
  endpoints: string[];
  timestamp: number;
}

export interface SignedDescriptor extends InstanceDescriptor {
  signature: string;
}

export function buildDescriptor(
  identity: InstanceIdentity,
  apiVersion: number,
  endpoints: string[] = [],
  timestamp: number = Date.now(),
): InstanceDescriptor {
  return {
    instanceId: identity.instanceId,
    publicKey: identity.publicKey,
    apiVersion,
    descriptorVersion: DESCRIPTOR_FORMAT_VERSION,
    endpoints: [...endpoints],
    timestamp,
  };
}

/**
 * Deterministic JSON so signer and verifier hash identical bytes. `endpoints`
 * are sorted so peer address order never changes the signed payload.
 */
export function canonicalizeDescriptor(descriptor: InstanceDescriptor): string {
  return JSON.stringify({
    apiVersion: descriptor.apiVersion,
    descriptorVersion: descriptor.descriptorVersion,
    endpoints: [...(descriptor.endpoints ?? [])].sort(),
    instanceId: descriptor.instanceId,
    publicKey: descriptor.publicKey,
    timestamp: descriptor.timestamp,
  });
}

/** Signs a descriptor with the instance Ed25519 private key (PEM). */
export function signDescriptor(
  descriptor: InstanceDescriptor,
  privateKeyPem: string,
): string {
  return sign(
    null,
    Buffer.from(canonicalizeDescriptor(descriptor)),
    privateKeyPem,
  ).toString("base64");
}

/**
 * Verifies a signed descriptor. When `publicKeyPem` is provided it must match
 * the key embedded in the descriptor (pinning); otherwise the embedded key is
 * trusted only if the instance id derives from it.
 *
 * Returns false for any tampered field, a mismatched instance id, or malformed
 * keys/signatures rather than throwing.
 */
export function verifyDescriptor(
  descriptor: InstanceDescriptor,
  signatureBase64: string,
  publicKeyPem?: string,
): boolean {
  try {
    if (!signatureBase64) {
      return false;
    }
    const pem = publicKeyPem ?? descriptor.publicKey;
    if (!pem || !descriptor.publicKey) {
      return false;
    }
    if (publicKeyPem && publicKeyPem !== descriptor.publicKey) {
      return false;
    }
    if (descriptor.instanceId !== deriveInstanceId(descriptor.publicKey)) {
      return false;
    }
    createPublicKey(pem);
    return verify(
      null,
      Buffer.from(canonicalizeDescriptor(descriptor)),
      pem,
      Buffer.from(signatureBase64, "base64"),
    );
  } catch {
    return false;
  }
}
