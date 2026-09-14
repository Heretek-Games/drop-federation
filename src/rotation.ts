/**
 * Instance key rotation (#2).
 *
 * A self-certifying instance id is derived from its public key, so rotating the
 * key changes the id. A **rotation certificate** signed by the *previous* key
 * binds the old id to the new one, letting a peer that pinned the old key
 * verify the transition offline. The chain of certificates is published so any
 * peer can follow the instance across rotations.
 */
import { createPublicKey, sign, verify } from "node:crypto";
import { deriveInstanceId, type InstanceIdentity } from "./identity.js";

export interface RotationCertificate {
  previousInstanceId: string;
  previousPublicKey: string;
  nextInstanceId: string;
  nextPublicKey: string;
  timestamp: number;
}

export interface SignedRotation {
  certificate: RotationCertificate;
  /** Base64 Ed25519 signature by the previous key. */
  signature: string;
}

export function buildRotation(
  previous: InstanceIdentity,
  next: InstanceIdentity,
  timestamp: number = Date.now(),
): RotationCertificate {
  return {
    previousInstanceId: previous.instanceId,
    previousPublicKey: previous.publicKey,
    nextInstanceId: next.instanceId,
    nextPublicKey: next.publicKey,
    timestamp,
  };
}

/** Deterministic JSON so signer and verifier hash identical bytes. */
export function canonicalizeRotation(certificate: RotationCertificate): string {
  return JSON.stringify({
    nextInstanceId: certificate.nextInstanceId,
    nextPublicKey: certificate.nextPublicKey,
    previousInstanceId: certificate.previousInstanceId,
    previousPublicKey: certificate.previousPublicKey,
    timestamp: certificate.timestamp,
  });
}

export function signRotation(
  certificate: RotationCertificate,
  previousPrivateKeyPem: string,
): string {
  return sign(
    null,
    Buffer.from(canonicalizeRotation(certificate)),
    previousPrivateKeyPem,
  ).toString("base64");
}

/** Verify one certificate: both ids must be self-certifying and the signature must be the previous key's. */
export function verifyRotation(rotation: SignedRotation): boolean {
  try {
    const { certificate, signature } = rotation;
    if (!certificate || !signature) return false;
    if (
      certificate.previousInstanceId !==
      deriveInstanceId(certificate.previousPublicKey)
    ) {
      return false;
    }
    if (certificate.nextInstanceId !== deriveInstanceId(certificate.nextPublicKey)) {
      return false;
    }
    createPublicKey(certificate.previousPublicKey);
    return verify(
      null,
      Buffer.from(canonicalizeRotation(certificate)),
      certificate.previousPublicKey,
      Buffer.from(signature, "base64"),
    );
  } catch {
    return false;
  }
}

/**
 * Verify an ordered chain. When `expectedStartInstanceId` is given the chain
 * must begin at that instance; each link must connect to the next.
 */
export function verifyRotationChain(
  chain: SignedRotation[],
  expectedStartInstanceId?: string,
): boolean {
  for (const rotation of chain) {
    if (!verifyRotation(rotation)) return false;
  }
  if (chain.length === 0) return true;
  if (
    expectedStartInstanceId &&
    chain[0]!.certificate.previousInstanceId !== expectedStartInstanceId
  ) {
    return false;
  }
  for (let index = 1; index < chain.length; index += 1) {
    if (
      chain[index]!.certificate.previousInstanceId !==
      chain[index - 1]!.certificate.nextInstanceId
    ) {
      return false;
    }
  }
  return true;
}
