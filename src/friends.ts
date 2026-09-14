/**
 * Persisted friend model (#3, minimal plugin-side slice).
 *
 * Friend requests move through `pending -> accepted | rejected` and live in
 * plugin storage under `friends:requests`. Requests may carry an Ed25519
 * signature over the canonical request payload; the route verifies it when a
 * `signature`/`publicKey` pair is supplied and records whether it was verified.
 *
 * The full trust handshake (challenge/response, scoped peer tokens, revocation)
 * still lives in the Drop server and is tracked in issue #3; this module only
 * persists the request lifecycle so peers survive restarts.
 */
import { createHash, createPublicKey, sign, verify } from "node:crypto";

export const FRIENDS_STORAGE_KEY = "friends:requests";

export type FriendRequestStatus = "pending" | "accepted" | "rejected";
export type FriendRequestDirection = "incoming" | "outgoing";

/** Fields covered by a friend request signature. */
export interface FriendRequestPayload {
  remoteInstanceUrl: string;
  targetUser?: string;
  remoteInstanceId?: string;
  timestamp: number;
}

export interface FriendRequest extends FriendRequestPayload {
  id: string;
  direction: FriendRequestDirection;
  status: FriendRequestStatus;
  publicKey?: string;
  signature?: string;
  signatureVerified: boolean;
  createdAt: number;
  updatedAt: number;
}

/** Deterministic identifier for a peer request. */
export function friendRequestId(
  remoteInstanceUrl: string,
  targetUser?: string,
): string {
  return createHash("sha256")
    .update(`${remoteInstanceUrl}\n${targetUser ?? ""}`)
    .digest("hex")
    .slice(0, 16);
}

/** Deterministic JSON so signer and verifier hash identical bytes. */
export function canonicalizeFriendRequest(payload: FriendRequestPayload): string {
  return JSON.stringify({
    remoteInstanceId: payload.remoteInstanceId ?? null,
    remoteInstanceUrl: payload.remoteInstanceUrl,
    targetUser: payload.targetUser ?? null,
    timestamp: payload.timestamp,
  });
}

/** Signs a friend request payload with an Ed25519 private key (PEM). */
export function signFriendRequest(
  payload: FriendRequestPayload,
  privateKeyPem: string,
): string {
  return sign(
    null,
    Buffer.from(canonicalizeFriendRequest(payload)),
    privateKeyPem,
  ).toString("base64");
}

/** Verifies a friend request signature against an Ed25519 public key (PEM). */
export function verifyFriendRequestSignature(
  payload: FriendRequestPayload,
  signatureBase64: string,
  publicKeyPem: string,
): boolean {
  try {
    if (!signatureBase64) {
      return false;
    }
    createPublicKey(publicKeyPem);
    return verify(
      null,
      Buffer.from(canonicalizeFriendRequest(payload)),
      publicKeyPem,
      Buffer.from(signatureBase64, "base64"),
    );
  } catch {
    return false;
  }
}

/** Rebuilds the signature payload from a persisted request. */
export function friendRequestPayload(
  request: FriendRequest,
): FriendRequestPayload {
  return {
    remoteInstanceUrl: request.remoteInstanceUrl,
    targetUser: request.targetUser,
    remoteInstanceId: request.remoteInstanceId,
    timestamp: request.timestamp,
  };
}

/** Re-verifies a persisted request's signature, if one was supplied. */
export function verifyFriendRequest(request: FriendRequest): boolean {
  if (!request.signature || !request.publicKey) {
    return false;
  }
  return verifyFriendRequestSignature(
    friendRequestPayload(request),
    request.signature,
    request.publicKey,
  );
}

/** Inserts or replaces a request by id, preserving insertion order. */
export function upsertFriendRequest(
  requests: FriendRequest[],
  request: FriendRequest,
): FriendRequest[] {
  const index = requests.findIndex((candidate) => candidate.id === request.id);
  if (index === -1) {
    return [...requests, request];
  }
  return requests.map((candidate, i) => (i === index ? request : candidate));
}

/** Looks a request up by id, remote instance id, or remote instance URL. */
export function findFriendRequest(
  requests: FriendRequest[],
  identifier: string,
): FriendRequest | undefined {
  return requests.find(
    (request) =>
      request.id === identifier ||
      request.remoteInstanceId === identifier ||
      request.remoteInstanceUrl === identifier,
  );
}

export function listFriendRequests(
  requests: FriendRequest[],
  status?: FriendRequestStatus,
): FriendRequest[] {
  return status
    ? requests.filter((request) => request.status === status)
    : requests;
}

/** Remove every request matching a request id, instance id, or instance URL. */
export function removeFriendRequest(
  requests: FriendRequest[],
  identifier: string,
): FriendRequest[] {
  return requests.filter(
    (request) =>
      request.id !== identifier &&
      request.remoteInstanceId !== identifier &&
      request.remoteInstanceUrl !== identifier,
  );
}
