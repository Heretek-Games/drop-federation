/**
 * Cross-instance presence tracking (#20).
 *
 * Presence is kept generic: a record carries the user, their status, the
 * instance that observed it, and the last update time. Federation peers exchange
 * these records over the `federation:presence` WebSocket channel; stale records
 * are dropped rather than trusted forever.
 */
export type PresenceStatus = "online" | "offline" | "playing";

export interface PresenceRecord {
  userId: string;
  status: PresenceStatus;
  gameId?: string;
  instanceId?: string;
  updatedAt: number;
}

export const DEFAULT_STALE_AFTER_MS = 5 * 60 * 1000;

export interface PresenceUpdate {
  userId: string;
  status: PresenceStatus;
  gameId?: string;
  instanceId?: string;
  now: number;
}

/** Folds an incoming update into the previous record, preserving the game
 *  title across heartbeats that only repeat the `playing` status. */
export function applyPresenceUpdate(
  existing: PresenceRecord | undefined,
  update: PresenceUpdate,
): PresenceRecord {
  const gameId =
    update.status === "playing"
      ? (update.gameId ?? existing?.gameId)
      : undefined;
  return {
    userId: update.userId,
    status: update.status,
    gameId,
    instanceId: update.instanceId ?? existing?.instanceId,
    updatedAt: update.now,
  };
}

/** Keeps only online/playing records seen within the freshness window. */
export function activePresence(
  records: PresenceRecord[],
  now: number,
  staleAfterMs: number = DEFAULT_STALE_AFTER_MS,
): PresenceRecord[] {
  return records.filter(
    (record) =>
      record.status !== "offline" && now - record.updatedAt <= staleAfterMs,
  );
}

/** Prefix under which remote peer heartbeats are persisted. */
export const PEER_STORAGE_PREFIX = "presence:peer:";

/** Peers are considered gone if not heard from within this window. */
export const DEFAULT_PEER_STALE_AFTER_MS = 15 * 60 * 1000;

/** Minimal persisted record of a remote instance we have seen presence from. */
export interface PeerRecord {
  instanceId: string;
  instanceUrl?: string;
  publicKey?: string;
  lastSeenAt: number;
}

export interface PeerHeartbeat {
  instanceId: string;
  instanceUrl?: string;
  publicKey?: string;
  now: number;
}

export function peerStorageKey(instanceId: string): string {
  return `${PEER_STORAGE_PREFIX}${instanceId}`;
}

/** Folds a heartbeat into the previous peer record, keeping known metadata. */
export function applyPeerHeartbeat(
  existing: PeerRecord | undefined,
  update: PeerHeartbeat,
): PeerRecord {
  return {
    instanceId: update.instanceId,
    instanceUrl: update.instanceUrl ?? existing?.instanceUrl,
    publicKey: update.publicKey ?? existing?.publicKey,
    lastSeenAt: update.now,
  };
}

/**
 * Whether a heartbeat's `publicKey` is consistent with the known peer. A
 * first-seen key is accepted (trust-on-first-use); a key that conflicts with the
 * stored one is rejected so a peer cannot silently swap its key after contact.
 */
export function isHeartbeatKeyConsistent(
  existing: PeerRecord | undefined,
  publicKey?: string,
): boolean {
  if (!existing || !publicKey || !existing.publicKey) return true;
  return existing.publicKey === publicKey;
}

/** Env flag that explicitly permits a peer to rotate its heartbeat key. */
export const ALLOW_KEY_ROTATION_ENV = "FEDERATION_ALLOW_KEY_ROTATION";

/** Whether heartbeat key rotation is explicitly permitted (default: off). */
export function allowHeartbeatKeyRotation(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return env[ALLOW_KEY_ROTATION_ENV] === "true";
}

/** Prefix under which the first-seen public key of a peer is pinned. */
export const PINNED_KEY_STORAGE_PREFIX = "federation_pinned_key:";

/** Stable storage key for an instance's pinned heartbeat public key. */
export function pinnedKeyStorageKey(instanceId: string): string {
  return `${PINNED_KEY_STORAGE_PREFIX}${instanceId}`;
}

export interface HeartbeatKeyDecision {
  accepted: boolean;
  pin?: string;
  rePinned: boolean;
}

/**
 * Compares an incoming heartbeat key with the pinned key for that instance.
 * The first key seen is pinned; a mismatch is rejected unless rotation is
 * explicitly allowed, in which case the caller re-pins the new key.
 */
export function decideHeartbeatKey(
  pinnedKey: string | null | undefined,
  incomingKey?: string,
  allowRotation: boolean = false,
): HeartbeatKeyDecision {
  if (!incomingKey) {
    return { accepted: true, pin: pinnedKey ?? undefined, rePinned: false };
  }
  if (!pinnedKey) {
    return { accepted: true, pin: incomingKey, rePinned: false };
  }
  if (pinnedKey === incomingKey) {
    return { accepted: true, pin: pinnedKey, rePinned: false };
  }
  if (allowRotation) {
    return { accepted: true, pin: incomingKey, rePinned: true };
  }
  return { accepted: false, pin: pinnedKey, rePinned: false };
}

/** Keeps only peers heard from within the freshness window. */
export function activePeers(
  peers: PeerRecord[],
  now: number,
  staleAfterMs: number = DEFAULT_PEER_STALE_AFTER_MS,
): PeerRecord[] {
  return peers.filter((peer) => now - peer.lastSeenAt <= staleAfterMs);
}
