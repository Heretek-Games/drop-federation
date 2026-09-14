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

/** Keeps only peers heard from within the freshness window. */
export function activePeers(
  peers: PeerRecord[],
  now: number,
  staleAfterMs: number = DEFAULT_PEER_STALE_AFTER_MS,
): PeerRecord[] {
  return peers.filter((peer) => now - peer.lastSeenAt <= staleAfterMs);
}
