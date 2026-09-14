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
