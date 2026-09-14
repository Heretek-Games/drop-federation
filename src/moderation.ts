/**
 * Federation moderation and resource-abuse controls.
 *
 * Federation is safe-by-default: peers must be explicitly accepted, and any
 * peer can be blocked or revoked immediately. This module provides the
 * pure-data pieces (block list + sliding-window rate limiter) used by the
 * plugin routes; it deliberately has no I/O so it is easy to test.
 */

export interface BlockedPeer {
  /** Remote instance base URL (advertised for peer transport). */
  instanceUrl: string;
  /** Self-certifying remote instance id, when known. */
  instanceId?: string;
  reason?: string;
  timestamp: number;
}

export interface PeerIdentifier {
  instanceId?: string;
  instanceUrl?: string;
}

export const BLOCKED_STORAGE_KEY = "friends:blocked";

/** Per-remote-instance friend-request budget. */
export const DEFAULT_RATE_LIMIT_WINDOW_MS = 60_000;
export const DEFAULT_RATE_LIMIT_MAX = 20;

/** Find the block entry matching either the instance id or URL. */
export function isBlocked(
  blocked: BlockedPeer[],
  identifier: PeerIdentifier,
): BlockedPeer | undefined {
  return blocked.find(
    (entry) =>
      (identifier.instanceId !== undefined &&
        entry.instanceId === identifier.instanceId) ||
      (identifier.instanceUrl !== undefined &&
        entry.instanceUrl === identifier.instanceUrl),
  );
}

/** Insert or replace a block entry (keyed by instance URL, then id). */
export function addBlocked(
  blocked: BlockedPeer[],
  entry: BlockedPeer,
): BlockedPeer[] {
  const remaining = blocked.filter(
    (candidate) =>
      candidate.instanceUrl !== entry.instanceUrl &&
      !(
        entry.instanceId !== undefined &&
        candidate.instanceId === entry.instanceId
      ),
  );
  return [...remaining, entry];
}

/** Remove any block entry matching the identifier. */
export function removeBlocked(
  blocked: BlockedPeer[],
  identifier: PeerIdentifier,
): BlockedPeer[] {
  return blocked.filter(
    (entry) =>
      !(
        (identifier.instanceId !== undefined &&
          entry.instanceId === identifier.instanceId) ||
        (identifier.instanceUrl !== undefined &&
          entry.instanceUrl === identifier.instanceUrl)
      ),
  );
}

/**
 * Sliding-window rate limiter. Keeps timestamps per key and rejects once the
 * window is saturated. In-memory by design: federation resource protection is
 * per-process, matching the plugin runtime's single-process WebSocket state.
 */
export class SlidingWindowRateLimiter {
  private readonly hits = new Map<string, number[]>();

  constructor(
    private readonly windowMs: number = DEFAULT_RATE_LIMIT_WINDOW_MS,
    private readonly max: number = DEFAULT_RATE_LIMIT_MAX,
    private readonly now: () => number = Date.now,
  ) {}

  /** Record an attempt and report whether it is within budget. */
  allow(key: string): boolean {
    const now = this.now();
    const cutoff = now - this.windowMs;
    const recent = (this.hits.get(key) ?? []).filter(
      (timestamp) => timestamp > cutoff,
    );
    if (recent.length >= this.max) {
      this.hits.set(key, recent);
      return false;
    }
    recent.push(now);
    this.hits.set(key, recent);
    return true;
  }

  reset(): void {
    this.hits.clear();
  }
}
