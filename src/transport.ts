/**
 * Peer transport helpers (#4).
 *
 * Federation peers exchange a self-certifying instance ID plus candidate
 * addresses. A peer is dialed by fetching its signed descriptor over HTTP and
 * verifying it offline; the descriptor is the trust anchor, not the transport.
 * Relays only ever retransmit already-encrypted peer traffic, so this direct
 * path is preferred and a relay fallback is opt-in.
 */
import {
  verifyDescriptor,
  type SignedDescriptor,
} from "./descriptor.js";

/** Minimal fetch surface so dialing is unit-testable. */
export type FetchLike = (
  input: string,
  init?: { signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export const DEFAULT_DIAL_TIMEOUT_MS = 5_000;

/**
 * Validate and normalize a peer base URL. Only `http`/`https` are accepted and
 * trailing slashes are stripped so `/descriptor` joins predictably.
 */
export function normalizePeerUrl(raw: string): string | undefined {
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
    return trimmed.replace(/\/+$/, "");
  } catch {
    return undefined;
  }
}

export interface PeerDialResult {
  url: string;
  descriptor: SignedDescriptor;
}

export interface RelayDialResult extends PeerDialResult {
  viaRelay: boolean;
}

/** Path a relay exposes to retransmit one peer document. */
export const RELAY_PATH = "/relay/descriptor";

/**
 * Fetch and verify a peer's descriptor.
 *
 * Throws on an invalid URL, a non-OK response, a missing signature, or a failed
 * signature/instance-id check — a peer is only trusted after verification.
 */
export async function dialPeer(
  rawUrl: string,
  fetchImpl: FetchLike,
  timeoutMs: number = DEFAULT_DIAL_TIMEOUT_MS,
): Promise<PeerDialResult> {
  const url = normalizePeerUrl(rawUrl);
  if (!url) {
    throw new Error("Peer URL must be a valid http(s) URL");
  }

  const response = await fetchImpl(`${url}/descriptor`, {
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) {
    throw new Error(`Peer descriptor request failed with HTTP ${response.status}`);
  }

  const payload = (await response.json()) as Partial<SignedDescriptor>;
  if (
    !payload ||
    typeof payload.instanceId !== "string" ||
    typeof payload.publicKey !== "string" ||
    typeof payload.signature !== "string"
  ) {
    throw new Error("Peer descriptor is missing required fields");
  }

  const descriptor = payload as SignedDescriptor;
  if (!verifyDescriptor(descriptor, descriptor.signature)) {
    throw new Error("Peer descriptor signature is invalid");
  }

  return { url, descriptor };
}

/**
 * Fetch a peer's descriptor through a relay that only retransmits it. The
 * descriptor is still verified end to end, so a malicious relay can censor but
 * not forge a peer. `target` is the peer's base URL (direct-dial address).
 */
export async function dialPeerViaRelay(
  relayUrl: string,
  targetUrl: string,
  fetchImpl: FetchLike,
  timeoutMs: number = DEFAULT_DIAL_TIMEOUT_MS,
): Promise<PeerDialResult> {
  const relay = normalizePeerUrl(relayUrl);
  if (!relay) {
    throw new Error("Relay URL must be a valid http(s) URL");
  }
  const target = normalizePeerUrl(targetUrl);
  if (!target) {
    throw new Error("Peer URL must be a valid http(s) URL");
  }

  const url = `${relay}${RELAY_PATH}?target=${encodeURIComponent(target)}`;
  const response = await fetchImpl(url, {
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) {
    throw new Error(`Relay descriptor request failed with HTTP ${response.status}`);
  }

  const payload = (await response.json()) as Partial<SignedDescriptor>;
  if (
    !payload ||
    typeof payload.instanceId !== "string" ||
    typeof payload.publicKey !== "string" ||
    typeof payload.signature !== "string"
  ) {
    throw new Error("Relayed descriptor is missing required fields");
  }

  const descriptor = payload as SignedDescriptor;
  if (!verifyDescriptor(descriptor, descriptor.signature)) {
    throw new Error("Relayed descriptor signature is invalid");
  }

  return { url: target, descriptor };
}

/**
 * Try a direct dial first; when it fails and a relay is configured, fall back
 * to the relay. Returns whether the relay was used.
 */
export async function dialPeerWithRelay(
  targetUrl: string,
  options: {
    relayUrl?: string;
    fetchImpl: FetchLike;
    timeoutMs?: number;
  },
): Promise<RelayDialResult> {
  try {
    const direct = await dialPeer(
      targetUrl,
      options.fetchImpl,
      options.timeoutMs,
    );
    return { ...direct, viaRelay: false };
  } catch (directError) {
    if (!options.relayUrl) {
      throw directError;
    }
    const relayed = await dialPeerViaRelay(
      options.relayUrl,
      targetUrl,
      options.fetchImpl,
      options.timeoutMs,
    );
    return { ...relayed, viaRelay: true };
  }
}
