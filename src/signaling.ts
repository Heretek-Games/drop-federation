/**
 * WebRTC signaling relay (#4/#19).
 *
 * Peers on different instances need to exchange SDP offers/answers and ICE
 * candidates. This module defines the message contract and a bounded,
 * per-target mailbox; the plugin routes expose it so a client can hand a
 * signaling message to a peer and drain its own queue. Actual peer connections
 * are established by a WebRTC stack on the client; the relay never inspects or
 * trusts the payload.
 */

export const SIGNALING_KINDS = ["offer", "answer", "candidate", "bye"] as const;
export type SignalingKind = (typeof SIGNALING_KINDS)[number];

export interface SignalingMessage {
  kind: SignalingKind;
  payload: unknown;
  /** Originating instance id, when known. */
  from?: string;
  timestamp: number;
}

export const MAX_SIGNALING_PAYLOAD_BYTES = 64 * 1024;
export const MAX_SIGNALING_QUEUE = 64;

/** Storage key for a target instance's mailbox. */
export function signalingKey(instanceId: string): string {
  return `signaling:${instanceId}`;
}

function isKind(value: unknown): value is SignalingKind {
  return (
    typeof value === "string" &&
    (SIGNALING_KINDS as readonly string[]).includes(value)
  );
}

/**
 * Validate and normalize an inbound signaling message. Returns `undefined` for
 * an unknown kind, a missing payload, or an oversized payload.
 */
export function parseSignalingMessage(
  input: unknown,
  from?: string,
  now: number = Date.now(),
): SignalingMessage | undefined {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return undefined;
  }
  const record = input as { kind?: unknown; payload?: unknown };
  if (!isKind(record.kind)) return undefined;
  if (record.payload === undefined || record.payload === null) return undefined;

  let serialized: string;
  try {
    serialized = JSON.stringify(record.payload);
  } catch {
    return undefined;
  }
  if (serialized.length > MAX_SIGNALING_PAYLOAD_BYTES) return undefined;

  return {
    kind: record.kind,
    payload: record.payload,
    ...(from ? { from } : {}),
    timestamp: now,
  };
}

/** Append a message, keeping only the most recent `MAX_SIGNALING_QUEUE`. */
export function enqueueMessage(
  queue: SignalingMessage[],
  message: SignalingMessage,
): SignalingMessage[] {
  const next = [...queue, message];
  return next.length > MAX_SIGNALING_QUEUE
    ? next.slice(next.length - MAX_SIGNALING_QUEUE)
    : next;
}
