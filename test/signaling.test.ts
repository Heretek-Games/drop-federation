import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MAX_SIGNALING_PAYLOAD_BYTES,
  MAX_SIGNALING_QUEUE,
  enqueueMessage,
  parseSignalingMessage,
  signalingKey,
  type SignalingMessage,
} from "../src/index.js";

test("parseSignalingMessage validates kind, payload and size", () => {
  const parsed = parseSignalingMessage(
    { kind: "offer", payload: { sdp: "v=0" } },
    "inst-a",
    123,
  );
  assert.deepEqual(parsed, {
    kind: "offer",
    payload: { sdp: "v=0" },
    from: "inst-a",
    timestamp: 123,
  });

  assert.equal(parseSignalingMessage({ kind: "bogus", payload: {} }), undefined);
  assert.equal(parseSignalingMessage({ kind: "offer" }), undefined);
  assert.equal(parseSignalingMessage("nope"), undefined);
  assert.equal(
    parseSignalingMessage({
      kind: "candidate",
      payload: "x".repeat(MAX_SIGNALING_PAYLOAD_BYTES + 1),
    }),
    undefined,
  );
});

test("enqueueMessage caps the mailbox at the most recent messages", () => {
  let queue: SignalingMessage[] = [];
  for (let index = 0; index < MAX_SIGNALING_QUEUE + 5; index += 1) {
    queue = enqueueMessage(queue, {
      kind: "candidate",
      payload: index,
      timestamp: index,
    });
  }
  assert.equal(queue.length, MAX_SIGNALING_QUEUE);
  assert.equal(queue[queue.length - 1]?.payload, MAX_SIGNALING_QUEUE + 4);
});

test("signalingKey namespaces per instance", () => {
  assert.equal(signalingKey("abc"), "signaling:abc");
});
