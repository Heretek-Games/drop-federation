import { test } from "node:test";
import assert from "node:assert/strict";
import {
  activePresence,
  applyPresenceUpdate,
  isHeartbeatKeyConsistent,
  type PresenceRecord,
} from "../src/index.js";

test("applyPresenceUpdate keeps the game title across playing heartbeats", () => {
  const existing: PresenceRecord = {
    userId: "u1",
    status: "playing",
    gameId: "game-1",
    instanceId: "inst-a",
    updatedAt: 1000,
  };

  const heartbeat = applyPresenceUpdate(existing, {
    userId: "u1",
    status: "playing",
    now: 2000,
  });
  assert.equal(heartbeat.gameId, "game-1");
  assert.equal(heartbeat.instanceId, "inst-a");
  assert.equal(heartbeat.updatedAt, 2000);

  const idle = applyPresenceUpdate(existing, {
    userId: "u1",
    status: "online",
    now: 3000,
  });
  assert.equal(idle.gameId, undefined);
});

test("activePresence drops offline and stale records", () => {
  const now = 10_000;
  const records: PresenceRecord[] = [
    { userId: "fresh", status: "online", updatedAt: now - 100 },
    { userId: "stale", status: "online", updatedAt: now - 10_000 },
    { userId: "offline", status: "offline", updatedAt: now },
  ];
  const active = activePresence(records, now, 1000);
  assert.deepEqual(
    active.map((r) => r.userId),
    ["fresh"],
  );
});

test("isHeartbeatKeyConsistent rejects key substitution after first contact", () => {
  const peer = {
    instanceId: "inst-a",
    publicKey: "key-a",
    lastSeenAt: 1000,
  };
  // First sighting or no key assertion is allowed.
  assert.equal(isHeartbeatKeyConsistent(undefined, "key-a"), true);
  assert.equal(isHeartbeatKeyConsistent(peer, undefined), true);
  // Same key is allowed; a conflicting key is rejected.
  assert.equal(isHeartbeatKeyConsistent(peer, "key-a"), true);
  assert.equal(isHeartbeatKeyConsistent(peer, "key-b"), false);
});
