import { test } from "node:test";
import assert from "node:assert/strict";
import {
  activePresence,
  allowHeartbeatKeyRotation,
  applyPresenceUpdate,
  decideHeartbeatKey,
  isHeartbeatKeyConsistent,
  pinnedKeyStorageKey,
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

test("decideHeartbeatKey pins first use and gates key changes", () => {
  // First contact is pinned; the same key stays accepted.
  assert.deepEqual(decideHeartbeatKey(undefined, "key-a"), {
    accepted: true,
    pin: "key-a",
    rePinned: false,
  });
  assert.deepEqual(decideHeartbeatKey("key-a", "key-a"), {
    accepted: true,
    pin: "key-a",
    rePinned: false,
  });
  // A changed key is rejected unless rotation is explicitly allowed.
  assert.deepEqual(decideHeartbeatKey("key-a", "key-b"), {
    accepted: false,
    pin: "key-a",
    rePinned: false,
  });
  assert.deepEqual(decideHeartbeatKey("key-a", "key-b", true), {
    accepted: true,
    pin: "key-b",
    rePinned: true,
  });
  // Heartbeats without a key assertion keep the existing pin.
  assert.deepEqual(decideHeartbeatKey("key-a", undefined), {
    accepted: true,
    pin: "key-a",
    rePinned: false,
  });

  assert.equal(pinnedKeyStorageKey("inst-a"), "federation_pinned_key:inst-a");
  assert.equal(allowHeartbeatKeyRotation({} as NodeJS.ProcessEnv), false);
  assert.equal(
    allowHeartbeatKeyRotation({
      FEDERATION_ALLOW_KEY_ROTATION: "true",
    } as NodeJS.ProcessEnv),
    true,
  );
});
