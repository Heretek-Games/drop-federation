import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SlidingWindowRateLimiter,
  addBlocked,
  isBlocked,
  removeBlocked,
  type BlockedPeer,
} from "../src/index.js";

test("block list supports add, lookup by id or url, and removal", () => {
  let blocked: BlockedPeer[] = [];
  blocked = addBlocked(blocked, {
    instanceUrl: "https://a.example",
    instanceId: "aa",
    timestamp: 1,
  });

  assert.equal(isBlocked(blocked, { instanceUrl: "https://a.example" })?.instanceId, "aa");
  assert.equal(isBlocked(blocked, { instanceId: "aa" })?.instanceUrl, "https://a.example");
  assert.equal(isBlocked(blocked, { instanceId: "bb" }), undefined);

  // Re-adding by instance id replaces the existing entry.
  blocked = addBlocked(blocked, {
    instanceUrl: "https://b.example",
    instanceId: "aa",
    timestamp: 2,
  });
  assert.equal(blocked.length, 1);
  assert.equal(blocked[0].instanceUrl, "https://b.example");

  blocked = removeBlocked(blocked, { instanceId: "aa" });
  assert.equal(blocked.length, 0);
});

test("rate limiter enforces a sliding window per key", () => {
  let now = 0;
  const limiter = new SlidingWindowRateLimiter(1_000, 2, () => now);

  assert.equal(limiter.allow("a"), true);
  assert.equal(limiter.allow("a"), true);
  assert.equal(limiter.allow("a"), false);
  assert.equal(limiter.allow("b"), true, "keys are independent");

  now = 1_001;
  assert.equal(limiter.allow("a"), true, "window should have slid");
});
