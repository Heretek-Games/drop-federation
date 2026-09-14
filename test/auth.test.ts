import { test } from "node:test";
import assert from "node:assert/strict";
import { matchesBearerToken, safeEqual } from "../src/index.js";

test("safeEqual compares equal and unequal strings", () => {
  assert.equal(safeEqual("secret-token", "secret-token"), true);
  assert.equal(safeEqual("secret-token", "secret-tokeN"), false);
  assert.equal(safeEqual("short", "longer-value"), false);
  assert.equal(safeEqual("", ""), true);
});

test("matchesBearerToken accepts only the exact bearer token", () => {
  assert.equal(matchesBearerToken("Bearer abc123", "abc123"), true);
  assert.equal(matchesBearerToken("bearer abc123", "abc123"), false);
  assert.equal(matchesBearerToken("Bearer abc124", "abc123"), false);
  assert.equal(matchesBearerToken("Basic abc123", "abc123"), false);
  assert.equal(matchesBearerToken(undefined, "abc123"), false);
  assert.equal(matchesBearerToken("Bearer abc123", ""), false);
});
