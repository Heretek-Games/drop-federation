import { test } from "node:test";
import assert from "node:assert/strict";
import {
  normalizeSharingSettings,
  visibleGames,
  type ODPGameEntry,
} from "../src/index.js";

const catalog: ODPGameEntry[] = [
  { gameId: "a", title: "A", version: "1.0.0", updatedAt: 1 },
  { gameId: "b", title: "B", version: "1.0.0", updatedAt: 2 },
];

test("normalizeSharingSettings defaults to none and validates input", () => {
  assert.deepEqual(normalizeSharingSettings(undefined), {
    scope: "none",
    games: [],
  });
  // `library` scope does not carry a game list.
  assert.deepEqual(normalizeSharingSettings({ scope: "library", games: ["a"] }), {
    scope: "library",
    games: [],
  });
  assert.deepEqual(
    normalizeSharingSettings({ scope: "games", games: ["a", "", 5] }),
    { scope: "games", games: ["a"] },
  );
  assert.deepEqual(normalizeSharingSettings({ scope: "bogus" }), {
    scope: "none",
    games: [],
  });
});

test("visibleGames respects scope and revocation", () => {
  assert.deepEqual(visibleGames(catalog, { scope: "none", games: [] }), []);
  assert.deepEqual(
    visibleGames(catalog, { scope: "library", games: [] }).map((g) => g.gameId),
    ["a", "b"],
  );
  assert.deepEqual(
    visibleGames(catalog, { scope: "games", games: ["b"] }).map((g) => g.gameId),
    ["b"],
  );
});
