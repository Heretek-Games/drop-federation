import { test } from "node:test";
import assert from "node:assert/strict";
import {
  canonicalizeCatalog,
  mergeCatalog,
  searchCatalog,
  signCatalog,
  verifyCatalogSignature,
  type ODPCatalog,
  type ODPGameEntry,
} from "../src/index.js";
import { generateInstanceIdentity } from "../src/index.js";

const catalog: ODPCatalog = {
  instanceId: "inst-1",
  generatedAt: 1000,
  games: [
    { gameId: "b", title: "B", version: "1.0", updatedAt: 1 },
    { gameId: "a", title: "A", version: "1.0", updatedAt: 2 },
  ],
};

test("canonicalizeCatalog is order independent", () => {
  const reordered: ODPCatalog = {
    ...catalog,
    games: [...catalog.games].reverse(),
  };
  assert.equal(canonicalizeCatalog(catalog), canonicalizeCatalog(reordered));
});

test("sign and verify a catalog with an instance identity", () => {
  const identity = generateInstanceIdentity();
  const signature = signCatalog(catalog, identity.privateKey ?? "");
  assert.equal(verifyCatalogSignature(catalog, signature, identity.publicKey), true);
});

test("tampered catalogs fail verification", () => {
  const identity = generateInstanceIdentity();
  const signature = signCatalog(catalog, identity.privateKey ?? "");
  const tampered: ODPCatalog = {
    ...catalog,
    games: [{ gameId: "b", title: "Hijacked", version: "9.9", updatedAt: 999 }],
  };
  assert.equal(
    verifyCatalogSignature(tampered, signature, identity.publicKey),
    false,
  );
  assert.equal(verifyCatalogSignature(catalog, "not-base64", "bad-key"), false);
});

test("mergeCatalog keeps the newest entry per game", () => {
  const local: ODPGameEntry[] = [
    { gameId: "a", title: "A old", version: "1.0", updatedAt: 1 },
  ];
  const remote: ODPGameEntry[] = [
    { gameId: "a", title: "A new", version: "2.0", updatedAt: 5 },
    { gameId: "b", title: "B", version: "1.0", updatedAt: 3 },
  ];
  const merged = mergeCatalog(local, remote);
  assert.deepEqual(
    merged.map((entry) => entry.gameId),
    ["a", "b"],
  );
  assert.equal(merged[0].title, "A new");
});

test("searchCatalog matches titles across catalogs and tags the source", () => {
  const catalogs = [
    {
      instanceId: "local",
      games: [
        { gameId: "a", title: "Hollow Knight", version: "1.0", updatedAt: 1 },
      ],
    },
    {
      instanceId: "peer-1",
      games: [
        { gameId: "b", title: "Hollow Knight: Silksong", version: "0.5", updatedAt: 10 },
        { gameId: "c", title: "Celeste", version: "1.0", updatedAt: 5 },
      ],
    },
  ];

  const results = searchCatalog(catalogs, "hollow");
  assert.equal(results.length, 2);
  assert.equal(results[0].gameId, "b");
  assert.equal(results[0].sourceInstanceId, "peer-1");
  assert.deepEqual(
    results.map((entry) => entry.sourceInstanceId),
    ["peer-1", "local"],
  );

  assert.deepEqual(searchCatalog(catalogs, "   "), []);
  assert.equal(searchCatalog(catalogs, "celeste", 0).length, 0);
});

