import { test } from "node:test";
import assert from "node:assert/strict";
import { MockPluginContext } from "@droposs/plugin-sdk";
import FederationPlugin, {
  generateInstanceIdentity,
  signCatalog,
  verifyDescriptor,
  verifyRotationChain,
} from "../src/index.js";

// Legacy tests exercise unsigned requests; the strict default is covered by a
// dedicated test that removes this opt-out.
process.env.DROP_FEDERATION_ALLOW_UNSIGNED_REQUESTS = "true";

test("generateInstanceIdentity produces distinct, unique instance IDs", () => {
  const id1 = generateInstanceIdentity();
  const id2 = generateInstanceIdentity();

  assert.ok(id1.instanceId, "id1 must have an instanceId");
  assert.ok(id2.instanceId, "id2 must have an instanceId");
  assert.equal(id1.instanceId.length, 32);
  assert.equal(id2.instanceId.length, 32);
  assert.notEqual(
    id1.instanceId,
    id2.instanceId,
    "Generated instance IDs must not collide",
  );
  assert.notEqual(
    id1.instanceId,
    "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0t",
    "Instance ID must not be the PEM header base64",
  );
});

test("FederationPlugin initializes identity and registers routes and webhooks", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "network",
    "websocket",
  ]);

  await plugin.init(ctx);

  // Stored identity check
  const storedIdentity = await ctx.storage.get<{ instanceId: string }>(
    "instance_identity",
  );
  assert.ok(storedIdentity, "Identity must be persisted in storage");
  assert.ok(storedIdentity.instanceId);

  // GET /descriptor
  const descriptorRoute = ctx.routes.get("GET /descriptor");
  assert.ok(descriptorRoute, "GET /descriptor must be registered");
  const descriptor = (await descriptorRoute.handler({} as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(descriptor.instanceId, storedIdentity.instanceId);
  assert.equal(descriptor.apiVersion, 2);
  assert.equal(descriptor.descriptorVersion, 2);
  assert.equal(typeof descriptor.signature, "string");
  assert.equal(verifyDescriptor(descriptor, descriptor.signature), true);

  const tampered = { ...descriptor, instanceId: "0".repeat(32) };
  assert.equal(verifyDescriptor(tampered, descriptor.signature), false);

  // POST /friends/request validation
  const friendRoute = ctx.routes.get("POST /friends/request");
  assert.ok(friendRoute, "POST /friends/request must be registered");

  const missingRes = (await friendRoute.handler({ body: {} } as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(missingRes.error, "remoteInstanceUrl is required");

  // POST /friends/request success
  let broadcastedPayload: any = null;
  ctx.eventListeners.set(
    "federation:friends",
    new Set([
      (ev) => {
        broadcastedPayload = ev;
      },
    ]),
  );

  const successRes = (await friendRoute.handler(
    {
      body: {
        remoteInstanceUrl: "https://drop.example.com",
        targetUser: "alice",
      },
    } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(successRes.success, true);
  assert.equal(successRes.request.status, "pending");
  assert.equal(successRes.request.signatureVerified, false);
  assert.equal(broadcastedPayload.type, "request");
  assert.equal(broadcastedPayload.remoteInstanceUrl, "https://drop.example.com");
  assert.equal(broadcastedPayload.targetUser, "alice");
  assert.equal(broadcastedPayload.requestId, successRes.request.id);
  assert.equal(broadcastedPayload.status, "pending");

  // WebSocket presence check
  const wsHandler = ctx.wsHandlers.get("federation:presence");
  assert.ok(
    wsHandler,
    "federation:presence websocket handler must be registered",
  );
  let sentMsg: any = null;
  await wsHandler(
    {},
    {
      userId: "user-1",
      send: (msg) => {
        sentMsg = msg;
      },
    },
  );
  assert.deepEqual(sentMsg, {
    event: "presence_ack",
    instanceId: storedIdentity.instanceId,
  });
});

test("federation moderation routes block, revoke and unblock peers", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "network",
    "websocket",
  ]);
  await plugin.init(ctx);

  const request = ctx.routes.get("POST /friends/request");
  assert.ok(request);
  await request.handler(
    {
      body: {
        remoteInstanceUrl: "https://peer.example",
        targetUser: "bob",
        remoteInstanceId: "peerid",
      },
    } as any,
    { params: {}, query: {} },
  );

  const remove = ctx.routes.get("POST /friends/remove");
  assert.ok(remove);
  const removed = (await remove.handler({ body: { remoteInstanceId: "peerid" } } as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(removed.success, true);
  assert.equal(removed.removed, true);

  const block = ctx.routes.get("POST /friends/block");
  assert.ok(block);
  const blocked = (await block.handler(
    {
      body: {
        remoteInstanceUrl: "https://peer.example",
        remoteInstanceId: "peerid",
        reason: "spam",
      },
    } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(blocked.success, true);
  assert.equal(blocked.blocked.instanceId, "peerid");

  const blockedList = ctx.routes.get("GET /friends/blocked");
  assert.ok(blockedList);
  const list = (await blockedList.handler({} as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(list.count, 1);

  // Requests from a blocked instance are rejected before persistence.
  const rejected = (await request.handler(
    { body: { remoteInstanceUrl: "https://peer.example", targetUser: "bob" } } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(rejected.code, "blocked");

  const unblock = ctx.routes.get("POST /friends/unblock");
  assert.ok(unblock);
  const unblocked = (await unblock.handler(
    { body: { remoteInstanceUrl: "https://peer.example" } } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(unblocked.unblocked, 1);
});

test("friend requests are rate limited per remote instance", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "network",
    "websocket",
  ]);
  await plugin.init(ctx);

  const request = ctx.routes.get("POST /friends/request");
  assert.ok(request);
  for (let i = 0; i < 20; i++) {
    const res = (await request.handler(
      {
        body: {
          remoteInstanceUrl: "https://flood.example",
          targetUser: `user-${i}`,
        },
      } as any,
      { params: {}, query: {} },
    )) as any;
    assert.equal(res.success, true, `request ${i} should succeed`);
  }

  const overflow = (await request.handler(
    { body: { remoteInstanceUrl: "https://flood.example", targetUser: "x" } } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(overflow.code, "rate_limited");
});

test("ODP search discovers subscribed remote catalogs", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "network",
    "websocket",
  ]);
  await plugin.init(ctx);

  const remote = generateInstanceIdentity();
  const catalog = {
    instanceId: remote.instanceId,
    generatedAt: 1,
    games: [
      {
        gameId: "remote-game",
        title: "Remote Game",
        version: "1.0.0",
        updatedAt: 10,
      },
    ],
  };
  const signature = signCatalog(catalog, remote.privateKey as string);

  const subscribe = ctx.routes.get("POST /odp/subscribe");
  assert.ok(subscribe);
  const accepted = (await subscribe.handler(
    {
      body: { catalog, signature, publicKey: remote.publicKey },
    } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(accepted.accepted, true);

  const search = ctx.routes.get("GET /odp/search");
  assert.ok(search);
  const found = (await search.handler({} as any, {
    params: {},
    query: { q: "remote" },
  })) as any;
  assert.equal(found.count, 1);
  assert.equal(found.results[0].sourceInstanceId, remote.instanceId);

  const discover = ctx.routes.get("GET /odp/discover");
  assert.ok(discover);
  const catalogs = (await discover.handler({} as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(catalogs.count, 1);
});

test("peers/dial validates input before dialing", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "network",
    "websocket",
  ]);
  await plugin.init(ctx);

  const dial = ctx.routes.get("POST /peers/dial");
  assert.ok(dial, "POST /peers/dial must be registered");

  const missing = (await dial.handler({ body: {} } as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(missing.error, "url is required");

  const invalid = (await dial.handler({ body: { url: "ftp://peer" } } as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(invalid.success, false);
  assert.match(invalid.error, /valid http/);
});

test("identity rotation is operator-only and publishes a verifiable chain", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "network",
    "websocket",
  ]);
  await plugin.init(ctx);

  const descriptorRoute = ctx.routes.get("GET /descriptor");
  assert.ok(descriptorRoute);
  const before = (await descriptorRoute.handler({} as any, {
    params: {},
    query: {},
  })) as any;

  const rotate = ctx.routes.get("POST /identity/rotate");
  assert.ok(rotate, "POST /identity/rotate must be registered");

  // Disabled unless the operator configures an admin token.
  const disabled = (await rotate.handler({} as any, {
    params: {},
    query: {},
  })) as any;
  assert.match(disabled.error, /disabled/);

  const previousToken = process.env.DROP_FEDERATION_ADMIN_TOKEN;
  process.env.DROP_FEDERATION_ADMIN_TOKEN = "s3cret";
  try {
    const unauth = (await rotate.handler({ headers: new Headers() } as any, {
      params: {},
      query: {},
    })) as any;
    assert.equal(unauth.error, "Unauthorized");

    const rotated = (await rotate.handler(
      { headers: new Headers({ authorization: "Bearer s3cret" }) } as any,
      { params: {}, query: {} },
    )) as any;
    assert.equal(rotated.success, true);
    assert.notEqual(rotated.instanceId, before.instanceId);

    const after = (await descriptorRoute.handler({} as any, {
      params: {},
      query: {},
    })) as any;
    assert.equal(after.instanceId, rotated.instanceId);
    assert.equal(verifyDescriptor(after, after.signature), true);

    const chainRoute = ctx.routes.get("GET /identity/rotations");
    assert.ok(chainRoute);
    const chain = (await chainRoute.handler({} as any, {
      params: {},
      query: {},
    })) as any;
    assert.equal(chain.count, 1);
    assert.equal(
      verifyRotationChain(chain.rotations, before.instanceId),
      true,
    );
  } finally {
    if (previousToken === undefined) {
      delete process.env.DROP_FEDERATION_ADMIN_TOKEN;
    } else {
      process.env.DROP_FEDERATION_ADMIN_TOKEN = previousToken;
    }
  }
});

test("opt-in sharing scopes gate the shared library and revoke immediately", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "network",
    "websocket",
  ]);
  await plugin.init(ctx);

  await ctx.storage.set("odp:catalog", {
    instanceId: "self",
    generatedAt: 1,
    games: [
      { gameId: "g1", title: "One", version: "1.0.0", updatedAt: 1 },
      { gameId: "g2", title: "Two", version: "1.0.0", updatedAt: 2 },
    ],
  });

  const shared = ctx.routes.get("GET /shared/library");
  const setSharing = ctx.routes.get("POST /sharing");
  const getSharing = ctx.routes.get("GET /sharing");
  assert.ok(shared && setSharing && getSharing);

  const before = (await shared.handler({} as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(before.count, 0, "nothing is shared by default");

  const previousToken = process.env.DROP_FEDERATION_ADMIN_TOKEN;
  process.env.DROP_FEDERATION_ADMIN_TOKEN = "s3cret";
  try {
    const unauth = (await setSharing.handler(
      { body: { scope: "library" }, headers: new Headers() } as any,
      { params: {}, query: {} },
    )) as any;
    assert.equal(unauth.error, "Unauthorized");

    const authHeaders = {
      headers: new Headers({ authorization: "Bearer s3cret" }),
    };

    const set = (await setSharing.handler(
      { ...authHeaders, body: { scope: "library" } } as any,
      { params: {}, query: {} },
    )) as any;
    assert.equal(set.success, true);

    const listed = (await shared.handler({} as any, {
      params: {},
      query: {},
    })) as any;
    assert.equal(listed.count, 2);

    await setSharing.handler(
      { ...authHeaders, body: { scope: "games", games: ["g2"] } } as any,
      { params: {}, query: {} },
    );
    const onlyTwo = (await shared.handler({} as any, {
      params: {},
      query: {},
    })) as any;
    assert.deepEqual(
      onlyTwo.games.map((game: { gameId: string }) => game.gameId),
      ["g2"],
    );

    const revoked = (await setSharing.handler(
      { ...authHeaders, body: { scope: "none" } } as any,
      { params: {}, query: {} },
    )) as any;
    assert.equal(revoked.settings.scope, "none");
    const afterRevoke = (await shared.handler({} as any, {
      params: {},
      query: {},
    })) as any;
    assert.equal(afterRevoke.count, 0);

    const settings = (await getSharing.handler(authHeaders as any, {
      params: {},
      query: {},
    })) as any;
    assert.equal(settings.settings.scope, "none");
  } finally {
    if (previousToken === undefined) {
      delete process.env.DROP_FEDERATION_ADMIN_TOKEN;
    } else {
      process.env.DROP_FEDERATION_ADMIN_TOKEN = previousToken;
    }
  }
});

test("catalog subscriptions can be listed and revoked", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "network",
    "websocket",
  ]);
  await plugin.init(ctx);

  const remote = generateInstanceIdentity();
  const catalog = {
    instanceId: remote.instanceId,
    generatedAt: 1,
    games: [
      { gameId: "sub-game", title: "Subscribed", version: "1.0.0", updatedAt: 1 },
    ],
  };
  const signature = signCatalog(catalog, remote.privateKey as string);

  const subscribe = ctx.routes.get("POST /odp/subscribe");
  assert.ok(subscribe);
  await subscribe.handler(
    { body: { catalog, signature, publicKey: remote.publicKey } } as any,
    { params: {}, query: {} },
  );

  const list = ctx.routes.get("GET /odp/subscriptions");
  assert.ok(list);
  const listed = (await list.handler({} as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(listed.count, 1);
  assert.equal(listed.subscriptions[0].instanceId, remote.instanceId);
  assert.equal(listed.subscriptions[0].games, 1);
  assert.equal(typeof listed.subscriptions[0].subscribedAt, "number");

  const remove = ctx.routes.get("DELETE /odp/subscriptions/:instanceId");
  assert.ok(remove);
  const removed = (await remove.handler({} as any, {
    params: { instanceId: remote.instanceId },
    query: {},
  })) as any;
  assert.equal(removed.removed, true);

  const after = (await list.handler({} as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(after.count, 0);

  // Revocation removes it from discovery search too.
  const search = ctx.routes.get("GET /odp/search");
  assert.ok(search);
  const found = (await search.handler({} as any, {
    params: {},
    query: { q: "Subscribed" },
  })) as any;
  assert.equal(found.count, 0);
});

test("signaling mailbox delivers and drains per target", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "network",
    "websocket",
  ]);
  await plugin.init(ctx);

  const post = ctx.routes.get("POST /signaling/:instanceId");
  const get = ctx.routes.get("GET /signaling/:instanceId");
  const del = ctx.routes.get("DELETE /signaling/:instanceId");
  assert.ok(post && get && del);

  const unauth = (await post.handler(
    { body: { kind: "offer", payload: {} } } as any,
    { params: { instanceId: "peer-1" }, query: {}, userId: undefined },
  )) as any;
  assert.equal(unauth.error, "Authentication required to signal");

  const invalid = (await post.handler(
    { body: { kind: "bogus", payload: {} } } as any,
    { params: { instanceId: "peer-1" }, query: {}, userId: "u1" },
  )) as any;
  assert.equal(invalid.error, "invalid signaling message");

  const posted = (await post.handler(
    { body: { kind: "offer", payload: { sdp: "v=0" } } } as any,
    { params: { instanceId: "peer-1" }, query: {}, userId: "u1" },
  )) as any;
  assert.equal(posted.success, true);

  const drained = (await get.handler({} as any, {
    params: { instanceId: "peer-1" },
    query: {},
    userId: "u1",
  })) as any;
  assert.equal(drained.count, 1);
  assert.equal(drained.messages[0].kind, "offer");

  // Draining consumes the mailbox.
  const empty = (await get.handler({} as any, {
    params: { instanceId: "peer-1" },
    query: {},
    userId: "u1",
  })) as any;
  assert.equal(empty.count, 0);

  await post.handler(
    { body: { kind: "bye", payload: {} } } as any,
    { params: { instanceId: "peer-1" }, query: {}, userId: "u1" },
  );
  await del.handler({} as any, {
    params: { instanceId: "peer-1" },
    query: {},
    userId: "u1",
  });
  const after = (await get.handler({} as any, {
    params: { instanceId: "peer-1" },
    query: {},
    userId: "u1",
  })) as any;
  assert.equal(after.count, 0);
});

test("signaling mailboxes are isolated per user", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "network",
    "websocket",
  ]);
  await plugin.init(ctx);

  const post = ctx.routes.get("POST /signaling/:instanceId")!;
  const get = ctx.routes.get("GET /signaling/:instanceId")!;

  await post.handler(
    { body: { kind: "offer", payload: { sdp: "alice" } } } as any,
    { params: { instanceId: "peer-1" }, query: {}, userId: "alice" },
  );

  // Another user must not see or drain alice's mailbox.
  const bob = (await get.handler({} as any, {
    params: { instanceId: "peer-1" },
    query: {},
    userId: "bob",
  })) as any;
  assert.equal(bob.count, 0);

  const alice = (await get.handler({} as any, {
    params: { instanceId: "peer-1" },
    query: {},
    userId: "alice",
  })) as any;
  assert.equal(alice.count, 1);
});

test("unsigned friend requests are rejected unless explicitly allowed", async () => {
  const saved = process.env.DROP_FEDERATION_ALLOW_UNSIGNED_REQUESTS;
  delete process.env.DROP_FEDERATION_ALLOW_UNSIGNED_REQUESTS;
  try {
    const plugin = new FederationPlugin();
    const ctx = new MockPluginContext("drop-federation", [
      "routes",
      "storage",
      "events",
      "network",
      "websocket",
    ]);
    await plugin.init(ctx);
    const route = ctx.routes.get("POST /friends/request")!;
    const res = (await route.handler(
      {
        body: {
          remoteInstanceUrl: "https://unsigned.example",
          targetUser: "alice",
        },
      } as any,
      { params: {}, query: {} },
    )) as any;
    assert.equal(res.code, "signature_required");
  } finally {
    process.env.DROP_FEDERATION_ALLOW_UNSIGNED_REQUESTS = saved;
  }
});

test("heartbeat keys are pinned and key rotation is gated by env", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "network",
    "websocket",
  ]);
  await plugin.init(ctx);

  const wsHandler = ctx.wsHandlers.get("federation:presence");
  assert.ok(wsHandler, "federation:presence websocket handler must be registered");

  const warnings: string[] = [];
  ctx.logger.warn = (message: string) => {
    warnings.push(message);
  };

  await wsHandler(
    {
      instanceId: "pinned-peer",
      instanceUrl: "https://pinned.example",
      publicKey: "key-a",
    },
    { send: () => {} },
  );
  assert.equal(
    await ctx.storage.get<string>("federation_pinned_key:pinned-peer"),
    "key-a",
  );

  // A swapped key is rejected and the stored peer keeps the pinned key.
  await wsHandler(
    {
      instanceId: "pinned-peer",
      instanceUrl: "https://pinned.example",
      publicKey: "key-b",
    },
    { send: () => {} },
  );
  const rejected = await ctx.storage.get<{ publicKey?: string }>(
    "presence:peer:pinned-peer",
  );
  assert.equal(rejected?.publicKey, "key-a");
  assert.ok(
    warnings.some((message) =>
      message.includes("does not match the pinned key"),
    ),
  );

  const previous = process.env.FEDERATION_ALLOW_KEY_ROTATION;
  process.env.FEDERATION_ALLOW_KEY_ROTATION = "true";
  try {
    await wsHandler(
      {
        instanceId: "pinned-peer",
        instanceUrl: "https://pinned.example",
        publicKey: "key-b",
      },
      { send: () => {} },
    );
  } finally {
    if (previous === undefined) {
      delete process.env.FEDERATION_ALLOW_KEY_ROTATION;
    } else {
      process.env.FEDERATION_ALLOW_KEY_ROTATION = previous;
    }
  }

  assert.equal(
    await ctx.storage.get<string>("federation_pinned_key:pinned-peer"),
    "key-b",
  );
  const rotated = await ctx.storage.get<{ publicKey?: string }>(
    "presence:peer:pinned-peer",
  );
  assert.equal(rotated?.publicKey, "key-b");
  assert.ok(
    warnings.some((message) => message.includes("Re-pinning public key")),
  );
});
