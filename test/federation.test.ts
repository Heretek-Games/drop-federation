import { test } from "node:test";
import assert from "node:assert/strict";
import { MockPluginContext } from "@droposs/plugin-sdk";
import FederationPlugin, {
  generateInstanceIdentity,
  signCatalog,
  verifyDescriptor,
} from "../src/index.js";

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
