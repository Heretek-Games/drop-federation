import { test } from "node:test";
import assert from "node:assert/strict";
import { MockPluginContext } from "@droposs/plugin-sdk";
import FederationPlugin, {
  generateInstanceIdentity,
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
  assert.equal(descriptor.descriptorVersion, 1);
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
