import { test } from "node:test";
import assert from "node:assert/strict";
import { MockPluginContext } from "@droposs/plugin-sdk";
import FederationPlugin, {
  FRIENDS_STORAGE_KEY,
  canonicalizeFriendRequest,
  findFriendRequest,
  friendRequestId,
  generateInstanceIdentity,
  listFriendRequests,
  signFriendRequest,
  upsertFriendRequest,
  verifyFriendRequest,
  verifyFriendRequestSignature,
  type FriendRequest,
} from "../src/index.js";

function makeRequest(overrides: Partial<FriendRequest> = {}): FriendRequest {
  const now = 1000;
  return {
    id: "req-1",
    remoteInstanceUrl: "https://drop.example.com",
    remoteInstanceId: "inst-a",
    targetUser: "alice",
    timestamp: now,
    direction: "outgoing",
    status: "pending",
    signatureVerified: false,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

test("friendRequestId is deterministic and distinct per peer", () => {
  assert.equal(
    friendRequestId("https://a.example", "alice"),
    friendRequestId("https://a.example", "alice"),
  );
  assert.notEqual(
    friendRequestId("https://a.example", "alice"),
    friendRequestId("https://b.example", "alice"),
  );
  assert.notEqual(
    friendRequestId("https://a.example", "alice"),
    friendRequestId("https://a.example", "bob"),
  );
});

test("friend request signatures verify over the canonical payload", () => {
  const identity = generateInstanceIdentity();
  const payload = {
    remoteInstanceUrl: "https://drop.example.com",
    targetUser: "alice",
    remoteInstanceId: "inst-a",
    timestamp: 1000,
  };
  const signature = signFriendRequest(payload, identity.privateKey ?? "");
  assert.equal(
    verifyFriendRequestSignature(payload, signature, identity.publicKey),
    true,
  );
  assert.equal(
    verifyFriendRequestSignature(
      { ...payload, targetUser: "mallory" },
      signature,
      identity.publicKey,
    ),
    false,
  );
  assert.equal(
    verifyFriendRequestSignature(payload, "not-base64", identity.publicKey),
    false,
  );
  assert.equal(canonicalizeFriendRequest(payload).includes("alice"), true);
});

test("upsert/find/list helpers maintain the request lifecycle", () => {
  const pending = makeRequest();
  let requests = upsertFriendRequest([], pending);
  requests = upsertFriendRequest(requests, {
    ...pending,
    status: "accepted",
    updatedAt: 2000,
  });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].status, "accepted");

  assert.equal(findFriendRequest(requests, "req-1")?.id, "req-1");
  assert.equal(findFriendRequest(requests, "inst-a")?.id, "req-1");
  assert.equal(
    findFriendRequest(requests, "https://drop.example.com")?.id,
    "req-1",
  );
  assert.equal(findFriendRequest(requests, "missing"), undefined);

  requests = upsertFriendRequest(requests, makeRequest({ id: "req-2" }));
  assert.equal(listFriendRequests(requests).length, 2);
  assert.equal(listFriendRequests(requests, "pending").length, 1);
  assert.equal(listFriendRequests(requests, "accepted").length, 1);
});

test("plugin persists signed friend requests and verifies them", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
      "routes",
      "storage",
      "events",
      "network",
      "websocket",
    ]);
  await plugin.init(ctx);

  const route = ctx.routes.get("POST /friends/request");
  assert.ok(route);

  let broadcasted: any = null;
  ctx.eventListeners.set(
    "federation:friends",
    new Set([(event) => (broadcasted = event)]),
  );

  const identity = generateInstanceIdentity();
  const payload = {
    remoteInstanceUrl: "https://drop.example.com",
    targetUser: "alice",
    remoteInstanceId: identity.instanceId,
    timestamp: 1000,
  };
  const signature = signFriendRequest(payload, identity.privateKey ?? "");

  const response = (await route!.handler(
    { body: { ...payload, publicKey: identity.publicKey, signature } } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(response.success, true);
  assert.equal(response.request.status, "pending");
  assert.equal(response.request.signatureVerified, true);
  assert.equal(verifyFriendRequest(response.request), true);
  assert.equal(broadcasted.type, "request");
  assert.equal(broadcasted.requestId, response.request.id);
  assert.equal(broadcasted.status, "pending");

  const stored = await ctx.storage.get<FriendRequest[]>(FRIENDS_STORAGE_KEY);
  assert.equal(stored?.length, 1);
  assert.equal(stored?.[0].signatureVerified, true);
});

test("plugin rejects unsigned signature claims, missing URLs and tampered signatures", async () => {
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

  const missing = (await route.handler({ body: {} } as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(missing.error, "remoteInstanceUrl is required");

  const halfSigned = (await route.handler(
    {
      body: {
        remoteInstanceUrl: "https://drop.example.com",
        signature: "abc",
      },
    } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(halfSigned.error, "signature and publicKey must be provided together");

  const identity = generateInstanceIdentity();
  const signature = signFriendRequest(
    {
      remoteInstanceUrl: "https://drop.example.com",
      targetUser: "alice",
      timestamp: 1,
    },
    identity.privateKey ?? "",
  );
  const invalid = (await route.handler(
    {
      body: {
        remoteInstanceUrl: "https://drop.example.com",
        targetUser: "mallory",
        timestamp: 1,
        publicKey: identity.publicKey,
        signature,
      },
    } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(invalid.error, "invalid friend request signature");

  const stored = await ctx.storage.get<FriendRequest[]>(FRIENDS_STORAGE_KEY);
  assert.equal(stored?.length ?? 0, 0);
});

test("plugin accepts and rejects persisted friend requests", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
      "routes",
      "storage",
      "events",
      "network",
      "websocket",
    ]);
  await plugin.init(ctx);

  const requestRoute = ctx.routes.get("POST /friends/request")!;
  const acceptRoute = ctx.routes.get("POST /friends/accept")!;
  const rejectRoute = ctx.routes.get("POST /friends/reject")!;

  const created = (await requestRoute.handler(
    {
      body: {
        remoteInstanceUrl: "https://a.example",
        targetUser: "alice",
        remoteInstanceId: "inst-a",
      },
    } as any,
    { params: {}, query: {} },
  )) as any;

  const unknown = (await acceptRoute.handler(
    { body: { requestId: "nope" } } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(unknown.error, "friend request not found");

  const accepted = (await acceptRoute.handler(
    { body: { remoteInstanceId: "inst-a" } } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(accepted.success, true);
  assert.equal(accepted.request.status, "accepted");

  const doubleAccept = (await acceptRoute.handler(
    { body: { requestId: created.request.id } } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(doubleAccept.error, "friend request already accepted");

  const second = (await requestRoute.handler(
    {
      body: {
        remoteInstanceUrl: "https://b.example",
        targetUser: "bob",
        remoteInstanceId: "inst-b",
      },
    } as any,
    { params: {}, query: {} },
  )) as any;
  const rejected = (await rejectRoute.handler(
    { body: { requestId: second.request.id } } as any,
    { params: {}, query: {} },
  )) as any;
  assert.equal(rejected.success, true);
  assert.equal(rejected.request.status, "rejected");

  const listRoute = ctx.routes.get("GET /friends")!;
  const all = (await listRoute.handler({} as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(all.count, 2);

  const acceptedOnly = (await listRoute.handler({} as any, {
    params: {},
    query: { status: "accepted" },
  })) as any;
  assert.equal(acceptedOnly.count, 1);
  assert.equal(acceptedOnly.friends[0].remoteInstanceId, "inst-a");
});

test("plugin records remote presence peers and lists only fresh ones", async () => {
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
    "routes",
    "storage",
    "events",
    "websocket",
  ]);
  await plugin.init(ctx);

  const wsHandler = ctx.wsHandlers.get("federation:presence")!;
  await wsHandler(
    {
      instanceId: "peer-instance-1",
      instanceUrl: "https://peer.example",
      publicKey: "peer-pem",
    },
    { send: () => {} },
  );

  const peersRoute = ctx.routes.get("GET /peers")!;
  const result = (await peersRoute.handler({} as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(result.count, 1);
  assert.equal(result.peers[0].instanceId, "peer-instance-1");
  assert.equal(result.peers[0].instanceUrl, "https://peer.example");

  const stale = { ...result.peers[0], lastSeenAt: 0 };
  await ctx.storage.set("presence:peer:stale-instance", stale);
  const filtered = (await peersRoute.handler({} as any, {
    params: {},
    query: {},
  })) as any;
  assert.equal(filtered.count, 1);
});
