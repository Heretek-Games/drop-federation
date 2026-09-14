import type { PluginContext, ServerPlugin } from "@droposs/plugin-sdk";
import {
  fromStoredIdentity,
  generateInstanceIdentity,
  toStoredIdentity,
  type InstanceIdentity,
  type StoredInstanceIdentity,
} from "./identity.js";
import {
  buildDescriptor,
  signDescriptor,
} from "./descriptor.js";
import {
  FRIENDS_STORAGE_KEY,
  findFriendRequest,
  friendRequestId,
  listFriendRequests,
  upsertFriendRequest,
  verifyFriendRequestSignature,
  type FriendRequest,
  type FriendRequestStatus,
} from "./friends.js";
import { KEY_PASSPHRASE_ENV, resolveKeyPassphrase } from "./keystore.js";
import {
  activePeers,
  applyPeerHeartbeat,
  applyPresenceUpdate,
  peerStorageKey,
  PEER_STORAGE_PREFIX,
  type PeerRecord,
  type PresenceRecord,
  type PresenceStatus,
} from "./presence.js";

export * from "./descriptor.js";
export * from "./friends.js";
export * from "./identity.js";
export * from "./keystore.js";
export * from "./odp.js";
export * from "./presence.js";
import {
  mergeCatalog,
  signCatalog,
  verifyCatalogSignature,
  type ODPCatalog,
} from "./odp.js";

const INSTANCE_IDENTITY_KEY = "instance_identity";
const API_VERSION = 2;

async function getRequestBody<T = any>(event: any): Promise<T> {
  if (event && event.body !== undefined) {
    return event.body;
  }
  try {
    // @ts-ignore
    const h3 = await import("h3").catch(() => null);
    if (h3?.readBody) {
      return (await h3.readBody(event)) || ({} as T);
    }
    return (event?.body || {}) as T;
  } catch {
    return (event?.body || {}) as T;
  }
}

/**
 * Loads the persisted instance identity or generates a new one. Legacy
 * plaintext keys are re-sealed in place when a passphrase is configured; when
 * none is configured the key stays plaintext and the caller gets a warning so
 * the operator is never silently exposed.
 */
async function loadOrCreateIdentity(
  ctx: PluginContext,
  passphrase?: string,
): Promise<InstanceIdentity> {
  const stored = await ctx.storage.get<StoredInstanceIdentity>(
    INSTANCE_IDENTITY_KEY,
  );

  if (!stored) {
    const identity = generateInstanceIdentity();
    await ctx.storage.set(
      INSTANCE_IDENTITY_KEY,
      toStoredIdentity(identity, passphrase),
    );
    ctx.logger.info(`Generated new instance identity: ${identity.instanceId}`);
    return identity;
  }

  const legacyPlaintext = Boolean(stored.privateKey && !stored.sealedPrivateKey);
  if (legacyPlaintext && passphrase) {
    const resealed = toStoredIdentity(
      {
        instanceId: stored.instanceId,
        publicKey: stored.publicKey,
        privateKey: stored.privateKey,
      },
      passphrase,
    );
    await ctx.storage.set(INSTANCE_IDENTITY_KEY, resealed);
    ctx.logger.info(
      "Encrypted instance private key at rest (passphrase configured).",
    );
    return fromStoredIdentity(resealed, passphrase);
  }

  if (legacyPlaintext) {
    ctx.logger.warn(
      `Instance private key is stored unencrypted. Set ${KEY_PASSPHRASE_ENV} ` +
        "to enable AES-256-GCM at-rest protection; see docs/security.md",
    );
  }

  return fromStoredIdentity(stored, passphrase);
}

export default class FederationPlugin implements ServerPlugin {
  metadata = {
    id: "drop-federation",
    name: "Friends Federation & Instance Peering",
    version: "0.1.0",
    apiVersion: API_VERSION,
    capabilities: [
      "routes" as const,
      "storage" as const,
      "events" as const,
      "network" as const,
      "websocket" as const,
    ],
  };

  async init(ctx: PluginContext): Promise<void> {
    ctx.logger.info("Initializing Friends Federation plugin...");

    const passphrase = resolveKeyPassphrase();
    const identity = await loadOrCreateIdentity(ctx, passphrase);

    // REST: signed instance descriptor
    ctx.registerRoute("GET", "/descriptor", async () => {
      const descriptor = buildDescriptor(identity, API_VERSION);
      if (!identity.privateKey) {
        ctx.logger.warn(
          "Instance private key unavailable; serving unsigned descriptor",
        );
        return descriptor;
      }
      return {
        ...descriptor,
        signature: signDescriptor(descriptor, identity.privateKey),
      };
    });

    const readFriends = async (): Promise<FriendRequest[]> =>
      (await ctx.storage.get<FriendRequest[]>(FRIENDS_STORAGE_KEY)) ?? [];
    const persistFriends = async (friends: FriendRequest[]): Promise<void> => {
      await ctx.storage.set(FRIENDS_STORAGE_KEY, friends);
    };

    // REST: Friend requests (persisted; broadcast kept for live listeners)
    ctx.registerRoute("POST", "/friends/request", async (event) => {
      const body = (await getRequestBody(event)) || ({} as any);
      const {
        remoteInstanceUrl,
        targetUser,
        remoteInstanceId,
        publicKey,
        signature,
        direction,
      } = body as {
        remoteInstanceUrl?: string;
        targetUser?: string;
        remoteInstanceId?: string;
        publicKey?: string;
        signature?: string;
        direction?: string;
      };
      if (!remoteInstanceUrl) {
        return { error: "remoteInstanceUrl is required" };
      }

      const timestamp =
        typeof (body as any).timestamp === "number"
          ? (body as any).timestamp
          : Date.now();
      let signatureVerified = false;
      if (signature || publicKey) {
        if (!signature || !publicKey) {
          return { error: "signature and publicKey must be provided together" };
        }
        const payload = {
          remoteInstanceUrl,
          targetUser,
          remoteInstanceId,
          timestamp,
        };
        if (!verifyFriendRequestSignature(payload, signature, publicKey)) {
          return { error: "invalid friend request signature" };
        }
        signatureVerified = true;
      } else {
        ctx.logger.warn(
          `Friend request for ${remoteInstanceUrl} has no signature; ` +
            "peer identity is unverified",
        );
      }

      const now = Date.now();
      const request: FriendRequest = {
        id: friendRequestId(remoteInstanceUrl, targetUser),
        remoteInstanceUrl,
        targetUser,
        remoteInstanceId,
        timestamp,
        direction: direction === "incoming" ? "incoming" : "outgoing",
        status: "pending",
        publicKey,
        signature,
        signatureVerified,
        createdAt: now,
        updatedAt: now,
      };
      await persistFriends(
        upsertFriendRequest(await readFriends(), request),
      );
      ctx.broadcast("federation:friends", {
        type: "request",
        requestId: request.id,
        remoteInstanceUrl,
        targetUser,
        status: request.status,
      });
      return { success: true, request };
    });

    const decide = (decision: Exclude<FriendRequestStatus, "pending">) =>
      async (event: any) => {
        const body = (await getRequestBody(event)) || ({} as any);
        const identifier =
          body.requestId ?? body.remoteInstanceId ?? body.remoteInstanceUrl;
        if (!identifier) {
          return {
            error: "requestId, remoteInstanceId or remoteInstanceUrl is required",
          };
        }
        const friends = await readFriends();
        const existing = findFriendRequest(friends, identifier);
        if (!existing) {
          return { error: "friend request not found" };
        }
        if (existing.status !== "pending") {
          return { error: `friend request already ${existing.status}` };
        }
        const updated: FriendRequest = {
          ...existing,
          status: decision,
          updatedAt: Date.now(),
        };
        await persistFriends(upsertFriendRequest(friends, updated));
        ctx.broadcast("federation:friends", {
          type: decision,
          request: updated,
        });
        return { success: true, request: updated };
      };

    ctx.registerRoute("POST", "/friends/accept", decide("accepted"));
    ctx.registerRoute("POST", "/friends/reject", decide("rejected"));

    // REST: list friends/requests, optionally filtered by status
    ctx.registerRoute("GET", "/friends", async (_event, routeCtx) => {
      const rawStatus = Array.isArray(routeCtx?.query?.status)
        ? routeCtx.query.status[0]
        : routeCtx?.query?.status;
      const status =
        rawStatus === "pending" ||
        rawStatus === "accepted" ||
        rawStatus === "rejected"
          ? rawStatus
          : undefined;
      const friends = listFriendRequests(await readFriends(), status);
      return { friends, count: friends.length };
    });

    // Open Depot Protocol: signed catalog syndication
    const emptyCatalog = (): ODPCatalog => ({
      instanceId: identity.instanceId,
      generatedAt: Date.now(),
      games: [],
    });

    ctx.registerRoute("GET", "/odp/catalog", async () => {
      const catalog =
        (await ctx.storage.get<ODPCatalog>("odp:catalog")) ?? emptyCatalog();
      const signature = identity.privateKey
        ? signCatalog(catalog, identity.privateKey)
        : undefined;
      return { catalog, signature };
    });

    ctx.registerRoute("POST", "/odp/subscribe", async (event) => {
      const body = await getRequestBody(event);
      const { catalog, signature, publicKey } = (body || {}) as {
        catalog?: ODPCatalog;
        signature?: string;
        publicKey?: string;
      };
      if (!catalog || !signature || !publicKey) {
        return { error: "catalog, signature and publicKey are required" };
      }
      if (!verifyCatalogSignature(catalog, signature, publicKey)) {
        return { accepted: false, error: "invalid catalog signature" };
      }

      const existing =
        (await ctx.storage.get<ODPCatalog>("odp:catalog")) ?? emptyCatalog();
      const merged: ODPCatalog = {
        instanceId: existing.instanceId,
        generatedAt: Date.now(),
        games: mergeCatalog(existing.games, catalog.games),
      };
      await ctx.storage.set("odp:catalog", merged);
      return { accepted: true, games: merged.games.length };
    });

    // WebSocket: cross-instance presence + peer heartbeats
    ctx.registerWebSocket("federation:presence", async (msg, wsCtx) => {
      const update = (msg ?? {}) as {
        userId?: string;
        status?: PresenceStatus;
        gameId?: string;
        instanceId?: string;
        instanceUrl?: string;
        publicKey?: string;
      };
      const originInstanceId = update.instanceId ?? identity.instanceId;

      if (update.userId) {
        const key = `presence:${update.userId}`;
        const existing = await ctx.storage.get<PresenceRecord>(key);
        const record = applyPresenceUpdate(existing ?? undefined, {
          userId: update.userId,
          status: update.status ?? "online",
          gameId: update.gameId,
          instanceId: originInstanceId,
          now: Date.now(),
        });
        await ctx.storage.set(key, record);
        ctx.broadcast("federation:presence:update", record);
      }

      if (update.instanceId && update.instanceId !== identity.instanceId) {
        const key = peerStorageKey(update.instanceId);
        const existingPeer = await ctx.storage.get<PeerRecord>(key);
        const peer = applyPeerHeartbeat(existingPeer ?? undefined, {
          instanceId: update.instanceId,
          instanceUrl: update.instanceUrl,
          publicKey: update.publicKey,
          now: Date.now(),
        });
        await ctx.storage.set(key, peer);
        ctx.broadcast("federation:peers:update", peer);
      }

      wsCtx.send({ event: "presence_ack", instanceId: identity.instanceId });
    });

    // REST: known (fresh) federation peers
    ctx.registerRoute("GET", "/peers", async () => {
      const keys = await ctx.storage.listKeys();
      const peers: PeerRecord[] = [];
      for (const key of keys.filter((candidate) =>
        candidate.startsWith(PEER_STORAGE_PREFIX),
      )) {
        const peer = await ctx.storage.get<PeerRecord>(key);
        if (peer) {
          peers.push(peer);
        }
      }
      const active = activePeers(peers, Date.now());
      return { peers: active, count: active.length };
    });
  }

  async teardown(): Promise<void> {
    // Teardown
  }
}
