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
  removeFriendRequest,
  upsertFriendRequest,
  verifyFriendRequestSignature,
  type FriendRequest,
  type FriendRequestStatus,
} from "./friends.js";
import {
  BLOCKED_STORAGE_KEY,
  SlidingWindowRateLimiter,
  addBlocked,
  isBlocked,
  removeBlocked,
  type BlockedPeer,
} from "./moderation.js";
import { KEY_PASSPHRASE_ENV, resolveKeyPassphrase } from "./keystore.js";
import {
  dialPeerWithRelay,
  normalizePeerUrl,
  type FetchLike,
} from "./transport.js";
import {
  buildRotation,
  signRotation,
  type SignedRotation,
} from "./rotation.js";
import {
  DEFAULT_SHARING_SETTINGS,
  SHARING_STORAGE_KEY,
  normalizeSharingSettings,
  visibleGames,
  type SharingSettings,
} from "./sharing.js";
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
export * from "./moderation.js";
export * from "./odp.js";
export * from "./presence.js";
export * from "./rotation.js";
export * from "./sharing.js";
export * from "./transport.js";
import {
  searchCatalog,
  signCatalog,
  verifyCatalogSignature,
  type ODPCatalog,
} from "./odp.js";

const INSTANCE_IDENTITY_KEY = "instance_identity";
const ROTATIONS_STORAGE_KEY = "instance_rotations";
const ADMIN_TOKEN_ENV = "DROP_FEDERATION_ADMIN_TOKEN";
const API_VERSION = 2;

/** Read the `Authorization` header from a plugin route event. */
async function readAuthHeader(event: unknown): Promise<string | undefined> {
  const headers = (event as { headers?: unknown } | null)?.headers;
  if (headers && typeof (headers as Headers).get === "function") {
    return (headers as Headers).get("authorization") ?? undefined;
  }
  if (headers && typeof headers === "object") {
    const record = headers as Record<string, unknown>;
    const value = record["authorization"] ?? record["Authorization"];
    if (typeof value === "string") return value;
  }
  try {
    // @ts-ignore optional h3 host binding
    const h3 = await import("h3").catch(() => null);
    if (h3?.getHeader && event) {
      return (h3.getHeader(event, "authorization") as string | undefined) ?? undefined;
    }
  } catch {
    // Ignore: treated as unauthenticated.
  }
  return undefined;
}

/** Whether the request carries the configured operator (admin) token. */
async function authorizedOperator(event: unknown): Promise<boolean> {
  const expected = process.env[ADMIN_TOKEN_ENV]?.trim();
  if (!expected) return false;
  const header = await readAuthHeader(event);
  const [scheme, token] = (header ?? "").split(" ");
  return scheme === "Bearer" && token === expected;
}

/** Peer-transport addresses advertised in the descriptor. */
function advertisedEndpoints(): string[] {
  const raw = process.env.DROP_FEDERATION_ENDPOINTS;
  if (!raw) return [];
  return raw
    .split(/[,\s]+/)
    .map((value) => normalizePeerUrl(value))
    .filter((value): value is string => Boolean(value));
}

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
    let identity = await loadOrCreateIdentity(ctx, passphrase);

    // REST: signed instance descriptor
    ctx.registerRoute("GET", "/descriptor", async () => {
      const descriptor = buildDescriptor(
        identity,
        API_VERSION,
        advertisedEndpoints(),
      );
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

    // REST: published key-rotation chain (peers verify it offline)
    ctx.registerRoute("GET", "/identity/rotations", async () => {
      const rotations =
        (await ctx.storage.get<SignedRotation[]>(ROTATIONS_STORAGE_KEY)) ?? [];
      return { rotations, count: rotations.length };
    });

    // REST: rotate the instance key (operator-only; disabled without a token)
    ctx.registerRoute("POST", "/identity/rotate", async (event) => {
      const expected = process.env[ADMIN_TOKEN_ENV]?.trim();
      if (!expected) {
        return {
          error:
            "Key rotation is disabled (DROP_FEDERATION_ADMIN_TOKEN is not set)",
        };
      }
      const header = await readAuthHeader(event);
      const [scheme, token] = (header ?? "").split(" ");
      if (scheme !== "Bearer" || token !== expected) {
        return { error: "Unauthorized" };
      }
      if (!identity.privateKey) {
        return { error: "Instance private key is unavailable" };
      }

      const next = generateInstanceIdentity();
      const certificate = buildRotation(identity, next);
      const signature = signRotation(certificate, identity.privateKey);
      const rotations =
        (await ctx.storage.get<SignedRotation[]>(ROTATIONS_STORAGE_KEY)) ?? [];
      rotations.push({ certificate, signature });
      await ctx.storage.set(ROTATIONS_STORAGE_KEY, rotations);
      await ctx.storage.set(
        INSTANCE_IDENTITY_KEY,
        toStoredIdentity(next, passphrase),
      );
      identity = next;
      ctx.logger.info(`Rotated instance identity to ${next.instanceId}`);

      return {
        success: true,
        instanceId: next.instanceId,
        rotation: { certificate, signature },
      };
    });

    const readFriends = async (): Promise<FriendRequest[]> =>
      (await ctx.storage.get<FriendRequest[]>(FRIENDS_STORAGE_KEY)) ?? [];
    const persistFriends = async (friends: FriendRequest[]): Promise<void> => {
      await ctx.storage.set(FRIENDS_STORAGE_KEY, friends);
    };
    const readBlocked = async (): Promise<BlockedPeer[]> =>
      (await ctx.storage.get<BlockedPeer[]>(BLOCKED_STORAGE_KEY)) ?? [];
    const requestLimiter = new SlidingWindowRateLimiter();

    // Drop any cached presence/peer record for a revoked instance.
    const forgetPeer = async (instanceId?: string): Promise<void> => {
      if (instanceId) {
        await ctx.storage.delete(peerStorageKey(instanceId));
      }
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
      if (!requestLimiter.allow(remoteInstanceUrl)) {
        ctx.logger.warn(
          `Friend request rate limit exceeded for ${remoteInstanceUrl}`,
        );
        return { error: "Rate limit exceeded", code: "rate_limited" };
      }
      const blocked = isBlocked(await readBlocked(), {
        instanceId: remoteInstanceId,
        instanceUrl: remoteInstanceUrl,
      });
      if (blocked) {
        return { error: "Instance is blocked", code: "blocked" };
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

    // REST: revoke an accepted friend or pending request immediately
    ctx.registerRoute("POST", "/friends/remove", async (event) => {
      const body = (await getRequestBody(event)) || ({} as any);
      const identifier =
        body.requestId ?? body.remoteInstanceId ?? body.remoteInstanceUrl;
      if (!identifier) {
        return {
          error: "requestId, remoteInstanceId or remoteInstanceUrl is required",
        };
      }
      const existing = findFriendRequest(await readFriends(), identifier);
      await persistFriends(
        removeFriendRequest(await readFriends(), identifier),
      );
      await forgetPeer(existing?.remoteInstanceId);
      ctx.broadcast("federation:friends", {
        type: "removed",
        identifier,
      });
      return { success: true, removed: Boolean(existing) };
    });

    // REST: block an instance (drops any peer state and rejects future requests)
    ctx.registerRoute("POST", "/friends/block", async (event) => {
      const body = (await getRequestBody(event)) || ({} as any);
      const instanceUrl: string | undefined =
        body.remoteInstanceUrl ?? body.instanceUrl;
      if (!instanceUrl) {
        return { error: "remoteInstanceUrl is required" };
      }
      const existing = findFriendRequest(await readFriends(), instanceUrl);
      const entry: BlockedPeer = {
        instanceUrl,
        instanceId: body.remoteInstanceId ?? existing?.remoteInstanceId,
        reason: typeof body.reason === "string" ? body.reason : undefined,
        timestamp: Date.now(),
      };
      await ctx.storage.set(
        BLOCKED_STORAGE_KEY,
        addBlocked(await readBlocked(), entry),
      );
      await persistFriends(removeFriendRequest(await readFriends(), instanceUrl));
      await forgetPeer(entry.instanceId);
      ctx.broadcast("federation:friends", { type: "blocked", entry });
      return { success: true, blocked: entry };
    });

    // REST: lift a block
    ctx.registerRoute("POST", "/friends/unblock", async (event) => {
      const body = (await getRequestBody(event)) || ({} as any);
      const instanceUrl: string | undefined =
        body.remoteInstanceUrl ?? body.instanceUrl;
      const instanceId: string | undefined = body.remoteInstanceId;
      if (!instanceUrl && !instanceId) {
        return { error: "remoteInstanceUrl or remoteInstanceId is required" };
      }
      const blocked = await readBlocked();
      const next = removeBlocked(blocked, { instanceId, instanceUrl });
      await ctx.storage.set(BLOCKED_STORAGE_KEY, next);
      return { success: true, unblocked: blocked.length - next.length };
    });

    // REST: list blocked instances
    ctx.registerRoute("GET", "/friends/blocked", async () => {
      const blocked = await readBlocked();
      return { blocked, count: blocked.length };
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

      // Our published catalog stays our own; the verified remote catalog is
      // stored separately so discovery search can attribute each result.
      await ctx.storage.set(`odp:remote:${catalog.instanceId}`, catalog);
      return { accepted: true, games: catalog.games.length };
    });

    // REST: cross-instance discovery search across local + subscribed catalogs
    ctx.registerRoute("GET", "/odp/search", async (_event, routeCtx) => {
      const rawQuery = routeCtx?.query?.q;
      const query = Array.isArray(rawQuery) ? rawQuery[0] : (rawQuery ?? "");
      const rawLimit = routeCtx?.query?.limit;
      const parsedLimit = Number(Array.isArray(rawLimit) ? rawLimit[0] : rawLimit);
      const limit =
        Number.isFinite(parsedLimit) && parsedLimit > 0
          ? Math.min(Math.floor(parsedLimit), 100)
          : 25;

      const local =
        (await ctx.storage.get<ODPCatalog>("odp:catalog")) ?? emptyCatalog();
      const catalogs = [
        { instanceId: identity.instanceId, games: local.games },
      ];
      const keys = await ctx.storage.listKeys();
      for (const key of keys.filter((candidate) =>
        candidate.startsWith("odp:remote:"),
      )) {
        const remote = await ctx.storage.get<ODPCatalog>(key);
        if (remote) {
          catalogs.push({ instanceId: remote.instanceId, games: remote.games });
        }
      }

      const results = searchCatalog(catalogs, query, limit);
      return { query, results, count: results.length };
    });

    // REST: subscribed remote catalogs
    ctx.registerRoute("GET", "/odp/discover", async () => {
      const keys = await ctx.storage.listKeys();
      const catalogs: ODPCatalog[] = [];
      for (const key of keys.filter((candidate) =>
        candidate.startsWith("odp:remote:"),
      )) {
        const remote = await ctx.storage.get<ODPCatalog>(key);
        if (remote) catalogs.push(remote);
      }
      return { catalogs, count: catalogs.length };
    });

    // REST: opt-in library sharing settings (operator only)
    ctx.registerRoute("GET", "/sharing", async (event) => {
      if (!(await authorizedOperator(event))) {
        return { error: "Unauthorized" };
      }
      const settings =
        (await ctx.storage.get<SharingSettings>(SHARING_STORAGE_KEY)) ??
        DEFAULT_SHARING_SETTINGS;
      return { settings };
    });

    ctx.registerRoute("POST", "/sharing", async (event) => {
      if (!(await authorizedOperator(event))) {
        return { error: "Unauthorized" };
      }
      const body = (await getRequestBody(event)) || ({} as any);
      const settings = normalizeSharingSettings(
        (body as { settings?: unknown }).settings ?? body,
      );
      await ctx.storage.set(SHARING_STORAGE_KEY, settings);
      return { success: true, settings };
    });

    // REST: the games this instance currently shares (public read; empty when off)
    ctx.registerRoute("GET", "/shared/library", async () => {
      const settings =
        (await ctx.storage.get<SharingSettings>(SHARING_STORAGE_KEY)) ??
        DEFAULT_SHARING_SETTINGS;
      const catalog =
        (await ctx.storage.get<ODPCatalog>("odp:catalog")) ?? emptyCatalog();
      const games = visibleGames(catalog.games, settings);
      return {
        instanceId: identity.instanceId,
        scope: settings.scope,
        games,
        count: games.length,
      };
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

    // REST: dial a peer directly, verifying its signed descriptor, and record it
    ctx.registerRoute("POST", "/peers/dial", async (event) => {
      const body = (await getRequestBody(event)) || ({} as any);
      const url: unknown = body.url ?? body.endpoint;
      if (typeof url !== "string" || !url) {
        return { error: "url is required" };
      }
      try {
        const relayUrl = process.env.DROP_FEDERATION_RELAY_URL?.trim() || undefined;
        const { url: peerUrl, descriptor, viaRelay } = await dialPeerWithRelay(
          url,
          { relayUrl, fetchImpl: ctx.fetch as unknown as FetchLike },
        );
        const key = peerStorageKey(descriptor.instanceId);
        const existing = await ctx.storage.get<PeerRecord>(key);
        const peer = applyPeerHeartbeat(existing ?? undefined, {
          instanceId: descriptor.instanceId,
          instanceUrl: peerUrl,
          publicKey: descriptor.publicKey,
          now: Date.now(),
        });
        await ctx.storage.set(key, peer);
        ctx.broadcast("federation:peers:update", peer);
        return { success: true, descriptor, peer, viaRelay };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : "peer dial failed",
        };
      }
    });
  }

  async teardown(): Promise<void> {
    // Teardown
  }
}
