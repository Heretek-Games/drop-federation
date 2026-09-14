import type { PluginContext, ServerPlugin } from "@droposs/plugin-sdk";
import { generateInstanceIdentity, type InstanceIdentity } from "./identity.js";
import {
  applyPresenceUpdate,
  type PresenceRecord,
  type PresenceStatus,
} from "./presence.js";

export * from "./identity.js";
export * from "./presence.js";
export * from "./odp.js";
import {
  mergeCatalog,
  signCatalog,
  verifyCatalogSignature,
  type ODPCatalog,
} from "./odp.js";

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

export default class FederationPlugin implements ServerPlugin {
  metadata = {
    id: "drop-federation",
    name: "Friends Federation & Instance Peering",
    version: "0.1.0",
    apiVersion: 2,
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

    // Ensure instance identity exists
    let identity = await ctx.storage.get<InstanceIdentity>("instance_identity");
    if (!identity) {
      identity = generateInstanceIdentity();
      await ctx.storage.set("instance_identity", identity);
      ctx.logger.info(
        `Generated new instance identity: ${identity.instanceId}`,
      );
    }

    // REST: Instance descriptor
    ctx.registerRoute("GET", "/descriptor", async () => {
      return {
        instanceId: identity?.instanceId,
        publicKey: identity?.publicKey,
        apiVersion: 2,
        timestamp: Date.now(),
      };
    });

    // REST: Friend requests
    ctx.registerRoute("POST", "/friends/request", async (event) => {
      const body = await getRequestBody(event);
      const { remoteInstanceUrl, targetUser } = (body || {}) as any;
      if (!remoteInstanceUrl) {
        return { error: "remoteInstanceUrl is required" };
      }
      ctx.broadcast("federation:friends", {
        type: "request",
        remoteInstanceUrl,
        targetUser,
      });
      return { success: true };
    });

    // Open Depot Protocol: signed catalog syndication
    const emptyCatalog = (): ODPCatalog => ({
      instanceId: identity?.instanceId ?? "",
      generatedAt: Date.now(),
      games: [],
    });

    ctx.registerRoute("GET", "/odp/catalog", async () => {
      const catalog =
        (await ctx.storage.get<ODPCatalog>("odp:catalog")) ?? emptyCatalog();
      const signature = identity?.privateKey
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

    // WebSocket: Cross-instance presence
    ctx.registerWebSocket("federation:presence", async (msg, wsCtx) => {
      const update = (msg ?? {}) as {
        userId?: string;
        status?: PresenceStatus;
        gameId?: string;
      };
      if (update.userId) {
        const key = `presence:${update.userId}`;
        const existing = await ctx.storage.get<PresenceRecord>(key);
        const record = applyPresenceUpdate(existing ?? undefined, {
          userId: update.userId,
          status: update.status ?? "online",
          gameId: update.gameId,
          instanceId: identity?.instanceId,
          now: Date.now(),
        });
        await ctx.storage.set(key, record);
        ctx.broadcast("federation:presence:update", record);
      }
      wsCtx.send({ event: "presence_ack", instanceId: identity?.instanceId });
    });
  }

  async teardown(): Promise<void> {
    // Teardown
  }
}
