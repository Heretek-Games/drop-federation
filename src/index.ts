import type { PluginContext, ServerPlugin } from "@droposs/plugin-sdk";
import { generateInstanceIdentity, type InstanceIdentity } from "./identity.js";

export * from "./identity.js";

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

    // WebSocket: Cross-instance presence
    ctx.registerWebSocket("federation:presence", (msg, wsCtx) => {
      wsCtx.send({ event: "presence_ack", instanceId: identity?.instanceId });
    });
  }

  async teardown(): Promise<void> {
    // Teardown
  }
}
