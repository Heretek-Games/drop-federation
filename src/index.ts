import type { PluginContext, ServerPlugin } from "@drop/plugin-sdk";
import { generateInstanceIdentity, type InstanceIdentity } from "./identity.js";

export * from "./identity.js";

export default class FederationPlugin implements ServerPlugin {
  metadata = {
    id: "drop-federation",
    name: "Friends Federation & Instance Peering",
    version: "0.1.0",
    apiVersion: 1,
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
      ctx.logger.info(`Generated new instance identity: ${identity.instanceId}`);
    }

    // REST: Instance descriptor
    ctx.registerRoute("GET", "/descriptor", async () => {
      return {
        instanceId: identity?.instanceId,
        publicKey: identity?.publicKey,
        apiVersion: 1,
        timestamp: Date.now(),
      };
    });

    // REST: Friend requests
    ctx.registerRoute("POST", "/friends/request", async (event) => {
      const { remoteInstanceUrl, targetUser } = (event.body || {}) as any;
      if (!remoteInstanceUrl) {
        return { error: "remoteInstanceUrl is required" };
      }
      ctx.broadcast("federation:friends", { type: "request", remoteInstanceUrl, targetUser });
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
