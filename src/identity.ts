import { createHash, generateKeyPairSync } from "node:crypto";

export interface InstanceIdentity {
  instanceId: string;
  publicKey: string;
  privateKey?: string;
}

export function generateInstanceIdentity(): InstanceIdentity {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  return {
    instanceId: createHash("sha256")
      .update(publicKey)
      .digest("hex")
      .slice(0, 32),
    publicKey,
    privateKey,
  };
}
