/**
 * Open Depot Protocol (ODP) catalog syndication (#21).
 *
 * A federated Drop instance publishes a signed catalog descriptor so peers can
 * subscribe to remote catalogs without a central authority. Descriptors are
 * canonicalised before signing so both sides agree on the exact bytes.
 */
import { createPublicKey, sign, verify } from "node:crypto";

export interface ODPGameEntry {
  gameId: string;
  title: string;
  version: string;
  metadataSource?: string;
  updatedAt: number;
}

export interface ODPCatalog {
  instanceId: string;
  generatedAt: number;
  games: ODPGameEntry[];
}

/** Deterministic JSON for a catalog entry (sorted, stable shape). */
export function canonicalizeGame(entry: ODPGameEntry): string {
  return JSON.stringify({
    gameId: entry.gameId,
    metadataSource: entry.metadataSource ?? null,
    title: entry.title,
    updatedAt: entry.updatedAt,
    version: entry.version,
  });
}

/** Deterministic JSON for a whole catalog (games sorted by id). */
export function canonicalizeCatalog(catalog: ODPCatalog): string {
  const games = [...catalog.games]
    .sort((a, b) => a.gameId.localeCompare(b.gameId))
    .map((entry) => JSON.parse(canonicalizeGame(entry)) as Record<string, unknown>);
  return JSON.stringify({
    games,
    generatedAt: catalog.generatedAt,
    instanceId: catalog.instanceId,
  });
}

/** Signs a catalog with the instance's Ed25519 private key (PEM). */
export function signCatalog(catalog: ODPCatalog, privateKeyPem: string): string {
  return sign(
    null,
    Buffer.from(canonicalizeCatalog(catalog)),
    privateKeyPem,
  ).toString("base64");
}

/** Verifies a catalog signature against a peer's Ed25519 public key (PEM). */
export function verifyCatalogSignature(
  catalog: ODPCatalog,
  signatureBase64: string,
  publicKeyPem: string,
): boolean {
  try {
    createPublicKey(publicKeyPem);
    return verify(
      null,
      Buffer.from(canonicalizeCatalog(catalog)),
      publicKeyPem,
      Buffer.from(signatureBase64, "base64"),
    );
  } catch {
    return false;
  }
}

/**
 * Merges a remote catalog into the local one, preferring the entry with the
 * newer `updatedAt` per game id.
 */
export function mergeCatalog(
  local: ODPGameEntry[],
  remote: ODPGameEntry[],
): ODPGameEntry[] {
  const merged = new Map<string, ODPGameEntry>();
  for (const entry of [...local, ...remote]) {
    const existing = merged.get(entry.gameId);
    if (!existing || entry.updatedAt > existing.updatedAt) {
      merged.set(entry.gameId, entry);
    }
  }
  return [...merged.values()].sort((a, b) => a.gameId.localeCompare(b.gameId));
}
