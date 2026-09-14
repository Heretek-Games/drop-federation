/**
 * Opt-in library sharing (#6).
 *
 * Federation is safe-by-default: nothing is shared until the operator opts in.
 * Sharing is scoped to the whole catalog, an explicit allow-list of game ids,
 * or nothing. Revoking (`scope: "none"`) makes the shared library empty
 * immediately.
 */
import type { ODPGameEntry } from "./odp.js";

export type SharingScope = "none" | "library" | "games";

export interface SharingSettings {
  scope: SharingScope;
  /** Game ids shared when `scope === "games"`. */
  games: string[];
}

export const SHARING_STORAGE_KEY = "federation:sharing";

export const DEFAULT_SHARING_SETTINGS: SharingSettings = {
  scope: "none",
  games: [],
};

/** Validate and normalize an operator-supplied sharing payload. */
export function normalizeSharingSettings(input: unknown): SharingSettings {
  const record = (input ?? {}) as {
    scope?: unknown;
    games?: unknown;
  };
  const scope: SharingScope =
    record.scope === "library" || record.scope === "games"
      ? record.scope
      : "none";
  const games = Array.isArray(record.games)
    ? record.games.filter(
        (game): game is string => typeof game === "string" && game.trim().length > 0,
      )
    : [];
  return { scope, games: scope === "games" ? games : [] };
}

/** The subset of a catalog the operator currently shares. */
export function visibleGames(
  catalog: ODPGameEntry[],
  settings: SharingSettings,
): ODPGameEntry[] {
  if (settings.scope === "none") return [];
  if (settings.scope === "library") return catalog;
  const allowed = new Set(settings.games);
  return catalog.filter((game) => allowed.has(game.gameId));
}
