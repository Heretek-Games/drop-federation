import { timingSafeEqual } from "node:crypto";

/**
 * Constant-time string comparison. Returns `false` for a length mismatch
 * without throwing, so callers can compare attacker-controlled tokens safely.
 */
export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Whether an `Authorization` header carries the expected bearer token.
 * `expected` must be non-empty; the comparison is constant-time.
 */
export function matchesBearerToken(
  authHeader: string | undefined,
  expected: string,
): boolean {
  if (!expected) return false;
  const [scheme, token] = (authHeader ?? "").trim().split(/\s+/);
  if (scheme !== "Bearer" || !token) return false;
  return safeEqual(token, expected);
}
