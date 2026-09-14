/**
 * At-rest protection for sensitive plugin secrets (#7 follow-up).
 *
 * The plugin SDK's `PluginStorage` is a plain key/value store with no
 * encryption support, so this module provides application-level envelope
 * encryption using only `node:crypto`. Secrets are sealed with AES-256-GCM
 * under a key derived from an operator-provided passphrase (scrypt).
 *
 * This protects against offline reads of the storage backend (database dumps,
 * backups, files copied off the host). It does NOT protect against a compromised
 * running server, because the passphrase is present in the process environment.
 *
 * See `docs/security.md` for the threat model and mitigation plan.
 */
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";

/** Environment variable holding the operator passphrase for storage encryption. */
export const KEY_PASSPHRASE_ENV = "DROP_FEDERATION_KEY_PASSPHRASE";

const SEALED_SECRET_VERSION = 1 as const;
const SCRYPT_KEY_LENGTH = 32;
const SALT_BYTES = 16;
const IV_BYTES = 12;

export interface SealedSecret {
  version: typeof SEALED_SECRET_VERSION;
  algorithm: "aes-256-gcm";
  kdf: "scrypt";
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
}

export function resolveKeyPassphrase(
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  const value = env[KEY_PASSPHRASE_ENV];
  return value && value.length > 0 ? value : undefined;
}

export function isSealedSecret(value: unknown): value is SealedSecret {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as Partial<SealedSecret>;
  return (
    candidate.version === SEALED_SECRET_VERSION &&
    candidate.algorithm === "aes-256-gcm" &&
    candidate.kdf === "scrypt" &&
    typeof candidate.salt === "string" &&
    typeof candidate.iv === "string" &&
    typeof candidate.tag === "string" &&
    typeof candidate.ciphertext === "string"
  );
}

/** Encrypts `plaintext` with AES-256-GCM under a scrypt-derived key. */
export function sealSecret(plaintext: string, passphrase: string): SealedSecret {
  if (!passphrase) {
    throw new Error("A non-empty passphrase is required to seal a secret");
  }
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = scryptSync(passphrase, salt, SCRYPT_KEY_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  return {
    version: SEALED_SECRET_VERSION,
    algorithm: "aes-256-gcm",
    kdf: "scrypt",
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

/** Decrypts a sealed secret. Throws when the passphrase or ciphertext is wrong. */
export function openSecret(sealed: SealedSecret, passphrase: string): string {
  if (!isSealedSecret(sealed)) {
    throw new Error("Unsupported sealed secret format");
  }
  const key = scryptSync(
    passphrase,
    Buffer.from(sealed.salt, "base64"),
    SCRYPT_KEY_LENGTH,
  );
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(sealed.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(sealed.tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(sealed.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}
