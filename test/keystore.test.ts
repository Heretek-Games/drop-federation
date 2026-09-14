import { test } from "node:test";
import assert from "node:assert/strict";
import { MockPluginContext } from "@droposs/plugin-sdk";
import FederationPlugin, {
  KEY_PASSPHRASE_ENV,
  fromStoredIdentity,
  generateInstanceIdentity,
  isSealedSecret,
  openSecret,
  resolveKeyPassphrase,
  sealSecret,
  toStoredIdentity,
  verifyDescriptor,
  type StoredInstanceIdentity,
} from "../src/index.js";

const PASSPHRASE = "correct horse battery staple";

test("sealSecret/openSecret round-trips and rejects wrong passphrases", () => {
  const sealed = sealSecret("super-secret-pem", PASSPHRASE);
  assert.equal(isSealedSecret(sealed), true);
  assert.equal(sealed.ciphertext.includes("super-secret-pem"), false);
  assert.equal(openSecret(sealed, PASSPHRASE), "super-secret-pem");
  assert.throws(() => openSecret(sealed, "wrong-passphrase"));
});

test("sealed secrets use a fresh salt/IV and detect tampering", () => {
  const first = sealSecret("value", PASSPHRASE);
  const second = sealSecret("value", PASSPHRASE);
  assert.notEqual(first.ciphertext, second.ciphertext);

  const tampered = { ...first, ciphertext: second.ciphertext };
  assert.throws(() => openSecret(tampered, PASSPHRASE));
});

test("resolveKeyPassphrase ignores empty values", () => {
  assert.equal(resolveKeyPassphrase({}), undefined);
  assert.equal(resolveKeyPassphrase({ [KEY_PASSPHRASE_ENV]: "" }), undefined);
  assert.equal(
    resolveKeyPassphrase({ [KEY_PASSPHRASE_ENV]: "hunter2" }),
    "hunter2",
  );
});

test("toStoredIdentity seals the key and fromStoredIdentity requires the passphrase", () => {
  const identity = generateInstanceIdentity();
  const stored = toStoredIdentity(identity, PASSPHRASE);
  assert.equal(stored.protection, "passphrase");
  assert.equal(stored.privateKey, undefined);
  assert.ok(stored.sealedPrivateKey);

  const restored = fromStoredIdentity(stored, PASSPHRASE);
  assert.equal(restored.privateKey, identity.privateKey);
  assert.throws(() => fromStoredIdentity(stored));
});

test("plugin with a passphrase never writes the private key in plaintext", async () => {
  process.env[KEY_PASSPHRASE_ENV] = PASSPHRASE;
  try {
    const plugin = new FederationPlugin();
    const ctx = new MockPluginContext("drop-federation", [
      "routes",
      "storage",
      "events",
      "network",
      "websocket",
    ]);
    await plugin.init(ctx);

    const stored = await ctx.storage.get<StoredInstanceIdentity>(
      "instance_identity",
    );
    assert.ok(stored);
    assert.equal(stored.privateKey, undefined);
    assert.ok(isSealedSecret(stored.sealedPrivateKey));

    const descriptorRoute = ctx.routes.get("GET /descriptor");
    const descriptor = (await descriptorRoute!.handler({} as any, {
      params: {},
      query: {},
    })) as any;
    assert.equal(verifyDescriptor(descriptor, descriptor.signature), true);

    const restored = fromStoredIdentity(stored, PASSPHRASE);
    assert.match(restored.privateKey ?? "", /PRIVATE KEY/);
  } finally {
    delete process.env[KEY_PASSPHRASE_ENV];
  }
});

test("plugin migrates a legacy plaintext key when a passphrase is configured", async () => {
  process.env[KEY_PASSPHRASE_ENV] = PASSPHRASE;
  try {
    const identity = generateInstanceIdentity();
    const plugin = new FederationPlugin();
    const ctx = new MockPluginContext("drop-federation", [
      "routes",
      "storage",
      "events",
      "network",
      "websocket",
    ]);
    await ctx.storage.set<StoredInstanceIdentity>("instance_identity", {
      instanceId: identity.instanceId,
      publicKey: identity.publicKey,
      privateKey: identity.privateKey,
      protection: "plaintext",
    });

    await plugin.init(ctx);

    const stored = await ctx.storage.get<StoredInstanceIdentity>(
      "instance_identity",
    );
    assert.ok(stored);
    assert.equal(stored.privateKey, undefined);
    assert.ok(isSealedSecret(stored.sealedPrivateKey));
    assert.equal(
      openSecret(stored.sealedPrivateKey!, PASSPHRASE),
      identity.privateKey,
    );
  } finally {
    delete process.env[KEY_PASSPHRASE_ENV];
  }
});

test("plugin refuses to boot on a sealed key when the passphrase is missing", async () => {
  const identity = generateInstanceIdentity();
  const sealed = toStoredIdentity(identity, PASSPHRASE);
  const plugin = new FederationPlugin();
  const ctx = new MockPluginContext("drop-federation", [
      "routes",
      "storage",
      "events",
      "network",
      "websocket",
    ]);
  await ctx.storage.set<StoredInstanceIdentity>("instance_identity", sealed);

  delete process.env[KEY_PASSPHRASE_ENV];
  await assert.rejects(() => plugin.init(ctx), /DROP_FEDERATION_KEY_PASSPHRASE/);
});
