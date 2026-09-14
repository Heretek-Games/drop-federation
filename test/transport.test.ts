import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildDescriptor,
  dialPeer,
  generateInstanceIdentity,
  normalizePeerUrl,
  signDescriptor,
  type FetchLike,
  type SignedDescriptor,
} from "../src/index.js";

function descriptorFetch(
  payload: unknown,
  status = 200,
  ok = true,
): FetchLike {
  return async () => ({ ok, status, json: async () => payload });
}

test("normalizePeerUrl accepts http(s) and strips trailing slashes", () => {
  assert.equal(normalizePeerUrl("https://peer.example/"), "https://peer.example");
  assert.equal(normalizePeerUrl("http://host:9000//"), "http://host:9000");
  assert.equal(normalizePeerUrl("  https://peer.example  "), "https://peer.example");
  assert.equal(normalizePeerUrl("ftp://peer.example"), undefined);
  assert.equal(normalizePeerUrl("not a url"), undefined);
  assert.equal(normalizePeerUrl(""), undefined);
});

test("dialPeer verifies and returns a signed descriptor", async () => {
  const identity = generateInstanceIdentity();
  const descriptor = {
    ...buildDescriptor(identity, 2, ["https://peer.example"]),
    signature: "",
  };
  descriptor.signature = signDescriptor(descriptor, identity.privateKey ?? "");

  const result = await dialPeer(
    "https://peer.example/",
    descriptorFetch(descriptor),
  );
  assert.equal(result.url, "https://peer.example");
  assert.equal(result.descriptor.instanceId, identity.instanceId);
});

test("dialPeer rejects invalid URLs, non-OK responses, bad signatures and bad shape", async () => {
  await assert.rejects(
    () => dialPeer("ftp://peer.example", descriptorFetch({})),
    /valid http/,
  );

  const identity = generateInstanceIdentity();
  const good: SignedDescriptor = {
    ...buildDescriptor(identity, 2),
    signature: "",
  };
  good.signature = signDescriptor(good, identity.privateKey ?? "");

  await assert.rejects(
    () => dialPeer("https://peer.example", descriptorFetch(good, 500, false)),
    /HTTP 500/,
  );

  const tampered = { ...good, instanceId: "0".repeat(32) };
  await assert.rejects(
    () => dialPeer("https://peer.example", descriptorFetch(tampered)),
    /signature is invalid/,
  );

  await assert.rejects(
    () => dialPeer("https://peer.example", descriptorFetch({ instanceId: "x" })),
    /missing required fields/,
  );
});
