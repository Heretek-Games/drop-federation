import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildDescriptor,
  canonicalizeDescriptor,
  deriveInstanceId,
  generateInstanceIdentity,
  signDescriptor,
  verifyDescriptor,
  type InstanceDescriptor,
} from "../src/index.js";

test("canonicalizeDescriptor is field-order independent", () => {
  const identity = generateInstanceIdentity();
  const descriptor = buildDescriptor(identity, 2, [], 1000);
  const reordered = {
    timestamp: descriptor.timestamp,
    publicKey: descriptor.publicKey,
    instanceId: descriptor.instanceId,
    descriptorVersion: descriptor.descriptorVersion,
    apiVersion: descriptor.apiVersion,
  } as InstanceDescriptor;
  assert.equal(canonicalizeDescriptor(descriptor), canonicalizeDescriptor(reordered));
});

test("sign and verify a descriptor with the instance identity", () => {
  const identity = generateInstanceIdentity();
  const descriptor = buildDescriptor(identity, 2, [], 1000);
  const signature = signDescriptor(descriptor, identity.privateKey ?? "");

  assert.equal(verifyDescriptor(descriptor, signature), true);
  assert.equal(verifyDescriptor(descriptor, signature, identity.publicKey), true);
});

test("tampered descriptor fields fail verification", () => {
  const identity = generateInstanceIdentity();
  const descriptor = buildDescriptor(identity, 2, [], 1000);
  const signature = signDescriptor(descriptor, identity.privateKey ?? "");

  const tamperedTimestamp: InstanceDescriptor = { ...descriptor, timestamp: 2000 };
  assert.equal(verifyDescriptor(tamperedTimestamp, signature), false);

  const tamperedInstanceId: InstanceDescriptor = {
    ...descriptor,
    instanceId: "f".repeat(32),
  };
  assert.equal(verifyDescriptor(tamperedInstanceId, signature), false);

  const tamperedPublicKey: InstanceDescriptor = {
    ...descriptor,
    publicKey: generateInstanceIdentity().publicKey,
  };
  assert.equal(verifyDescriptor(tamperedPublicKey, signature), false);
});

test("verification rejects a signature from another instance and malformed input", () => {
  const identity = generateInstanceIdentity();
  const other = generateInstanceIdentity();
  const descriptor = buildDescriptor(identity, 2, [], 1000);
  const otherSignature = signDescriptor(descriptor, other.privateKey ?? "");

  assert.equal(verifyDescriptor(descriptor, otherSignature), false);
  assert.equal(
    verifyDescriptor(descriptor, "not-base64", "not-a-pem"),
    false,
  );
  assert.equal(verifyDescriptor(descriptor, ""), false);
});

test("instanceId is self-certifying for the embedded public key", () => {
  const identity = generateInstanceIdentity();
  assert.equal(identity.instanceId, deriveInstanceId(identity.publicKey));
  assert.equal(identity.instanceId.length, 32);
});

test("advertised endpoints are signed and tamper-evident", () => {
  const identity = generateInstanceIdentity();
  const descriptor = buildDescriptor(
    identity,
    2,
    ["https://b.example/", "https://a.example"],
    1000,
  );
  const signature = signDescriptor(descriptor, identity.privateKey ?? "");
  assert.equal(verifyDescriptor(descriptor, signature), true);

  // Order does not change the signed payload.
  const reordered: InstanceDescriptor = {
    ...descriptor,
    endpoints: ["https://a.example", "https://b.example/"],
  };
  assert.equal(canonicalizeDescriptor(reordered), canonicalizeDescriptor(descriptor));

  const tampered: InstanceDescriptor = {
    ...descriptor,
    endpoints: ["https://evil.example"],
  };
  assert.equal(verifyDescriptor(tampered, signature), false);
});

