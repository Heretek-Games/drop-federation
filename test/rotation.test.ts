import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildRotation,
  generateInstanceIdentity,
  signRotation,
  verifyRotation,
  verifyRotationChain,
  type SignedRotation,
} from "../src/index.js";

test("a rotation certificate is signed by the previous key", () => {
  const previous = generateInstanceIdentity();
  const next = generateInstanceIdentity();
  const certificate = buildRotation(previous, next, 1234);
  const signature = signRotation(certificate, previous.privateKey as string);

  assert.equal(verifyRotation({ certificate, signature }), true);

  const tampered = {
    certificate: {
      ...certificate,
      nextPublicKey: generateInstanceIdentity().publicKey,
    },
    signature,
  };
  assert.equal(verifyRotation(tampered), false);

  const wrongKey = signRotation(certificate, next.privateKey as string);
  assert.equal(verifyRotation({ certificate, signature: wrongKey }), false);
});

test("verifyRotationChain links consecutive rotations", () => {
  const a = generateInstanceIdentity();
  const b = generateInstanceIdentity();
  const c = generateInstanceIdentity();

  const abCert = buildRotation(a, b, 1);
  const ab: SignedRotation = {
    certificate: abCert,
    signature: signRotation(abCert, a.privateKey as string),
  };
  const bcCert = buildRotation(b, c, 2);
  const bc: SignedRotation = {
    certificate: bcCert,
    signature: signRotation(bcCert, b.privateKey as string),
  };

  assert.equal(verifyRotationChain([ab, bc], a.instanceId), true);
  assert.equal(verifyRotationChain([ab, bc], b.instanceId), false);
  assert.equal(verifyRotationChain([], a.instanceId), true);
  // Out of order: the linkage constraint fails.
  assert.equal(verifyRotationChain([bc, ab]), false);
});
