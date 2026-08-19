/**
 * The sign-in form returns one message whether or not the address has an account.
 * That only hides which accounts exist if the two branches also take the same
 * time, so the unknown-address branch verifies against a decoy hash.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { decoyPasswordHash, hashPassword, verifyPassword } from "../dist/index.js";

test("the decoy carries the same stored format and parameters as a real hash", async () => {
  const real = await hashPassword("a perfectly ordinary passphrase");
  const decoy = decoyPasswordHash();
  const realParts = real.split("$");
  const decoyParts = decoy.split("$");
  assert.equal(decoyParts.length, realParts.length);
  // Prefix, version, and the three cost parameters must match, or the decoy
  // would cost a different amount of work and the oracle would come back.
  assert.deepEqual(decoyParts.slice(0, 5), realParts.slice(0, 5));
});

test("no password matches the decoy, and each decoy is distinct", async () => {
  const decoy = decoyPasswordHash();
  assert.equal(await verifyPassword("", decoy), false);
  assert.equal(await verifyPassword("a perfectly ordinary passphrase", decoy), false);
  assert.notEqual(decoy, decoyPasswordHash());
});

test("verifying against the decoy costs about what a real verification costs", async () => {
  const real = await hashPassword("a perfectly ordinary passphrase");
  const decoy = decoyPasswordHash();

  async function timeOne(stored) {
    const started = process.hrtime.bigint();
    await verifyPassword("some attempted password", stored);
    return Number(process.hrtime.bigint() - started) / 1e6;
  }

  // Warm up so the first scrypt does not pay for lazy initialization.
  await timeOne(real);
  const realMs = Math.min(await timeOne(real), await timeOne(real));
  const decoyMs = Math.min(await timeOne(decoy), await timeOne(decoy));

  // The reported oracle was a 70x gap. A 4x band is loose enough for a loaded
  // machine and still fails outright if the decoy branch stops hashing.
  const ratio = Math.max(realMs, decoyMs) / Math.max(1, Math.min(realMs, decoyMs));
  assert.ok(ratio < 4, `real ${realMs.toFixed(1)}ms vs decoy ${decoyMs.toFixed(1)}ms`);
});
