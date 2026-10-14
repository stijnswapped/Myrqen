import { test } from "node:test";
import assert from "node:assert/strict";
import { jwtConfiguration } from "../dist/rules/jwt-configuration.js";
import { runRules } from "./helpers/run-rules.mjs";

/**
 * Each rule is pinned by a defect and its correctly written sibling. The sources are
 * written inline for these tests and are named after nothing in any corpus.
 */
const run = (rule, source, file = "src/routes.js", extra = {}) => runRules([rule], source, file, extra);

test("a guessable inline HMAC key is reported without repeating the key", async () => {
  const found = await run(jwtConfiguration, `
    import jwt from "jsonwebtoken";
    export function issue(user) {
      return jwt.sign({ sub: user.id, role: user.role }, "secret", { expiresIn: "1h" });
    }
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].category, "jwt_weak_secret");
  assert.equal(found[0].severity, "high");
  assert.ok(!JSON.stringify(found[0]).includes('"secret"'), "the key must not appear in the finding");
});

test("an environment key with a placeholder fallback is reported as needing review", async () => {
  const found = await run(jwtConfiguration, `
    const jwt = require("jsonwebtoken");
    const JWT_SECRET = process.env.JWT_SECRET || "changeme";
    function authenticate(req, res, next) {
      req.user = jwt.verify(req.headers.authorization.slice(7), JWT_SECRET, { algorithms: ["HS256"] });
      next();
    }
    module.exports = { authenticate };
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].verification, "needs_review");
  assert.equal(found[0].severity, "medium");
});

test("an environment key with no fallback is not reported", async () => {
  const found = await run(jwtConfiguration, `
    import jwt from "jsonwebtoken";
    const key = process.env.JWT_SECRET;
    if (!key) throw new Error("JWT_SECRET is required");
    export const verify = (token) => jwt.verify(token, key, { algorithms: ["HS256"] });
  `);
  assert.equal(found.length, 0);
});

test("ignoreExpiration and a constant algorithm list containing none are both reported", async () => {
  const found = await run(jwtConfiguration, `
    import jwt from "jsonwebtoken";
    const ACCEPTED = ["HS256", "none"];
    export function readSession(token) {
      return jwt.verify(token, process.env.SESSION_KEY, { algorithms: ACCEPTED });
    }
    export function readLegacy(token) {
      return jwt.verify(token, process.env.SESSION_KEY, { algorithms: ["HS256"], ignoreExpiration: true });
    }
  `);
  assert.equal(found.length, 2);
  assert.deepEqual(found.map((f) => f.severity).sort(), ["critical", "medium"]);
});

test("tokens signed with algorithm none are reported", async () => {
  const found = await run(jwtConfiguration, `
    import jwt from "jsonwebtoken";
    export const preview = (claims) => jwt.sign(claims, "", { algorithm: "none" });
  `);
  assert.ok(found.some((f) => f.category === "jwt_verification_bypass" && /without a signature/.test(f.title)));
});

test("a jose key from TextEncoder over a long random environment value is not reported", async () => {
  const found = await run(jwtConfiguration, `
    import { SignJWT, jwtVerify } from "jose";
    const key = new TextEncoder().encode(process.env.AUTH_SECRET);
    export const sign = (sub) => new SignJWT({ sub }).setProtectedHeader({ alg: "HS256" }).sign(key);
    export const verify = (token) => jwtVerify(token, key, { algorithms: ["HS256"] });
  `);
  assert.equal(found.length, 0);
});
