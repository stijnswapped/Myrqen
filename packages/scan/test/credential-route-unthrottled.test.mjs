import { test } from "node:test";
import assert from "node:assert/strict";
import { credentialRouteUnthrottled } from "../dist/rules/credential-route-unthrottled.js";
import { runRules } from "./helpers/run-rules.mjs";

/**
 * Each rule is pinned by a defect and its correctly written sibling. The sources are
 * written inline for these tests and are named after nothing in any corpus.
 */
const run = (rule, source, file = "src/routes.js", extra = {}) => runRules([rule], source, file, extra);

const EXPRESS_ONLY = { "package.json": JSON.stringify({ name: "api", dependencies: { express: "^4.21.0", bcrypt: "^5.1.1" } }) };
const WITH_LIMITER = { "package.json": JSON.stringify({ name: "api", dependencies: { express: "^4.21.0", "express-rate-limit": "^7.4.0" } }) };

const LOGIN = `
  const express = require("express");
  const bcrypt = require("bcrypt");
  const { findUserByEmail, startSession } = require("./accounts");
  const router = express.Router();
  router.post("/login", async (req, res) => {
    const user = await findUserByEmail(req.body.email);
    if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) {
      return res.status(401).json({ error: "invalid_credentials" });
    }
    res.json(await startSession(user));
  });
  module.exports = router;
`;

test("a sign-in route in a project that declares no limiter is reported low, needing review", async () => {
  const found = await run(credentialRouteUnthrottled, LOGIN, "src/auth.js", EXPRESS_ONLY);
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, "low");
  assert.equal(found[0].verification, "needs_review");
  assert.equal(found[0].category, "missing_rate_limit_on_credentials");
});

test("the same route is silent when the project declares a limiter", async () => {
  const found = await run(credentialRouteUnthrottled, LOGIN, "src/auth.js", WITH_LIMITER);
  assert.equal(found.length, 0);
});

test("the same route is silent when no manifest declares dependencies", async () => {
  const found = await run(credentialRouteUnthrottled, LOGIN, "src/auth.js", { "package.json": JSON.stringify({ name: "case" }) });
  assert.equal(found.length, 0);
});

test("a module that mentions throttling is silent", async () => {
  const found = await run(credentialRouteUnthrottled, LOGIN.replace("const router", "const { throttle } = require('./limits');\n  const router"), "src/auth.js", EXPRESS_ONLY);
  assert.equal(found.length, 0);
});

test("a login path whose handler checks no credential is not reported", async () => {
  const found = await run(credentialRouteUnthrottled, `
    const express = require("express");
    const router = express.Router();
    router.post("/login", (req, res) => res.redirect("/auth/start"));
    module.exports = router;
  `, "src/auth.js", EXPRESS_ONLY);
  assert.equal(found.length, 0);
});
