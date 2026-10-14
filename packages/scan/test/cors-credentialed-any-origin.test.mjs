import { test } from "node:test";
import assert from "node:assert/strict";
import { corsCredentialedAnyOrigin } from "../dist/rules/cors-credentialed-any-origin.js";
import { runRules } from "./helpers/run-rules.mjs";

/**
 * Each rule is pinned by a defect and its correctly written sibling. The sources are
 * written inline for these tests and are named after nothing in any corpus.
 */
const run = (rule, source, file = "src/routes.js", extra = {}) => runRules([rule], source, file, extra);

test("a credentialed cors() whose origin callback always approves is reported", async () => {
  const found = await run(corsCredentialedAnyOrigin, `
    const express = require("express");
    const cors = require("cors");
    const app = express();
    app.use(cors({ origin: (origin, callback) => callback(null, true), credentials: true }));
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].category, "insecure_cors_configuration");
  assert.equal(found[0].severity, "high");
});

test("an origin callback that checks a list is not", async () => {
  const found = await run(corsCredentialedAnyOrigin, `
    const cors = require("cors");
    const ALLOWED = new Set(["https://app.example.com"]);
    const options = {
      origin(origin, callback) {
        callback(null, !origin || ALLOWED.has(origin));
      },
      credentials: true
    };
    module.exports = cors(options);
  `);
  assert.equal(found.length, 0);
});

test("options held in a constant with origin true and credentials are reported", async () => {
  const found = await run(corsCredentialedAnyOrigin, `
    import cors from "cors";
    const corsOptions = { origin: true, credentials: true };
    export const corsLayer = cors(corsOptions);
  `);
  assert.equal(found.length, 1);
});

test("Fastify and Nest spellings are reported; without credentials they are not", async () => {
  const found = await run(corsCredentialedAnyOrigin, `
    import fastifyCors from "@fastify/cors";
    export async function build(app, nest) {
      await app.register(fastifyCors, { origin: true, credentials: true });
      nest.enableCors({ origin: true });
    }
  `);
  assert.equal(found.length, 1);
});
