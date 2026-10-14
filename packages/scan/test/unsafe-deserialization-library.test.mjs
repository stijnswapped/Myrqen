import { test } from "node:test";
import assert from "node:assert/strict";
import { unsafeDeserializationLibraries } from "../dist/rules/unsafe-deserialization-libraries.js";
import { runRules } from "./helpers/run-rules.mjs";

/**
 * Each rule is pinned by a defect and its correctly written sibling. The sources are
 * written inline for these tests and are named after nothing in any corpus.
 */
const run = (rule, source, file = "src/routes.js", extra = {}) => runRules([rule], source, file, extra);

test("cryo.parse of a cookie is reported; JSON.parse is not", async () => {
  const found = await run(unsafeDeserializationLibraries, `
    const Cryo = require("cryo");
    module.exports = (app) => {
      app.get("/cart", (req, res) => {
        const cart = Cryo.parse(req.cookies.cart);
        res.json(cart);
      });
      app.get("/cart.json", (req, res) => {
        res.json(JSON.parse(req.cookies.cart));
      });
    };
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, "critical");
});

test("js-yaml unsafeLoadAll of a request body is reported", async () => {
  const found = await run(unsafeDeserializationLibraries, `
    import yaml from "js-yaml";
    export async function importManifests(req, res) {
      const documents = yaml.unsafeLoadAll(req.body);
      res.json({ count: documents.length });
    }
  `);
  assert.equal(found.length, 1);
});
