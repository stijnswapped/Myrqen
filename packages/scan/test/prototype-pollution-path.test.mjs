import { test } from "node:test";
import assert from "node:assert/strict";
import { prototypePollutionPath } from "../dist/rules/prototype-pollution-path.js";
import { runRules } from "./helpers/run-rules.mjs";

/**
 * Each rule is pinned by a defect and its correctly written sibling. The sources are
 * written inline for these tests and are named after nothing in any corpus.
 */
const run = (rule, source, file = "src/routes.js", extra = {}) => runRules([rule], source, file, extra);

test("two computed keys with a caller-chosen first key are reported", async () => {
  const found = await run(prototypePollutionPath, `
    const express = require("express");
    const app = express();
    const preferences = {};
    app.post("/preferences", (req, res) => {
      const { section, key, value } = req.body;
      preferences[section] = preferences[section] || {};
      preferences[section][key] = value;
      res.sendStatus(204);
    });
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].category, "prototype_pollution");
});

test("the same write with a reserved-key guard is not", async () => {
  const found = await run(prototypePollutionPath, `
    const express = require("express");
    const app = express();
    const preferences = Object.create(null);
    app.post("/preferences", (req, res) => {
      const { section, key, value } = req.body;
      if (["__proto__", "constructor", "prototype"].includes(section) || ["__proto__", "constructor", "prototype"].includes(key)) {
        return res.sendStatus(400);
      }
      preferences[section] = preferences[section] || Object.create(null);
      preferences[section][key] = value;
      res.sendStatus(204);
    });
  `);
  assert.equal(found.length, 0);
});

test("an iterative path setter called with a body field is reported at the write", async () => {
  const found = await run(prototypePollutionPath, `
    function assignPath(target, dotted, value) {
      const parts = dotted.split(".");
      const last = parts.pop();
      let cursor = target;
      for (const part of parts) {
        cursor[part] = cursor[part] ?? {};
        cursor = cursor[part];
      }
      cursor[last] = value;
    }
    module.exports = (app, settings) => {
      app.patch("/settings", (req, res) => {
        assignPath(settings, req.body.path, req.body.value);
        res.json(settings);
      });
    };
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "PATCH /settings");
});

test("the same setter only called with fixed paths is not", async () => {
  const found = await run(prototypePollutionPath, `
    function assignPath(target, dotted, value) {
      const parts = dotted.split(".");
      const last = parts.pop();
      let cursor = target;
      for (const part of parts) {
        cursor[part] = cursor[part] ?? {};
        cursor = cursor[part];
      }
      cursor[last] = value;
    }
    module.exports = (app, settings) => {
      app.patch("/settings/theme", (req, res) => {
        assignPath(settings, "ui.theme", String(req.body.theme));
        res.json(settings);
      });
    };
  `);
  assert.equal(found.length, 0);
});

test("zipObjectDeep over caller paths is reported", async () => {
  const found = await run(prototypePollutionPath, `
    import _ from "lodash";
    export function importRow(req, res) {
      const record = _.zipObjectDeep(req.body.columns, req.body.values);
      res.json(record);
    }
  `);
  assert.equal(found.length, 1);
});
