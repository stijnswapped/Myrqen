import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseFile } from "../dist/ast/parse.js";
import { discoverRoutes } from "../dist/ast/routes.js";
import { parsingRules } from "../dist/rules/parsing.js";

/**
 * Every case is written inline. None of it is copied from the benchmark corpus:
 * a rule that only fires on a known fixture is worthless in a real repository, so
 * these use different names, routes, frameworks, and shapes.
 *
 * The rules are driven directly rather than through `scan()`, so the tests hold
 * whether or not the file has been registered in the engine's rule list yet.
 */
async function analyze(source, filename = "src/handler.js") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-parsing-"));
  const target = path.join(root, filename);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, source, "utf8");
  try {
    const parsed = await parseFile(root, target);
    assert.ok(!("error" in parsed), `the fixture must parse: ${parsed.error ?? ""}`);
    const candidates = [];
    const context = {
      file: parsed,
      routes: discoverRoutes(parsed),
      report: (candidate) => candidates.push(candidate)
    };
    for (const rule of parsingRules) rule.run(context);
    // The engine deduplicates on rule, file, and line; mirror that here so a test
    // measures findings a reader would see rather than raw reports.
    const seen = new Map();
    for (const candidate of candidates) {
      const key = `${candidate.ruleId}::${candidate.location.line}`;
      if (!seen.has(key)) seen.set(key, candidate);
    }
    return [...seen.values()];
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const of = (candidates, category) => candidates.filter((candidate) => candidate.category === category);

/* ---------------- template_injection ---------------- */

test("a template posted by the caller and handed to a compiler is reported", async () => {
  const found = await analyze(`
    const handlebars = require("handlebars");
    const express = require("express");
    const app = express();
    app.post("/campaigns/:id/preview", async (req, res) => {
      const draft = req.body;
      const render = handlebars.compile(draft.markup);
      res.send(render({ recipient: { name: "Sample" } }));
    });
  `);
  const hits = of(found, "template_injection");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "critical");
  assert.equal(hits[0].route, "POST /campaigns/:id/preview");
});

test("a fixed template rendered with caller-supplied data is not reported", async () => {
  const found = await analyze(`
    const ejs = require("ejs");
    const LAYOUT = "<h1><%= title %></h1><p><%= intro %></p>";
    const express = require("express");
    const app = express();
    app.post("/campaigns/preview", async (req, res) => {
      res.send(ejs.render(LAYOUT, { title: String(req.body.title || ""), intro: String(req.body.intro || "") }));
    });
  `);
  assert.deepEqual(of(found, "template_injection"), [], "caller data as render context is the correct usage");
});

test("a template read from disk at boot and selected by key is not reported", async () => {
  const found = await analyze(`
    const fs = require("node:fs");
    const nunjucks = require("nunjucks");
    const LAYOUTS = ["welcome", "receipt"];
    const COMPILED = new Map(LAYOUTS.map((name) => [name, nunjucks.compile(fs.readFileSync(name + ".njk", "utf8"))]));
    const express = require("express");
    const app = express();
    app.post("/mail/preview", async (req, res) => {
      const render = COMPILED.get(String(req.body.layout));
      if (!render) return res.status(400).json({ error: "unknown layout", layouts: LAYOUTS });
      res.send(render({ name: String(req.body.name || "") }));
    });
  `);
  assert.deepEqual(of(found, "template_injection"), []);
});

test("a hand-rolled renderer built with new Function is one finding, not two", async () => {
  const found = await analyze([
    'const express = require("express");',
    'const app = express();',
    'app.post("/snippets/render", async (req, res) => {',
    '  const body = req.body;',
    '  const renderer = new Function("data", "var out = \'{{\'; return out + \'" + body.snippet + "\';");',
    '  res.send(renderer({ name: "sample" }));',
    '});'
  ].join("\n"));
  assert.equal(of(found, "template_injection").length, 1, "the renderer is reported as template injection");
  assert.deepEqual(of(found, "code_injection"), [], "and not a second time as code injection");
});

/* ---------------- xml_external_entity ---------------- */

test("a parser with entity substitution and DTD loading enabled is reported", async () => {
  const found = await analyze(`
    const libxml = require("libxmljs2");
    const express = require("express");
    const app = express();
    app.post("/catalogues/import", async (req, res) => {
      const document = await req.text();
      const parsed = libxml.parseXml(document, { noblanks: true, noent: true, dtdload: true });
      res.json({ root: parsed.root().name() });
    });
  `);
  const hits = of(found, "xml_external_entity");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high");
  assert.equal(hits[0].route, "POST /catalogues/import");
});

test("a parser with entities and DTDs switched off is not reported", async () => {
  const found = await analyze(`
    const libxml = require("libxmljs2");
    const express = require("express");
    const app = express();
    app.post("/catalogues/import", async (req, res) => {
      const document = await req.text();
      const parsed = libxml.parseXml(document, { noblanks: true, noent: false, dtdload: false, dtdattr: false, nonet: true });
      res.json({ root: parsed.root().name() });
    });
  `);
  assert.deepEqual(of(found, "xml_external_entity"), [], "the safe configuration is the same call with the flags off");
});

test("a DOM parser told to resolve external references is reported", async () => {
  const found = await analyze(`
    const { DOMParser } = require("@xmldom/xmldom");
    const express = require("express");
    const app = express();
    app.post("/feeds/import", async (req, res) => {
      const parser = new DOMParser({ resolveExternals: true });
      const document = parser.parseFromString(req.body.feed, "text/xml");
      res.json({ ok: Boolean(document) });
    });
  `);
  assert.equal(of(found, "xml_external_entity").length, 1);
});

/* ---------------- nosql_injection ---------------- */

test("a caller-supplied filter object spread into a Mongo query is reported", async () => {
  const found = await analyze(`
    const { GraphQLError } = require("graphql");
    const { getCollection } = require("../lib/mongo");
    const resolvers = {
      Query: {
        articles: async (_parent, args, context) => {
          const { filter = {}, first = 20 } = args;
          const articles = await getCollection("articles");
          const query = { tenantId: context.viewer.tenantId, archivedAt: null, ...filter };
          return articles.find(query).limit(Math.min(first, 100)).toArray();
        }
      }
    };
    module.exports = { resolvers };
  `);
  const hits = of(found, "nosql_injection");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high");
  assert.equal(hits[0].route, "POST /graphql");
});

test("a facet payload projected through a rebuilding helper is not reported", async () => {
  const found = await analyze(`
    const { GraphQLError } = require("graphql");
    const { getCollection } = require("../lib/mongo");
    const FACETS = { state: "state", authorEmail: "authorEmail" };
    function buildFacets(filter) {
      const conditions = {};
      for (const [key, field] of Object.entries(FACETS)) {
        const value = filter[key];
        if (value === undefined) continue;
        if (typeof value !== "string" && typeof value !== "number") throw new Error("bad facet");
        conditions[field] = String(value);
      }
      return conditions;
    }
    const resolvers = {
      Query: {
        articles: async (_parent, args, context) => {
          const { filter = {} } = args;
          const articles = await getCollection("articles");
          const query = { ...buildFacets(filter), tenantId: context.viewer.tenantId };
          return articles.find(query).toArray();
        }
      }
    };
    module.exports = { resolvers };
  `);
  assert.deepEqual(of(found, "nosql_injection"), []);
});

test("body fields used raw as filter values are reported when the route declares no schema", async () => {
  const found = await analyze(`
    export default async function (fastify) {
      const invites = fastify.mongo.db.collection("invites");
      fastify.post("/invites/claim", { config: { rateLimit: { max: 5 } } }, async (request, reply) => {
        const { email, code } = request.body;
        const pending = await invites.findOne({ email: email, code: code, claimedAt: null });
        if (!pending) return reply.code(400).send({ error: "expired" });
        return reply.send({ workspaceId: pending.workspaceId });
      });
    }
  `, "src/invites.js");
  const hits = of(found, "nosql_injection");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].route, "POST /invites/claim");
});

test("the same filter is not reported when the route validates the body", async () => {
  const found = await analyze(`
    const claimSchema = {
      body: {
        type: "object",
        required: ["email", "code"],
        additionalProperties: false,
        properties: { email: { type: "string", format: "email" }, code: { type: "string", pattern: "^[a-f0-9]{32}$" } }
      }
    };
    export default async function (fastify) {
      const invites = fastify.mongo.db.collection("invites");
      fastify.post("/invites/claim", { schema: claimSchema }, async (request, reply) => {
        const { email, code } = request.body;
        const pending = await invites.findOne({ email: email, code: code, claimedAt: null });
        if (!pending) return reply.code(400).send({ error: "expired" });
        return reply.send({ workspaceId: pending.workspaceId });
      });
    }
  `, "src/invites.js");
  assert.deepEqual(of(found, "nosql_injection"), [], "a route schema rejects an operator object before the handler runs");
});

test("a value coerced to a string before the query is not reported", async () => {
  const found = await analyze(`
    const { MongoClient } = require("mongodb");
    const express = require("express");
    const app = express();
    const users = new MongoClient(process.env.MONGO_URL).db().collection("users");
    app.post("/sessions", async (req, res) => {
      const account = await users.findOne({ email: String(req.body.email).toLowerCase(), status: "active" });
      res.json({ found: Boolean(account) });
    });
  `);
  assert.deepEqual(of(found, "nosql_injection"), []);
});

test("a lookup by path parameter is not reported, because a path parameter is a string", async () => {
  const found = await analyze(`
    const { MongoClient } = require("mongodb");
    const express = require("express");
    const app = express();
    const orders = new MongoClient(process.env.MONGO_URL).db().collection("orders");
    app.get("/orders/:orderId", async (req, res) => {
      const order = await orders.findOne({ _id: req.params.orderId, accountId: req.user.accountId });
      res.json({ order });
    });
  `);
  assert.deepEqual(of(found, "nosql_injection"), []);
});

test("Array.prototype.find with a callback is not a query", async () => {
  const found = await analyze(`
    const { MongoClient } = require("mongodb");
    const ROUTES = [{ method: "GET", path: "/health" }];
    module.exports = function dispatch(request) {
      return ROUTES.find((entry) => entry.method === request.method && entry.path === request.url);
    };
  `);
  assert.deepEqual(of(found, "nosql_injection"), []);
});

test("a terminating typeof check on each field is enough to stay quiet", async () => {
  const found = await analyze(`
    const { MongoClient } = require("mongodb");
    const express = require("express");
    const app = express();
    const invites = new MongoClient(process.env.MONGO_URL).db().collection("invites");
    app.post("/invites/claim", async (req, res) => {
      const { email, code } = req.body;
      if (typeof email !== "string" || typeof code !== "string") {
        return res.status(400).json({ error: "email and code must be strings" });
      }
      const pending = await invites.findOne({ email: email, code: code, claimedAt: null });
      res.json({ found: Boolean(pending) });
    });
  `);
  assert.deepEqual(of(found, "nosql_injection"), []);
});

test("a wholly caller-controlled update document is reported", async () => {
  const found = await analyze(`
    const { MongoClient } = require("mongodb");
    const express = require("express");
    const app = express();
    const profiles = new MongoClient(process.env.MONGO_URL).db().collection("profiles");
    app.patch("/profile", async (req, res) => {
      await profiles.updateOne({ _id: req.user.profileId }, req.body);
      res.json({ ok: true });
    });
  `);
  assert.equal(of(found, "nosql_injection").length, 1, "the caller chooses the update operator, not only the value");
});

test("a caller-controlled $where clause is reported as critical", async () => {
  const found = await analyze(`
    const { MongoClient } = require("mongodb");
    const express = require("express");
    const app = express();
    const reports = new MongoClient(process.env.MONGO_URL).db().collection("reports");
    app.get("/reports/search", async (req, res) => {
      const rows = await reports.find({ tenantId: req.user.tenantId, $where: req.query.predicate }).toArray();
      res.json({ rows });
    });
  `);
  const hits = of(found, "nosql_injection");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "critical");
});


test("a filter assembled by assignment carries the caller's keys into the query", async () => {
  const source = `
    const { MongoClient } = require("mongodb");
    const express = require("express");
    const app = express();
    const invoices = new MongoClient(process.env.MONGO_URL).db().collection("invoices");
    app.post("/invoices/lookup", async (req, res) => {
      const filter = { orgId: req.user.orgId, voided: false };
      if (req.body.reference) filter.reference = String(req.body.reference);
      if (req.body.minTotal !== undefined) {
        filter.$where = "this.total >= " + req.body.minTotal;
      }
      res.json({ invoices: await invoices.find(filter).toArray() });
    });
  `;
  const found = await analyze(source);
  const hits = of(found, "nosql_injection");
  assert.equal(hits.length, 1, "a query with optional criteria is built in steps, not as one literal");
  assert.equal(hits[0].severity, "critical", "$where is evaluated by the database server");
  const line = source.split("\n")[hits[0].location.line - 1];
  assert.match(line, /filter\.\$where/, "the report anchors on the assignment that added the key");
});

test("Object.assign of the request body into a filter is reported like a spread", async () => {
  const found = await analyze(`
    const { MongoClient } = require("mongodb");
    const express = require("express");
    const app = express();
    const invoices = new MongoClient(process.env.MONGO_URL).db().collection("invoices");
    app.post("/invoices/lookup", async (req, res) => {
      const filter = { orgId: req.user.orgId };
      Object.assign(filter, req.body.criteria);
      res.json({ invoices: await invoices.find(filter).toArray() });
    });
  `);
  const hits = of(found, "nosql_injection");
  assert.equal(hits.length, 1, "merging the caller's object in is the same defect as spreading it in");
});

test("a filter assembled by assignment from coerced and guarded values stays quiet", async () => {
  const found = await analyze(`
    const { MongoClient } = require("mongodb");
    const express = require("express");
    const app = express();
    const invoices = new MongoClient(process.env.MONGO_URL).db().collection("invoices");
    app.post("/invoices/lookup", async (req, res) => {
      const filter = { orgId: req.user.orgId, voided: false };
      if (req.body.reference) filter.reference = String(req.body.reference);
      if (req.body.minTotal !== undefined) {
        const floor = Number(req.body.minTotal);
        if (!Number.isFinite(floor)) return res.status(400).json({ error: "minTotal must be a number" });
        filter.total = { $gte: floor };
        filter.settledAt = { $ne: null };
      }
      res.json({ invoices: await invoices.find(filter).toArray() });
    });
  `);
  assert.deepEqual(of(found, "nosql_injection"), [], "every added key is a scalar the caller cannot reshape");
});

test("a key written onto the filter after the query is not part of that query", async () => {
  const found = await analyze(`
    const { MongoClient } = require("mongodb");
    const express = require("express");
    const app = express();
    const invoices = new MongoClient(process.env.MONGO_URL).db().collection("invoices");
    const audits = new MongoClient(process.env.MONGO_URL).db().collection("audits");
    app.post("/invoices/lookup", async (req, res) => {
      const filter = { orgId: req.user.orgId };
      const rows = await invoices.find(filter).toArray();
      filter.note = req.body.note;
      await audits.insertOne(filter);
      res.json({ invoices: rows });
    });
  `);
  assert.deepEqual(of(found, "nosql_injection"), [], "the query ran before the key existed");
});

/* ---------------- unsafe_deserialization ---------------- */

test("a request payload handed to node-serialize is reported as critical", async () => {
  const found = await analyze(`
    const serialize = require("node-serialize");
    const express = require("express");
    const app = express();
    app.post("/editor/restore", async (req, res) => {
      const restored = serialize.unserialize(Buffer.from(req.body.state, "base64").toString("utf8"));
      res.json({ id: restored.id });
    });
  `);
  const hits = of(found, "unsafe_deserialization");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "critical");
  assert.equal(hits[0].route, "POST /editor/restore");
});

test("a YAML load pinned to a data-only schema is not reported", async () => {
  const found = await analyze(`
    const yaml = require("js-yaml");
    const express = require("express");
    const app = express();
    app.post("/pipelines/import", async (req, res) => {
      const definition = yaml.load(req.body.definition, { schema: yaml.JSON_SCHEMA });
      res.json({ steps: definition.steps.length });
    });
  `);
  assert.deepEqual(of(found, "unsafe_deserialization"), []);
});

test("a YAML load with no schema restriction is reported", async () => {
  const found = await analyze(`
    const yaml = require("js-yaml");
    const express = require("express");
    const app = express();
    app.post("/pipelines/import", async (req, res) => {
      const definition = yaml.load(req.body.definition);
      res.json({ steps: definition.steps.length });
    });
  `);
  assert.equal(of(found, "unsafe_deserialization").length, 1);
});

test("JSON.parse followed by a field-by-field check is not reported", async () => {
  const found = await analyze(`
    const express = require("express");
    const app = express();
    function readCheckpoint(text) {
      const raw = JSON.parse(text);
      if (!raw || typeof raw !== "object") return null;
      if (typeof raw.title !== "string" || raw.title.length > 200) return null;
      return { title: raw.title };
    }
    app.post("/editor/restore", async (req, res) => {
      const restored = readCheckpoint(Buffer.from(req.body.state, "base64").toString("utf8"));
      if (!restored) return res.status(422).json({ error: "invalid" });
      res.json({ title: restored.title });
    });
  `);
  assert.deepEqual(of(found, "unsafe_deserialization"), []);
});


test("a deserializing helper is reported when a handler hands it the request payload", async () => {
  const found = await analyze(`
    const serialize = require("node-serialize");
    const express = require("express");
    const app = express();
    function revive(blob) {
      return serialize.unserialize(blob);
    }
    app.post("/editor/restore", async (req, res) => {
      const restored = revive(req.body.snapshot);
      res.json({ id: restored.id });
    });
  `);
  const hits = of(found, "unsafe_deserialization");
  assert.equal(hits.length, 1, "splitting the handler into a helper does not make the payload trusted");
  assert.equal(hits[0].severity, "critical");
});

test("the same helper is not reported when nothing hands it caller data", async () => {
  const found = await analyze(`
    const fs = require("fs");
    const serialize = require("node-serialize");
    const express = require("express");
    const app = express();
    const SEED = fs.readFileSync("/etc/acme/seed.bin", "utf8");
    function revive(blob) {
      return serialize.unserialize(blob);
    }
    app.post("/editor/restore", async (req, res) => {
      const restored = revive(SEED);
      res.json({ id: restored.id, requested: String(req.body.snapshot || "") });
    });
  `);
  assert.deepEqual(of(found, "unsafe_deserialization"), [], "the helper only ever parses a file the application ships");
});

/* ---------------- prototype_pollution ---------------- */

test("a recursive merge of the request body with no reserved-key guard is reported", async () => {
  const found = await analyze(`
    const express = require("express");
    const app = express();
    const DEFAULTS = { theme: "system", editor: { wrap: true } };
    function foldInto(target, patch) {
      for (const key of Object.keys(patch)) {
        const value = patch[key];
        if (value && typeof value === "object" && !Array.isArray(value)) {
          if (typeof target[key] !== "object" || target[key] === null) target[key] = {};
          foldInto(target[key], value);
        } else {
          target[key] = value;
        }
      }
      return target;
    }
    app.patch("/profiles/:profileId/settings", async (req, res) => {
      const merged = foldInto({ ...DEFAULTS }, req.body);
      res.json({ settings: merged });
    });
  `);
  const hits = of(found, "prototype_pollution");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high");
  assert.equal(hits[0].route, "PATCH /profiles/:profileId/settings");
});

test("the same merge is not reported once it skips the reserved keys", async () => {
  const found = await analyze(`
    const express = require("express");
    const app = express();
    const RESERVED = new Set(["__proto__", "constructor", "prototype"]);
    const DEFAULTS = { theme: "system" };
    function foldInto(target, patch) {
      for (const key of Object.keys(patch)) {
        if (RESERVED.has(key)) continue;
        const value = patch[key];
        if (value && typeof value === "object" && !Array.isArray(value)) {
          if (!Object.hasOwn(target, key)) target[key] = Object.create(null);
          foldInto(target[key], value);
        } else {
          target[key] = value;
        }
      }
      return target;
    }
    app.patch("/profiles/:profileId/settings", async (req, res) => {
      res.json({ settings: foldInto({ ...DEFAULTS }, req.body) });
    });
  `);
  assert.deepEqual(of(found, "prototype_pollution"), []);
});

test("the merge finding points at the assignment that writes the untrusted key", async () => {
  const source = `
    const express = require("express");
    const app = express();
    const DEFAULTS = { theme: "system" };
    function foldInto(target, patch) {
      for (const key of Object.keys(patch)) {
        const value = patch[key];
        if (value && typeof value === "object" && !Array.isArray(value)) {
          foldInto(target[key], value);
        } else {
          target[key] = value;
        }
      }
      return target;
    }
    app.patch("/profiles/:profileId/settings", async (req, res) => {
      res.json({ settings: foldInto({ ...DEFAULTS }, req.body) });
    });
  `;
  const found = await analyze(source);
  const hits = of(found, "prototype_pollution");
  assert.equal(hits.length, 1);
  const line = source.split("\n")[hits[0].location.line - 1];
  assert.match(line, /target\[key\] = value/, "the declaration is not the line a reader has to change");
});

test("a repository method that happens to be called merge is not a deep merge", async () => {
  const found = await analyze(`
    const express = require("express");
    const drafts = require("../repositories/drafts");
    const app = express();
    app.post("/drafts/:draftId/merge", async (req, res) => {
      const merged = await drafts.merge(req.params.draftId, { title: String(req.body.title || ""), revision: 2 });
      res.json({ draft: merged });
    });
  `);
  assert.deepEqual(of(found, "prototype_pollution"), [], "a domain method named merge is not lodash");
});

test("a lodash deep merge of the request body into an existing object is reported", async () => {
  const found = await analyze(`
    const _ = require("lodash");
    const express = require("express");
    const app = express();
    const settings = require("../repositories/settings");
    app.patch("/workspaces/:workspaceId/settings", async (req, res) => {
      const stored = await settings.load(req.params.workspaceId);
      _.merge(stored, req.body);
      await settings.save(req.params.workspaceId, stored);
      res.json({ settings: stored });
    });
  `);
  assert.equal(of(found, "prototype_pollution").length, 1);
});

/* ---------------- code_injection ---------------- */

test("a formula compiled into a vm script is reported", async () => {
  const found = await analyze(`
    const vm = require("node:vm");
    const express = require("express");
    const app = express();
    app.post("/reports/columns", async (req, res) => {
      const { expression } = req.body;
      const compiled = new vm.Script("(row) => (" + expression + ")");
      const project = compiled.runInThisContext();
      res.json({ sample: project({ revenue: 10 }) });
    });
  `);
  const hits = of(found, "code_injection");
  assert.equal(hits.length, 1, "the compilation is reported once, at the point the source is built");
  assert.equal(hits[0].severity, "critical");
  assert.equal(hits[0].route, "POST /reports/columns");
});

test("a catalogue of server-defined projections is not reported", async () => {
  const found = await analyze(`
    const express = require("express");
    const app = express();
    const METRICS = {
      margin: (row) => Number(row.revenue || 0) - Number(row.cost || 0),
      rate: (row) => (row.views ? Number(row.clicks || 0) / Number(row.views) : 0)
    };
    app.post("/reports/columns", async (req, res) => {
      const project = Object.hasOwn(METRICS, String(req.body.metric)) ? METRICS[req.body.metric] : null;
      if (!project) return res.status(400).json({ error: "unknown metric", supported: Object.keys(METRICS) });
      res.json({ sample: project({ revenue: 10, cost: 4 }) });
    });
  `);
  assert.deepEqual(of(found, "code_injection"), []);
});

test("a caller-controlled module specifier is reported", async () => {
  const found = await analyze(`
    const express = require("express");
    const app = express();
    app.post("/plugins/run", async (req, res) => {
      const plugin = require("../plugins/" + req.body.name);
      res.json({ result: plugin.run() });
    });
  `);
  const hits = of(found, "code_injection");
  assert.equal(hits.length, 1);
  assert.match(hits[0].title, /module/);
});

test("vm.runInContext with caller data is reported and a fixed script is not", async () => {
  const reported = await analyze(`
    const vm = require("node:vm");
    const express = require("express");
    const app = express();
    app.post("/sandbox", async (req, res) => {
      const context = vm.createContext({});
      res.json({ value: vm.runInContext(req.body.script, context, { timeout: 50 }) });
    });
  `);
  assert.equal(of(reported, "code_injection").length, 1);

  const quiet = await analyze(`
    const vm = require("node:vm");
    const express = require("express");
    const app = express();
    const SCRIPT = "1 + 1";
    app.post("/sandbox", async (req, res) => {
      res.json({ value: vm.runInNewContext(SCRIPT, { input: Number(req.body.input) }, { timeout: 50 }) });
    });
  `);
  assert.deepEqual(of(quiet, "code_injection"), [], "a fixed script with caller data as context is not code injection");
});

test("a timer taking a real callback is not reported", async () => {
  const found = await analyze(`
    const express = require("express");
    const app = express();
    app.post("/jobs", async (req, res) => {
      const delay = Number(req.body.delay || 0);
      setTimeout(() => console.info("job ran"), delay);
      res.json({ scheduled: true });
    });
  `);
  assert.deepEqual(of(found, "code_injection"), []);
});

/* ---------------- route attribution ---------------- */

test("a handler reached through a dispatch table keeps its route", async () => {
  const found = await analyze(`
    const http = require("node:http");
    const serialize = require("node-serialize");
    async function restoreSnapshot(request, response) {
      const body = await readBody(request);
      const restored = serialize.unserialize(body);
      response.end(JSON.stringify({ id: restored.id }));
    }
    async function readBody(request) { return new Promise((resolve) => request.on("end", () => resolve(""))); }
    const routes = { "POST /api/snapshots/restore": restoreSnapshot };
    http.createServer(async (request, response) => {
      const url = new URL(request.url, "http://localhost");
      const handler = routes[request.method + " " + url.pathname];
      if (handler) return handler(request, response);
      response.statusCode = 404;
      response.end();
    }).listen(8080);
  `);
  const hits = of(found, "unsafe_deserialization");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].route, "POST /api/snapshots/restore");
});

test("a handler reached through a switch keeps its route, and a regex route is named after the handler's parameter", async () => {
  const table = await analyze(`
    const http = require("node:http");
    const vm = require("node:vm");
    async function evaluate(request, response, url) {
      const source = url.searchParams.get("expression");
      const script = new vm.Script("(" + source + ")");
      response.end(String(script.runInThisContext()));
    }
    http.createServer(async (request, response) => {
      const url = new URL(request.url, "http://localhost");
      switch (request.method + " " + url.pathname) {
        case "POST /api/calculator/evaluate":
          return evaluate(request, response, url);
        default:
          response.statusCode = 404;
          response.end();
      }
    }).listen(8080);
  `);
  assert.equal(of(table, "code_injection")[0]?.route, "POST /api/calculator/evaluate");

  const regex = await analyze(`
    const http = require("node:http");
    const libxml = require("libxmljs2");
    const IMPORT_PATH = /^\\/api\\/suppliers\\/([a-z0-9-]+)\\/documents$/;
    async function importDocument(request, response, supplierId) {
      const document = await request.text();
      const parsed = libxml.parseXml(document, { noent: true, dtdload: true });
      response.end(JSON.stringify({ supplierId, root: parsed.root().name() }));
    }
    http.createServer(async (request, response) => {
      const url = new URL(request.url, "http://localhost");
      if (request.method === "POST" && IMPORT_PATH.test(url.pathname)) {
        return importDocument(request, response, url.pathname.split("/")[3]);
      }
      response.statusCode = 404;
      response.end();
    }).listen(8080);
  `);
  assert.equal(of(regex, "xml_external_entity")[0]?.route, "POST /api/suppliers/:supplierId/documents");
});
