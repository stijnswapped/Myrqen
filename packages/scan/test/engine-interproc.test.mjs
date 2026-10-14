import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * Inter-procedural, cross-file taint.
 *
 * Every positive has a near-miss negative beside it, because the risk of following a value
 * across a boundary is inventing a flow, and a scanner that invents flows is worse than
 * one that misses them. The negatives are the half of this file that matters most.
 */
async function scanFiles(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-interproc-"));
  for (const [relativePath, contents] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, contents, "utf8");
  }
  try {
    return await scan({ repoRoot: root });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const PKG = JSON.stringify({ name: "app", version: "1.0.0", type: "module", dependencies: { express: "^4.19.0", pg: "^8.11.0" } });

const findings = (result, category, file) =>
  result.candidates.filter((candidate) => candidate.category === category && (!file || candidate.location.file === file));

/* ---------- two hops across three files ---------- */

const ROUTE = (argument) => `import express from "express";
import { showReport } from "../controllers/reports.js";
export const router = express.Router();
router.get("/reports/:id", async (req, res) => {
  res.json(await showReport(${argument}));
});
`;
const CONTROLLER = `import { runReport } from "../services/report-service.js";
export async function showReport(sort) {
  const rows = await runReport(sort);
  return { rows };
}
`;
const SERVICE = `import { pool } from "../db.js";
export async function runReport(column) {
  const { rows } = await pool.query(\`SELECT id, total FROM invoices ORDER BY \${column}\`);
  return rows;
}
`;
const DB = `import pg from "pg";\nexport const pool = new pg.Pool();\n`;

test("a value from a route reaches a SQL sink two calls and two files away", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/routes/reports.js": ROUTE("req.query.sort"),
    "src/controllers/reports.js": CONTROLLER,
    "src/services/report-service.js": SERVICE,
    "src/db.js": DB
  });
  const hits = findings(result, "sql_injection", "src/services/report-service.js");
  assert.equal(hits.length, 1, JSON.stringify(result.candidates.map((c) => [c.ruleId, c.location])));
  assert.match(hits[0].reasoning + JSON.stringify(hits[0].evidence), /req\.query\.sort|handed to/);
});

test("the same chain stays silent when the route coerces the value to a number", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/routes/reports.js": ROUTE("Number(req.query.sort)"),
    "src/controllers/reports.js": CONTROLLER,
    "src/services/report-service.js": SERVICE,
    "src/db.js": DB
  });
  assert.equal(findings(result, "sql_injection").length, 0);
});

test("the same chain stays silent when the route hands over a constant", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/routes/reports.js": ROUTE('"created_at"'),
    "src/controllers/reports.js": CONTROLLER,
    "src/services/report-service.js": SERVICE,
    "src/db.js": DB
  });
  assert.equal(findings(result, "sql_injection").length, 0);
});

/* ---------- CommonJS ---------- */

test("CommonJS: a required service module is followed", async () => {
  const route = `const express = require("express");
const reports = require("../services/reports");
const router = express.Router();
router.get("/export", async (req, res) => {
  res.json(await reports.exportRows(req.query.order));
});
module.exports = router;
`;
  const service = `const { pool } = require("../db");
async function exportRows(order) {
  const result = await pool.query("SELECT * FROM exports ORDER BY " + order);
  return result.rows;
}
module.exports = { exportRows };
`;
  const result = await scanFiles({
    "package.json": JSON.stringify({ name: "cjs", version: "1.0.0", dependencies: { express: "^4.19.0", pg: "^8.11.0" } }),
    "src/routes/export.js": route,
    "src/services/reports.js": service,
    "src/db.js": 'const { Pool } = require("pg");\nmodule.exports = { pool: new Pool() };\n'
  });
  assert.equal(findings(result, "sql_injection", "src/services/reports.js").length, 1);
});

/* ---------- object arguments are seeded per property ---------- */

const SEARCH_ROUTE = `import express from "express";
import { searchOrders } from "./search.js";
export const router = express.Router();
router.get("/orders", async (req, res) => {
  res.json(await searchOrders({ term: req.query.q, viewer: req.user }));
});
`;

test("an object argument taints the property the caller filled", async () => {
  const service = `import { pool } from "./db.js";
export async function searchOrders(options) {
  return pool.query(\`SELECT * FROM orders WHERE note LIKE '%\${options.term}%' AND owner = $1\`, [options.viewer.id]);
}
`;
  const result = await scanFiles({ "package.json": PKG, "src/route.js": SEARCH_ROUTE, "src/search.js": service, "src/db.js": DB });
  assert.equal(findings(result, "sql_injection", "src/search.js").length, 1);
});

test("an object argument does not taint the identity riding beside the value", async () => {
  const service = `import { pool } from "./db.js";
export async function searchOrders({ term, viewer }) {
  return pool.query(\`SELECT * FROM orders WHERE owner = '\${viewer.id}' AND note LIKE $1\`, [\`%\${term}%\`]);
}
`;
  const result = await scanFiles({ "package.json": PKG, "src/route.js": SEARCH_ROUTE, "src/search.js": service, "src/db.js": DB });
  assert.equal(findings(result, "sql_injection").length, 0, JSON.stringify(result.candidates.map((c) => [c.ruleId, c.location])));
});

/* ---------- the authenticated subject is not caller data ---------- */

test("a session identity handed to a service is not treated as caller data", async () => {
  const route = `import express from "express";
import { listMine } from "./svc.js";
export const router = express.Router();
router.get("/mine", async (req, res) => {
  res.json(await listMine(req.user.id));
});
`;
  const svc = `import { pool } from "./db.js";
export async function listMine(userId) {
  return pool.query(\`SELECT * FROM notes WHERE owner_id = '\${userId}'\`);
}
`;
  const result = await scanFiles({ "package.json": PKG, "src/route.js": route, "src/svc.js": svc, "src/db.js": DB });
  assert.equal(findings(result, "sql_injection").length, 0);
});

/* ---------- a utility called from everywhere is not a finding about any caller ---------- */

test("a file helper handed caller paths from many modules is treated as a utility", async () => {
  const helper = `import fs from "node:fs/promises";
export async function readIfPresent(target) {
  try { return await fs.readFile(target, "utf8"); } catch { return null; }
}
`;
  const files = { "package.json": PKG, "src/util/read.js": helper };
  for (const name of ["a", "b", "c", "d"]) {
    files[`src/routes/${name}.js`] = `import express from "express";
import { readIfPresent } from "../util/read.js";
export const router = express.Router();
router.get("/${name}", async (req, res) => {
  res.send(await readIfPresent(req.query.file));
});
`;
  }
  const result = await scanFiles(files);
  assert.equal(findings(result, "path_traversal", "src/util/read.js").length, 0);
});

/* ---------- classes, injection and aliases ---------- */

test("a controller class reaches a repository through an injected service, two hops", async () => {
  const controller = `import express from "express";
import { InvoiceService } from "./invoice.service.js";
const service = new InvoiceService();
export const router = express.Router();
router.get("/invoices", async (req, res) => {
  res.json(await service.list(req.query.status));
});
`;
  const svc = `import { InvoiceRepository } from "./invoice.repository.js";
export class InvoiceService {
  constructor() { this.repository = new InvoiceRepository(); }
  async list(status) { return this.repository.byStatus(status); }
}
`;
  const repo = `import { pool } from "./db.js";
export class InvoiceRepository {
  async byStatus(status) {
    return pool.query("SELECT * FROM invoices WHERE status = '" + status + "'");
  }
}
`;
  const result = await scanFiles({
    "package.json": PKG,
    "src/controller.js": controller,
    "src/invoice.service.js": svc,
    "src/invoice.repository.js": repo,
    "src/db.js": DB
  });
  assert.equal(findings(result, "sql_injection", "src/invoice.repository.js").length, 1);
});

test("a tsconfig path alias and an index re-export are followed", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "tsconfig.json": JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@services/*": ["src/services/*"] } } }),
    "src/app/route.ts": `import express from "express";
import { runSearch } from "@services/search";
export const router = express.Router();
router.get("/s", async (req, res) => { res.json(await runSearch(String(req.query.q))); });
`,
    "src/services/search/index.ts": 'export { runSearch } from "./run";\n',
    "src/services/search/run.ts": `import { exec } from "node:child_process";
export function runSearch(term: string) {
  return new Promise((resolve) => exec(\`grep -r \${term} /srv/index\`, (_e, out) => resolve(out)));
}
`
  });
  assert.equal(findings(result, "command_injection", "src/services/search/run.ts").length, 1,
    JSON.stringify(result.candidates.map((c) => [c.ruleId, c.location])));
});

test("a callee that validates its parameter against an allowlist stays silent", async () => {
  const svc = `import { pool } from "./db.js";
const SORTABLE = new Set(["created_at", "total"]);
export async function runReport(column) {
  if (!SORTABLE.has(column)) throw new Error("bad sort");
  const { rows } = await pool.query(\`SELECT id FROM invoices ORDER BY \${column}\`);
  return rows;
}
`;
  const result = await scanFiles({
    "package.json": PKG,
    "src/routes/reports.js": ROUTE("req.query.sort"),
    "src/controllers/reports.js": CONTROLLER,
    "src/services/report-service.js": svc,
    "src/db.js": DB
  });
  assert.equal(findings(result, "sql_injection").length, 0);
});
