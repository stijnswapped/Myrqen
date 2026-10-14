import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * The false positives holdout-5 found, each pinned as a pair.
 *
 * Every one of these was correct code this engine reported. They are kept together
 * because they share a cause worth naming: each rule understood the guard perfectly
 * well in one spelling and not in another — a frozen options object rather than a
 * bare one, an abort call rather than a `throw` statement, a lookup table rather
 * than a membership test, a tenant column the vocabulary had never heard of.
 *
 * So each test asserts both directions. Silence on the correct form proves the guard
 * is recognised; a report on the broken form proves nothing was switched off to buy
 * that silence. A one-directional version of this file would be indistinguishable
 * from deleting the rules.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-fp5-"));
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

const categories = (result) => result.candidates.map((candidate) => candidate.category);
const PKG = (deps) => JSON.stringify({ name: "case", version: "1.0.0", private: true, dependencies: deps });

/* ------------------------------------------- a frozen verify-options constant */

const session = (options) => `const jwt = require("jsonwebtoken");
${options}
async function attach(ctx, next) {
  const token = ctx.headers.authorization;
  if (!token) return next();
  let claims;
  try { claims = jwt.verify(token, process.env.MEDIA_SECRET, OPTIONS); } catch { return next(); }
  ctx.state.user = { id: claims.sub };
  return next();
}
module.exports = { attach };
`;

test("verify options pinned in a frozen constant are recognised", async () => {
  const result = await scanSource({
    "package.json": PKG({ jsonwebtoken: "^9.0.2" }),
    "src/session.js": session(`const OPTIONS = Object.freeze({ algorithms: ["HS256"], issuer: "media", audience: "api" });`)
  });
  assert.deepEqual(categories(result), []);
});

test("a frozen constant that pins no algorithm is still reported", async () => {
  const result = await scanSource({
    "package.json": PKG({ jsonwebtoken: "^9.0.2" }),
    "src/session.js": session(`const OPTIONS = Object.freeze({ issuer: "media", audience: "api" });`)
  });
  assert.deepEqual(categories(result), ["jwt_verification_bypass"]);
});

/* ------------------------------------------------ an abort call is a terminator */

const mongoHandler = (guard) => `const mongoose = require("mongoose");
const { Asset } = require("./models");
async function handler(ctx) {
  const { assetId } = ctx.request.body || {};
${guard}
  const asset = await Asset.findOne({ _id: assetId }).lean();
  ctx.body = { asset };
}
module.exports = { handler };
`;

test("a validating predicate whose failure aborts the request is a guard", async () => {
  const result = await scanSource({
    "package.json": PKG({ mongoose: "^8.4.0", koa: "^2.15.0" }),
    "src/assets.js": mongoHandler(`  if (!mongoose.isValidObjectId(assetId)) ctx.throw(400, "bad id");`)
  });
  assert.deepEqual(categories(result), []);
});

test("an abort call guarding a different value is not a guard for this one", async () => {
  const result = await scanSource({
    "package.json": PKG({ mongoose: "^8.4.0", koa: "^2.15.0" }),
    "src/assets.js": mongoHandler(`  if (!mongoose.isValidObjectId(ctx.params.other)) ctx.throw(400, "bad id");`)
  });
  assert.deepEqual(categories(result), ["nosql_injection"]);
});

test("an existence check is not a type check", async () => {
  const result = await scanSource({
    "package.json": PKG({ mongoose: "^8.4.0", koa: "^2.15.0" }),
    "src/assets.js": mongoHandler(`  if (!assetId) ctx.throw(400, "missing");`)
  });
  assert.deepEqual(categories(result), ["nosql_injection"]);
});

/* ------------------------------------------------------- an allowlist as a table */

const sorted = (assignment) => `const express = require("express");
const { pool } = require("./db");
const SORT_COLUMNS = { bucket: "bucket", total: "total", events: "events" };
const router = express.Router();
router.get("/usage", async (req, res) => {
${assignment}
  const rows = await pool.query(\`SELECT * FROM usage ORDER BY \${sortColumn}\`);
  res.json(rows);
});
module.exports = router;
`;

test("a value read out of a constant lookup table is not the caller's data", async () => {
  const result = await scanSource({
    "package.json": PKG({ express: "^4.19.2" }),
    "src/usage.js": sorted(`  const sortColumn = SORT_COLUMNS[req.query.sort ?? "bucket"];`)
  });
  assert.deepEqual(categories(result), []);
});

test("the caller's data spliced in directly is still reported", async () => {
  const result = await scanSource({
    "package.json": PKG({ express: "^4.19.2" }),
    "src/usage.js": sorted(`  const sortColumn = req.query.sort ?? "bucket";`)
  });
  assert.deepEqual(categories(result), ["sql_injection"]);
});

/* --------------------------------------- a tenant column the vocabulary lacks */

const scopedRead = (binding) => `const express = require("express");
const { queryOne } = require("./db");
const { getSession } = require("./session");
const router = express.Router();
router.get("/:refundId", requireSession, async (req, res) => {
  const session = getSession(req);
  const refund = await queryOne(
    "SELECT id, amount FROM refunds WHERE id = $1 AND merchant_id = $2",
    ${binding},
  );
  if (!refund) return res.status(404).json({ error: "not_found" });
  res.json({ refund });
});
module.exports = router;
`;

test("a predicate filtered by the caller's own identity is scoped, whatever the column is called", async () => {
  const result = await scanSource({
    "package.json": PKG({ express: "^4.19.2" }),
    "src/refunds.js": scopedRead(`[req.params.refundId, session.merchantId]`)
  });
  assert.deepEqual(categories(result), []);
});

test("the same column filled from the caller is not a scope", async () => {
  const result = await scanSource({
    "package.json": PKG({ express: "^4.19.2" }),
    "src/refunds.js": scopedRead(`[req.params.refundId, req.query.merchantId]`)
  });
  assert.deepEqual(categories(result), ["broken_object_level_authorization"]);
});

/* ------------------------------------------------- ownership checked after the fetch */

const checkAfterFetch = (gate) => `const express = require("express");
const { prisma } = require("./db");
const { getMembership } = require("./auth");
const router = express.Router();
router.get("/:id/documents", requireSession, async (req, res) => {
  const folder = await prisma.folder.findUnique({ where: { id: req.params.id } });
  if (!folder) return res.status(404).json({ error: "not_found" });
${gate}
  const docs = await prisma.document.findMany({ where: { folderId: folder.id } });
  // The folder row itself is returned, which is what makes an unscoped read of it a
  // disclosure rather than an internal step towards a scoped query.
  res.json({ folder, docs });
});
module.exports = router;
`;

test("a membership check on the fetched row's tenant is an ownership check", async () => {
  const result = await scanSource({
    "package.json": PKG({ express: "^4.19.2", "@prisma/client": "^5.14.0" }),
    "src/folders.js": checkAfterFetch(`  const membership = await getMembership(req.user.id, folder.workspaceId);
  if (!membership) return res.status(404).json({ error: "not_found" });`)
  });
  assert.deepEqual(categories(result), []);
});

test("a fetch with nothing checked afterwards is still reported", async () => {
  const result = await scanSource({
    "package.json": PKG({ express: "^4.19.2", "@prisma/client": "^5.14.0" }),
    "src/folders.js": checkAfterFetch(``)
  });
  assert.deepEqual(categories(result), ["broken_object_level_authorization"]);
});
