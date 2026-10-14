import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";
import { parseFile } from "../dist/ast/parse.js";
import { buildModuleGraph } from "../dist/engine/modules.js";
import { requestHandlers } from "../dist/engine/handlers.js";

/**
 * Request handlers by the framework's contract — position, not parameter name — and the
 * middleware in front of each one.
 */
async function withProject(files, body) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-handlers-"));
  for (const [relativePath, contents] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, contents, "utf8");
  }
  try {
    return await body(root);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

async function handlersOf(files, registeredIn) {
  return withProject(files, async (root) => {
    const parsed = [];
    for (const relativePath of Object.keys(files)) {
      if (/\.[cm]?[jt]sx?$/.test(relativePath)) parsed.push(await parseFile(root, path.join(root, relativePath)));
    }
    const graph = await buildModuleGraph(root, parsed);
    const file = parsed.find((candidate) => candidate.relativePath === registeredIn);
    return requestHandlers(graph, file).map((handler) => ({
      file: handler.file.relativePath,
      method: handler.method,
      path: handler.path,
      isMiddleware: handler.isMiddleware,
      requestParameters: handler.requestParameters,
      middleware: handler.middleware.map((ref) => ({ name: ref.name, authenticates: ref.authenticates, authorizes: ref.authorizes }))
    }));
  });
}

const PKG = JSON.stringify({ name: "app", version: "1.0.0", type: "module", dependencies: { express: "^4.19.0", pg: "^8.11.0" } });
const findings = (result, category, file) =>
  result.candidates.filter((candidate) => candidate.category === category && (!file || candidate.location.file === file));
const scanFiles = (files) => withProject(files, (root) => scan({ repoRoot: root }));

test("an imported controller method registered on a router is a handler, with its gates", async () => {
  const handlers = await handlersOf(
    {
      "src/routes.js": `import express from "express";
import { requireUser } from "./auth.js";
import { orders } from "./orders.controller.js";
export const router = express.Router();
router.use(requireUser);
router.get("/orders/:id", requireRole("admin"), orders.show);
`,
      "src/auth.js": "export function requireUser(req, res, next) { if (!req.session) return res.status(401).end(); next(); }\n",
      "src/orders.controller.js": "export const orders = {\n  async show(request, response) { response.json(request.params.id); }\n};\n"
    },
    "src/routes.js"
  );
  const show = handlers.find((handler) => !handler.isMiddleware);
  assert.equal(show.file, "src/orders.controller.js");
  assert.equal(show.method, "GET");
  assert.equal(show.path, "/orders/:id");
  assert.deepEqual(show.requestParameters, [0]);
  assert.deepEqual(
    show.middleware.map((ref) => [ref.name, ref.authenticates, ref.authorizes]),
    [
      ["requireUser", true, false],
      ["requireRole", true, true]
    ]
  );
});

test("an Express error handler takes the request second", async () => {
  const handlers = await handlersOf(
    { "src/app.js": 'import express from "express";\nconst app = express();\napp.use((err, req, res, next) => res.status(500).end());\n' },
    "src/app.js"
  );
  assert.deepEqual(handlers[0].requestParameters, [1]);
});

test("a handler whose request parameter has an unusual name is still read as receiving caller data", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/routes.js": `import express from "express";
import { pool } from "./db.js";
export const router = express.Router();
router.get("/invoices", async (incoming, outgoing) => {
  const { rows } = await pool.query(\`SELECT * FROM invoices WHERE status = '\${incoming.query.status}'\`);
  outgoing.json(rows);
});
`,
    "src/db.js": 'import pg from "pg";\nexport const pool = new pg.Pool();\n'
  });
  assert.equal(findings(result, "sql_injection", "src/routes.js").length, 1);
});

test("a handler registered from another module is read as receiving caller data", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/routes.js": `import express from "express";
import { listInvoices } from "./invoices.js";
export const router = express.Router();
router.get("/invoices", listInvoices);
`,
    "src/invoices.js": `import { pool } from "./db.js";
export async function listInvoices(incoming, outgoing) {
  const { rows } = await pool.query("SELECT * FROM invoices WHERE status = '" + incoming.query.status + "'");
  outgoing.json(rows);
}
`,
    "src/db.js": 'import pg from "pg";\nexport const pool = new pg.Pool();\n'
  });
  assert.equal(findings(result, "sql_injection", "src/invoices.js").length, 1);
});

test("a function that is never registered and only has a parameter called context does not start a chain", async () => {
  const result = await scanFiles({
    "package.json": JSON.stringify({ name: "cli", version: "1.0.0", type: "module" }),
    "src/detect.js": `import { probe } from "./probe.js";
export async function detect(context) {
  const binary = context.paths.find((candidate) => candidate.endsWith("agent"));
  return probe(binary);
}
`,
    "src/probe.js": `import { execFile } from "node:child_process";
export function probe(command) {
  return new Promise((resolve) => execFile(command, ["--version"], (_e, out) => resolve(out)));
}
`
  });
  assert.equal(findings(result, "command_injection").length, 0);
});

test("a node:http server callback is a handler", async () => {
  const handlers = await handlersOf(
    { "src/server.js": 'import http from "node:http";\nhttp.createServer(async (incoming, outgoing) => { outgoing.end(); }).listen(3000);\n' },
    "src/server.js"
  );
  assert.equal(handlers.length, 1);
  assert.equal(handlers[0].method, "ANY");
});

test("a Next.js App Router export wrapped in a helper is a handler with its context", async () => {
  const handlers = await handlersOf(
    {
      "app/api/orders/[id]/route.ts": `import { withAuth } from "@/lib/auth";
export const GET = withAuth(async (incoming: Request, ctx: { params: { id: string } }) => Response.json(ctx.params.id));
export async function POST(incoming: Request) { return Response.json(await incoming.json()); }
`
    },
    "app/api/orders/[id]/route.ts"
  );
  const verbs = handlers.map((handler) => [handler.method, handler.requestParameters]);
  assert.deepEqual(verbs.sort(), [["GET", [0, 1]], ["POST", [0]]].sort());
});

test("a validating helper in another module clears what it returns", async () => {
  const route = (helper) => `import express from "express";
import { pool } from "./db.js";
import { ${helper} } from "./validate.js";
export const router = express.Router();
router.get("/invoices", async (req, res) => {
  const sort = ${helper}(req.query.sort);
  const { rows } = await pool.query(\`SELECT * FROM invoices ORDER BY \${sort}\`);
  res.json(rows);
});
`;
  const validate = `const COLUMNS = new Set(["created_at", "total"]);
export function sortColumn(raw) {
  return COLUMNS.has(raw) ? raw : "created_at";
}
export function passThrough(raw) {
  return String(raw).trim();
}
`;
  const db = 'import pg from "pg";\nexport const pool = new pg.Pool();\n';
  const safe = await scanFiles({ "package.json": PKG, "src/route.js": route("sortColumn"), "src/validate.js": validate, "src/db.js": db });
  assert.equal(findings(safe, "sql_injection").length, 0, "an allowlist helper's result is one of its own constants");
  const unsafe = await scanFiles({ "package.json": PKG, "src/route.js": route("passThrough"), "src/validate.js": validate, "src/db.js": db });
  assert.equal(findings(unsafe, "sql_injection", "src/route.js").length, 1, "a helper that hands the value back keeps it tainted");
});

test("a body reader written as a Promise is not mistaken for a sanitiser", async () => {
  const result = await scanFiles({
    "package.json": JSON.stringify({ name: "plain", version: "1.0.0" }),
    "src/server.js": `const http = require("node:http");
const { exec } = require("node:child_process");
function readJson(stream) {
  return new Promise((resolve) => {
    const chunks = [];
    stream.on("data", (chunk) => chunks.push(chunk));
    stream.on("end", () => resolve(JSON.parse(Buffer.concat(chunks).toString())));
  });
}
http.createServer(async (incoming, outgoing) => {
  const { name } = await readJson(incoming);
  exec("convert /srv/in/" + name + " /srv/out.pdf");
  outgoing.end();
}).listen(8080);
`
  });
  assert.equal(findings(result, "command_injection").length, 1);
});
