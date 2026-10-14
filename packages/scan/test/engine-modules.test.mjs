import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import ts from "typescript";
import { parseFile } from "../dist/ast/parse.js";
import { buildModuleGraph } from "../dist/engine/modules.js";

/**
 * The module graph: which file and which declaration a local name refers to.
 *
 * Every cross-file question the engine asks — "which function does this call reach",
 * "which parameter does this argument land in" — starts with resolving a name through an
 * import. Each spelling below is one a real project uses, and each one that fails to
 * resolve is a flow the engine silently stops following.
 */
async function graphOf(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-modules-"));
  for (const [relativePath, contents] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, contents, "utf8");
  }
  const parsed = [];
  for (const relativePath of Object.keys(files)) {
    if (!/\.[cm]?[jt]sx?$/.test(relativePath)) continue;
    parsed.push(await parseFile(root, path.join(root, relativePath)));
  }
  const graph = await buildModuleGraph(root, parsed);
  await fs.rm(root, { recursive: true, force: true });
  return { graph, byPath: new Map(parsed.map((file) => [file.relativePath, file])) };
}

function definitionName(definition) {
  if (!definition) return null;
  const node = definition.node;
  if (node.name && ts.isIdentifier(node.name)) return `${definition.file.relativePath}#${node.name.text}`;
  const parent = node.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    return `${definition.file.relativePath}#${parent.name.text}`;
  }
  if (parent && ts.isBinaryExpression(parent) && ts.isPropertyAccessExpression(parent.left)) {
    return `${definition.file.relativePath}#${parent.left.name.text}`;
  }
  if (parent && (ts.isPropertyAssignment(parent) || ts.isMethodDeclaration(parent)) && ts.isIdentifier(parent.name)) {
    return `${definition.file.relativePath}#${parent.name.text}`;
  }
  return `${definition.file.relativePath}#<${ts.SyntaxKind[node.kind]}>`;
}

test("a named ESM import resolves to the exported function declaration", async () => {
  const { graph, byPath } = await graphOf({
    "src/service.ts": "export function findOrder(id: string) { return id; }\n",
    "src/route.ts": 'import { findOrder as lookup } from "./service";\nlookup("1");\n'
  });
  const resolved = graph.resolveLocal(byPath.get("src/route.ts"), "lookup");
  assert.equal(definitionName(resolved), "src/service.ts#findOrder");
});

test("a default import resolves to the default-exported function", async () => {
  const { graph, byPath } = await graphOf({
    "src/handler.js": "export default async function handle(req) { return req; }\n",
    "src/app.js": 'import handle from "./handler.js";\n'
  });
  assert.equal(definitionName(graph.resolveLocal(byPath.get("src/app.js"), "handle")), "src/handler.js#handle");
});

test("re-exports and star re-exports from an index file are followed", async () => {
  const { graph, byPath } = await graphOf({
    "src/lib/search.ts": "export const runSearch = (term: string) => term;\n",
    "src/lib/ids.ts": "export function parseId(raw: string) { return Number(raw); }\n",
    "src/lib/index.ts": 'export { runSearch as search } from "./search";\nexport * from "./ids";\n',
    "src/route.ts": 'import { search, parseId } from "./lib";\n'
  });
  const route = byPath.get("src/route.ts");
  assert.equal(definitionName(graph.resolveLocal(route, "search")), "src/lib/search.ts#runSearch");
  assert.equal(definitionName(graph.resolveLocal(route, "parseId")), "src/lib/ids.ts#parseId");
});

test("a re-export of a local binding under another name is followed", async () => {
  const { graph, byPath } = await graphOf({
    "src/a.ts": "function inner(x: string) { return x; }\nexport { inner as outer };\n",
    "src/b.ts": 'import { outer } from "./a";\n'
  });
  assert.equal(definitionName(graph.resolveLocal(byPath.get("src/b.ts"), "outer")), "src/a.ts#inner");
});

test("CommonJS: module.exports object, exports.name and destructured require", async () => {
  const { graph, byPath } = await graphOf({
    "lib/db.js": "function query(sql) { return sql; }\nfunction one(sql) { return sql; }\nmodule.exports = { query, first: one };\n",
    "lib/util.js": "exports.slugify = function slugify(text) { return text; };\nmodule.exports.clean = (v) => v;\n",
    "routes/a.js":
      'const { query, first: pick } = require("../lib/db");\nconst util = require("../lib/util");\nconst clean = require("../lib/util").clean;\n'
  });
  const route = byPath.get("routes/a.js");
  assert.equal(definitionName(graph.resolveLocal(route, "query")), "lib/db.js#query");
  assert.equal(definitionName(graph.resolveLocal(route, "pick")), "lib/db.js#one");
  assert.equal(definitionName(graph.resolveLocal(route, "clean")), "lib/util.js#clean");
  assert.equal(definitionName(graph.resolveMember(route, "util", "slugify")), "lib/util.js#slugify");
});

test("CommonJS: module.exports = function is the default", async () => {
  const { graph, byPath } = await graphOf({
    "lib/render.js": "module.exports = function render(template, data) { return template; };\n",
    "app.js": 'const render = require("./lib/render");\n'
  });
  assert.equal(definitionName(graph.resolveLocal(byPath.get("app.js"), "render")), "lib/render.js#render");
});

test("a namespace import resolves members to exports", async () => {
  const { graph, byPath } = await graphOf({
    "src/repo.ts": "export async function byId(id: string) { return id; }\n",
    "src/route.ts": 'import * as repo from "./repo";\n'
  });
  assert.equal(definitionName(graph.resolveMember(byPath.get("src/route.ts"), "repo", "byId")), "src/repo.ts#byId");
});

test("tsconfig paths with a wildcard resolve an aliased specifier", async () => {
  const { graph, byPath } = await graphOf({
    "tsconfig.json": JSON.stringify({
      // comments are legal in tsconfig and must not break the read
      compilerOptions: { baseUrl: ".", paths: { "@server/*": ["src/server/*"], "~db": ["src/db/client.ts"] } }
    }),
    "src/server/orders/service.ts": "export function load(id: string) { return id; }\n",
    "src/db/client.ts": "export function raw(sql: string) { return sql; }\n",
    "src/app/route.ts": 'import { load } from "@server/orders/service";\nimport { raw } from "~db";\n'
  });
  const route = byPath.get("src/app/route.ts");
  assert.equal(definitionName(graph.resolveLocal(route, "load")), "src/server/orders/service.ts#load");
  assert.equal(definitionName(graph.resolveLocal(route, "raw")), "src/db/client.ts#raw");
});

test("tsconfig paths survive comments and trailing commas, and extends is followed", async () => {
  const { graph, byPath } = await graphOf({
    "tsconfig.base.json": '{\n  // shared\n  "compilerOptions": { "baseUrl": ".", "paths": { "@lib/*": ["lib/*"], }, },\n}\n',
    "tsconfig.json": '{ "extends": "./tsconfig.base.json" }\n',
    "lib/mail.ts": "export function send(to: string) { return to; }\n",
    "src/x.ts": 'import { send } from "@lib/mail";\n'
  });
  assert.equal(definitionName(graph.resolveLocal(byPath.get("src/x.ts"), "send")), "lib/mail.ts#send");
});

test("an exported singleton instance resolves a method on its class", async () => {
  const { graph, byPath } = await graphOf({
    "src/orders.service.ts":
      "export class OrdersService {\n  find(id: string) { return id; }\n}\nexport const ordersService = new OrdersService();\n",
    "src/route.ts": 'import { ordersService } from "./orders.service";\n'
  });
  assert.equal(
    definitionName(graph.resolveMember(byPath.get("src/route.ts"), "ordersService", "find")),
    "src/orders.service.ts#find"
  );
});

test("an exported object literal of methods resolves each member", async () => {
  const { graph, byPath } = await graphOf({
    "src/svc.js": "export default {\n  async list(filter) { return filter; },\n  remove: async (id) => id\n};\n",
    "src/route.js": 'import svc from "./svc.js";\n'
  });
  const route = byPath.get("src/route.js");
  assert.equal(definitionName(graph.resolveMember(route, "svc", "list")), "src/svc.js#list");
  assert.equal(definitionName(graph.resolveMember(route, "svc", "remove")), "src/svc.js#remove");
});

test("a bare package specifier is never resolved into the project", async () => {
  const { graph, byPath } = await graphOf({
    "src/express.ts": "export function Router() { return null; }\n",
    "src/app.ts": 'import { Router } from "express";\n'
  });
  assert.equal(graph.resolveLocal(byPath.get("src/app.ts"), "Router"), null);
});

test("an ambiguous suffix alias is refused rather than guessed", async () => {
  const { graph, byPath } = await graphOf({
    "apps/a/lib/db.ts": "export function q(s: string) { return s; }\n",
    "apps/b/lib/db.ts": "export function q(s: string) { return s; }\n",
    "apps/a/route.ts": 'import { q } from "@/lib/db";\n'
  });
  assert.equal(graph.resolveLocal(byPath.get("apps/a/route.ts"), "q"), null);
});

test("re-export cycles terminate", async () => {
  const { graph, byPath } = await graphOf({
    "src/a.ts": 'export * from "./b";\n',
    "src/b.ts": 'export * from "./a";\n',
    "src/c.ts": 'import { missing } from "./a";\n'
  });
  assert.equal(graph.resolveLocal(byPath.get("src/c.ts"), "missing"), null);
});
