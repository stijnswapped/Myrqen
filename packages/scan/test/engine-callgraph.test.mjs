import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import ts from "typescript";
import { parseFile } from "../dist/ast/parse.js";
import { buildModuleGraph } from "../dist/engine/modules.js";
import { resolveCall } from "../dist/engine/callgraph.js";

/**
 * Which function a call reaches. Each shape here is one a layered application uses to hand
 * a value from a handler to the code that eventually does something with it.
 */
async function project(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-callgraph-"));
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
  const byPath = new Map(parsed.map((file) => [file.relativePath, file]));
  return {
    graph,
    /** The target of the first call in `file` whose callee text is `calleeText`. */
    target(file, calleeText) {
      const parsedFile = byPath.get(file);
      let found = null;
      const visit = (node) => {
        if (found) return;
        if ((ts.isCallExpression(node) || ts.isNewExpression(node)) && node.expression.getText(parsedFile.source) === calleeText) {
          found = node;
          return;
        }
        node.forEachChild(visit);
      };
      visit(parsedFile.source);
      assert.ok(found, `no call to ${calleeText} in ${file}`);
      const resolved = resolveCall(graph, parsedFile, found);
      if (!resolved) return null;
      const fn = resolved.fn;
      const name = fn.name && ts.isIdentifier(fn.name)
        ? fn.name.text
        : ts.isConstructorDeclaration(fn)
          ? "constructor"
          : fn.parent && ts.isVariableDeclaration(fn.parent) && ts.isIdentifier(fn.parent.name)
            ? fn.parent.name.text
            : fn.parent && ts.isPropertyAssignment(fn.parent) && ts.isIdentifier(fn.parent.name)
              ? fn.parent.name.text
              : fn.parent && ts.isPropertyDeclaration(fn.parent) && ts.isIdentifier(fn.parent.name)
                ? fn.parent.name.text
                : "<anonymous>";
      return `${resolved.file.relativePath}#${name}`;
    }
  };
}

test("a local function declared below its caller is reached", async () => {
  const p = await project({
    "src/a.ts": "export function handle(req: any) { return lookup(req.query.id); }\nfunction lookup(id: string) { return id; }\n"
  });
  assert.equal(p.target("src/a.ts", "lookup"), "src/a.ts#lookup");
});

test("a nested helper shadows a module-level one of the same name", async () => {
  const p = await project({
    "src/a.ts":
      "function pick(x: string) { return x; }\nexport function handle(req: any) {\n  const pick = (y: string) => y.trim();\n  return pick(req.query.id);\n}\n"
  });
  assert.equal(p.target("src/a.ts", "pick"), "src/a.ts#pick");
  // The inner arrow is the target, not the module-level declaration: it has one statement.
  const p2 = await project({
    "src/a.ts": "export function handle(req: any) {\n  const pick = (y: string) => y.trim();\n  return pick(req.query.id);\n}\n"
  });
  assert.equal(p2.target("src/a.ts", "pick"), "src/a.ts#pick");
});

test("a parameter that shadows an imported function is not resolved", async () => {
  const p = await project({
    "src/lib.ts": "export function run(x: string) { return x; }\n",
    "src/a.ts": 'import { run } from "./lib";\nexport function each(run: (v: string) => void, value: string) { run(value); }\n'
  });
  assert.equal(p.target("src/a.ts", "run"), null);
});

test("an imported function, a namespace member and a CommonJS member are reached", async () => {
  const p = await project({
    "src/repo.ts": "export async function byId(id: string) { return id; }\n",
    "src/route.ts": 'import * as repo from "./repo";\nimport { byId } from "./repo";\nrepo.byId("1");\nbyId("2");\n',
    "lib/db.js": "function query(sql) { return sql; }\nmodule.exports = { query };\n",
    "routes/x.js": 'const db = require("../lib/db");\ndb.query("select 1");\n'
  });
  assert.equal(p.target("src/route.ts", "repo.byId"), "src/repo.ts#byId");
  assert.equal(p.target("src/route.ts", "byId"), "src/repo.ts#byId");
  assert.equal(p.target("routes/x.js", "db.query"), "lib/db.js#query");
});

test("this.method() reaches a sibling method in the same class", async () => {
  const p = await project({
    "src/c.ts": "export class C {\n  run(id: string) { return this.load(id); }\n  private load(id: string) { return id; }\n}\n"
  });
  assert.equal(p.target("src/c.ts", "this.load"), "src/c.ts#load");
});

test("an injected member typed with an imported class reaches its method", async () => {
  const p = await project({
    "src/orders.service.ts": "export class OrdersService {\n  find(id: string) { return id; }\n}\n",
    "src/orders.controller.ts":
      'import { OrdersService } from "./orders.service";\nexport class OrdersController {\n  constructor(private readonly orders: OrdersService) {}\n  show(id: string) { return this.orders.find(id); }\n}\n'
  });
  assert.equal(p.target("src/orders.controller.ts", "this.orders.find"), "src/orders.service.ts#find");
});

test("a member assigned a new instance in the constructor reaches its method", async () => {
  const p = await project({
    "src/store.js": "export class Store {\n  get(key) { return key; }\n}\n",
    "src/svc.js":
      'import { Store } from "./store.js";\nexport class Svc {\n  constructor() { this.store = new Store(); }\n  read(k) { return this.store.get(k); }\n}\n'
  });
  assert.equal(p.target("src/svc.js", "this.store.get"), "src/store.js#get");
});

test("a local variable holding a new instance reaches the class method", async () => {
  const p = await project({
    "src/report.ts": "export class ReportBuilder {\n  where(clause: string) { return clause; }\n}\n",
    "src/route.ts":
      'import { ReportBuilder } from "./report";\nexport function handle(req: any) {\n  const builder = new ReportBuilder();\n  return builder.where(req.query.q);\n}\n'
  });
  assert.equal(p.target("src/route.ts", "builder.where"), "src/report.ts#where");
});

test("a constructor call reaches the constructor", async () => {
  const p = await project({
    "src/q.ts": "export class Query {\n  constructor(private filter: string) {}\n}\n",
    "src/route.ts": 'import { Query } from "./q";\nexport const h = (req: any) => new Query(req.query.f);\n'
  });
  assert.equal(p.target("src/route.ts", "Query"), "src/q.ts#constructor");
});

test("an exported singleton's method and a default-exported object's method are reached", async () => {
  const p = await project({
    "src/svc.ts": "class Svc {\n  list(f: string) { return f; }\n}\nexport const svc = new Svc();\n",
    "src/obj.js": "export default {\n  async remove(id) { return id; }\n};\n",
    "src/route.ts": 'import { svc } from "./svc";\nimport obj from "./obj.js";\nsvc.list("a");\nobj.remove("b");\n'
  });
  assert.equal(p.target("src/route.ts", "svc.list"), "src/svc.ts#list");
  assert.equal(p.target("src/route.ts", "obj.remove"), "src/obj.js#remove");
});

test("a method on a library object is not resolved", async () => {
  const p = await project({
    "src/route.ts": 'import express from "express";\nconst router = express.Router();\nrouter.get("/x", () => null);\n'
  });
  assert.equal(p.target("src/route.ts", "router.get"), null);
});
