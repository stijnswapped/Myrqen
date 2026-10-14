import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * The middleware a route is registered behind, read by the object- and function-level
 * authorization rules when the handler lives in another module.
 *
 * A layered Express application registers `router.get(path, requireAuth, controller.show)`
 * in one file and writes `show` in another. Read one file at a time, the controller has no
 * identity and no guard, so both rules stayed silent whatever the routes file said. The
 * engine's handler registry carries the middleware across, and each rule asks it the
 * question it was already asking of a same-file registration.
 */
async function scanFiles(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-middleware-"));
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

const PKG = JSON.stringify({ name: "app", version: "1.0.0", type: "module", dependencies: { express: "^4.19.0", "@prisma/client": "^5.0.0" } });

const MIDDLEWARE = `export function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).end();
  req.user = verify(token);
  next();
}
export function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).end();
  next();
}
export function requireProjectMember(req, res, next) {
  next();
}
function verify(token) {
  return { id: token };
}
`;

const CONTROLLER = `import { prisma } from "../db.js";
export async function showProject(req, res) {
  const project = await prisma.project.findUnique({ where: { id: req.params.id } });
  res.json(project);
}
export async function updateRole(req, res) {
  const member = await prisma.membership.update({ where: { id: req.params.id }, data: { role: req.body.role } });
  res.json(member);
}
`;

const DB = `import { PrismaClient } from "@prisma/client";\nexport const prisma = new PrismaClient();\n`;

const routes = (projectGate, roleGate, preamble = "") => `import express from "express";
import { requireAuth, requireAdmin, requireProjectMember } from "./middleware/auth.js";
import { showProject, updateRole } from "./controllers/projects.js";
export const router = express.Router();
${preamble}router.get("/projects/:id", ${projectGate}showProject);
router.post("/members/:id/role", ${roleGate}updateRole);
`;

const app = (routesFile) => ({
  "package.json": PKG,
  "src/middleware/auth.js": MIDDLEWARE,
  "src/controllers/projects.js": CONTROLLER,
  "src/db.js": DB,
  "src/routes.js": routesFile
});

const byRule = (result, ruleId) => result.candidates.filter((candidate) => candidate.ruleId === ruleId);

test("BOLA: a handler behind authenticating middleware in another module is judged", async () => {
  const result = await scanFiles(app(routes("requireAuth, ", "requireAuth, ")));
  const bola = byRule(result, "record-not-scoped-to-caller").map((candidate) => candidate.location.file);
  assert.deepEqual(bola.sort(), ["src/controllers/projects.js", "src/controllers/projects.js"]);
});

test("BOLA: an object-level guard in the registration, in another module, excuses the handler", async () => {
  const result = await scanFiles(app(routes("requireAuth, requireProjectMember, ", "requireAuth, ")));
  const bola = byRule(result, "record-not-scoped-to-caller");
  assert.equal(bola.length, 1);
  assert.match(bola[0].title, /membership/i);
});

test("BOLA: router-level authentication counts for every route after it", async () => {
  const result = await scanFiles(app(routes("", "", "router.use(requireAuth);\n")));
  assert.equal(byRule(result, "record-not-scoped-to-caller").length, 2);
});

test("BOLA: with no identity anywhere in the chain, the handler is not judged", async () => {
  const result = await scanFiles(app(routes("", "")));
  assert.equal(byRule(result, "record-not-scoped-to-caller").length, 0);
});

test("BFLA: a role write behind authentication only, registered in another module, is reported", async () => {
  const result = await scanFiles(app(routes("requireAuth, ", "requireAuth, ")));
  const bfla = byRule(result, "privileged-operation-without-role-check");
  assert.equal(bfla.length, 1);
  assert.equal(bfla[0].location.file, "src/controllers/projects.js");
});

test("BFLA: authorising middleware in the registration, in another module, is the role check", async () => {
  const result = await scanFiles(app(routes("requireAuth, ", "requireAuth, requireAdmin, ")));
  assert.equal(byRule(result, "privileged-operation-without-role-check").length, 0);
});

test("BFLA: an unauthenticated handler is the other rule's finding, not this one", async () => {
  const result = await scanFiles(app(routes("", "")));
  assert.equal(byRule(result, "privileged-operation-without-role-check").length, 0);
});

test("BFLA: a createServer dispatcher's branches are still judged one by one", async () => {
  const server = `import http from "node:http";
import { users, sessions } from "./db.js";
function currentUser(request) {
  const token = request.headers.authorization;
  return token ? sessions.get(token) : null;
}
http.createServer((request, response) => {
  const route = \`\${request.method} \${new URL(request.url, "http://x").pathname}\`;
  if (route === "GET /api/admin/users") {
    const user = currentUser(request);
    if (!user) return response.writeHead(401).end();
    return response.writeHead(200).end(JSON.stringify(users));
  }
  response.writeHead(404).end();
}).listen(4810);
`;
  const result = await scanFiles({
    "package.json": JSON.stringify({ name: "app", version: "1.0.0", type: "module" }),
    "src/server.js": server,
    "src/db.js": "export const users = [];\nexport const sessions = new Map();\n"
  });
  assert.equal(byRule(result, "privileged-operation-without-role-check").length, 1);
});
