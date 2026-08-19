import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(path.join(HERE, "..", "data"));
const PORT = Number(process.env.PORT ?? 4020);
const SESSION_TTL_MS = 30 * 60 * 1000;

// Only these destinations may be fetched on a user's behalf.
const IMPORT_ALLOWLIST = new Set(["http://127.0.0.1:4020"]);

const users = [
  { id: 1, email: "alice@example.test", password: "alice-password-1", role: "customer" },
  { id: 2, email: "bob@example.test", password: "bob-password-1", role: "customer" },
  { id: 3, email: "root@example.test", password: "root-password-1", role: "admin" }
];
const products = [
  { id: 1, name: "Blue widget", price: 4200 },
  { id: 2, name: "Red widget", price: 1900 }
];
const orders = [
  { id: 101, userId: 1, item: "Blue widget", total: 4200 },
  { id: 102, userId: 2, item: "Red widget", total: 1900 }
];
const sessions = new Map();

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]
  );
}

function currentUser(request) {
  const cookie = request.headers.cookie ?? "";
  const match = /(?:^|;\s*)session=([^;]+)/.exec(cookie);
  if (!match) return null;
  const record = sessions.get(match[1]);
  if (!record) return null;
  if (Date.now() - record.createdAt > SESSION_TTL_MS) {
    sessions.delete(match[1]);
    return null;
  }
  return users.find((user) => user.id === record.userId) ?? null;
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return {};
  }
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", `http://127.0.0.1:${PORT}`);
  const route = `${request.method} ${url.pathname}`;

  try {
    if (route === "GET /health") return json(response, 200, { ok: true });

    if (route === "POST /api/login") {
      const body = await readBody(request);
      const user = users.find((candidate) => candidate.email === body.email && candidate.password === body.password);
      if (!user) return json(response, 401, { error: "invalid credentials" });
      const token = crypto.randomBytes(32).toString("base64url");
      sessions.set(token, { userId: user.id, createdAt: Date.now() });
      response.setHeader("set-cookie", `session=${token}; Path=/; HttpOnly; SameSite=Lax`);
      return json(response, 200, { session: token, role: user.role });
    }

    if (request.method === "GET" && /^\/api\/orders\/\d+$/.test(url.pathname)) {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      const id = Number(url.pathname.split("/").pop());
      // Ownership is part of the lookup, not a later check.
      const order = orders.find((candidate) => candidate.id === id && candidate.userId === user.id);
      if (!order) return json(response, 404, { error: "not found" });
      return json(response, 200, order);
    }

    if (route === "GET /api/admin/users") {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      if (user.role !== "admin") return json(response, 403, { error: "forbidden" });
      return json(response, 200, users.map(({ id, email, role }) => ({ id, email, role })));
    }

    if (route === "GET /api/products/search") {
      const term = (url.searchParams.get("q") ?? "").toLowerCase();
      // Filtering happens in code, so no caller input becomes executable logic.
      const rows = products.filter((product) => product.name.toLowerCase().includes(term));
      return json(response, 200, { rows });
    }

    if (route === "GET /search") {
      const term = url.searchParams.get("q") ?? "";
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return response.end(`<h1>Results for ${escapeHtml(term)}</h1>`);
    }

    if (route === "POST /api/import") {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      const body = await readBody(request);
      let target;
      try {
        target = new URL(String(body.url ?? ""));
      } catch {
        return json(response, 400, { error: "url must be absolute" });
      }
      if (!IMPORT_ALLOWLIST.has(target.origin)) return json(response, 403, { error: "destination not allowed" });
      const fetched = await fetch(target, { redirect: "error" });
      return json(response, 200, { status: fetched.status });
    }

    if (route === "GET /api/files") {
      const name = url.searchParams.get("name") ?? "";
      const resolved = path.resolve(PUBLIC_DIR, name);
      if (!resolved.startsWith(`${PUBLIC_DIR}${path.sep}`)) return json(response, 403, { error: "forbidden" });
      try {
        return json(response, 200, { name, contents: fs.readFileSync(resolved, "utf8").slice(0, 2000) });
      } catch {
        return json(response, 404, { error: "not found" });
      }
    }

    if (route === "POST /api/checkout") {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      const body = await readBody(request);
      const product = products.find((candidate) => candidate.id === Number(body.productId));
      if (!product) return json(response, 404, { error: "unknown product" });
      const quantity = Number(body.quantity ?? 1);
      if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
        return json(response, 400, { error: "quantity must be between 1 and 100" });
      }
      const order = { id: 200 + orders.length, userId: user.id, item: product.name, total: product.price * quantity };
      orders.push(order);
      return json(response, 200, { order });
    }

    return json(response, 404, { error: "no such route" });
  } catch (error) {
    // Detail is logged server-side; the client gets a generic message.
    process.stderr.write(`request failed: ${error.message}\n`);
    return json(response, 500, { error: "internal error" });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  process.stdout.write(`safe-app listening on http://127.0.0.1:${PORT}\n`);
});
