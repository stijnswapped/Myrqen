import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { orders, products, query, sessions, users } from "./db.js";
import { applyPromotion, invoiceByReference, invoicesForUser } from "./invoices.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(HERE, "..", "data");
const PORT = Number(process.env.PORT ?? 4010);

// Hard-coded credential left in source on purpose. The value is a canary rather
// than a provider-shaped key: a real vendor shape would make this repository
// unpublishable, because every public secret scanner blocks it on sight.
const BILLING_API_SECRET = "mqcanary-9f4b2d61c05a7e38b6d3f7a1e29c7b50";
const BUILD_INFO = { commit: "fixture", node: process.version, secretKey: BILLING_API_SECRET };

function json(response, status, body) {
  const payload = JSON.stringify(body);
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(payload);
}

function html(response, status, body) {
  response.writeHead(status, { "content-type": "text/html; charset=utf-8" });
  response.end(body);
}

function readCookies(request) {
  const header = request.headers.cookie ?? "";
  const out = {};
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key) out[key] = rest.join("=");
  }
  return out;
}

function currentUser(request) {
  const { session } = readCookies(request);
  if (!session) return null;
  const record = sessions.get(session);
  if (!record) return null;
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
    if (route === "GET /") {
      return html(response, 200, "<h1>vuln-shop</h1><p>Myrqen fixture. Never deploy.</p>");
    }

    if (route === "GET /health") {
      return json(response, 200, { ok: true });
    }

    // No rate limiting and no lockout on credential checks.
    if (route === "POST /api/login") {
      const body = await readBody(request);
      const user = users.find((candidate) => candidate.email === body.email && candidate.password === body.password);
      if (!user) return json(response, 401, { error: "invalid credentials" });
      // Predictable session identifier derived from a low-entropy counter.
      const token = crypto.createHash("md5").update(`${user.id}:${sessions.size}`).digest("hex");
      sessions.set(token, { userId: user.id, createdAt: Date.now() });
      response.setHeader("set-cookie", `session=${token}; Path=/`);
      return json(response, 200, { session: token, role: user.role });
    }

    if (route === "GET /api/me") {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      return json(response, 200, { id: user.id, email: user.email, role: user.role });
    }

    // Broken object level authorization: the record is loaded by identifier with
    // no ownership check against the authenticated subject.
    if (request.method === "GET" && /^\/api\/orders\/\d+$/.test(url.pathname)) {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      const id = Number(url.pathname.split("/").pop());
      const order = orders.find((candidate) => candidate.id === id);
      if (!order) return json(response, 404, { error: "not found" });
      return json(response, 200, order);
    }

    if (route === "GET /api/orders") {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      return json(response, 200, orders.filter((order) => order.userId === user.id));
    }

    // Broken function level authorization: an administrative listing that only
    // checks that someone is signed in.
    if (route === "GET /api/admin/users") {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      return json(response, 200, users);
    }

    // Unsafe query composition: the client-controlled filter is interpolated
    // straight into the query predicate.
    if (route === "GET /api/products/search") {
      const term = url.searchParams.get("q") ?? "";
      const where = `row.name.toLowerCase().includes("${term.toLowerCase()}")`;
      const rows = query("products", where);
      return json(response, 200, { where, rows });
    }

    // Reflected cross-site scripting: the search term is written into HTML
    // without escaping.
    if (route === "GET /search") {
      const term = url.searchParams.get("q") ?? "";
      return html(response, 200, `<h1>Results for ${term}</h1><ul>${products.map((p) => `<li>${p.name}</li>`).join("")}</ul>`);
    }

    // Server-side request forgery: a user-supplied URL is fetched with no
    // allowlist and the response body is returned to the caller.
    if (route === "POST /api/import") {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      const body = await readBody(request);
      const target = body.url;
      if (!target) return json(response, 400, { error: "url required" });
      const fetched = await fetch(target, { redirect: "follow" }).catch((error) => ({ error }));
      if (fetched.error) return json(response, 502, { error: String(fetched.error.message ?? fetched.error) });
      const text = await fetched.text();
      return json(response, 200, { fetched: target, status: fetched.status, body: text.slice(0, 2000) });
    }

    // Path traversal: the requested name is joined onto a base directory with no
    // containment check.
    if (route === "GET /api/files") {
      const name = url.searchParams.get("name") ?? "";
      const target = path.join(PUBLIC_DIR, name);
      try {
        const contents = fs.readFileSync(target, "utf8");
        return json(response, 200, { name, contents: contents.slice(0, 2000) });
      } catch (error) {
        return json(response, 404, { error: "not found", detail: String(error.message) });
      }
    }

    // Business logic defect: quantity is trusted, so a negative quantity yields a
    // negative total and a credit.
    if (route === "POST /api/checkout") {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      const body = await readBody(request);
      const product = products.find((candidate) => candidate.id === Number(body.productId));
      if (!product) return json(response, 404, { error: "unknown product" });
      const quantity = Number(body.quantity ?? 1);
      const total = product.price * quantity;
      const order = { id: 200 + orders.length, userId: user.id, item: product.name, total, address: "n/a", card: "0000" };
      orders.push(order);
      return json(response, 200, { order, total });
    }

    /*
     * Three defects the static pass cannot see, and which exist so the whole-product
     * measurement can lose a case. Each is invisible for a different reason.
     */

    // Cross-module: authenticated, then delegated. The ownership predicate belongs in
    // `invoices.js`, one module boundary away, which is past what an intra-procedural
    // taint model can follow. Only exercising it as two different customers shows it.
    if (request.method === "GET" && /^\/api\/invoices\/[a-z0-9-]+$/.test(url.pathname)) {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      const reference = url.pathname.split("/").pop();
      const invoice = invoiceByReference(reference);
      if (!invoice) return json(response, 404, { error: "not found" });
      return json(response, 200, invoice);
    }

    // The correctly scoped listing beside it, so the defect above is a slip.
    if (route === "GET /api/invoices") {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      return json(response, 200, invoicesForUser(user.id));
    }

    // Account enumeration: the response distinguishes "no such account" from
    // "account exists". Every line here reads correctly; the defect is the pair of
    // outcomes, which no rule models and only a differential probe reveals.
    if (route === "POST /api/password-reset") {
      const body = await readBody(request);
      const account = users.find((candidate) => candidate.email === body.email);
      if (!account) return json(response, 404, { error: "no account with that address" });
      return json(response, 200, { sent: true, hint: `a link was sent to ${account.email}` });
    }

    // Replayable promotion: redemption is never recorded, so the same code applies
    // again on every request. Correct line by line; visible only by doing it twice.
    if (route === "POST /api/promotions/redeem") {
      const user = currentUser(request);
      if (!user) return json(response, 401, { error: "sign in first" });
      const body = await readBody(request);
      const order = orders.find((candidate) => candidate.id === Number(body.orderId) && candidate.userId === user.id);
      if (!order) return json(response, 404, { error: "not found" });
      const outcome = applyPromotion(String(body.code ?? ""), order.total);
      if (!outcome.applied) return json(response, 422, { error: "unknown code" });
      order.total = outcome.total;
      return json(response, 200, { orderId: order.id, total: order.total });
    }

    // Debug endpoint exposing internal configuration, including a secret.
    if (route === "GET /debug/config") {
      return json(response, 200, { build: BUILD_INFO, env: { PORT, SESSION_SECRET: process.env.SESSION_SECRET } });
    }

    return json(response, 404, { error: "no such route", route });
  } catch (error) {
    // Verbose error handler returns the stack to the client.
    return json(response, 500, { error: error.message, stack: error.stack });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  process.stdout.write(`vuln-shop listening on http://127.0.0.1:${PORT}\n`);
});
