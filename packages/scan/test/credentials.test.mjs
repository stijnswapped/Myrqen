import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { discoverRoutes } from "../dist/ast/routes.js";
import { parseFile } from "../dist/ast/parse.js";
import * as credentials from "../dist/rules/credentials.js";

/**
 * Every case is written as source here, never as a reference to a corpus file: a
 * rule that only fires on a known fixture is worthless in a real repository.
 *
 * The rules are driven directly rather than through `scan()`, so these tests hold
 * whether or not the file has been added to the central rule registry yet.
 */
const RULES = Object.values(credentials).filter(
  (value) => value && typeof value === "object" && typeof value.run === "function"
);

async function analyse(relativePath, source) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-credentials-"));
  const target = path.join(root, relativePath);
  try {
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, source, "utf8");
    const parsed = await parseFile(root, target);
    assert.ok(!("error" in parsed), `the fixture must parse: ${parsed.error ?? ""}`);
    const candidates = [];
    const context = { file: parsed, routes: discoverRoutes(parsed), report: (candidate) => candidates.push(candidate) };
    for (const rule of RULES) rule.run(context);
    // The engine deduplicates on ruleId::file::line, so a rule that fires twice on
    // one line is one finding. The tests must see what a reader would see.
    const unique = new Map();
    for (const candidate of candidates) {
      const key = `${candidate.ruleId}::${candidate.location.file}::${candidate.location.line}`;
      if (!unique.has(key)) unique.set(key, candidate);
    }
    return [...unique.values()];
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const categories = (found) => found.map((candidate) => candidate.category);
const of = (found, category) => found.filter((candidate) => candidate.category === category);

/* ------------------------------------------------------------ password storage */

test("a password stored as a bare SHA-256 digest is reported", async () => {
  const found = await analyse(
    "src/register.js",
    `
      const crypto = require("crypto");
      const express = require("express");
      const router = express.Router();
      router.post("/members", async (req, res) => {
        const password = String(req.body.password || "");
        const passwordHash = crypto.createHash("sha256").update(password).digest("hex");
        await req.app.locals.db.query("INSERT INTO members (email, password_hash) VALUES ($1, $2)", [req.body.email, passwordHash]);
        res.status(201).json({ ok: true });
      });
      module.exports = router;
    `
  );
  const reported = of(found, "weak_password_hashing");
  assert.equal(reported.length, 1, `expected one weak_password_hashing, got ${JSON.stringify(categories(found))}`);
  assert.equal(reported[0].route, "POST /members");
});

test("a password put through argon2id with real parameters is not reported", async () => {
  const found = await analyse(
    "src/enrol.js",
    `
      const argon2 = require("argon2");
      const OPTIONS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };
      async function enrol(password, store) {
        const passwordHash = await argon2.hash(password, OPTIONS);
        await store.save({ passwordHash });
      }
      module.exports = { enrol };
    `
  );
  assert.deepEqual(of(found, "weak_password_hashing"), []);
});

test("bcrypt with an adequate cost is not reported and a low cost is", async () => {
  const strong = await analyse(
    "src/strong.js",
    `
      const bcrypt = require("bcryptjs");
      const ROUNDS = 12;
      async function store(password, rows) {
        const passwordHash = await bcrypt.hash(password, ROUNDS);
        await rows.insert({ passwordHash });
      }
      module.exports = { store };
    `
  );
  assert.deepEqual(of(strong, "weak_password_hashing"), []);

  const weak = await analyse(
    "src/weak.js",
    `
      const bcrypt = require("bcryptjs");
      const ROUNDS = 4;
      async function store(password, rows) {
        const passwordHash = await bcrypt.hash(password, ROUNDS);
        await rows.insert({ passwordHash });
      }
      module.exports = { store };
    `
  );
  assert.equal(of(weak, "weak_password_hashing").length, 1);
});

test("hashing a random token for storage is not mistaken for password hashing", async () => {
  const found = await analyse(
    "src/confirm.js",
    `
      const crypto = require("crypto");
      function mintConfirmation() {
        const token = crypto.randomBytes(32).toString("base64url");
        const tokenDigest = crypto.createHash("sha256").update(token).digest("hex");
        return { token, tokenDigest };
      }
      module.exports = { mintConfirmation };
    `
  );
  assert.deepEqual(categories(found), [], "a SHA-256 digest of a 256-bit random token is the correct pattern");
});

/* ---------------------------------------------------------- secret comparison */

test("an API secret compared with !== is reported as timing unsafe", async () => {
  const found = await analyse(
    "src/partner-auth.js",
    `
      const express = require("express");
      const router = express.Router();
      async function authenticate(req, res, next) {
        const presented = req.get("x-partner-key") || "";
        const [keyId, secret] = presented.split(".");
        const row = await req.app.locals.db.lookup(keyId);
        if (!row) return res.status(401).json({ error: "unknown key" });
        if (secret !== row.secret_token) return res.status(401).json({ error: "unknown key" });
        next();
      }
      router.get("/ping", authenticate, (req, res) => res.json({ ok: true }));
      module.exports = { router, authenticate };
    `
  );
  const reported = of(found, "timing_unsafe_comparison");
  assert.equal(reported.length, 1, `got ${JSON.stringify(categories(found))}`);
  assert.equal(reported[0].route, "GET /ping", "the middleware is attributed to the route that installs it");
});

test("the same check written with timingSafeEqual is not reported", async () => {
  const found = await analyse(
    "src/service-auth.js",
    `
      const crypto = require("crypto");
      function secretsMatch(presented, expected) {
        const a = Buffer.from(presented, "utf8");
        const b = Buffer.from(expected, "utf8");
        if (a.length !== b.length) return false;
        return crypto.timingSafeEqual(a, b);
      }
      async function authenticate(req, res, next) {
        const presented = req.get("x-service-token") || "";
        const [tokenId, secret] = presented.split(".");
        const row = await req.app.locals.db.lookup(tokenId);
        if (!row || !secretsMatch(secret, row.secret_token)) return res.status(401).end();
        next();
      }
      module.exports = { authenticate };
    `
  );
  assert.deepEqual(of(found, "timing_unsafe_comparison"), []);
});

test("comparing a username, a route, or a parser token is not a credential check", async () => {
  const found = await analyse(
    "src/dispatch.js",
    `
      const SyntaxKind = { PlusToken: 1, MinusToken: 2 };
      function handle(req, res, node) {
        if (req.body.username === "root") return res.status(403).end();
        if (req.url === "/health") return res.end("ok");
        if (node.operatorToken === SyntaxKind.PlusToken) return res.end("plus");
        return res.end("other");
      }
      module.exports = { handle };
    `
  );
  assert.deepEqual(of(found, "timing_unsafe_comparison"), []);
});

/* ------------------------------------------------------------- randomness */

test("a reset token built from Math.random is reported with its route", async () => {
  const found = await analyse(
    "src/reset.js",
    `
      const http = require("node:http");
      function buildToken() {
        return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
      }
      async function requestReset(request, response) {
        const token = buildToken();
        await response.end(token);
      }
      const server = http.createServer(async (request, response) => {
        const url = new URL(request.url, "http://localhost");
        if (request.method !== "POST") { response.writeHead(405); return response.end(); }
        switch (url.pathname) {
          case "/auth/reset":
            await requestReset(request, response);
            return;
          default:
            response.writeHead(404);
            response.end();
        }
      });
      module.exports = { server };
    `
  );
  const reported = of(found, "insecure_randomness");
  assert.equal(reported.length, 1, `got ${JSON.stringify(categories(found))}`);
  assert.equal(reported[0].route, "POST /auth/reset");
});

test("a pairing code accumulated a character at a time from Math.random is reported", async () => {
  const found = await analyse(
    "main/pairing-bridge.js",
    `
      const { ipcMain } = require("electron");
      const { randomUUID } = require("node:crypto");
      const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
      const pending = new Map();
      function jitter(baseMs) {
        return baseMs + Math.floor(Math.random() * 250);
      }
      function pairingCode() {
        let code = "";
        for (let i = 0; i < 8; i += 1) {
          code += CODE_ALPHABET[Math.floor(Math.random() * CODE_ALPHABET.length)];
        }
        return code;
      }
      ipcMain.handle("pairing:start", async () => {
        const id = randomUUID();
        const code = pairingCode();
        pending.set(id, { code });
        return { id, code };
      });
      module.exports = { pairingCode };
    `
  );
  const reported = of(found, "insecure_randomness");
  assert.equal(
    reported.length,
    1,
    `a code that admits a device is a bearer credential, and the jitter beside it is not: ${JSON.stringify(categories(found))}`
  );
  assert.equal(reported[0].location.line, 12, "the report points at the draw, not at the jitter above it");
});

test("a coupon code, a status code and a country code drawn from Math.random stay silent", async () => {
  const found = await analyse(
    "src/catalogue.js",
    `
      const ALPHABET = "ABCDE";
      function promoCode() {
        let couponCode = "";
        for (let i = 0; i < 6; i += 1) couponCode += ALPHABET[Math.floor(Math.random() * ALPHABET.length)];
        return couponCode;
      }
      function flakyStatus() {
        const statusCode = [200, 201, 204][Math.floor(Math.random() * 3)];
        return statusCode;
      }
      function anyCountry(list) {
        const countryCode = list[Math.floor(Math.random() * list.length)];
        return countryCode;
      }
      module.exports = { promoCode, flakyStatus, anyCountry };
    `
  );
  assert.deepEqual(
    categories(found),
    [],
    "\"code\" only names something unguessable when a qualifier says what it admits the holder to"
  );
});

test("an access pin assembled with padStart and a backup code built from the clock are reported", async () => {
  const found = await analyse(
    "src/enrolment.js",
    `
      let issued = 0;
      function accessPin() {
        return String(Math.floor(Math.random() * 1e6)).padStart(6, "0");
      }
      function nextBackup() {
        issued += 1;
        const backupCode = \`\${Date.now().toString(36)}-\${issued}\`;
        return backupCode;
      }
      module.exports = { accessPin, nextBackup };
    `
  );
  const reported = of(found, "insecure_randomness");
  assert.equal(reported.length, 2, `both assemblies are the same defect: ${JSON.stringify(categories(found))}`);
});

test("a generated value is reported for how it is checked, even when its name says nothing", async () => {
  const found = await analyse(
    "src/claims.js",
    `
      const store = new Map();
      function newValue() {
        return Math.random().toString(36).slice(2);
      }
      function issue(userId) {
        const value = newValue();
        store.set(userId, { value });
        return value;
      }
      function redeem(userId, presented) {
        const record = store.get(userId);
        return { ok: record.value === String(presented) };
      }
      module.exports = { issue, redeem };
    `
  );
  const reported = of(found, "insecure_randomness");
  assert.equal(
    reported.length,
    1,
    `a value checked against what the caller presents is a bearer credential whatever it is called: ${JSON.stringify(categories(found))}`
  );
  assert.match(reported[0].reasoning, /checked against/);
  assert.deepEqual(of(found, "weak_session_identifier"), [], "being verified does not make the value a session handle");
});

test("a randomly chosen variant compared with the same field from the query is not reported", async () => {
  const found = await analyse(
    "src/experiment.js",
    `
      const variants = ["a", "b"];
      function pickVariant() {
        return variants[Math.floor(Math.random() * variants.length)];
      }
      function render(req) {
        const variant = pickVariant();
        if (variant === req.query.variant) return "sticky";
        return variant;
      }
      module.exports = { render };
    `
  );
  assert.deepEqual(
    categories(found),
    [],
    "the same field on both sides is the caller's own value echoed back, not a secret against a guess"
  );
});

test("Math.random used for retry jitter is not reported", async () => {
  const found = await analyse(
    "src/retry.js",
    `
      function nextDelay(attempt) {
        const jitter = Math.random() * 250;
        return Math.min(30000, 2 ** attempt * 100) + jitter;
      }
      module.exports = { nextDelay };
    `
  );
  assert.deepEqual(categories(found), []);
});

test("a session identifier digested from an id, a counter and the clock is reported", async () => {
  const found = await analyse(
    "src/sign-in.js",
    `
      const crypto = require("node:crypto");
      let issued = 0;
      function nextSessionId(account) {
        issued += 1;
        const seed = \`\${account.id}:\${issued}:\${Date.now()}\`;
        return crypto.createHash("md5").update(seed).digest("hex");
      }
      async function signIn(request, response) {
        const sessionId = nextSessionId({ id: 7 });
        response.end(sessionId);
      }
      const ROUTES = [{ method: "POST", path: "/portal/sign-in", handler: signIn }];
      module.exports = { ROUTES };
    `
  );
  const reported = of(found, "weak_session_identifier");
  assert.equal(reported.length, 1, `got ${JSON.stringify(categories(found))}`);
  assert.equal(reported[0].route, "POST /portal/sign-in");
  assert.deepEqual(of(found, "weak_hash_algorithm"), [], "the specific defect is reported once, not twice");
});

test("a session identifier drawn from crypto.randomBytes is not reported", async () => {
  const found = await analyse(
    "src/console-sign-in.js",
    `
      const crypto = require("node:crypto");
      function nextSessionId() {
        return crypto.randomBytes(32).toString("hex");
      }
      async function signIn(request, response) {
        const sessionId = nextSessionId();
        response.end(sessionId);
      }
      module.exports = { signIn };
    `
  );
  assert.deepEqual(categories(found), []);
});

/* ------------------------------------------------------- legacy digest algorithm */

test("MD5 over an uploaded body is reported as a weak digest, but a cache key is not", async () => {
  const flagged = await analyse(
    "src/integrity.js",
    `
      const crypto = require("node:crypto");
      function bundleIntegrity(body) {
        return crypto.createHash("md5").update(body).digest("hex");
      }
      module.exports = { bundleIntegrity };
    `
  );
  assert.equal(of(flagged, "weak_hash_algorithm").length, 1);

  const quiet = await analyse(
    "src/thumbnails.js",
    `
      const crypto = require("node:crypto");
      function thumbnailCacheKey(url) {
        return crypto.createHash("md5").update(url).digest("hex");
      }
      module.exports = { thumbnailCacheKey };
    `
  );
  assert.deepEqual(of(quiet, "weak_hash_algorithm"), []);
});

/* -------------------------------------------------------------- JWT handling */

test("reading claims from jwt.decode is reported as a verification bypass", async () => {
  const found = await analyse(
    "src/partner-tokens.js",
    `
      import jwt from "jsonwebtoken";
      export default async function plugin(fastify) {
        fastify.decorate("verifyPartner", async (request, reply) => {
          const [scheme, token] = (request.headers.authorization ?? "").split(" ");
          if (scheme !== "Bearer" || !token) return reply.code(401).send({ error: "no token" });
          const claims = jwt.decode(token, { json: true });
          if (!claims || claims.iss !== "https://partners.example.com/") return reply.code(401).send({ error: "no" });
          request.partner = claims.sub;
        });
        fastify.get("/partner/feed", { preHandler: [fastify.verifyPartner] }, async (request, reply) => reply.send({ ok: true }));
      }
    `
  );
  const reported = of(found, "jwt_verification_bypass");
  assert.equal(reported.length, 1, `got ${JSON.stringify(categories(found))}`);
  assert.equal(reported[0].severity, "critical");
  assert.equal(reported[0].route, "GET /partner/feed");
});

test("a verify with pinned algorithms and a stopping catch is not reported", async () => {
  const found = await analyse(
    "src/vendor-tokens.js",
    `
      import jwt from "jsonwebtoken";
      const PUBLIC_KEY = process.env.VENDOR_JWT_PUBLIC_KEY;
      export default async function plugin(fastify) {
        fastify.decorate("verifyVendor", async (request, reply) => {
          const [scheme, token] = (request.headers.authorization ?? "").split(" ");
          if (scheme !== "Bearer" || !token) return reply.code(401).send({ error: "no token" });
          let claims;
          try {
            claims = jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"], issuer: "https://vendors.example.com/", audience: "api" });
          } catch (error) {
            return reply.code(401).send({ error: "no" });
          }
          request.vendor = claims.sub;
        });
        fastify.get("/vendor/feed", { preHandler: [fastify.verifyVendor] }, async (request, reply) => reply.send({ ok: true }));
      }
    `
  );
  assert.deepEqual(of(found, "jwt_verification_bypass"), []);
});

test("a verify with no algorithms option is reported", async () => {
  const found = await analyse(
    "src/unpinned.js",
    `
      import jwt from "jsonwebtoken";
      const PUBLIC_KEY = process.env.JWT_PUBLIC_KEY;
      export function subjectOf(bearer) {
        const claims = jwt.verify(bearer, PUBLIC_KEY);
        return claims.sub;
      }
    `
  );
  assert.equal(of(found, "jwt_verification_bypass").length, 1);
});

test("a verify whose catch swallows the failure is reported", async () => {
  const found = await analyse(
    "src/swallowed.js",
    `
      import jwt from "jsonwebtoken";
      const PUBLIC_KEY = process.env.JWT_PUBLIC_KEY;
      export async function handler(request, reply) {
        let claims = null;
        try {
          claims = jwt.verify(request.headers.authorization, PUBLIC_KEY, { algorithms: ["RS256"] });
        } catch (error) {
          request.log.warn("token rejected");
        }
        reply.send({ subject: claims && claims.sub });
      }
    `
  );
  assert.equal(of(found, "jwt_verification_bypass").length, 1);
});

test("decoding to read the key id before verifying the same token is not reported", async () => {
  const found = await analyse(
    "src/kid-lookup.js",
    `
      import jwt from "jsonwebtoken";
      import { keyForKid } from "./keys.js";
      export function claimsOf(bearer) {
        const peeked = jwt.decode(bearer, { complete: true });
        const key = keyForKid(peeked && peeked.header.kid);
        return jwt.verify(bearer, key, { algorithms: ["RS256"] });
      }
    `
  );
  assert.deepEqual(of(found, "jwt_verification_bypass"), []);
});

/* ------------------------------------------------------------------ cookies */

test("a session cookie without HttpOnly or Secure is reported", async () => {
  const found = await analyse(
    "src/member-sign-in.js",
    `
      const SESSION_COOKIE = "app_session";
      export default async function plugin(fastify) {
        fastify.post("/sessions", async (request, reply) => {
          reply.setCookie(SESSION_COOKIE, "abc", { path: "/", httpOnly: false, secure: false, sameSite: "none" });
          return reply.code(201).send({ ok: true });
        });
      }
    `
  );
  const reported = of(found, "insecure_cookie_configuration");
  assert.equal(reported.length, 1, `got ${JSON.stringify(categories(found))}`);
  assert.equal(reported[0].severity, "high");
  assert.equal(reported[0].route, "POST /sessions");
});

test("a session cookie whose flags come from a hoisted constant is not reported", async () => {
  const found = await analyse(
    "src/operator-sign-in.js",
    `
      const SESSION_COOKIE = "operator_session";
      const COOKIE_OPTIONS = { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 28800 };
      export default async function plugin(fastify) {
        fastify.post("/operator/sessions", async (request, reply) => {
          reply.setCookie(SESSION_COOKIE, "abc", COOKIE_OPTIONS);
          return reply.code(201).send({ ok: true });
        });
      }
    `
  );
  assert.deepEqual(of(found, "insecure_cookie_configuration"), []);
});

test("a session cookie whose options are spread from a shared helper is not reported", async () => {
  const found = await analyse(
    "src/login-route.js",
    `
      import { SESSION_COOKIE, sessionCookieOptions } from "./auth.js";
      export async function POST(request) {
        const response = Response.json({ ok: true });
        response.cookies.set(SESSION_COOKIE, "abc", { ...sessionCookieOptions(true), expires: new Date() });
        return response;
      }
    `
  );
  assert.deepEqual(
    of(found, "insecure_cookie_configuration"),
    [],
    "the flags may all be set inside the helper, which this pass cannot read"
  );
});

test("a double-submit CSRF cookie and a theme cookie are readable by design", async () => {
  const found = await analyse(
    "src/preferences-route.js",
    `
      const CSRF_COOKIE = "mq_csrf";
      const THEME_COOKIE = "mq_theme";
      export async function POST(request) {
        const response = Response.json({ ok: true });
        response.cookies.set(CSRF_COOKIE, "token-value", { httpOnly: false, secure: true, sameSite: "lax", path: "/" });
        response.cookies.set(THEME_COOKIE, "dark", { httpOnly: false, path: "/" });
        return response;
      }
    `
  );
  assert.deepEqual(of(found, "insecure_cookie_configuration"), []);
});

test("SameSite=None with an origin allowlist and a CSRF check is not reported", async () => {
  const found = await analyse(
    "src/embedded-route.js",
    `
      import { timingSafeEqual } from "node:crypto";
      const SESSION_COOKIE = "mq_session";
      const CSRF_HEADER = "x-mq-csrf";
      const ALLOWED_ORIGINS = new Set(["https://app.example.com", "https://portal.example.com"]);
      const SESSION_COOKIE_OPTIONS = { httpOnly: true, secure: true, sameSite: "none", path: "/", maxAge: 28800 };
      function tokensMatch(a, b) {
        const left = Buffer.from(a);
        const right = Buffer.from(b);
        return left.length === right.length && timingSafeEqual(left, right);
      }
      export async function POST(request) {
        const origin = request.headers.get("origin");
        if (!origin || !ALLOWED_ORIGINS.has(origin)) return Response.json({ error: "no" }, { status: 403 });
        if (!tokensMatch(request.headers.get(CSRF_HEADER) ?? "", "cookie-value")) {
          return Response.json({ error: "no" }, { status: 403 });
        }
        const response = Response.json({ ok: true });
        response.cookies.set(SESSION_COOKIE, "abc", SESSION_COOKIE_OPTIONS);
        return response;
      }
    `
  );
  assert.deepEqual(of(found, "insecure_cookie_configuration"), []);
});

test("SameSite=None with no compensating check is reported", async () => {
  const found = await analyse(
    "src/embedded-unguarded-route.js",
    `
      const SESSION_COOKIE = "mq_session";
      const SESSION_COOKIE_OPTIONS = { httpOnly: true, secure: true, sameSite: "none", path: "/", maxAge: 28800 };
      export async function POST(request) {
        const response = Response.json({ ok: true });
        response.cookies.set(SESSION_COOKIE, "abc", SESSION_COOKIE_OPTIONS);
        return response;
      }
    `
  );
  assert.equal(of(found, "insecure_cookie_configuration").length, 1);
});

/* -------------------------------------------------------- credential literals */

test("a credential-shaped default behind an environment read is reported", async () => {
  // Assembled rather than written out: a provider-shaped literal in a published
  // repository is blocked by GitHub's push protection and by every downstream secret
  // scanner, which would make this repository unpublishable over a synthetic value.
  const live = ["sk", "live", "51QtPfZK2mDq7RhX8bNvT3yWcJm4LpQ2s"].join("_");
  const found = await analyse(
    "app/api/billing/route.ts",
    `
      const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "${live}";
      export async function POST(request: Request) {
        return Response.json({ configured: STRIPE_SECRET_KEY.length > 0 });
      }
    `
  );
  const reported = of(found, "hardcoded_secret");
  assert.equal(reported.length, 1, `got ${JSON.stringify(categories(found))}`);
  assert.equal(reported[0].severity, "high");
  assert.equal(reported[0].route, "POST /api/billing");
  assert.ok(!JSON.stringify(reported[0]).includes("sk_live_51QtPfZ"), "the report must not reproduce the secret");
});

test("a private key in a template literal is reported", async () => {
  // The PEM header is assembled at runtime rather than written out. A literal
  // `-----BEGIN … PRIVATE KEY-----` in a published repository is blocked by GitHub's
  // push protection and by every downstream secret scanner, so a test that contains
  // one makes this repository unpublishable — and a synthetic key still teaches a
  // reader to scroll past the shape that matters most.
  const header = ["-----BEGIN", "RSA", "PRIVATE", "KEY-----"].join(" ");
  const footer = ["-----END", "RSA", "PRIVATE", "KEY-----"].join(" ");
  const found = await analyse(
    "src/signing.js",
    `
      const SIGNING_PRIVATE_KEY = \`${header}
      MIIEowIBAAKCAQEA0000000000000000000000000000000000000000
      ${footer}\`;
      module.exports = { SIGNING_PRIVATE_KEY };
    `
  );
  assert.equal(of(found, "hardcoded_secret").length, 1);
});

test("a connection string with an inline password is reported", async () => {
  const found = await analyse(
    "src/db.js",
    `
      const DATABASE_URL = "postgres://reporting:Hn3xQv8LpZ2r@db.internal:5432/analytics";
      module.exports = { DATABASE_URL };
    `
  );
  assert.equal(of(found, "hardcoded_secret").length, 1);
});

test("placeholders, self-naming fixtures, and publishable keys are not reported", async () => {
  const found = await analyse(
    "src/config.js",
    `
      const API_KEY = "changeme";
      const SEED_PASSWORD = "alice-password-1";
      const DOC_TOKEN = "<your-token-here>";
      const STRIPE_PUBLISHABLE_KEY = "pk_live_51QtPfZK2mDq7RhX8bNvT3yWcJm4LpQ2s";
      const PRICE_IDS = { monthly: "price_1QtPfZK2mDq7RhX8bNvT3yWc", yearly: "price_1QtPgAK2mDq7RhX8ZzLm9QpR" };
      module.exports = { API_KEY, SEED_PASSWORD, DOC_TOKEN, STRIPE_PUBLISHABLE_KEY, PRICE_IDS };
    `
  );
  assert.deepEqual(of(found, "hardcoded_secret"), []);
});

test("an empty-string default behind an environment read is not reported", async () => {
  const found = await analyse(
    "src/client.js",
    `
      const WAREHOUSE_KEY = process.env.NEXT_PUBLIC_WAREHOUSE_SERVICE_KEY ?? "";
      module.exports = { WAREHOUSE_KEY };
    `
  );
  assert.deepEqual(of(found, "hardcoded_secret"), []);
});

/* ------------------------------------------------------------------ contract */

test("every rule states a superseded predecessor where one exists", () => {
  assert.ok(credentials.SUPERSEDES.length > 0);
  for (const entry of credentials.SUPERSEDES) {
    assert.equal(typeof entry.retire, "string");
    assert.equal(typeof entry.replacedBy, "string");
  }
});

test("no rule writes placeholder prose", async () => {
  const found = await analyse(
    "src/everything.js",
    `
      const crypto = require("crypto");
      const express = require("express");
      const router = express.Router();
      router.post("/accounts", async (req, res) => {
        const passwordHash = crypto.createHash("sha256").update(String(req.body.password)).digest("hex");
        res.json({ passwordHash });
      });
      module.exports = router;
    `
  );
  assert.ok(found.length > 0);
  for (const candidate of found) {
    for (const field of ["summary", "impact", "remediation", "verificationPlan", "reasoning"]) {
      assert.ok(candidate[field].length > 60, `${candidate.ruleId}.${field} must be written for a reader`);
      assert.ok(!/TODO|TBD|placeholder|lorem/i.test(candidate[field]), `${candidate.ruleId}.${field} is placeholder prose`);
    }
    assert.ok(["strong_evidence", "needs_review"].includes(candidate.verification));
    assert.ok(candidate.taxonomy.length > 0);
  }
});

/* -------------------------------------------- regressions found on real code */

test("a session identifier is classified by how the value is used, not by its name", async () => {
  const found = await analyse(
    "src/store-login.js",
    `
      const crypto = require("node:crypto");
      const sessions = new Map();
      const users = [];
      async function handle(request, response) {
        const body = await readBody(request);
        const user = users.find((candidate) => candidate.email === body.email);
        if (!user) return response.end("no");
        const token = crypto.createHash("md5").update(\`\${user.id}:\${sessions.size}\`).digest("hex");
        sessions.set(token, { userId: user.id, createdAt: Date.now() });
        response.setHeader("set-cookie", \`session=\${token}; Path=/\`);
        return response.end("ok");
      }
      module.exports = { handle };
    `
  );
  const reported = of(found, "weak_session_identifier");
  assert.equal(
    reported.length,
    1,
    `a value called \`token\` that keys a \`sessions\` map and lands in a \`session\` cookie is a session identifier: ${JSON.stringify(categories(found))}`
  );
  assert.deepEqual(of(found, "insecure_randomness"), [], "the two categories are mutually exclusive");
  assert.deepEqual(of(found, "weak_hash_algorithm"), [], "the same digest is not also reported as a weak algorithm");
  assert.match(reported[0].reasoning, /sessions\.set\(\)|session` cookie/);
});

test("a token that is neither stored as a session nor written to a cookie stays generic randomness", async () => {
  const found = await analyse(
    "src/reset-request.js",
    `
      const resetTokens = require("./reset-tokens.js");
      function buildToken() {
        return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
      }
      async function requestReset(request, response) {
        const token = buildToken();
        await resetTokens.create({ userId: 1, token, expiresAt: new Date(Date.now() + 1800000) });
        return response.end("sent");
      }
      module.exports = { requestReset };
    `
  );
  assert.equal(of(found, "insecure_randomness").length, 1);
  assert.deepEqual(of(found, "weak_session_identifier"), []);
});

test("an integrity check between two digests is not a timing-unsafe secret comparison", async () => {
  const found = await analyse(
    "src/verify-artifact.js",
    `
      const crypto = require("node:crypto");
      function verifyArtifact(body, artifact) {
        if (body.byteLength !== artifact.size) return { ok: false };
        const digest = crypto.createHash("sha256").update(body).digest("hex");
        if (digest !== artifact.sha256) return { ok: false, reason: "digest mismatch" };
        return { ok: true };
      }
      module.exports = { verifyArtifact };
    `
  );
  assert.deepEqual(
    of(found, "timing_unsafe_comparison"),
    [],
    "a prefix of SHA-256(x) does not invert the hash, and comparing digests is this rule's own remediation"
  );
});

test("a session cookie with all flags merely absent is medium, an explicit false is high", async () => {
  const absent = await analyse(
    "src/plain-login.js",
    `
      async function handle(request, response) {
        response.setHeader("set-cookie", "session=abc123def456; Path=/");
        return response.end("ok");
      }
      module.exports = { handle };
    `
  );
  const absentReported = of(absent, "insecure_cookie_configuration");
  assert.equal(absentReported.length, 1);
  assert.equal(absentReported[0].severity, "medium");

  const disabled = await analyse(
    "src/opted-out-login.js",
    `
      const SESSION_COOKIE = "app_session";
      export default async function plugin(fastify) {
        fastify.post("/sessions", async (request, reply) => {
          reply.setCookie(SESSION_COOKIE, "abc", { path: "/", httpOnly: false, secure: false, sameSite: "none" });
          return reply.code(201).send({ ok: true });
        });
      }
    `
  );
  const disabledReported = of(disabled, "insecure_cookie_configuration");
  assert.equal(disabledReported.length, 1);
  assert.equal(disabledReported[0].severity, "high");
});

test("a correct session cookie over plain http is not reported for Secure alone", async () => {
  const found = await analyse(
    "src/local-login.js",
    `
      async function handle(request, response) {
        response.setHeader("set-cookie", "session=abc123def456; Path=/; HttpOnly; SameSite=Lax");
        return response.end("ok");
      }
      module.exports = { handle };
    `
  );
  assert.deepEqual(of(found, "insecure_cookie_configuration"), []);
});

/* ------------------------------------------- a credential that authenticates to nothing */

/*
 * `postgres://user:pass@localhost/db` is what a framework's generator writes into its
 * development datastore config, and the username, password and database name are usually
 * the project's name three times. There is no disclosure to report: the credential cannot
 * be used from anywhere but the machine it is already on, and "rotate this at the issuer"
 * is advice with no issuer.
 *
 * The pair matters more than the suppression. Only the *host* decides — a real hostname or
 * a routable private address stays reported however development-ish the file looks around
 * it, because that one can be used by whoever reads the repository.
 */

test("a loopback connection string is not a leaked credential", async () => {
  const found = await analyse(
    "config/datastores.js",
    `
    module.exports.datastores = {
      default: {
        adapter: 'sails-postgresql',
        url: 'postgres://northgate:northgate@localhost:5432/northgate_dev'
      }
    };
    `
  );
  assert.deepEqual(of(found, "hardcoded_secret"), []);
});

test("the same shape pointed at a container hostname is not one either", async () => {
  const found = await analyse(
    "config/queue.ts",
    `
    export const queue = {
      // docker compose puts redis on the same private network under this name
      url: "redis://default:devpassword@redis:6379"
    };
    `
  );
  assert.deepEqual(of(found, "hardcoded_secret"), []);
});

test("the same shape pointed at a real host is reported", async () => {
  const found = await analyse(
    "config/datastores.ts",
    `
    export const datastores = {
      default: {
        url: "postgres://reporting:Hunter2LiveValue@db.prod.example.com:5432/main"
      }
    };
    `
  );
  assert.equal(of(found, "hardcoded_secret").length, 1);
});

test("a routable private address is a real host", async () => {
  // 10.0.0.0/8 is private and is not loopback: whoever reads the repository can reach it
  // from anywhere on that network, which is the whole exposure.
  const found = await analyse(
    "config/datastores.ts",
    `
    export const datastores = {
      default: { url: "postgres://svc:S3cretLiveValue@10.0.4.12:5432/orders" }
    };
    `
  );
  assert.equal(of(found, "hardcoded_secret").length, 1);
});
