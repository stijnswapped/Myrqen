import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { discoverRoutes } from "../dist/ast/routes.js";
import { parseFile } from "../dist/ast/parse.js";
import * as perimeter from "../dist/rules/perimeter.js";

/**
 * Every case here is written as source, never as a reference to a corpus file, and
 * uses names, routes, and domains that appear nowhere in `benchmark/corpus`. A rule
 * that only fires on a known fixture is worthless in a real repository, and a test
 * that reads the fixture cannot detect that.
 *
 * The rules are exercised directly rather than through `scan()` so the tests do not
 * depend on when the rule file is registered in `src/index.ts`.
 */
const RULES = Object.values(perimeter).filter(
  (value) => value && typeof value === "object" && typeof value.run === "function"
);

async function findings(relativePath, source) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-perimeter-"));
  try {
    const target = path.join(root, relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, source, "utf8");
    const parsed = await parseFile(root, target);
    assert.ok(!("error" in parsed), `the fixture must parse: ${parsed.error ?? ""}`);
    const candidates = [];
    const context = { file: parsed, routes: discoverRoutes(parsed), report: (candidate) => candidates.push(candidate) };
    for (const rule of RULES) rule.run(context);
    return candidates;
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const categories = (candidates) => candidates.map((candidate) => candidate.category);
const of = (candidates, category) => candidates.filter((candidate) => candidate.category === category);

/* ---------------------------------------------------------------- redirects */

test("a redirect to a caller-supplied destination is reported", async () => {
  const result = await findings(
    "src/enter.js",
    `
    const express = require("express");
    const router = express.Router();
    router.post("/enter", async (req, res) => {
      const landing = req.body.landing || "/home";
      await startSession(req, res);
      res.redirect(landing);
    });
    module.exports = router;
    `
  );
  const open = of(result, "open_redirect");
  assert.equal(open.length, 1, "the unvalidated destination is one finding");
  assert.equal(open[0].route, "POST /enter");
  assert.match(open[0].title, /never constrained to this site/);
});

test("a helper that rejects protocol-relative destinations silences the redirect rule", async () => {
  const result = await findings(
    "src/enter-guarded.js",
    `
    const express = require("express");
    const router = express.Router();
    const FALLBACK = "/home";
    function sameSitePath(value) {
      if (typeof value !== "string" || value.length === 0) return FALLBACK;
      if (!value.startsWith("/")) return FALLBACK;
      if (value.startsWith("//") || value.includes("\\\\")) return FALLBACK;
      return value;
    }
    router.post("/enter", async (req, res) => {
      const landing = sameSitePath(req.body.landing);
      await startSession(req, res);
      res.redirect(landing);
    });
    module.exports = router;
    `
  );
  assert.deepEqual(of(result, "open_redirect"), [], "a leading-slash test plus a double-slash rejection is the fix");
});

test("resolving a destination against the app origin and comparing origins is accepted", async () => {
  const result = await findings(
    "src/enter-resolved.ts",
    `
    import { Hono } from "hono";
    const enter = new Hono();
    const SITE = "https://console.pinelake.test";
    function landing(raw: string | undefined): string {
      if (!raw) return "/overview";
      let resolved: URL;
      try {
        resolved = new URL(raw, SITE);
      } catch {
        return "/overview";
      }
      if (resolved.origin !== SITE) return "/overview";
      return resolved.pathname + resolved.search;
    }
    enter.get("/enter", async (c) => {
      const requested = c.req.query("landing");
      return c.redirect(landing(requested), 302);
    });
    export default enter;
    `
  );
  assert.deepEqual(of(result, "open_redirect"), [], "an origin comparison after resolution is the strongest form");
});

test("a leading-slash check on its own is reported as the weak guard it is", async () => {
  const result = await findings(
    "src/enter-weak.js",
    `
    const express = require("express");
    const router = express.Router();
    router.post("/enter", async (req, res) => {
      const landing = req.body.landing || "/home";
      if (!landing.startsWith("/")) {
        return res.status(400).json({ error: "bad landing" });
      }
      await startSession(req, res);
      res.redirect(landing);
    });
    module.exports = router;
    `
  );
  const open = of(result, "open_redirect");
  assert.equal(open.length, 1);
  assert.match(open[0].title, /protocol-relative URL satisfies/);
});

test("a framework redirect built from a fixed path and the request's own origin is not a finding", async () => {
  const result = await findings(
    "app/api/enter/route.ts",
    `
    import { NextResponse, type NextRequest } from "next/server";
    export async function GET(request: NextRequest) {
      const { searchParams } = request.nextUrl;
      const ticket = searchParams.get("ticket");
      if (!ticket) {
        return NextResponse.redirect(new URL("/enter?error=no_ticket", request.nextUrl.origin));
      }
      return NextResponse.redirect(new URL("/overview", request.nextUrl.origin));
    }
    `
  );
  assert.deepEqual(of(result, "open_redirect"), [], "the relative reference is a constant, so nothing is caller-chosen");
});

test("a redirect whose path prefix is fixed cannot leave the site and is not reported", async () => {
  const result = await findings(
    "src/basket-actions.ts",
    `
    import { redirect } from "next/navigation";
    export async function submitBasket(form: FormData) {
      const basket = await createBasket(form);
      redirect(\`/baskets/\${basket.id}?state=\${basket.state}\`);
    }
    `
  );
  assert.deepEqual(of(result, "open_redirect"), [], "a `/baskets/...` prefix pins the destination to this origin");
});

/* --------------------------------------------------------- path containment */

test("a caller-supplied name joined onto a directory and read is reported", async () => {
  const result = await findings(
    "src/ledger-files.js",
    `
    const express = require("express");
    const fs = require("fs");
    const path = require("path");
    const router = express.Router();
    const LEDGER_ROOT = process.env.LEDGER_ROOT || "/srv/ledgers";
    router.get("/:bookId/pages/:page", async (req, res) => {
      const { bookId, page } = req.params;
      const target = path.join(LEDGER_ROOT, bookId, page);
      const body = await fs.promises.readFile(target);
      res.type("application/pdf").send(body);
    });
    module.exports = router;
    `
  );
  const traversal = of(result, "path_traversal");
  assert.equal(traversal.length, 1);
  assert.equal(traversal[0].route, "GET /:bookId/pages/:page");
});

test("reducing the caller's segment with path.basename silences the traversal rule", async () => {
  const result = await findings(
    "src/ledger-files-safe.js",
    `
    const express = require("express");
    const fs = require("fs");
    const path = require("path");
    const router = express.Router();
    const LEDGER_ROOT = process.env.LEDGER_ROOT || "/srv/ledgers";
    router.get("/:bookId/pages/:page", async (req, res) => {
      const { page } = req.params;
      const target = path.join(LEDGER_ROOT, path.basename(page));
      const body = await fs.promises.readFile(target);
      res.type("application/pdf").send(body);
    });
    module.exports = router;
    `
  );
  assert.deepEqual(of(result, "path_traversal"), [], "basename removes every separator, so nothing can escape");
});

test("basename used only for the download header does not excuse the raw join", async () => {
  const result = await findings(
    "src/ledger-files-header.js",
    `
    const express = require("express");
    const fs = require("fs");
    const path = require("path");
    const router = express.Router();
    const LEDGER_ROOT = process.env.LEDGER_ROOT || "/srv/ledgers";
    router.get("/:bookId/pages/:page", async (req, res) => {
      const { page } = req.params;
      const target = path.join(LEDGER_ROOT, page);
      res.set("Content-Disposition", 'attachment; filename="' + path.basename(page) + '"');
      fs.createReadStream(target).pipe(res);
    });
    module.exports = router;
    `
  );
  assert.equal(of(result, "path_traversal").length, 1, "the value that reaches the path is still the raw one");
});

test("a resolve-and-confine helper silences the traversal rule", async () => {
  const result = await findings(
    "src/ledger-files-confined.js",
    `
    const express = require("express");
    const fs = require("fs");
    const path = require("path");
    const router = express.Router();
    const LEDGER_ROOT = process.env.LEDGER_ROOT || "/srv/ledgers";
    function inside(root, name) {
      const candidate = path.resolve(root, path.basename(name));
      const base = path.resolve(root) + path.sep;
      return candidate.startsWith(base) ? candidate : null;
    }
    router.get("/:bookId/pages/:page", async (req, res) => {
      const target = inside(LEDGER_ROOT, req.params.page);
      if (!target) return res.status(400).json({ error: "bad page" });
      fs.createReadStream(target).pipe(res);
    });
    module.exports = router;
    `
  );
  assert.deepEqual(of(result, "path_traversal"), []);
});

test("an anchored character-set guard with no separators counts as containment", async () => {
  const result = await findings(
    "src/snapshot-write.js",
    `
    const express = require("express");
    const fs = require("fs");
    const path = require("path");
    const router = express.Router();
    const SNAPSHOT_ROOT = "/srv/snapshots";
    const TAG_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
    router.post("/snapshots", async (req, res) => {
      const tag = String(req.body.tag || "").trim().toLowerCase();
      if (!TAG_PATTERN.test(tag)) {
        return res.status(400).json({ error: "bad tag" });
      }
      await fs.promises.writeFile(path.join(SNAPSHOT_ROOT, tag + ".json"), "{}");
      res.status(201).json({ tag });
    });
    module.exports = router;
    `
  );
  assert.deepEqual(of(result, "path_traversal"), [], "the pattern cannot express a slash, a backslash, or a dot");
});

test("a metadata read is not reported as a file-content traversal", async () => {
  const result = await findings(
    "src/ledger-exists.js",
    `
    const express = require("express");
    const fs = require("fs");
    const path = require("path");
    const router = express.Router();
    router.get("/:page/exists", async (req, res) => {
      const info = await fs.promises.stat(path.join("/srv/ledgers", req.params.page)).catch(() => null);
      res.json({ exists: Boolean(info) });
    });
    module.exports = router;
    `
  );
  assert.deepEqual(of(result, "path_traversal"), [], "stat discloses existence, and the download rule owns the read");
});

/* ------------------------------------------------------------------ archives */

test("an archive entry name joined onto the destination and written is reported", async () => {
  const result = await findings(
    "src/bundle-import.js",
    `
    const fs = require("node:fs");
    const path = require("node:path");
    const yauzl = require("yauzl");
    function unpack(archive, destination) {
      return new Promise((resolve, reject) => {
        archive.on("entry", (entry) => {
          const target = path.join(destination, entry.fileName);
          archive.openReadStream(entry, (err, stream) => {
            if (err) return reject(err);
            stream.pipe(fs.createWriteStream(target));
            archive.readEntry();
          });
        });
        archive.on("end", resolve);
        archive.readEntry();
      });
    }
    module.exports = { unpack };
    `
  );
  const slip = of(result, "zip_slip");
  assert.equal(slip.length, 1);
  assert.match(slip[0].summary, /entry name inside an archive is attacker-supplied/);
});

test("resolving each entry against the destination and skipping escapes is accepted", async () => {
  const result = await findings(
    "src/bundle-import-safe.js",
    `
    const fs = require("node:fs");
    const path = require("node:path");
    const yauzl = require("yauzl");
    function confine(destination, entryName) {
      const root = path.resolve(destination);
      const candidate = path.resolve(root, entryName);
      if (candidate !== root && !candidate.startsWith(root + path.sep)) return null;
      return candidate;
    }
    function unpack(archive, destination, skipped) {
      return new Promise((resolve, reject) => {
        archive.on("entry", (entry) => {
          const target = confine(destination, entry.fileName);
          if (!target) {
            skipped.push(entry.fileName);
            archive.readEntry();
            return;
          }
          archive.openReadStream(entry, (err, stream) => {
            if (err) return reject(err);
            stream.pipe(fs.createWriteStream(target));
            archive.readEntry();
          });
        });
        archive.on("end", resolve);
        archive.readEntry();
      });
    }
    module.exports = { unpack };
    `
  );
  assert.deepEqual(of(result, "zip_slip"), []);
});

/* ------------------------------------------------------------------- uploads */

test("an upload stored with an extension taken from the client filename is reported", async () => {
  const result = await findings(
    "src/badge-upload.js",
    `
    import fs from "node:fs";
    import path from "node:path";
    import { randomUUID } from "node:crypto";
    import { pipeline } from "node:stream/promises";
    const BADGE_DIR = process.env.BADGE_DIR || "/srv/public/badges";
    export default async function (fastify) {
      fastify.post("/badges", async (request, reply) => {
        const upload = await request.file({ limits: { fileSize: 1048576 } });
        const extension = path.extname(upload.filename).toLowerCase();
        const stored = \`\${randomUUID()}\${extension}\`;
        await pipeline(upload.file, fs.createWriteStream(path.join(BADGE_DIR, stored)));
        return reply.code(201).send({ badge: stored });
      });
    }
    `
  );
  const upload = of(result, "unrestricted_file_upload");
  assert.equal(upload.length, 1);
  assert.equal(upload[0].route, "POST /badges");
  assert.match(upload[0].summary, /served to the web/);
});

test("an extension derived from a verified type allowlist is accepted", async () => {
  const result = await findings(
    "src/badge-upload-safe.js",
    `
    import fs from "node:fs";
    import path from "node:path";
    import { randomUUID } from "node:crypto";
    const BADGE_DIR = process.env.BADGE_DIR || "/srv/public/badges";
    const SUFFIX_BY_TYPE = { "image/png": ".png", "image/jpeg": ".jpg" };
    export default async function (fastify) {
      fastify.post("/badges", async (request, reply) => {
        const upload = await request.file({ limits: { fileSize: 1048576 } });
        const extension = SUFFIX_BY_TYPE[upload.mimetype];
        if (!extension) return reply.code(415).send({ error: "bad type" });
        const contents = await upload.toBuffer();
        const stored = \`\${randomUUID()}\${extension}\`;
        await fs.promises.writeFile(path.join(BADGE_DIR, stored), contents);
        return reply.code(201).send({ badge: stored });
      });
    }
    `
  );
  assert.deepEqual(of(result, "unrestricted_file_upload"), []);
});

/* ---------------------------------------------------------------------- ssrf */

test("a fetch of a destination composed from the request body is reported", async () => {
  const result = await findings(
    "app/api/thumbnail/route.ts",
    `
    import { NextResponse } from "next/server";
    type Body = { source?: string };
    export async function POST(request: Request) {
      const payload = (await request.json()) as Body;
      const candidate = payload.source?.trim();
      if (!candidate) return NextResponse.json({ error: "source required" }, { status: 400 });
      let destination: URL;
      try {
        destination = new URL(candidate);
      } catch {
        return NextResponse.json({ error: "bad source" }, { status: 400 });
      }
      const upstream = await fetch(destination, { redirect: "follow" });
      return NextResponse.json({ status: upstream.status });
    }
    `
  );
  const ssrf = of(result, "server_side_request_forgery");
  assert.equal(ssrf.length, 1, "the `as` cast must not break the flow from request.json()");
  assert.equal(ssrf[0].route, "POST /api/thumbnail");
});

test("a hostname allowlist before the fetch is accepted", async () => {
  const result = await findings(
    "app/api/thumbnail-safe/route.ts",
    `
    import { NextResponse } from "next/server";
    const SOURCES = new Set(["images.pinelake.test", "cdn.pinelake.test"]);
    type Body = { source?: string };
    export async function POST(request: Request) {
      const payload = (await request.json()) as Body;
      const candidate = payload.source?.trim();
      if (!candidate) return NextResponse.json({ error: "source required" }, { status: 400 });
      let destination: URL;
      try {
        destination = new URL(candidate);
      } catch {
        return NextResponse.json({ error: "bad source" }, { status: 400 });
      }
      if (destination.protocol !== "https:" || !SOURCES.has(destination.hostname)) {
        return NextResponse.json({ error: "unsupported source" }, { status: 400 });
      }
      const upstream = await fetch(destination, { redirect: "error" });
      return NextResponse.json({ status: upstream.status });
    }
    `
  );
  assert.deepEqual(of(result, "server_side_request_forgery"), []);
});

test("an outbound request whose scheme and host are literal is not reported", async () => {
  const result = await findings(
    "src/exchange-rates.js",
    `
    const express = require("express");
    const router = express.Router();
    router.get("/rates/:currency", async (req, res) => {
      const upstream = await fetch(\`https://rates.pinelake.test/v1/\${req.params.currency}\`);
      res.json(await upstream.json());
    });
    module.exports = router;
    `
  );
  assert.deepEqual(of(result, "server_side_request_forgery"), [], "the caller cannot move the origin");
});

/* ---------------------------------------------------------------------- cors */

test("a reflected Origin header with credentials is reported", async () => {
  const result = await findings(
    "src/tile-headers.js",
    `
    const express = require("express");
    const router = express.Router();
    router.use((req, res, next) => {
      const origin = req.headers.origin;
      if (origin) {
        res.set("Access-Control-Allow-Origin", origin);
        res.set("Access-Control-Allow-Credentials", "true");
      }
      next();
    });
    router.get("/tiles", async (req, res) => res.json({ tiles: [] }));
    module.exports = router;
    `
  );
  const cors = of(result, "insecure_cors_configuration");
  assert.equal(cors.length, 1);
  assert.equal(cors[0].severity, "high");
  assert.equal(cors[0].route, "GET /tiles");
});

test("an allowlist test before the reflection is accepted", async () => {
  const result = await findings(
    "src/tile-headers-safe.js",
    `
    const express = require("express");
    const router = express.Router();
    const TILE_ORIGINS = new Set(["https://maps.pinelake.test", "https://docs.pinelake.test"]);
    router.use((req, res, next) => {
      const origin = req.headers.origin;
      res.vary("Origin");
      if (origin && TILE_ORIGINS.has(origin)) {
        res.set("Access-Control-Allow-Origin", origin);
        res.set("Access-Control-Allow-Credentials", "true");
      }
      next();
    });
    router.get("/tiles", async (req, res) => res.json({ tiles: [] }));
    module.exports = router;
    `
  );
  assert.deepEqual(of(result, "insecure_cors_configuration"), []);
});

test("a permissive cors origin callback is reported and a deciding one is not", async () => {
  const permissive = await findings(
    "src/tile-api.ts",
    `
    import { Hono } from "hono";
    import { cors } from "hono/cors";
    const tiles = new Hono();
    tiles.use("/tiles/*", cors({ origin: (origin) => origin ?? "*", credentials: true }));
    tiles.get("/tiles/list", async (c) => c.json({ tiles: [] }));
    export default tiles;
    `
  );
  assert.equal(of(permissive, "insecure_cors_configuration").length, 1);

  const deciding = await findings(
    "src/tile-api-safe.ts",
    `
    import { Hono } from "hono";
    import { cors } from "hono/cors";
    const tiles = new Hono();
    const TILE_ORIGINS = new Set(["https://maps.pinelake.test"]);
    tiles.use("/tiles/*", cors({ origin: (origin) => (TILE_ORIGINS.has(origin) ? origin : null), credentials: true }));
    tiles.get("/tiles/list", async (c) => c.json({ tiles: [] }));
    export default tiles;
    `
  );
  assert.deepEqual(of(deciding, "insecure_cors_configuration"), []);
});

/* --------------------------------------------------------------- rate limits */

test("a credential route with no limit beside limited siblings is reported", async () => {
  const result = await findings(
    "src/keys.js",
    `
    import bcrypt from "bcryptjs";
    import rateLimit from "@fastify/rate-limit";
    export default async function (fastify) {
      await fastify.register(rateLimit, { global: false });
      fastify.post("/keys/password", { schema: {} }, async (request, reply) => {
        const holder = await fastify.holders.byEmail(request.body.email);
        if (!holder || !(await bcrypt.compare(request.body.password, holder.passwordHash))) {
          return reply.code(401).send({ error: "invalid_credentials" });
        }
        return reply.code(201).send({ key: await fastify.signAccessToken(holder) });
      });
      fastify.post(
        "/keys/renew",
        { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } },
        async (request, reply) => {
          const stored = await fastify.keys.byToken(request.body.renewToken);
          if (!stored) return reply.code(401).send({ error: "invalid_token" });
          return reply.send({ key: await fastify.signAccessToken(stored.holder) });
        }
      );
    }
    `
  );
  const limits = of(result, "missing_rate_limit_on_credentials");
  assert.equal(limits.length, 1);
  assert.equal(limits[0].route, "POST /keys/password");
  assert.match(limits[0].summary, /POST \/keys\/renew/);
});

test("a credential route that carries its own limit is not reported", async () => {
  const result = await findings(
    "src/keys-limited.js",
    `
    import bcrypt from "bcryptjs";
    import rateLimit from "@fastify/rate-limit";
    export default async function (fastify) {
      await fastify.register(rateLimit, { global: false });
      fastify.post(
        "/keys/password",
        { config: { rateLimit: { max: 5, timeWindow: "15 minutes" } } },
        async (request, reply) => {
          const holder = await fastify.holders.byEmail(request.body.email);
          if (!holder || !(await bcrypt.compare(request.body.password, holder.passwordHash))) {
            return reply.code(401).send({ error: "invalid_credentials" });
          }
          return reply.code(201).send({ key: await fastify.signAccessToken(holder) });
        }
      );
    }
    `
  );
  assert.deepEqual(of(result, "missing_rate_limit_on_credentials"), []);
});

test("a module with no rate limiting at all produces no rate-limit finding", async () => {
  const result = await findings(
    "src/keys-bare.js",
    `
    const express = require("express");
    const bcrypt = require("bcrypt");
    const router = express.Router();
    router.post("/session", async (req, res) => {
      const holder = await lookup(req.body.email);
      if (!holder || !(await bcrypt.compare(req.body.password, holder.passwordHash))) {
        return res.status(401).json({ error: "no match" });
      }
      req.session.holderId = holder.id;
      res.status(201).json({ ok: true });
    });
    module.exports = router;
    `
  );
  assert.deepEqual(
    of(result, "missing_rate_limit_on_credentials"),
    [],
    "without in-file contrast the limiter may live in a gateway, and guessing would flag every correct sign-in"
  );
});

/* -------------------------------------------------------------- result bound */

test("a caller-chosen page size with no ceiling is reported for review", async () => {
  const result = await findings(
    "src/digest-resolvers.js",
    `
    const gql = require("graphql-tag");
    const prisma = require("../lib/prisma");
    const typeDefs = gql\`
      extend type Query {
        digest(first: Int): [DigestEntry!]!
      }
    \`;
    const resolvers = {
      Query: {
        digest: async (_parent, { first = 20 }, context) => {
          return prisma.digestEntry.findMany({
            where: { tenantId: context.viewer.tenantId },
            orderBy: { createdAt: "desc" },
            take: first
          });
        }
      }
    };
    module.exports = { typeDefs, resolvers };
    `
  );
  const unbounded = of(result, "unbounded_resource_consumption");
  assert.equal(unbounded.length, 1);
  assert.equal(unbounded[0].verification, "needs_review", "how much volume matters is a judgement about the data");
  assert.equal(unbounded[0].route, "POST /graphql");
});

test("a clamped page size is not reported", async () => {
  const result = await findings(
    "src/digest-resolvers-clamped.js",
    `
    const gql = require("graphql-tag");
    const prisma = require("../lib/prisma");
    const DEFAULT_PAGE = 20;
    const MAX_PAGE = 100;
    const typeDefs = gql\`
      extend type Query {
        digest(first: Int): [DigestEntry!]!
      }
    \`;
    function pageSize(first) {
      if (first === undefined || first === null) return DEFAULT_PAGE;
      return Math.min(Math.max(first, 1), MAX_PAGE);
    }
    const resolvers = {
      Query: {
        digest: async (_parent, { first }, context) => {
          return prisma.digestEntry.findMany({
            where: { tenantId: context.viewer.tenantId },
            orderBy: { createdAt: "desc" },
            take: pageSize(first)
          });
        }
      }
    };
    module.exports = { typeDefs, resolvers };
    `
  );
  assert.deepEqual(of(result, "unbounded_resource_consumption"), []);
});

test("a schema maximum on the page size counts as a ceiling", async () => {
  const result = await findings(
    "src/reports-router.ts",
    `
    import { z } from "zod";
    import { protectedProcedure, router } from "../trpc";
    export const reportsRouter = router({
      list: protectedProcedure
        .input(z.object({ limit: z.number().int().min(1).max(100).default(25) }))
        .query(async ({ ctx, input }) => {
          return ctx.db.report.findMany({
            where: { tenantId: ctx.session.tenantId },
            orderBy: { createdAt: "desc" },
            take: input.limit
          });
        })
    });
    `
  );
  assert.deepEqual(of(result, "unbounded_resource_consumption"), []);
});

/* --------------------------------------------------------------- whole shape */

test("a correct download route produces no perimeter finding of any kind", async () => {
  const result = await findings(
    "src/receipt-download.ts",
    `
    import { Hono } from "hono";
    import { readFile } from "node:fs/promises";
    import path from "node:path";
    const receipts = new Hono();
    const RECEIPT_ROOT = process.env.RECEIPT_ROOT ?? "/srv/receipts";
    receipts.get("/receipts/:claimId/:filename{.+}", async (c) => {
      const claimId = c.req.param("claimId");
      const filename = c.req.param("filename");
      const claimRoot = path.resolve(RECEIPT_ROOT, claimId);
      const target = path.resolve(claimRoot, filename);
      if (target !== claimRoot && !target.startsWith(claimRoot + path.sep)) {
        return c.json({ error: "not found" }, 404);
      }
      const body = await readFile(target);
      return new Response(body, { headers: { "content-type": "application/pdf" } });
    });
    export default receipts;
    `
  );
  assert.deepEqual(categories(result), [], "the correct form of the code must be silent");
});
