import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { discoverRoutes } from "../dist/ast/routes.js";
import { parseFile } from "../dist/ast/parse.js";
import * as perimeter from "../dist/rules/perimeter.js";

// Entry-point adapters register themselves on import. Without this the taint model
// sees no seeds for an Electron IPC handler, a worker route, or a file-based
// endpoint, and a test written around one of those would pass on an empty scan.
import "../dist/ast/frameworks/index.js";

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

test("an anchored pattern whose only backslash escapes a dot still counts as containment", async () => {
  const result = await findings(
    "src/reports/[name]/+server.ts",
    `
    import { createReadStream } from "node:fs";
    import { join } from "node:path";
    const REPORT_ROOT = "/srv/reports";
    const REPORT_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\\.csv$/;
    export const GET = async ({ params, locals }) => {
      const tenantRoot = join(REPORT_ROOT, locals.session.tenantId);
      const requested = params.name;
      if (!REPORT_NAME.test(requested)) throw new Error("not a report name");
      const target = join(tenantRoot, requested);
      return new Response(createReadStream(target));
    };
    `
  );
  assert.deepEqual(
    of(result, "path_traversal"),
    [],
    "an escaped dot is a dot; the pattern still cannot express a separator"
  );
});

test("an anchored pattern that allows a dot-dot hop is not containment", async () => {
  const result = await findings(
    "src/notes-read.js",
    `
    const express = require("express");
    const fs = require("fs");
    const path = require("path");
    const router = express.Router();
    const NOTE_NAME = /^[.a-z]{1,32}$/;
    router.get("/notes/:name", async (req, res) => {
      const name = req.params.name;
      if (!NOTE_NAME.test(name)) return res.status(400).json({ error: "bad name" });
      res.send(await fs.promises.readFile(path.join("/srv/notes", name), "utf8"));
    });
    module.exports = router;
    `
  );
  assert.equal(of(result, "path_traversal").length, 1, "a pattern that accepts `..` walks out of the directory");
});

test("a resolver that pins its own parameter to an anchored slug silences the traversal rule", async () => {
  const result = await findings(
    "src/library-bridge.js",
    `
    const { ipcMain } = require("electron");
    const { writeFile } = require("node:fs/promises");
    const path = require("node:path");
    const LIBRARY_ID = /^[a-z0-9][a-z0-9-]{5,39}$/;
    function libraryDir(libraryId) {
      if (!LIBRARY_ID.test(String(libraryId))) throw new Error("that is not a library id");
      return path.join("/srv/libraries", libraryId);
    }
    ipcMain.handle("library:write", async (_event, libraryId, noteName, contents) => {
      const dir = libraryDir(libraryId);
      const target = path.join(dir, path.basename(String(noteName), ".md") + ".md");
      await writeFile(target, String(contents ?? ""), "utf8");
      return { path: target };
    });
    `
  );
  assert.deepEqual(
    of(result, "path_traversal"),
    [],
    "the helper rejects anything that could carry a separator before it joins"
  );
});

test("a resolver that joins its parameter without pinning it is still reported", async () => {
  const result = await findings(
    "src/workspace-bridge.js",
    `
    const { ipcMain } = require("electron");
    const { writeFile } = require("node:fs/promises");
    const path = require("node:path");
    function workspaceDir(workspaceId) {
      return path.join("/srv/workspaces", workspaceId);
    }
    ipcMain.handle("workspace:write", async (_event, workspaceId, noteName, contents) => {
      const dir = workspaceDir(workspaceId);
      const target = path.join(dir, path.basename(String(noteName), ".md") + ".md");
      await writeFile(target, String(contents ?? ""), "utf8");
      return { path: target };
    });
    `
  );
  assert.equal(of(result, "path_traversal").length, 1, "nothing stops the workspace id from walking upwards");
});

test("a path whose caller-supplied parts are all reduced to a basename is not reported", async () => {
  const result = await findings(
    "src/ledger-export.controller.ts",
    `
    import { Body, Controller, Post } from "@nestjs/common";
    import { randomUUID } from "node:crypto";
    import { mkdtemp, rename, writeFile } from "node:fs/promises";
    import { tmpdir } from "node:os";
    import { basename, join } from "node:path";
    const OUTPUT_FORMATS = ["pdf", "xlsx"];
    @Controller("ledger")
    export class LedgerExportController {
      @Post("export")
      async export(@Body() body: { rows: string; filename: string; format: string }) {
        if (!OUTPUT_FORMATS.includes(body.format)) throw new Error("unsupported output format");
        const workdir = await mkdtemp(join(tmpdir(), "ledger-"));
        const source = join(workdir, randomUUID() + ".csv");
        await writeFile(source, body.rows, "utf8");
        const destination = join(workdir, basename(body.filename));
        await rename(source.replace(/\.csv$/, ".pdf"), destination);
        return { path: destination };
      }
    }
    `
  );
  assert.deepEqual(
    of(result, "path_traversal"),
    [],
    "every caller-supplied part of the destination went through basename"
  );
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

test("a URL resolved against a fixed origin with a validated path segment is not reported", async () => {
  const result = await findings(
    "src/embed-preview/+server.ts",
    `
    const SLUG = /^[a-z0-9-]{1,64}$/;
    export const GET = async ({ url }) => {
      const slug = url.searchParams.get("slug");
      if (!slug || !SLUG.test(slug)) throw new Error("bad slug");
      const upstream = new URL("/oembed/" + slug + ".json", "https://docs.example-suite.test");
      const response = await fetch(upstream, { signal: AbortSignal.timeout(4000) });
      return new Response(await response.text());
    };
    `
  );
  assert.deepEqual(
    of(result, "server_side_request_forgery"),
    [],
    "the base fixes scheme and host and the caller only extends the path"
  );
});

test("a URL resolved against a caller-supplied base is still reported", async () => {
  const result = await findings(
    "src/mirror-preview/+server.ts",
    `
    export const GET = async ({ url }) => {
      const base = url.searchParams.get("base");
      const upstream = new URL("/status.json", base);
      const response = await fetch(upstream, { signal: AbortSignal.timeout(4000) });
      return new Response(await response.text());
    };
    `
  );
  assert.equal(
    of(result, "server_side_request_forgery").length,
    1,
    "a base the caller chose decides the host and is no base at all"
  );
});

test("a host allowlist whose failing branch only logs does not silence the rule", async () => {
  const result = await findings(
    "src/link-preview/+server.ts",
    `
    const PREVIEW_HOSTS = new Set(["www.example-video.test", "docs.example-suite.test"]);
    export const POST = async ({ request }) => {
      const body = await request.json();
      const parsed = new URL(body.url);
      if (!PREVIEW_HOSTS.has(parsed.hostname)) {
        console.warn("preview host outside the allow list", parsed.hostname);
      }
      const response = await fetch(parsed, { redirect: "follow" });
      return new Response(await response.text());
    };
    `
  );
  assert.equal(
    of(result, "server_side_request_forgery").length,
    1,
    "execution falls out of the block and reaches the fetch with the caller's host"
  );
});

test("the same host allowlist reported through a throwing branch is accepted", async () => {
  const result = await findings(
    "src/embed-fetch/+server.ts",
    `
    const EMBED_HOSTS = new Set(["www.example-video.test", "docs.example-suite.test"]);
    export const POST = async ({ request }) => {
      const body = await request.json();
      const parsed = new URL(body.url);
      if (!EMBED_HOSTS.has(parsed.hostname)) {
        console.warn("embed host outside the allow list", parsed.hostname);
        throw new Error("that host cannot be embedded");
      }
      const response = await fetch(parsed, { redirect: "manual" });
      return new Response(await response.text());
    };
    `
  );
  assert.deepEqual(
    of(result, "server_side_request_forgery"),
    [],
    "failing the check stops the handler before any request is issued"
  );
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

/*
 * The contract here changed on 2026-08-25, and the old assertion is worth remembering.
 *
 * It asserted **silence** when a module mentions no rate limiting, on the grounds that a
 * limiter may live in a gateway and guessing would flag every correct sign-in handler.
 * The reasoning was sound; the consequence was not stated: an application with no rate
 * limiting anywhere got no finding at all, so the one shape most likely to be genuinely
 * unprotected was the one shape guaranteed silence.
 *
 * It now reports `needs_review` — a question, not a claim. That became shippable once
 * the corpus scorer stopped counting an unsettled candidate as a false claim; before
 * that, emitting it would have read as a precision collapse on every corpus. Measured
 * cost of the change: the asserted false-positive rate is unchanged on all seven
 * corpora, and one safe case in the development corpus draws a candidate.
 */
test("a module with no rate limiting at all asks the question rather than asserting it", async () => {
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
  const reported = of(result, "missing_rate_limit_on_credentials");
  assert.equal(reported.length, 1, "the route is not passed over in silence");
  assert.equal(
    reported[0].verification,
    "needs_review",
    "without in-file contrast the limiter may live in a gateway, so this is a question rather than a defect"
  );
  // The wording has to earn the reader's five seconds: it must say what is unknown and
  // how to settle it, or a candidate is just noise with a softer label.
  assert.match(reported[0].summary, /gateway|proxy|platform edge/);
  assert.match(reported[0].verificationPlan, /429|delay/);
});

test("a module whose other credential routes are limited still asserts the gap", async () => {
  // The contrast case must keep its confidence: this is a gap in a stated convention,
  // not a question about where the limiter runs.
  const result = await findings(
    "src/keys-mixed.js",
    `
    const express = require("express");
    const bcrypt = require("bcrypt");
    const rateLimit = require("express-rate-limit");
    const router = express.Router();
    router.post("/session", rateLimit({ windowMs: 60000, max: 10 }), async (req, res) => {
      const holder = await lookup(req.body.email);
      if (!holder || !(await bcrypt.compare(req.body.password, holder.passwordHash))) {
        return res.status(401).json({ error: "no match" });
      }
      res.status(201).json({ ok: true });
    });
    router.post("/password/reset", async (req, res) => {
      const holder = await lookup(req.body.email);
      if (!holder || !(await bcrypt.compare(req.body.code, holder.resetCodeHash))) {
        return res.status(401).json({ error: "no match" });
      }
      res.status(200).json({ ok: true });
    });
    module.exports = router;
    `
  );
  const reported = of(result, "missing_rate_limit_on_credentials");
  assert.equal(reported.length, 1);
  assert.equal(reported[0].verification, "strong_evidence");
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

/* ----------------------------------------------- redirects written as responses */

test("a 302 response whose Location comes from the caller is reported", async () => {
  const result = await findings(
    "src/oauth-return.ts",
    `
    import { Router } from "itty-router";
    const router = Router();
    router.get("/oauth/return", async (request, env) => {
      const url = new URL(request.url);
      const stateKey = url.searchParams.get("state");
      const state = await env.OAUTH_STATE.get(stateKey, "json");
      const destination = state.returnTo ?? "/dashboard";
      if (!destination.startsWith("/")) return new Response("must be relative", { status: 400 });
      return new Response(null, { status: 302, headers: { location: destination } });
    });
    export default { fetch: router.handle };
    `
  );
  const open = of(result, "open_redirect");
  assert.equal(open.length, 1, "a 3xx status plus a Location header is a redirect");
  assert.match(open[0].title, /leading-slash/, "a single leading-slash test is the weak guard");
});

test("a 302 response whose Location is resolved and origin-compared is not reported", async () => {
  const result = await findings(
    "src/saml-return.ts",
    `
    import { Router } from "itty-router";
    const router = Router();
    router.get("/saml/return", async (request, env) => {
      const url = new URL(request.url);
      const stateKey = url.searchParams.get("state");
      const state = await env.SAML_STATE.get(stateKey, "json");
      const requested = new URL(state.returnTo ?? "/dashboard", url.origin);
      if (requested.origin !== url.origin) return new Response("must be local", { status: 400 });
      const destination = requested.pathname + requested.search;
      return new Response(null, { status: 302, headers: { location: destination } });
    });
    export default { fetch: router.handle };
    `
  );
  assert.deepEqual(of(result, "open_redirect"), [], "the resolved origin is compared against this application's own");
});

test("a redirect to a URL whose origin was fixed at construction is not reported", async () => {
  const result = await findings(
    "src/oauth-start.ts",
    `
    import { Router } from "itty-router";
    const router = Router();
    router.get("/oauth/start", async (request, env) => {
      const url = new URL(request.url);
      const authorize = new URL("https://idp.example-suite.test/oauth/authorize");
      authorize.searchParams.set("client_id", env.IDP_CLIENT_ID);
      authorize.searchParams.set("redirect_uri", url.origin + "/oauth/return");
      return new Response(null, { status: 302, headers: { location: authorize.toString() } });
    });
    export default { fetch: router.handle };
    `
  );
  assert.deepEqual(
    of(result, "open_redirect"),
    [],
    "search parameters cannot move the browser off an origin the constructor fixed"
  );
});

/* ------------------------------------- cross-origin policy in a header map */

test("an Origin reflected into a header map with credentials is reported", async () => {
  const result = await findings(
    "src/embed-bridge.ts",
    `
    import { Router } from "itty-router";
    const router = Router();
    const PARTNER_SUFFIXES = ["example-suite.test", "example-status.test"];
    function corsHeaders(origin) {
      if (!origin) return {};
      const host = origin.replace(/^https?:\/\//, "");
      if (!PARTNER_SUFFIXES.some((suffix) => host.endsWith(suffix))) return {};
      return {
        "access-control-allow-origin": origin,
        "access-control-allow-credentials": "true",
        vary: "origin"
      };
    }
    router.get("/embed/summary", async (request, env) => {
      const row = await env.DB.prepare("select plan from accounts where id = ?1").first();
      return Response.json(row, { headers: corsHeaders(request.headers.get("origin")) });
    });
    export default { fetch: router.handle };
    `
  );
  const cors = of(result, "insecure_cors_configuration");
  assert.equal(cors.length, 1, "a suffix match is not an allowlist: any host ending in the domain passes");
  assert.equal(cors[0].severity, "high", "credentials alongside the reflection makes it session-riding");
});

test("an exact-origin allowlist before the same header map is accepted", async () => {
  const result = await findings(
    "src/widget-bridge.ts",
    `
    import { Router } from "itty-router";
    const router = Router();
    const PARTNER_ORIGINS = new Set(["https://app.example-suite.test", "https://status.example-status.test"]);
    function corsHeaders(origin) {
      if (!origin) return {};
      if (!PARTNER_ORIGINS.has(origin)) return {};
      return {
        "access-control-allow-origin": origin,
        "access-control-allow-credentials": "true",
        vary: "origin"
      };
    }
    router.get("/widget/summary", async (request, env) => {
      const row = await env.DB.prepare("select plan from accounts where id = ?1").first();
      return Response.json(row, { headers: corsHeaders(request.headers.get("origin")) });
    });
    export default { fetch: router.handle };
    `
  );
  assert.deepEqual(
    of(result, "insecure_cors_configuration"),
    [],
    "membership in a fixed set of exact origins decides the header"
  );
});

test("a wildcard allowed origin written in a header map is reported", async () => {
  const result = await findings(
    "src/public-bridge.ts",
    `
    import { Router } from "itty-router";
    const router = Router();
    router.get("/public/summary", async (request, env) => {
      const row = await env.DB.prepare("select plan from accounts where id = ?1").first();
      return Response.json(row, { headers: { "access-control-allow-origin": "*" } });
    });
    export default { fetch: router.handle };
    `
  );
  assert.equal(of(result, "insecure_cors_configuration").length, 1, "a wildcard lets any origin read the response");
});

test("a fixed allowed origin written in a header map is not reported", async () => {
  const result = await findings(
    "src/console-bridge.ts",
    `
    import { Router } from "itty-router";
    const router = Router();
    router.get("/console/summary", async (request, env) => {
      const row = await env.DB.prepare("select plan from accounts where id = ?1").first();
      return Response.json(row, {
        headers: {
          "access-control-allow-origin": "https://console.example-suite.test",
          "access-control-allow-credentials": "true"
        }
      });
    });
    export default { fetch: router.handle };
    `
  );
  assert.deepEqual(of(result, "insecure_cors_configuration"), [], "naming one origin is the correct answer");
});

/*
 * Guards found on a held-out corpus, where the engine reported the correctly
 * written half of a pair and stayed quiet about the defective half. Each of these
 * is the *safe* form, so a failure here is a false positive on code that is right,
 * which costs more than a miss.
 */

test("a containment check written with relative() is a real guard", async () => {
  const candidates = await findings(
    "server/handlers/plate-preview.ts",
    `import { isAbsolute, join, relative, resolve } from "@std/path";

const PLATE_ROOT = resolve("/srv/lithoworks/plates");

/** True when candidate really sits under base: reaching it needs no ".." hop. */
function withinPlateRoot(base, candidate) {
  const step = relative(base, candidate);
  return step !== "" && !step.startsWith("..") && !isAbsolute(step);
}

export async function platePreview(request, context) {
  const key = decodeURIComponent(context.params.key ?? "");
  if (!key) return new Response("no plate named", { status: 400 });

  const absolute = resolve(join(PLATE_ROOT, key));
  if (!withinPlateRoot(PLATE_ROOT, absolute)) {
    return new Response("no such plate", { status: 404 });
  }

  const bytes = await Deno.readFile(absolute);
  return new Response(bytes, { status: 200 });
}
`
  );
  assert.deepEqual(
    candidates.filter((candidate) => candidate.category === "path_traversal").map((c) => c.location.line),
    [],
    "relative() plus a '..' and isAbsolute test confines the path as well as resolve-and-startsWith does"
  );
});

test("the same handler without the containment check is still reported", async () => {
  const candidates = await findings(
    "server/handlers/plate-original.ts",
    `import { join, resolve } from "@std/path";

const PLATE_ROOT = resolve("/srv/lithoworks/plates");

export async function plateOriginal(request, context) {
  const key = decodeURIComponent(context.params.key ?? "");
  if (!key) return new Response("no plate named", { status: 400 });

  const absolute = resolve(join(PLATE_ROOT, key));
  const bytes = await Deno.readFile(absolute);
  return new Response(bytes, { status: 200 });
}
`
  );
  assert.ok(
    candidates.some((candidate) => candidate.category === "path_traversal"),
    "the unguarded sibling must still be found, or the guard above is just a rule switch"
  );
});

test("a validating helper still counts through toString() and a conditional", async () => {
  const candidates = await findings(
    "background/handlers/tile-card.js",
    `const TILE_HOSTS = new Set(["tiles.orrery.example", "static.orrery.example"]);

/** The URL we are willing to fetch, or null. Parsing first is the point. */
function tileTarget(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (!TILE_HOSTS.has(url.hostname)) return null;
  return url;
}

export async function tileCard(payload) {
  const raw = typeof payload.url === "string" ? payload.url.trim() : "";
  const target = raw ? tileTarget(raw) : null;
  if (!target) return { ok: false, error: "unsupported_source" };

  const key = target.toString();
  const response = await fetch(key, { credentials: "omit", redirect: "error" });
  return { ok: true, status: response.status };
}
`
  );
  assert.deepEqual(
    candidates.filter((candidate) => candidate.category === "server_side_request_forgery").map((c) => c.location.line),
    [],
    "rendering a validated URL back to a string is not a step away from the helper that validated it"
  );
});

test("the same fetch without the host allowlist is still reported", async () => {
  const candidates = await findings(
    "background/handlers/tile-preview.js",
    `export async function tilePreview(payload) {
  const url = typeof payload.url === "string" ? payload.url.trim() : "";
  if (!url) return { ok: false, error: "missing_url" };

  const response = await fetch(url, { credentials: "omit" });
  const body = (await response.text()).slice(0, 8192);
  return { ok: true, status: response.status, body };
}
`
  );
  assert.ok(
    candidates.some((candidate) => candidate.category === "server_side_request_forgery"),
    "the unvalidated sibling must still be found"
  );
});

test("an origin predicate anchored at a label boundary gates the reflection", async () => {
  const candidates = await findings(
    "src/sse/despatches.ts",
    `const ROOT_DOMAIN = "orrery.example";

/** hostname comes out of the parser, and the leading dot anchors the label. */
function isConsoleOrigin(origin: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:" || parsed.port !== "") return false;
  return parsed.hostname === ROOT_DOMAIN || parsed.hostname.endsWith(\`.\${ROOT_DOMAIN}\`);
}

export async function despatchStream(request: Request): Promise<Response> {
  const origin = request.headers.get("origin") ?? "";
  const headers = new Headers({ "content-type": "text/event-stream" });

  if (isConsoleOrigin(origin)) {
    headers.set("access-control-allow-origin", origin);
    headers.set("access-control-allow-credentials", "true");
    headers.set("vary", "origin");
  }

  return new Response("retry: 5000\\n\\n", { status: 200, headers });
}
`
  );
  assert.deepEqual(
    candidates.filter((candidate) => candidate.category === "insecure_cors_configuration").map((c) => c.location.line),
    [],
    "there is no fixed list to be a member of when the subdomains are per customer"
  );
});

test("an unanchored suffix test does not gate the reflection", async () => {
  const candidates = await findings(
    "src/sse/consignments.ts",
    `const ROOT_DOMAIN = "orrery.example";

function looksLikeOurs(origin: string): boolean {
  return origin.endsWith(ROOT_DOMAIN);
}

export async function consignmentStream(request: Request): Promise<Response> {
  const origin = request.headers.get("origin") ?? "";
  const headers = new Headers({ "content-type": "text/event-stream" });

  if (looksLikeOurs(origin)) {
    headers.set("access-control-allow-origin", origin);
    headers.set("access-control-allow-credentials", "true");
  }

  return new Response("retry: 5000\\n\\n", { status: 200, headers });
}
`
  );
  assert.ok(
    candidates.some((candidate) => candidate.category === "insecure_cors_configuration"),
    "an unanchored suffix also accepts notorrery.example, which is the whole reason the dot is required"
  );
});

/* ------------------------------------------------- D27: a guard before a helper */

/*
 * The 2×2 that isolated this: the guard is held fixed and only the shape of the sink
 * varies. Inline joins were silent when guarded and reported when not — correct. Both
 * helper shapes were reported either way, so extracting path resolution into a function
 * that confines its result *lost* the guard.
 *
 * That is the worst way for a rule to be wrong. Extracting the join into a confining
 * helper is the single most recommended fix for traversal, so the engine reported the
 * advice it gives and stayed quiet about the handler that ignored it.
 */

test("a guarded segment stays guarded when the path is built inside a helper", async () => {
  const candidates = await findings(
    "src/routes/archive-download.ts",
    `
      import express from "express";
      import path from "node:path";
      import fs from "node:fs";

      const ARCHIVE_ROOT = "/srv/archive";
      const LEAF_NAME = /^[a-z0-9._-]+$/;

      function resolveLeaf(leaf: string) {
        return path.join(ARCHIVE_ROOT, leaf);
      }

      export const router = express.Router();
      router.get("/archive/:leaf", (req, res) => {
        const leaf = String(req.params.leaf);
        if (!LEAF_NAME.test(leaf) || leaf.includes("..")) {
          res.status(400).end();
          return;
        }
        res.sendFile(resolveLeaf(leaf));
      });
    `
  );
  assert.deepEqual(of(candidates, "path_traversal"), [], `guarded, so nothing to report: ${categories(candidates)}`);
});

test("the same helper is still reported when nothing guards the segment", async () => {
  // The other half of the 2×2. Without this, the test above passes by silencing the rule.
  const candidates = await findings(
    "src/routes/archive-download.ts",
    `
      import express from "express";
      import path from "node:path";

      const ARCHIVE_ROOT = "/srv/archive";

      function resolveLeaf(leaf: string) {
        return path.join(ARCHIVE_ROOT, leaf);
      }

      export const router = express.Router();
      router.get("/archive/:leaf", (req, res) => {
        res.sendFile(resolveLeaf(String(req.params.leaf)));
      });
    `
  );
  assert.equal(of(candidates, "path_traversal").length, 1, `unguarded, so it must report: ${categories(candidates)}`);
});

test("a guard is the whole condition, not the one regex inside it", async () => {
  /*
   * `LEAF_NAME` permits a dot, so the pattern alone matches `..` and
   * `patternConfinesToOneSegment` rejects it — correctly, on its own. The condition beside
   * it closes exactly that hole. Reading the regex alone throws away the half of the guard
   * that makes it sound.
   */
  const candidates = await findings(
    "src/routes/report-download.ts",
    `
      import express from "express";
      import path from "node:path";

      const REPORT_ROOT = "/srv/reports";
      const LEAF_NAME = /^[A-Za-z0-9._-]+$/;

      export const router = express.Router();
      router.get("/reports/:leaf", (req, res) => {
        const leaf = String(req.params.leaf);
        if (!LEAF_NAME.test(leaf) || leaf.includes("..")) {
          res.status(400).end();
          return;
        }
        res.sendFile(path.join(REPORT_ROOT, leaf));
      });
    `
  );
  assert.deepEqual(of(candidates, "path_traversal"), [], `the condition rules out "..": ${categories(candidates)}`);
});

test("a path segment established by authentication is not the caller's to choose", async () => {
  /*
   * D28. `requireTenant` resolves the tenant from `req.user`, which the auth layer sets and
   * no client can supply — but the taint model treats everything reachable from `req` as
   * caller-controlled, so the tenant read as attacker-chosen and the correctly scoped
   * download became the reported defect.
   *
   * `IDENTITY_EVIDENCE` is the vocabulary the ownership rules already use for exactly this
   * question, and it already lists `requireTenant`. Reused rather than reinvented, and
   * general rather than shaped to this case: it is a list of identity-establishing calls
   * applied uniformly, not a name lifted out of a fixture.
   */
  const candidates = await findings(
    "src/routes/tenant-export.ts",
    `
      import express from "express";
      import { requireTenant } from "../lib/tenant-scope";
      import { resolveWithinTenantStore } from "../lib/store";
      const NAME = /^[A-Za-z0-9._-]+$/;

      export const router = express.Router();
      router.get("/exports/:filename", (req, res) => {
        const { tenantId } = requireTenant(req);
        const filename = String(req.params.filename);
        if (!NAME.test(filename) || filename.includes("..")) {
          res.status(400).end();
          return;
        }
        let absolute;
        try {
          absolute = resolveWithinTenantStore(tenantId, filename);
        } catch (error) {
          res.status(400).end();
          return;
        }
        res.sendFile(absolute);
      });
    `
  );
  assert.deepEqual(of(candidates, "path_traversal"), [], `tenant is server-established: ${categories(candidates)}`);
});

test("a tenant taken straight off a header is still the caller's to choose", async () => {
  // The control that stops the test above from passing by silencing the rule. This tenant
  // really is attacker-supplied, so the same handler must still report.
  const candidates = await findings(
    "src/routes/tenant-export.ts",
    `
      import express from "express";
      import { resolveWithinTenantStore } from "../lib/store";
      const NAME = /^[A-Za-z0-9._-]+$/;

      export const router = express.Router();
      router.get("/exports/:filename", (req, res) => {
        const tenantId = String(req.headers["x-tenant"]);
        const filename = String(req.params.filename);
        if (!NAME.test(filename) || filename.includes("..")) {
          res.status(400).end();
          return;
        }
        res.sendFile(resolveWithinTenantStore(tenantId, filename));
      });
    `
  );
  assert.equal(of(candidates, "path_traversal").length, 1, `header-supplied tenant: ${categories(candidates)}`);
});
