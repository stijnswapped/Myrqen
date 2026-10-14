import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * Process spawning behind a promisified alias, argument injection into a fixed
 * executable, raw SQL escape hatches, HTML written through a Response object,
 * error internals leaving through something other than `res.json`, and the route
 * attribution all of those need in order to be actionable.
 *
 * Sources are written inline and named after nothing in the corpus.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-spawn-"));
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

const ofCategory = (result, category) =>
  result.candidates.filter((candidate) => candidate.category === category);

/* ------------------------------------------------------------------ *
 * Spawning through an alias
 * ------------------------------------------------------------------ */

test("a command built from request data and run through promisify(exec) is reported", async () => {
  const result = await scanSource({
    "src/thumbnails.js": `
      const { exec } = require("node:child_process");
      const { promisify } = require("node:util");
      const runShell = promisify(exec);

      export async function renderThumbnail(req, res) {
        const target = "/srv/out/" + req.body.name + ".png";
        const { stdout } = await runShell("magick convert in.png \\"" + target + "\\"", { timeout: 5000 });
        res.json({ size: stdout.trim() });
      }
    `
  });
  const found = ofCategory(result, "command_injection");
  assert.equal(found.length, 1, "the alias is the only thing standing between the request and a shell");
  assert.equal(found[0].severity, "critical");
});

test("the same shape through promisify(execFile) with a fixed argv is not reported", async () => {
  const result = await scanSource({
    "src/thumbnails.js": `
      const { execFile } = require("node:child_process");
      const { promisify } = require("node:util");
      const path = require("node:path");
      const runFile = promisify(execFile);
      const OUT_ROOT = "/srv/out";

      export async function renderThumbnail(req, res) {
        const target = path.join(OUT_ROOT, req.body.name + ".png");
        await runFile("magick", ["convert", "in.png", target], { timeout: 5000 });
        res.json({ ok: true });
      }
    `
  });
  assert.deepEqual(ofCategory(result, "command_injection"), []);
  assert.deepEqual(
    ofCategory(result, "argument_injection"),
    [],
    "a path built on a fixed root can never begin with a dash"
  );
});

test("a free-text term in a bare positional argv slot is reported as argument injection", async () => {
  const result = await scanSource({
    "src/grep.js": `
      const { execFile } = require("node:child_process");
      const { promisify } = require("node:util");
      const runFile = promisify(execFile);
      const ROOT = "/var/log/app";

      export async function searchLogs(req, res) {
        const term = String(req.query.term || "").trim();
        const limit = Math.min(Number.parseInt(req.query.limit, 10) || 50, 200);
        const { stdout } = await runFile("rg", ["--json", \`--max-count=\${limit}\`, term, ROOT], { timeout: 10000 });
        res.json({ raw: stdout });
      }
    `
  });
  const found = ofCategory(result, "argument_injection");
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, "high");
  assert.match(found[0].remediation, /--/);
});

test("the same term passed as the value of a named option is not reported", async () => {
  const result = await scanSource({
    "src/grep.js": `
      const { execFile } = require("node:child_process");
      const { promisify } = require("node:util");
      const runFile = promisify(execFile);
      const ROOT = "/var/log/app";

      export async function searchLogs(req, res) {
        const term = String(req.query.term || "").trim();
        const { stdout } = await runFile("rg", ["--json", "--regexp", term, "--", ROOT], { timeout: 10000 });
        res.json({ raw: stdout });
      }
    `
  });
  assert.deepEqual(ofCategory(result, "argument_injection"), []);
});

test("a term after an end-of-options separator is not reported", async () => {
  const result = await scanSource({
    "src/grep.js": `
      const { execFile } = require("node:child_process");
      const { promisify } = require("node:util");
      const runFile = promisify(execFile);

      export async function readFileFor(req, res) {
        const name = String(req.query.name || "");
        const { stdout } = await runFile("cat", ["--", name], { timeout: 5000 });
        res.json({ raw: stdout });
      }
    `
  });
  assert.deepEqual(ofCategory(result, "argument_injection"), []);
});

/* ------------------------------------------------------------------ *
 * Raw SQL escape hatches
 * ------------------------------------------------------------------ */

test("a filter quoted into a $queryRawUnsafe clause is reported", async () => {
  const result = await scanSource({
    "src/segments.ts": `
      export async function segmentTotals(ctx: any, input: { tier?: string }) {
        const conditions = ["organization_id = $1"];
        const values: unknown[] = [ctx.session.organizationId];
        if (input.tier) {
          conditions.push(\`tier = '\${input.tier}'\`);
        }
        return ctx.db.$queryRawUnsafe(
          \`SELECT tier, count(*)::int AS members FROM accounts WHERE \${conditions.join(" AND ")} GROUP BY tier\`,
          ...values
        );
      }
    `
  });
  assert.equal(ofCategory(result, "sql_injection").length, 1);
});

test("the same filter bound as a placeholder is not reported", async () => {
  const result = await scanSource({
    "src/segments.ts": `
      export async function segmentTotals(ctx: any, input: { tier?: string }) {
        const conditions = ["organization_id = $1"];
        const values: unknown[] = [ctx.session.organizationId];
        if (input.tier) {
          values.push(input.tier);
          conditions.push(\`tier = $\${values.length}\`);
        }
        return ctx.db.$queryRawUnsafe(
          \`SELECT tier, count(*)::int AS members FROM accounts WHERE \${conditions.join(" AND ")} GROUP BY tier\`,
          ...values
        );
      }
    `
  });
  assert.deepEqual(ofCategory(result, "sql_injection"), []);
});

/* ------------------------------------------------------------------ *
 * HTML written through a Response object
 * ------------------------------------------------------------------ */

const FRAGMENT_ROUTE = (interpolation) => `
      export async function GET(request: Request) {
        const { searchParams } = new URL(request.url);
        const term = searchParams.get("term")?.trim() ?? "";
        const html = \`
          <section class="hits">
            <p class="summary">Results for &ldquo;\${${interpolation}}&rdquo;</p>
          </section>
        \`;
        return new Response(html, {
          status: 200,
          headers: { "content-type": "text/html; charset=utf-8" },
        });
      }
`;

test("a search term interpolated into an HTML Response is reported", async () => {
  const result = await scanSource({
    "app/api/hits/route.ts": FRAGMENT_ROUTE("term")
  });
  const found = ofCategory(result, "reflected_cross_site_scripting");
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "GET /api/hits", "a reader needs the endpoint to probe it");
});

test("the same fragment with the term escaped is not reported", async () => {
  const result = await scanSource({
    "app/api/hits/route.ts": `
      function escapeHtml(value: string) {
        return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;" })[char] ?? char);
      }
    ` + FRAGMENT_ROUTE("escapeHtml(term)")
  });
  assert.deepEqual(ofCategory(result, "reflected_cross_site_scripting"), []);
});

test("a JSON Response carrying request data is not an HTML sink", async () => {
  const result = await scanSource({
    "app/api/hits/route.ts": `
      export async function GET(request: Request) {
        const { searchParams } = new URL(request.url);
        const term = searchParams.get("term") ?? "";
        return new Response(JSON.stringify({ term }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
    `
  });
  assert.deepEqual(ofCategory(result, "reflected_cross_site_scripting"), []);
});

/* ------------------------------------------------------------------ *
 * Error internals on the way out
 * ------------------------------------------------------------------ */

test("a stack trace assigned to the framework response body is reported", async () => {
  const result = await scanSource({
    "src/sync.js": `
      const Router = require("@koa/router");
      const router = new Router({ prefix: "/feeds" });

      router.post("/:feedId/refresh", async (ctx) => {
        try {
          ctx.body = { refreshed: true };
        } catch (err) {
          ctx.status = 502;
          ctx.body = { error: "Refresh failed", message: err.message, stack: err.stack };
        }
      });

      module.exports = router;
    `
  });
  const found = ofCategory(result, "verbose_error_response");
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "POST /feeds/:feedId/refresh");
});

test("a stack trace returned from an error formatter is reported", async () => {
  const result = await scanSource({
    "src/gateway.js": `
      const { ApolloServer } = require("@apollo/server");

      const server = new ApolloServer({
        schema: require("./schema"),
        formatError: (formattedError, error) => {
          return {
            ...formattedError,
            extensions: {
              ...formattedError.extensions,
              stacktrace: error instanceof Error ? error.stack.split("\\n") : undefined,
            },
          };
        },
      });

      module.exports = server;
    `
  });
  assert.equal(ofCategory(result, "verbose_error_response").length, 1);
});

test("an error formatter that returns a message and an incident id is not reported", async () => {
  const result = await scanSource({
    "src/gateway.js": `
      const { ApolloServer } = require("@apollo/server");
      const { randomUUID } = require("node:crypto");
      const logger = require("../lib/logger");

      const server = new ApolloServer({
        schema: require("./schema"),
        formatError: (formattedError, error) => {
          const incidentId = randomUUID();
          logger.error({ err: error, incidentId }, "graphql error");
          return { message: "Something went wrong on our side.", extensions: { incidentId } };
        },
      });

      module.exports = server;
    `
  });
  assert.deepEqual(ofCategory(result, "verbose_error_response"), []);
});

test("a stack logged server-side but never returned is not reported", async () => {
  const result = await scanSource({
    "src/sync.js": `
      const logger = require("../lib/logger");

      export function onFailure(err, res) {
        logger.error({ stack: err.stack }, "sync failed");
        res.status(502).json({ error: "Sync failed, our team has been notified" });
      }
    `
  });
  assert.deepEqual(ofCategory(result, "verbose_error_response"), []);
});

/* ------------------------------------------------------------------ *
 * Route attribution for hand-rolled dispatch
 * ------------------------------------------------------------------ */

test("a finding in a handler reached through a route table carries the endpoint", async () => {
  const result = await scanSource({
    "src/server.js": `
      const http = require("node:http");
      const pool = require("../db/pool");

      async function searchNotes(request, response, url) {
        const term = url.searchParams.get("q") || "";
        const sql = \`SELECT id, title FROM notes WHERE body ILIKE '%\${term}%'\`;
        const { rows } = await pool.query(sql);
        response.end(JSON.stringify(rows));
      }

      const ROUTES = [{ method: "GET", pattern: /^\\/api\\/notes$/, handler: searchNotes }];

      const server = http.createServer(async (request, response) => {
        const url = new URL(request.url, "http://localhost");
        const route = ROUTES.find((entry) => entry.method === request.method && entry.pattern.test(url.pathname));
        if (route) await route.handler(request, response, url);
      });

      module.exports = { server };
    `
  });
  const found = ofCategory(result, "sql_injection");
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "GET /api/notes");
});

test("a finding in a handler reached through a Map keyed by method and path carries the endpoint", async () => {
  const result = await scanSource({
    "src/server.js": `
      const http = require("node:http");
      const pool = require("../db/pool");

      async function searchNotes(request, response) {
        const url = new URL(request.url, "http://localhost");
        const sql = "SELECT id FROM notes WHERE body ILIKE '%" + url.searchParams.get("q") + "%'";
        const { rows } = await pool.query(sql);
        response.end(JSON.stringify(rows));
      }

      const ROUTES = new Map([["POST /api/notes/search", searchNotes]]);

      const server = http.createServer(async (request, response) => {
        const url = new URL(request.url, "http://localhost");
        const handler = ROUTES.get(\`\${request.method} \${url.pathname}\`);
        if (handler) await handler(request, response);
      });

      module.exports = { server };
    `
  });
  const found = ofCategory(result, "sql_injection");
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "POST /api/notes/search");
});

/* ------------------------------------------------------------------ *
 * Argument injection with no shell in sight
 *
 * The shape these cover is the one a careful author reaches for on purpose: a
 * fixed executable, an argument array, no `shell: true` anywhere. That removes
 * command injection and leaves argument injection, which turns on a single
 * character — a program parsing options cannot tell an operand from an option
 * once the operand begins with a dash. The defences are a literal `--`, passing
 * the value as a named option's argument, and refusing a leading dash outright;
 * each of them has to silence the rule, and nothing else may.
 *
 * They also exercise the hop across a function boundary. A command-line program
 * parses its arguments in one place and does its work in a helper, so a model
 * that stops at the handler sees an argument array full of parameters with no
 * origin and reports nothing at all.
 * ------------------------------------------------------------------ */

test("a caller's value reaching argv through a helper's parameters is reported", async () => {
  const result = await scanSource({
    "bin/replicate.js": `#!/usr/bin/env node
      const { execFile } = require("node:child_process");
      const { promisify } = require("node:util");
      const { Command } = require("commander");
      const run = promisify(execFile);

      async function replicate({ upstream, workdir }) {
        await run("git", ["clone", "--depth", "1", upstream, workdir], { timeout: 60000 });
      }

      const program = new Command();
      program
        .requiredOption("--upstream <url>", "repository to copy")
        .requiredOption("--workdir <dir>", "where to put it")
        .action(async (options) => {
          await replicate(options);
        });
      program.parseAsync(process.argv);
    `
  });
  const found = ofCategory(result, "argument_injection");
  assert.equal(found.length, 1, "the helper's parameter is the caller's value under another name");
  assert.equal(found[0].location.line, 8);
  assert.equal(found[0].severity, "high");
  assert.match(found[0].reasoning, /handed to `replicate`/);
});

test("the same helper with an end-of-options separator before the value is not reported", async () => {
  const result = await scanSource({
    "bin/replicate.js": `#!/usr/bin/env node
      const { execFile } = require("node:child_process");
      const { promisify } = require("node:util");
      const { Command } = require("commander");
      const run = promisify(execFile);

      async function replicate({ upstream, workdir }) {
        await run("git", ["clone", "--depth", "1", "--", upstream, workdir], { timeout: 60000 });
      }

      const program = new Command();
      program
        .requiredOption("--upstream <url>", "repository to copy")
        .requiredOption("--workdir <dir>", "where to put it")
        .action(async (options) => {
          await replicate(options);
        });
      program.parseAsync(process.argv);
    `
  });
  assert.deepEqual(ofCategory(result, "argument_injection"), []);
});

test("a value an anchored pattern refuses to let start with a dash is not reported", async () => {
  const result = await scanSource({
    "bin/tagged.js": `#!/usr/bin/env node
      const { execFileSync } = require("node:child_process");
      const { Command } = require("commander");
      const TAG = /^[A-Za-z0-9][A-Za-z0-9._\\/-]{0,80}$/;

      function archive({ tag, out }) {
        if (!TAG.test(tag)) throw new Error(tag + " is not a usable tag");
        execFileSync("git", ["archive", "--format=tar", tag, "--output", out]);
      }

      const program = new Command();
      program
        .requiredOption("--tag <ref>", "tag to archive")
        .requiredOption("--out <file>", "file to write")
        .action((options) => {
          archive(options);
        });
      program.parseAsync(process.argv);
    `
  });
  assert.deepEqual(
    ofCategory(result, "argument_injection"),
    [],
    "the pattern is anchored and its first atom cannot match a dash"
  );
});

test("an anchored pattern that still permits a leading dash leaves the finding standing", async () => {
  const result = await scanSource({
    "bin/tagged.js": `#!/usr/bin/env node
      const { execFileSync } = require("node:child_process");
      const { Command } = require("commander");
      const TAG = /^[a-z0-9-]{1,80}$/;

      function archive({ tag, out }) {
        if (!TAG.test(tag)) throw new Error(tag + " is not a usable tag");
        execFileSync("git", ["archive", "--format=tar", tag, "--output", out]);
      }

      const program = new Command();
      program
        .requiredOption("--tag <ref>", "tag to archive")
        .requiredOption("--out <file>", "file to write")
        .action((options) => {
          archive(options);
        });
      program.parseAsync(process.argv);
    `
  });
  const found = ofCategory(result, "argument_injection");
  assert.equal(found.length, 1, "a trailing dash in the class is a literal, so `-x` still matches");
  assert.equal(found[0].location.line, 8);
});

test("an explicit refusal of a leading dash is not reported", async () => {
  const result = await scanSource({
    "bin/fetch.js": `#!/usr/bin/env node
      const { spawnSync } = require("node:child_process");
      const { Command } = require("commander");

      function download({ source, out }) {
        if (source.startsWith("-")) throw new Error("refusing an option-shaped source");
        spawnSync("curl", ["--silent", "--output", out, source]);
      }

      const program = new Command();
      program
        .requiredOption("--source <url>", "what to fetch")
        .requiredOption("--out <file>", "where to put it")
        .action((options) => {
          download(options);
        });
      program.parseAsync(process.argv);
    `
  });
  assert.deepEqual(ofCategory(result, "argument_injection"), []);
});

test("a leading-dash check that only warns leaves the finding standing", async () => {
  const result = await scanSource({
    "bin/fetch.js": `#!/usr/bin/env node
      const { spawnSync } = require("node:child_process");
      const { Command } = require("commander");

      function download({ source, out }) {
        if (source.startsWith("-")) console.warn("that looks like an option");
        spawnSync("curl", ["--silent", "--output", out, source]);
      }

      const program = new Command();
      program
        .requiredOption("--source <url>", "what to fetch")
        .requiredOption("--out <file>", "where to put it")
        .action((options) => {
          download(options);
        });
      program.parseAsync(process.argv);
    `
  });
  const found = ofCategory(result, "argument_injection");
  assert.equal(found.length, 1, "a check that lets execution continue is not a defence");
  assert.equal(found[0].location.line, 7);
});

test("a helper every call site feeds a constant is not reported", async () => {
  const result = await scanSource({
    "bin/verify.js": `#!/usr/bin/env node
      const { execFileSync } = require("node:child_process");
      const { Command } = require("commander");

      function inspect(ref) {
        return execFileSync("git", ["rev-parse", ref]).toString().trim();
      }

      const program = new Command();
      program
        .requiredOption("--label <text>", "what to print")
        .action((options) => {
          process.stdout.write(options.label + " " + inspect("HEAD") + "\\n");
        });
      program.parseAsync(process.argv);
    `
  });
  assert.deepEqual(
    ofCategory(result, "argument_injection"),
    [],
    "the hop reports what a call site actually passes, never what a parameter could hold"
  );
});

test("only the caller-supplied field of a call-site object literal is treated as the caller's", async () => {
  const result = await scanSource({
    "bin/pack.js": `#!/usr/bin/env node
      const { execFileSync } = require("node:child_process");
      const { Command } = require("commander");
      const ARCHIVE_ROOT = "/srv/archives";

      function pack({ root, member }) {
        execFileSync("tar", ["--create", "--file", "/dev/stdout", root, member]);
      }

      const program = new Command();
      program
        .requiredOption("--member <path>", "what to add")
        .action((options) => {
          pack({ root: ARCHIVE_ROOT, member: options.member });
        });
      program.parseAsync(process.argv);
    `
  });
  const found = ofCategory(result, "argument_injection");
  assert.equal(found.length, 1);
  assert.match(found[0].reasoning, /as `member`/);
  assert.match(found[0].reasoning, /argv\[4\]/, "the constant root in the slot before it is not the caller's");
});

test("a shell command a helper builds from its parameter is still command injection", async () => {
  const result = await scanSource({
    "src/reports.js": `
      const { exec } = require("node:child_process");
      const { promisify } = require("node:util");
      const runShell = promisify(exec);

      async function convert(name) {
        return runShell("soffice --convert-to pdf /srv/in/" + name);
      }

      export async function renderReport(req, res) {
        const { stdout } = await convert(req.body.name);
        res.json({ raw: stdout });
      }
    `
  });
  const found = ofCategory(result, "command_injection");
  assert.equal(found.length, 1, "a handler is not less exposed for having split its work into a helper");
  assert.equal(found[0].severity, "critical");
});

test("a value another helper returned does not carry inferred taint across a second boundary", async () => {
  const result = await scanSource({
    "src/probe.js": `
      const { execFile } = require("node:child_process");
      const { promisify } = require("node:util");
      const run = promisify(execFile);
      const NAME = /^[A-Za-z0-9._-]+$/;

      function resolveExecutable(name) {
        if (!NAME.test(name)) return null;
        return "/usr/local/bin/" + name;
      }

      async function version(executable) {
        return run(executable, ["--version"], { timeout: 2000 });
      }

      export async function toolVersion(req, res) {
        const executable = resolveExecutable(req.query.tool);
        if (!executable) return res.status(400).json({ error: "unknown tool" });
        res.json({ version: await version(executable) });
      }
    `
  });
  assert.deepEqual(
    ofCategory(result, "command_injection"),
    [],
    "the model assumed resolveExecutable passes its argument through; stacking that assumption on the hop invents the flow"
  );
  assert.deepEqual(ofCategory(result, "argument_injection"), []);
});
