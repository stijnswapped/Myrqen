import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { scan } from "../dist/index.js";

/**
 * The generic declared endpoint: a function handed to something, next to a path.
 *
 * Run 7 measured recall of 0.042 on classes whose sink is framework or store vocabulary,
 * against 0.875 where the sink is a Node primitive, across five stacks with no adapter.
 * The rules were fine; nothing had told the engine which bindings held the caller's data.
 *
 * Every case here is written as source rather than read from a corpus, and deliberately
 * uses frameworks that have *no* adapter — including two that did not exist when this was
 * written, spelled the way their documentation spells them. A rule that only fires on a
 * shape it has seen before is what this file exists to prevent.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-declared-"));
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

const of = (result, category) => result.candidates.filter((candidate) => candidate.category === category);
const failures = (result) => result.coverage.parseFailures.filter((entry) => entry.reason.startsWith("rule "));

const PKG = JSON.stringify({ name: "unknown-framework", version: "1.0.0", private: true, type: "module" });

/* ------------------------------------------------- the registration-with-options shape */

test("a handler declared beside a route in an options object receives the caller's data", async () => {
  const result = await scanSource({
    "package.json": PKG,
    "src/lib/store.ts": `export const rows = { one: async (_sql: string) => null as any };\n`,
    "src/handlers/statements.ts": `
      import { rows } from "../lib/store";

      declare const gateway: {
        http: (name: string, options: { route: string; methods: string[]; handler: unknown }) => void;
      };

      async function statementDetail(request: { params: Record<string, string> }) {
        const reference = request.params.reference;
        return await rows.one("select * from statements where reference = '" + reference + "'");
      }

      gateway.http("statementDetail", {
        route: "api/statements/{reference}",
        methods: ["GET"],
        handler: statementDetail
      });
    `
  });
  assert.deepEqual(failures(result), []);
  assert.equal(of(result, "sql_injection").length, 1, "the path literal names the handler as an HTTP entry point");
});

test("the same handler is silent when the reference is bound as a parameter", async () => {
  const result = await scanSource({
    "package.json": PKG,
    "src/lib/store.ts": `export const rows = { one: async (_sql: string, _values?: unknown[]) => null as any };\n`,
    "src/handlers/statements.ts": `
      import { rows } from "../lib/store";

      declare const gateway: {
        http: (name: string, options: { route: string; methods: string[]; handler: unknown }) => void;
      };

      async function statementDetail(request: { params: Record<string, string> }) {
        const reference = request.params.reference;
        return await rows.one("select * from statements where reference = $1", [reference]);
      }

      gateway.http("statementDetail", {
        route: "api/statements/{reference}",
        methods: ["GET"],
        handler: statementDetail
      });
    `
  });
  assert.deepEqual(of(result, "sql_injection"), []);
});

/* ------------------------------------- every parameter of a handler is the caller's */

test("a typed request object is caller data even when no field name says so", async () => {
  // The whole point: `reportKey` is on no list and never will be, because it is this
  // application's noun. A path literal established that the function answers HTTP.
  const result = await scanSource({
    "package.json": PKG,
    "src/reports.ts": `
      import { readFile } from "node:fs/promises";
      import { join } from "node:path";

      declare function endpoint<T>(options: { method: string; path: string }, handler: (input: T) => Promise<unknown>): unknown;

      interface DownloadRequest {
        reportKey: string;
      }

      export const download = endpoint<DownloadRequest>(
        { method: "GET", path: "/reports/:reportKey/export" },
        async ({ reportKey }) => {
          return await readFile(join("/srv/reports", reportKey), "utf8");
        }
      );
    `
  });
  assert.deepEqual(failures(result), []);
  assert.equal(of(result, "path_traversal").length, 1);
});

test("the same handler is silent when the key is resolved against a fixed set", async () => {
  const result = await scanSource({
    "package.json": PKG,
    "src/reports.ts": `
      import { readFile } from "node:fs/promises";
      import { join } from "node:path";

      declare function endpoint<T>(options: { method: string; path: string }, handler: (input: T) => Promise<unknown>): unknown;

      const EXPORTS = new Map<string, string>([
        ["quarterly", "quarterly.csv"],
        ["annual", "annual.csv"]
      ]);

      interface DownloadRequest {
        reportKey: string;
      }

      export const download = endpoint<DownloadRequest>(
        { method: "GET", path: "/reports/:reportKey/export" },
        async ({ reportKey }) => {
          const file = EXPORTS.get(reportKey);
          if (!file) throw new Error("unknown report");
          return await readFile(join("/srv/reports", file), "utf8");
        }
      );
    `
  });
  assert.deepEqual(of(result, "path_traversal"), [], "a literal Map is an allowlist however it is spelled");
});

/* ------------------------------------------------------------- the gate beside it */

test("middleware declared beside the handler counts as authentication", async () => {
  // Reading only the handler body would report a route that gates itself twice, which is
  // worse than a missed finding: it is a confident claim about correct code.
  const result = await scanSource({
    "package.json": PKG,
    "src/admin.ts": `
      declare const gateway: {
        route: (options: { path: string; preHandler: unknown[]; handler: unknown }) => void;
      };
      declare const authenticate: unknown;
      declare const requireOperatorRole: (role: string) => unknown;
      declare const store: { operators: { findOne: (where: unknown) => Promise<{ id: string; role: string } | null> } };

      async function operatorDetail(request: { params: Record<string, string> }) {
        const operator = await store.operators.findOne({ id: request.params.operatorId });
        return { operator };
      }

      gateway.route({
        path: "/admin/operators/:operatorId",
        preHandler: [authenticate, requireOperatorRole("manager")],
        handler: operatorDetail
      });
    `
  });
  assert.deepEqual(failures(result), []);
  assert.deepEqual(
    of(result, "missing_authentication"),
    [],
    "the preHandler array is where this framework puts the check"
  );
});

/* --------------------------------------------------------- what must not be claimed */

test("a client call to somebody else's URL is not an endpoint", async () => {
  const result = await scanSource({
    "package.json": PKG,
    "src/upstream.ts": `
      export async function publish(payload: unknown): Promise<void> {
        await fetch("https://api.example.com/v1/events", {
          method: "POST",
          body: JSON.stringify(payload)
        });
      }
    `
  });
  assert.deepEqual(failures(result), []);
  assert.deepEqual(of(result, "missing_authentication"), []);
  assert.deepEqual(of(result, "broken_object_level_authorization"), []);
});

test("a handler whose parameters carry nothing of the caller's is not claimed", async () => {
  const result = await scanSource({
    "package.json": PKG,
    "src/health.ts": `
      declare const gateway: { http: (options: { route: string; handler: unknown }) => void };

      gateway.http({
        route: "api/healthz",
        handler: async (res: { json: (body: unknown) => void }) => {
          res.json({ ok: true });
        }
      });
    `
  });
  assert.deepEqual(failures(result), []);
  assert.equal(result.candidates.length, 0);
});
