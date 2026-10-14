import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * Where a finding points.
 *
 * A finding on the wrong line is not a cosmetic problem. `pool.query(sql, params)`
 * and `createReadStream(absolute)` are the *innocent* lines of their flows: both
 * are correctly written, and a developer sent to either reads code with nothing to
 * fix. The defect is wherever the caller's value was composed into the statement
 * or the path, which is also where the remediation goes.
 *
 * Held-out corpus 3 disagreed with the engine on four cases for exactly this
 * reason, and on reading them the engine was wrong, not the corpus.
 *
 * The line numbers here are asserted against markers in the source rather than
 * counted by hand, so an edit to the fixture cannot silently move the assertion.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-location-"));
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

/** The 1-based line carrying a `// <<name` marker. */
function markerLine(source, name) {
  const lines = source.split("\n");
  const index = lines.findIndex((line) => line.includes(`// <<${name}`));
  assert.ok(index >= 0, `the fixture must carry a // <<${name} marker`);
  return index + 1;
}

const SEARCH_HANDLER = `import { pool } from "../lib/pool";

export async function searchLedger(request, response) {
  const url = new URL(request.url, "http://localhost");
  const state = url.searchParams.get("state");
  const term = url.searchParams.get("term");

  const clauses = ["tenant_id = $1"];
  const values = [currentTenant(request)];

  if (state) {
    values.push(state);
    clauses.push(\`state = $\${values.length}\`);
  }

  if (term) {
    values.push(\`%\${term}%\`); // <<parameterised
    clauses.push(\`memo ILIKE $\${values.length}\`);
  }

  const statement = \`
    SELECT id, memo, state
    FROM ledger_entries
    WHERE \${clauses.join(" AND ")}
    ORDER BY created_at DESC
  \`;

  const { rows } = await pool.query(statement, values); // <<sink
  return response.end(JSON.stringify(rows));
}

function currentTenant(request) {
  return request.headers["x-tenant"] ? "t_1" : null;
}
`;

const SEARCH_HANDLER_DEFECTIVE = SEARCH_HANDLER.replace(
  '    clauses.push(`memo ILIKE $${values.length}`);',
  '    clauses.push(`memo ILIKE \'%${term}%\'`); // <<composition'
).replace("    values.push(`%${term}%`); // <<parameterised\n", "");

test("SQL injection is reported at the composition, not at the parameterised call", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "ledgerworks", version: "1.0.0", type: "module" }),
    "src/ledger-search.js": SEARCH_HANDLER_DEFECTIVE
  });
  const found = result.candidates.filter((candidate) => candidate.category === "sql_injection");
  assert.equal(found.length, 1, JSON.stringify(found.map((c) => c.location)));
  assert.equal(
    found[0].location.line,
    markerLine(SEARCH_HANDLER_DEFECTIVE, "composition"),
    "the finding belongs on the clause that interpolates, which is also where the fix goes"
  );
  assert.notEqual(
    found[0].location.line,
    markerLine(SEARCH_HANDLER_DEFECTIVE, "sink"),
    "pool.query(statement, values) is a parameterised call and has nothing to fix on it"
  );
});

test("a push into the bound parameter array is never the reported line", async () => {
  // The mistake a first attempt at this made: `values.push(`%${term}%`)` is a
  // tainted template too, and it is the *correct* half of the same handler.
  // Choosing the narrowest tainted composition in the function landed on it.
  const source = SEARCH_HANDLER_DEFECTIVE.replace(
    '  if (term) {',
    '  if (term) {\n    values.push(`%${term}%`); // <<parameterised'
  );
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "ledgerworks", version: "1.0.0", type: "module" }),
    "src/ledger-search.js": source
  });
  const found = result.candidates.filter((candidate) => candidate.category === "sql_injection");
  assert.equal(found.length, 1);
  assert.notEqual(
    found[0].location.line,
    markerLine(source, "parameterised"),
    "pointing a reader at the parameter binding and calling it injection is worse than pointing at the sink"
  );
  assert.equal(found[0].location.line, markerLine(source, "composition"));
});

test("the correctly parameterised handler produces no finding at all", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "ledgerworks", version: "1.0.0", type: "module" }),
    "src/ledger-search.js": SEARCH_HANDLER
  });
  assert.deepEqual(
    result.candidates.filter((candidate) => candidate.category === "sql_injection").map((c) => c.location.line),
    []
  );
});

const DOWNLOAD = `import fs from "node:fs";
import path from "node:path";

const ASSET_ROOT = "/srv/parcelworks/assets";

export async function handle(request, response) {
  const url = new URL(request.url, "http://localhost");
  const wanted = url.searchParams.get("file") ?? "";
  if (!wanted) {
    response.writeHead(400);
    return response.end();
  }

  const absolute = path.join(ASSET_ROOT, wanted); // <<composition

  const stat = await fs.promises.stat(absolute);
  if (!stat.isFile()) {
    response.writeHead(404);
    return response.end();
  }

  response.writeHead(200);
  return response.end(fs.readFileSync(absolute, "utf8")); // <<sink
}
`;

test("path traversal is reported at the join that accepted the segment", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "parcelworks", version: "1.0.0", type: "module" }),
    "src/asset-download.js": DOWNLOAD
  });
  const found = result.candidates.filter((candidate) => candidate.category === "path_traversal");
  assert.ok(found.length >= 1, JSON.stringify(result.candidates.map((c) => c.category)));
  assert.equal(
    found[0].location.line,
    markerLine(DOWNLOAD, "composition"),
    "the read cannot be fixed; the join is where a containment check belongs"
  );
});

test("every reported route names a method", async () => {
  // A `Bun.serve({ fetch })` handler answers any path and dispatches internally.
  // Its address used to come out as a bare `/`, because the formatter dropped the
  // verb whenever it was ANY — which reads in a report as a GET on the root, and
  // gave findings inside dispatched handlers an address that was simply wrong.
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "tideapi", version: "1.0.0", type: "module" }),
    "src/server.ts": `import { Database } from "bun:sqlite";

const db = new Database("/var/lib/tide/tide.sqlite");
const readNote = db.query("select body from notes where id = ?");

Bun.serve({
  port: 8080,
  async fetch(request) {
    const url = new URL(request.url);
    const id = url.pathname.split("/").pop() ?? "";
    const rows = await db.query(\`select body from notes where id = '\${id}'\`).all();
    return new Response(JSON.stringify(rows), { status: 200 });
  }
});
`
  });
  const routes = result.candidates.map((candidate) => candidate.route).filter(Boolean);
  assert.ok(routes.length > 0, "the fixture must produce at least one routed finding");
  for (const route of routes) {
    assert.match(route, /^[A-Z]+ \//, `every reported route names a method; got ${JSON.stringify(route)}`);
  }
});
