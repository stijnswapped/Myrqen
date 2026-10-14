import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * Injection shapes belonging to the runtimes that are not Node: a statement run
 * on a transaction handle rather than on the pool, a Deno Postgres client whose
 * query methods are named after the rows they return, and process spawning
 * through `Deno.Command` and `Bun.spawn` in services that have no
 * `child_process` to import.
 *
 * Every vulnerable shape is paired with the near miss a careful author writes,
 * because the pair is the only thing that proves the rule is reading the
 * evidence rather than the vocabulary. Sources are written inline and named
 * after nothing in any corpus.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-runtime-injection-"));
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
 * Statements run on a handle rather than on the pool
 * ------------------------------------------------------------------ */

test("a statement concatenated onto a transaction handle is reported", async () => {
  const result = await scanSource({
    "src/ledger.ts": `
      import { pool } from "./pool.ts";

      export async function listEntries(request: Request): Promise<Response> {
        const note = new URL(request.url).searchParams.get("note") ?? "";
        const tx = await pool.begin();
        const rows = await tx.queryObject(
          \`SELECT id, amount FROM entries WHERE note LIKE '%\${note}%'\`
        );
        return Response.json(rows);
      }
    `
  });
  const found = ofCategory(result, "sql_injection");
  assert.equal(found.length, 1, "opening a transaction must not hide the statement it runs");
  assert.equal(found[0].severity, "critical");
});

test("the same transaction handle with the value bound is not reported", async () => {
  const result = await scanSource({
    "src/ledger.ts": `
      import { pool } from "./pool.ts";

      export async function listEntries(request: Request): Promise<Response> {
        const note = new URL(request.url).searchParams.get("note") ?? "";
        const tx = await pool.begin();
        const rows = await tx.queryObject("SELECT id, amount FROM entries WHERE note LIKE $1", [
          \`%\${note}%\`
        ]);
        return Response.json(rows);
      }
    `
  });
  assert.deepEqual(ofCategory(result, "sql_injection"), []);
});

test("a handle whose own name says nothing is followed back to the pool it came from", async () => {
  const result = await scanSource({
    "src/ledger.ts": `
      import { pool } from "./pool.ts";

      export async function listEntries(request: Request): Promise<Response> {
        const note = new URL(request.url).searchParams.get("note") ?? "";
        const handle = await pool.connect();
        const rows = await handle.queryArray(
          \`SELECT id, amount FROM entries WHERE note LIKE '%\${note}%'\`
        );
        return Response.json(rows);
      }
    `
  });
  assert.equal(ofCategory(result, "sql_injection").length, 1);
});

test("a weakly named handle calling a method that names no statement is left alone", async () => {
  const result = await scanSource({
    "src/ledger.ts": `
      import { db } from "./firestore.ts";

      export async function reassign(request: Request): Promise<Response> {
        const email = new URL(request.url).searchParams.get("email") ?? "";
        await db.runTransaction(async (transaction) => {
          const snapshot = await transaction.get(db.collection("users").where("email", "==", email));
          for (const doc of snapshot.docs) transaction.update(doc.ref, { owner: "ops" });
        });
        return new Response("ok");
      }
    `
  });
  assert.deepEqual(
    ofCategory(result, "sql_injection"),
    [],
    "a document store's transactional read spells `transaction`, `get` and `where` and contains no SQL"
  );
});

test("a parameterised tagged template on the same client stays silent", async () => {
  const result = await scanSource({
    "src/ledger.ts": `
      import { client } from "./pool.ts";

      export async function findEntry(request: Request): Promise<Response> {
        const id = new URL(request.url).searchParams.get("id") ?? "";
        const rows = await client.queryObject\`SELECT id, amount FROM entries WHERE id = \${id}\`;
        return Response.json(rows);
      }
    `
  });
  assert.deepEqual(ofCategory(result, "sql_injection"), []);
});

test("a concatenated fragment beside a bound parameter array is reported, and the reasoning says the array is there", async () => {
  const result = await scanSource({
    "src/ledger.ts": `
      import { pool } from "./pool.ts";

      export async function listEntries(request: Request, ownerId: string): Promise<Response> {
        const note = new URL(request.url).searchParams.get("note") ?? "";
        const predicates = ["owner_id = $1"];
        const values: unknown[] = [ownerId];

        if (note.length > 0) {
          predicates.push(\`note LIKE '%\${note}%'\`);
        }

        const connection = await pool.connect();
        const rows = await connection.queryObject(
          \`SELECT id, amount FROM entries WHERE \${predicates.join(" AND ")}\`,
          values
        );
        return Response.json(rows);
      }
    `
  });
  const found = ofCategory(result, "sql_injection");
  assert.equal(found.length, 1, "a bound array protects the values in it and nothing else");
  assert.match(
    found[0].reasoning,
    /parameter array/,
    "the report has to describe the call that is actually there"
  );
  assert.doesNotMatch(
    found[0].reasoning,
    /with no parameter array/,
    "claiming there is no parameter array when one is on the next line gets the finding dismissed"
  );
});

/* ------------------------------------------------------------------ *
 * Process spawning without child_process
 * ------------------------------------------------------------------ */

test("a shell command line built from request data and run through Deno.Command is reported", async () => {
  const result = await scanSource({
    "src/exports.ts": `
      export async function exportRows(request: Request): Promise<Response> {
        const table = new URL(request.url).searchParams.get("table") ?? "";
        const command = new Deno.Command("bash", {
          args: ["-c", \`psql -c "copy \${table} to stdout" > /tmp/out.csv\`]
        });
        const { code } = await command.output();
        return Response.json({ code });
      }
    `
  });
  const found = ofCategory(result, "command_injection");
  assert.equal(found.length, 1, "a runtime with no child_process still spawns processes");
  assert.equal(found[0].severity, "critical");
});

test("Deno.Command with a fixed program and a fixed argument list is not reported", async () => {
  const result = await scanSource({
    "src/exports.ts": `
      export async function diskUsage(request: Request): Promise<Response> {
        const command = new Deno.Command("bash", { args: ["-c", "df -h /srv"] });
        const { stdout } = await command.output();
        return new Response(stdout);
      }
    `
  });
  assert.deepEqual(ofCategory(result, "command_injection"), []);
});

test("a caller-controlled value checked against an allowlist before the shell runs is not reported", async () => {
  const result = await scanSource({
    "src/exports.ts": `
      const REPORTS = new Set(["daily", "weekly"]);

      export async function build(request: Request): Promise<Response> {
        const report = new URL(request.url).searchParams.get("report") ?? "";
        if (!REPORTS.has(report)) return new Response("unknown report", { status: 400 });
        const command = new Deno.Command("bash", { args: ["-c", \`./bin/report \${report}\`] });
        await command.output();
        return new Response("ok");
      }
    `
  });
  assert.deepEqual(ofCategory(result, "command_injection"), []);
});

test("a program name taken from the request is reported however fixed its arguments are", async () => {
  const result = await scanSource({
    "src/exports.ts": `
      export async function probe(request: Request): Promise<Response> {
        const tool = new URL(request.url).searchParams.get("tool") ?? "";
        const command = new Deno.Command(tool, { args: ["--version"] });
        const { stdout } = await command.output();
        return new Response(stdout);
      }
    `
  });
  assert.equal(ofCategory(result, "command_injection").length, 1);
});

test("an interpreter given a fixed script rather than a program to evaluate is not command injection", async () => {
  const result = await scanSource({
    "src/exports.ts": `
      export async function render(request: Request): Promise<Response> {
        const title = new URL(request.url).searchParams.get("title") ?? "";
        const command = new Deno.Command("node", { args: ["render.js", "--title", title] });
        await command.output();
        return new Response("ok");
      }
    `
  });
  assert.deepEqual(ofCategory(result, "command_injection"), []);
});

test("the same interpreter given the caller's value to evaluate is reported", async () => {
  const result = await scanSource({
    "src/exports.ts": `
      export async function render(request: Request): Promise<Response> {
        const expression = new URL(request.url).searchParams.get("expr") ?? "";
        const command = new Deno.Command("node", { args: ["-e", \`console.log(\${expression})\`] });
        await command.output();
        return new Response("ok");
      }
    `
  });
  assert.equal(ofCategory(result, "command_injection").length, 1);
});

test("Bun.spawn handing sh a caller-built command line is reported", async () => {
  const result = await scanSource({
    "src/backups.ts": `
      export async function backup(request: Request): Promise<Response> {
        const target = new URL(request.url).searchParams.get("target") ?? "";
        const child = Bun.spawn(["sh", "-c", \`pg_dump \${target} > /tmp/dump.sql\`]);
        await child.exited;
        return new Response("ok");
      }
    `
  });
  assert.equal(ofCategory(result, "command_injection").length, 1);
});

test("Bun.spawn of a fixed program with option parsing terminated is not reported", async () => {
  const result = await scanSource({
    "src/backups.ts": `
      export async function show(request: Request): Promise<Response> {
        const name = new URL(request.url).searchParams.get("name") ?? "";
        const child = Bun.spawn(["cat", "--", \`/srv/files/\${name}\`]);
        await child.exited;
        return new Response("ok");
      }
    `
  });
  assert.deepEqual(ofCategory(result, "command_injection"), []);
  assert.deepEqual(ofCategory(result, "argument_injection"), []);
});

test("the descriptor form of a runtime spawn is read the same way as the array form", async () => {
  const result = await scanSource({
    "src/backups.ts": `
      export async function scanHost(request: Request): Promise<Response> {
        const host = new URL(request.url).searchParams.get("host") ?? "";
        const process = Deno.run({ cmd: ["sh", "-c", \`nmap \${host}\`] });
        await process.status();
        return new Response("ok");
      }
    `
  });
  assert.equal(ofCategory(result, "command_injection").length, 1);
});

test("a fixed program given the caller's value in a bare argument slot is argument injection, not command injection", async () => {
  const result = await scanSource({
    "src/repos.ts": `
      export async function clone(request: Request): Promise<Response> {
        const repo = new URL(request.url).searchParams.get("repo") ?? "";
        const command = new Deno.Command("git", { args: ["clone", repo, "/tmp/work"] });
        await command.output();
        return new Response("ok");
      }
    `
  });
  assert.deepEqual(ofCategory(result, "command_injection"), []);
  const found = ofCategory(result, "argument_injection");
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, "high");
});
