import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import "../dist/index.js";
import { parseFile } from "../dist/ast/parse.js";
import { discoverRoutes } from "../dist/ast/routes.js";
import { parsingRules } from "../dist/rules/parsing.js";

/**
 * Message-driven entry points reaching the rules in `rules/parsing.ts`.
 *
 * These live apart from `parsing.test.mjs` because they need the framework
 * adapters, and the adapters only exist once the engine's entry module has been
 * imported. Importing it here rather than there keeps the older tests judging
 * rules in isolation, which is what they were written to do.
 *
 * Every shape is written from scratch and paired with the near miss that must
 * stay silent — the same feature done correctly. A rule that cannot tell the two
 * apart is worse than no rule, because the reader who is shown a defended
 * handler stops reading the next report.
 */
async function analyze(source, filename = "src/gateway.ts") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-payloads-"));
  const target = path.join(root, filename);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, source, "utf8");
  try {
    const parsed = await parseFile(root, target);
    assert.ok(!("error" in parsed), `the fixture must parse: ${parsed.error ?? ""}`);
    const candidates = [];
    const context = {
      file: parsed,
      routes: discoverRoutes(parsed),
      report: (candidate) => candidates.push(candidate)
    };
    for (const rule of parsingRules) rule.run(context);
    const seen = new Map();
    for (const candidate of candidates) {
      const key = `${candidate.ruleId}::${candidate.location.line}`;
      if (!seen.has(key)) seen.set(key, candidate);
    }
    return [...seen.values()];
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const of = (candidates, category) => candidates.filter((candidate) => candidate.category === category);

/* ---------------- nosql_injection through a declared payload ---------------- */

test("a websocket payload merged into a Mongo filter is reported", async () => {
  const found = await analyze(`
    import { WebSocketServer } from "ws";
    import { MongoClient } from "mongodb";
    const tickets = new MongoClient(process.env.MONGO_URL).db().collection("tickets");
    const wss = new WebSocketServer({ port: 8081 });
    wss.on("connection", (client, request) => {
      client.on("message", async (raw) => {
        const command = JSON.parse(String(raw));
        const rows = await tickets.find({ queueId: client.queueId, ...command.where }).limit(50).toArray();
        client.send(JSON.stringify({ rows }));
      });
    });
  `);
  const hits = of(found, "nosql_injection");
  assert.equal(hits.length, 1, "a socket message is caller data exactly as a request body is");
  assert.equal(hits[0].severity, "high");
  assert.match(hits[0].summary, /spread whole into the filter object/);
});

test("a websocket payload read field by field under a type check is not reported", async () => {
  const found = await analyze(`
    import { WebSocketServer } from "ws";
    import { MongoClient } from "mongodb";
    const PRIORITIES = new Set(["low", "normal", "urgent"]);
    const tickets = new MongoClient(process.env.MONGO_URL).db().collection("tickets");
    const wss = new WebSocketServer({ port: 8081 });
    wss.on("connection", (client) => {
      client.on("message", async (raw) => {
        const command = JSON.parse(String(raw));
        const where = { queueId: client.queueId };
        if (typeof command.where.priority === "string" && PRIORITIES.has(command.where.priority)) {
          where.priority = command.where.priority;
        }
        if (typeof command.where.assignee === "string") {
          where.assignee = command.where.assignee;
        }
        const rows = await tickets.find(where).limit(50).toArray();
        client.send(JSON.stringify({ rows }));
      });
    });
  `);
  assert.deepEqual(
    of(found, "nosql_injection"),
    [],
    "a field copied across only inside a typeof check cannot arrive as an operator"
  );
});

test("a payload field pinned to a scalar by a conditional expression is not reported", async () => {
  const found = await analyze(`
    import { WebSocketServer } from "ws";
    import { MongoClient } from "mongodb";
    const tickets = new MongoClient(process.env.MONGO_URL).db().collection("tickets");
    const wss = new WebSocketServer({ port: 8081 });
    wss.on("connection", (client) => {
      client.on("message", async (raw) => {
        const command = JSON.parse(String(raw));
        const where = { queueId: client.queueId };
        where.assignee = typeof command.assignee === "string" ? command.assignee : "unassigned";
        client.send(JSON.stringify({ rows: await tickets.find(where).toArray() }));
      });
    });
  `);
  assert.deepEqual(of(found, "nosql_injection"), [], "the branch that uses the field is the branch that pinned it");
});

test("a queue job's payload reaching a filter is reported", async () => {
  const found = await analyze(
    `
    import { Worker } from "bullmq";
    import { MongoClient } from "mongodb";
    const ledger = new MongoClient(process.env.MONGO_URL).db().collection("ledger");
    new Worker("reconcile-batch", async (task) => {
      const rows = await ledger.find({ bookId: task.data.selector }).toArray();
      return rows.length;
    }, { connection });
  `,
    "src/jobs/reconcile.ts"
  );
  const hits = of(found, "nosql_injection");
  assert.equal(hits.length, 1, "whoever enqueued the job composed that object");
});

test("a filter built from the queue's own bookkeeping is not reported", async () => {
  const found = await analyze(
    `
    import { Worker } from "bullmq";
    import { MongoClient } from "mongodb";
    const attempts = new MongoClient(process.env.MONGO_URL).db().collection("attempts");
    new Worker("reconcile-batch", async (task) => {
      const row = await attempts.findOne({ jobId: task.id, queue: task.queueName });
      return row ? row.state : "unseen";
    }, { connection });
  `,
    "src/jobs/reconcile.ts"
  );
  assert.deepEqual(
    of(found, "nosql_injection"),
    [],
    "the seed declares job.data as the payload, so the job's identity is the queue's and not the caller's"
  );
});

test("a parameter merely named like a payload is not caller data without an entry point", async () => {
  const found = await analyze(
    `
    import { MongoClient } from "mongodb";
    const ledger = new MongoClient(process.env.MONGO_URL).db().collection("ledger");
    /** Called from the scheduler with a selector this module composed itself. */
    export async function sweep(message) {
      return ledger.find({ bookId: message.selector, sweptAt: null }).toArray();
    }
  `,
    "src/jobs/sweep.ts"
  );
  assert.deepEqual(
    of(found, "nosql_injection"),
    [],
    "the rule asks the entry point which binding the caller filled in, and here nothing declares one"
  );
});

test("a payload field coerced to a string before the query is not reported", async () => {
  const found = await analyze(`
    import { WebSocketServer } from "ws";
    import { MongoClient } from "mongodb";
    const tickets = new MongoClient(process.env.MONGO_URL).db().collection("tickets");
    const wss = new WebSocketServer({ port: 8081 });
    wss.on("connection", (client) => {
      client.on("message", async (raw) => {
        const command = JSON.parse(String(raw));
        const row = await tickets.findOne({ reference: String(command.reference).trim() });
        client.send(JSON.stringify({ row }));
      });
    });
  `);
  assert.deepEqual(of(found, "nosql_injection"), [], "a coerced string can only be a value to match");
});
