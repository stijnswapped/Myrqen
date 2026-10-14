import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

/**
 * Every case is written inline rather than pulled from the benchmark corpus: an
 * adapter that only recognises a known fixture is worthless in a real repository,
 * so these use queue names, libraries, and parameter names that appear nowhere
 * else in the project.
 *
 * The adapter is driven directly instead of through `scan()`, so these hold
 * whether or not the registry has been wired up yet.
 */

const distFile = fileURLToPath(new URL("../dist/ast/frameworks/workers.js", import.meta.url));

if (!existsSync(distFile)) {
  test.skip("the workers adapter needs a built package (npm run build -w @myrqen/scan)", () => {});
} else {
  const { workersAdapter } = await import(pathToFileURL(distFile).href);

  const parse = (source, relativePath) => {
    const javascript = /\.[cm]?jsx?$/.test(relativePath);
    return {
      relativePath,
      absolutePath: `/repo/${relativePath}`,
      text: source,
      source: ts.createSourceFile(
        relativePath,
        source,
        ts.ScriptTarget.Latest,
        true,
        javascript ? ts.ScriptKind.JS : ts.ScriptKind.TS
      ),
      language: javascript ? "JavaScript" : "TypeScript"
    };
  };

  /** What the engine would collect: nothing at all unless the pre-check passes first. */
  const entryPoints = (source, relativePath = "src/jobs/worker.ts") => {
    const file = parse(source, relativePath);
    return workersAdapter.applies(file) ? workersAdapter.detect(file) : [];
  };

  const replacer = (key, value) => (key === "node" ? undefined : value);

  const only = (source, relativePath) => {
    const found = entryPoints(source, relativePath);
    assert.equal(found.length, 1, `expected exactly one entry point, got ${JSON.stringify(found, replacer)}`);
    return found[0];
  };

  /* ---------------- BullMQ and Bull v3 ---------------- */

  test("a BullMQ worker seeds its job parameter and is addressed by the queue name", () => {
    const entry = only(`
      import { Worker } from "bullmq";
      const worker = new Worker("statement-exports", async (job) => {
        const contents = await fs.readFile(job.data.path, "utf8");
        return contents.length;
      }, { connection });
    `);

    assert.equal(entry.framework, "workers");
    assert.equal(entry.kind, "queue");
    assert.equal(entry.method, "CONSUME");
    assert.equal(entry.path, "statement-exports");
    assert.deepEqual(entry.seeds, [{ name: "job", origin: "job.data (payload enqueued by an outside caller)" }]);
    assert.ok(entry.node && ts.isArrowFunction(entry.node), "the seeded node must be the processor itself");
  });

  test("a processor declared above the worker is resolved, and a constant queue name is looked up", () => {
    const entry = only(
      `
      const { Worker } = require("bullmq");
      const QUEUE = "invoice-render";

      async function renderInvoice(task) {
        return template(task.data.markup);
      }

      new Worker(QUEUE, renderInvoice);
    `,
      "src/jobs/invoices.js"
    );

    assert.equal(entry.path, "invoice-render");
    assert.deepEqual(entry.seeds, [{ name: "task", origin: "task.data (payload enqueued by an outside caller)" }]);
    assert.ok(entry.node && ts.isFunctionDeclaration(entry.node), "the named processor is the handler");
  });

  test("a Bull v3 queue.process registration is addressed by the name the queue was constructed with", () => {
    const entry = only(`
      import Queue from "bull";
      const thumbnails = new Queue("thumbnail-resize", process.env.REDIS_URL);
      thumbnails.process(5, async (job) => {
        await sharp(job.data.source).resize(job.data.width).toFile(job.data.target);
      });
    `);

    assert.equal(entry.path, "thumbnail-resize");
    assert.equal(entry.method, "CONSUME");
    assert.deepEqual(entry.seeds, [{ name: "job", origin: "job.data (payload enqueued by an outside caller)" }]);
  });

  test("a node:worker_threads Worker is not mistaken for a job processor", () => {
    // Same constructor name, different library. What separates them is the second
    // argument: options and a script path, never a processor function.
    const found = entryPoints(`
      import { Worker } from "node:worker_threads";
      const child = new Worker(new URL("./resize.js", import.meta.url), { workerData: { quality: 80 } });
      child.on("exit", (code) => log(code));
    `);

    assert.deepEqual(found, [], "no bullmq import means no queue entry point");
  });

  /* ---------------- kafkajs ---------------- */

  test("a kafkajs consumer seeds the destructured message and takes its address from subscribe", () => {
    const entry = only(`
      import { Kafka } from "kafkajs";
      const consumer = new Kafka({ brokers }).consumer({ groupId: "ledger" });

      await consumer.subscribe({ topic: "payments.settled", fromBeginning: false });
      await consumer.run({
        eachMessage: async ({ topic, partition, message }) => {
          const settlement = JSON.parse(message.value.toString());
          await ledger.apply(settlement);
        }
      });
    `);

    assert.equal(entry.path, "payments.settled");
    assert.equal(entry.method, "CONSUME");
    assert.deepEqual(entry.seeds, [
      { name: "message", origin: "message.value (payload published by an outside producer)" }
    ]);
  });

  test("a kafkajs consumer with no literal topic still declares an entry point", () => {
    const entry = only(`
      import { Kafka } from "kafkajs";
      await consumer.subscribe({ topic: config.topic });
      await consumer.run({
        eachMessage: async (payload) => {
          await handle(payload.message.value);
        }
      });
    `);

    assert.equal(entry.path, "kafka");
    assert.deepEqual(entry.seeds, [
      { name: "payload", origin: "payload.message.value (payload published by an outside producer)" }
    ]);
  });

  /* ---------------- amqplib ---------------- */

  test("an amqplib consumer seeds its message and is addressed by the queue it binds", () => {
    const entry = only(
      `
      const amqplib = require("amqplib");

      async function start(channel) {
        await channel.consume("orders.created", (msg) => {
          const order = JSON.parse(msg.content.toString());
          channel.ack(msg);
        }, { noAck: false });
      }
    `,
      "src/jobs/orders.cjs"
    );

    assert.equal(entry.path, "orders.created");
    assert.equal(entry.kind, "queue");
    assert.deepEqual(entry.seeds, [
      { name: "msg", origin: "msg.content (payload published by an outside producer)" }
    ]);
  });

  /* ---------------- worker threads ---------------- */

  test("a parentPort message listener seeds the payload and is reported as an inter-process channel", () => {
    const entry = only(`
      import { parentPort } from "node:worker_threads";

      parentPort.on("message", (task) => {
        parentPort.postMessage(run(task.command));
      });
    `);

    assert.equal(entry.kind, "ipc");
    assert.equal(entry.method, "CONSUME");
    assert.equal(entry.path, "message");
    assert.deepEqual(entry.seeds, [
      { name: "task", origin: "task (payload sent over the thread's message port)" }
    ]);
  });

  test("a destructured thread message is declared without seeds rather than guessed at", () => {
    const entry = only(`
      import { parentPort } from "node:worker_threads";
      parentPort.on("message", ({ jobId, attempt }) => retry(jobId, attempt));
    `);

    assert.equal(entry.path, "message");
    assert.equal(entry.seeds, undefined, "which property carries caller data is a per-application convention");
  });

  test("a message listener in a file that runs no threads is not claimed", () => {
    const found = entryPoints(`
      import { EventEmitter } from "node:events";
      const bus = new EventEmitter();
      bus.on("message", (payload) => audit(payload));
    `);

    assert.deepEqual(found, [], "without worker_threads there is nothing to say the payload crossed a boundary");
  });

  /* ---------------- AWS record batches ---------------- */

  test("an exported Lambda handler that reads event.Records is a queue consumer", () => {
    const entry = only(
      `
      export const handler = async (event) => {
        for (const record of event.Records) {
          await archive(JSON.parse(record.body));
        }
      };
    `,
      "src/functions/archive.ts"
    );

    assert.equal(entry.kind, "queue");
    assert.equal(entry.method, "CONSUME");
    assert.equal(entry.path, "sqs");
    assert.deepEqual(entry.seeds, [
      { name: "event", origin: "event.Records (message payloads delivered by the queue or topic)" }
    ]);
  });

  test("a CommonJS handler that destructures Records seeds the binding it actually holds", () => {
    const entry = only(
      `
      exports.handler = async ({ Records }) => {
        await Promise.all(Records.map((record) => index(record.body)));
      };
    `,
      "src/functions/index.js"
    );

    assert.equal(entry.path, "sqs");
    assert.deepEqual(entry.seeds, [
      { name: "Records", origin: "event.Records (message payloads delivered by the queue or topic)" }
    ]);
  });

  test("a function that reads Records off a client response is not an entry point", () => {
    // The word alone means nothing. Only a read off the handler's own first
    // parameter says the batch was delivered rather than fetched.
    const found = entryPoints(
      `
      export async function listRecords(client) {
        const response = await client.send(new ListStreamRecordsCommand());
        return response.Records;
      }
    `,
      "src/aws/streams.ts"
    );

    assert.deepEqual(found, [], "an AWS SDK response is not an inbound event");
  });
}
