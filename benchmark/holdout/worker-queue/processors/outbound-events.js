"use strict";

const { Worker } = require("bullmq");
const serializer = require("node-serialize");
const { connection } = require("../lib/redis");
const { logger } = require("../lib/logger");
const { deliverEvent } = require("../lib/event-store");

// Jobs on this queue are enqueued verbatim by the public intake endpoint:
// POST /intake/outbound writes { encoding, payload } straight onto the queue and
// returns 202 without inspecting the payload.
const QUEUE = "outbound-events";
const CONCURRENCY = 8;

function decode(job) {
  if (job.data.encoding === "v2") {
    return JSON.parse(job.data.payload);
  }
  return JSON.parse(Buffer.from(job.data.payload, "base64").toString("utf8"));
}

const worker = new Worker(
  QUEUE,
  async (job) => {
    const event = decode(job);
    if (!event || typeof event.type !== "string") {
      throw new Error(`job ${job.id} carried no event type`);
    }
    const outcome = await deliverEvent({
      type: event.type,
      tenantId: event.tenantId,
      occurredAt: event.occurredAt,
      attributes: event.attributes || {},
      receipt: serializer.serialize({ jobId: job.id, acceptedAt: Date.now() })
    });
    logger.info({ jobId: job.id, type: event.type, outcome: outcome.status }, "event delivered");
    return outcome;
  },
  { connection, concurrency: CONCURRENCY }
);

worker.on("failed", (job, err) => {
  logger.error({ jobId: job && job.id, reason: err.message }, "event job failed");
});

module.exports = { worker, decode };
