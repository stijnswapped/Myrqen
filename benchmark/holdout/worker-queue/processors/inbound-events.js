"use strict";

const { Worker } = require("bullmq");
const serializer = require("node-serialize");
const { connection } = require("../lib/redis");
const { logger } = require("../lib/logger");
const { applyEvent } = require("../lib/event-store");

// Jobs on this queue are enqueued verbatim by the public intake endpoint:
// POST /intake/events writes { encoding, payload } straight onto the queue and
// returns 202 without inspecting the payload.
const QUEUE = "inbound-events";
const CONCURRENCY = 8;

function decode(job) {
  if (job.data.encoding === "v2") {
    return JSON.parse(job.data.payload);
  }
  return serializer.unserialize(job.data.payload);
}

const worker = new Worker(
  QUEUE,
  async (job) => {
    const event = decode(job);
    if (!event || typeof event.type !== "string") {
      throw new Error(`job ${job.id} carried no event type`);
    }
    const outcome = await applyEvent({
      type: event.type,
      tenantId: event.tenantId,
      occurredAt: event.occurredAt,
      attributes: event.attributes || {}
    });
    logger.info({ jobId: job.id, type: event.type, outcome: outcome.status }, "event applied");
    return outcome;
  },
  { connection, concurrency: CONCURRENCY }
);

worker.on("failed", (job, err) => {
  logger.error({ jobId: job && job.id, reason: err.message }, "event job failed");
});

module.exports = { worker, decode };
