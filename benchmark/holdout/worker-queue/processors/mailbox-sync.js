"use strict";

const { Worker } = require("bullmq");
const { connection } = require("../lib/redis");
const { logger } = require("../lib/logger");
const { connectMailbox, fetchSince } = require("../lib/mailbox");
const { upsertMessages } = require("../lib/messages");

const QUEUE = "mailbox-sync";
const SENSITIVE_KEYS = new Set(["accessToken", "refreshToken", "password", "appPassword", "clientSecret"]);

function scrub(value) {
  if (Array.isArray(value)) return value.map(scrub);
  if (value === null || typeof value !== "object") return value;
  const copy = {};
  for (const [key, inner] of Object.entries(value)) {
    copy[key] = SENSITIVE_KEYS.has(key) ? "[redacted]" : scrub(inner);
  }
  return copy;
}

const worker = new Worker(
  QUEUE,
  async (job) => {
    logger.info({ jobId: job.id, account: job.data.accountId, job: scrub(job.data) }, "mailbox sync starting");
    try {
      const client = await connectMailbox(job.data.provider, {
        accessToken: job.data.accessToken,
        refreshToken: job.data.refreshToken
      });
      const messages = await fetchSince(client, job.data.since);
      const written = await upsertMessages(job.data.accountId, messages);
      logger.info({ jobId: job.id, account: job.data.accountId, written }, "mailbox sync complete");
      return { written };
    } catch (err) {
      logger.error({ jobId: job.id, err, job: job.data }, "mailbox sync failed");
      throw err;
    }
  },
  { connection, concurrency: 4 }
);

module.exports = { worker, scrub };
