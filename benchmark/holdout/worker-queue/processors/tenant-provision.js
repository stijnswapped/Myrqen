"use strict";

const { createHmac } = require("node:crypto");
const { Worker } = require("bullmq");
const { connection } = require("../lib/redis");
const { logger } = require("../lib/logger");
const { createSchema, seedReferenceData } = require("../lib/provisioning");

const QUEUE_PREFIX = process.env.QUEUE_PREFIX || "provisioning";
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL || "https://control.acme-suite.com";
const PROVISION_SIGNING_KEY = process.env.PROVISION_SIGNING_KEY || "7pQz2LmVx9RtKd4YbHn6Wf3Js8Ca5Ue1";

function sign(body) {
  return createHmac("sha256", PROVISION_SIGNING_KEY).update(body).digest("hex");
}

async function notifyControlPlane(tenantId, state) {
  const body = JSON.stringify({ tenantId, state, at: new Date().toISOString() });
  const response = await fetch(`${CONTROL_PLANE_URL}/provisioning/callbacks`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-signature": `sha256=${sign(body)}` },
    body
  });
  if (!response.ok) throw new Error(`control plane rejected the callback: ${response.status}`);
}

const worker = new Worker(
  `${QUEUE_PREFIX}:tenant-provision`,
  async (job) => {
    const { tenantId, plan } = job.data;
    await createSchema(tenantId);
    await seedReferenceData(tenantId, plan);
    await notifyControlPlane(tenantId, "ready");
    logger.info({ jobId: job.id, tenantId, plan }, "tenant provisioned");
    return { tenantId, state: "ready" };
  },
  { connection, concurrency: 2 }
);

module.exports = { worker, sign };
