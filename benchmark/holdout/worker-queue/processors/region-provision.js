"use strict";

const { createHmac } = require("node:crypto");
const { Worker } = require("bullmq");
const { connection } = require("../lib/redis");
const { logger } = require("../lib/logger");
const { createRegionShard, seedReferenceData } = require("../lib/provisioning");

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set before the worker starts`);
  return value;
}

const QUEUE_PREFIX = process.env.QUEUE_PREFIX || "provisioning";
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL || "https://control.acme-suite.com";
const PROVISION_SIGNING_KEY = requireEnv("REGION_PROVISION_SIGNING_KEY");

function sign(body) {
  return createHmac("sha256", PROVISION_SIGNING_KEY).update(body).digest("hex");
}

async function notifyControlPlane(regionId, state) {
  const body = JSON.stringify({ regionId, state, at: new Date().toISOString() });
  const response = await fetch(`${CONTROL_PLANE_URL}/provisioning/callbacks`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-signature": `sha256=${sign(body)}` },
    body
  });
  if (!response.ok) throw new Error(`control plane rejected the callback: ${response.status}`);
}

const worker = new Worker(
  `${QUEUE_PREFIX}:region-provision`,
  async (job) => {
    const { regionId, plan } = job.data;
    await createRegionShard(regionId);
    await seedReferenceData(regionId, plan);
    await notifyControlPlane(regionId, "ready");
    logger.info({ jobId: job.id, regionId, plan }, "region provisioned");
    return { regionId, state: "ready" };
  },
  { connection, concurrency: 2 }
);

module.exports = { worker, sign };
