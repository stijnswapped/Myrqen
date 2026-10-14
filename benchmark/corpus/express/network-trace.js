"use strict";

const express = require("express");
const { spawn } = require("child_process");
const { requireUser, requireRole } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = express.Router();

const PROBE_TIMEOUT_MS = 15000;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

// POST /support/network/trace
// Support console: traces the route to a customer's webhook host from our
// egress network, so a failed delivery can be told apart from a dead endpoint.
router.post("/network/trace", requireUser, requireRole("support"), (req, res) => {
  const { host } = req.body;
  if (typeof host !== "string" || !HOSTNAME.test(host)) {
    return res.status(400).json({ error: "host must be a hostname" });
  }

  const child = spawn("traceroute", ["-m", "12", "--", host], {
    timeout: PROBE_TIMEOUT_MS
  });

  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk;
  });
  child.stderr.on("data", (chunk) => {
    output += chunk;
  });
  child.on("close", (code) => {
    logger.info({ host, code, by: req.user.id }, "network trace finished");
    res.json({ reachable: code === 0, output });
  });
});

module.exports = router;
