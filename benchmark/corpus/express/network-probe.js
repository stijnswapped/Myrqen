"use strict";

const express = require("express");
const { spawn } = require("child_process");
const { requireUser, requireRole } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = express.Router();

const PROBE_TIMEOUT_MS = 15000;

// POST /support/network/probe
// Support console: checks whether a customer's webhook host answers from our
// egress network, so a failed delivery can be told apart from a dead endpoint.
router.post("/network/probe", requireUser, requireRole("support"), (req, res) => {
  const { host } = req.body;
  if (!host) {
    return res.status(400).json({ error: "host is required" });
  }

  const child = spawn("sh", ["-c", `ping -c 3 -W 2 ${host} && traceroute -m 12 ${host}`], {
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
    logger.info({ host, code, by: req.user.id }, "network probe finished");
    res.json({ reachable: code === 0, output });
  });
});

module.exports = router;
