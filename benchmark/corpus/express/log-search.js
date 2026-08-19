"use strict";

const express = require("express");
const { execFile } = require("child_process");
const { promisify } = require("util");
const { requireUser, requireAdmin } = require("../middleware/auth");
const logger = require("../lib/logger");

const runFile = promisify(execFile);
const router = express.Router();

const LOG_ROOT = process.env.LOG_ROOT || "/var/log/app";
const MAX_MATCHES = 200;

function collectMatches(stdout) {
  return stdout
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line))
    .filter((event) => event.type === "match")
    .map((event) => ({
      file: event.data.path.text,
      line: event.data.line_number,
      text: event.data.lines.text.trimEnd(),
    }));
}

// GET /operations/logs
// Support looks up a request id or an error string across the rotated log files
// without shelling into the box.
router.get("/logs", requireUser, requireAdmin, async (req, res, next) => {
  const pattern = String(req.query.q || "").trim();
  const limit = Math.min(Number.parseInt(req.query.limit, 10) || 50, MAX_MATCHES);

  if (pattern.length < 3) {
    return res.status(400).json({ error: "Search for at least three characters" });
  }

  try {
    const { stdout } = await runFile(
      "rg",
      ["--json", "--line-number", `--max-count=${limit}`, pattern, LOG_ROOT],
      { timeout: 15000, maxBuffer: 16 * 1024 * 1024 }
    );

    res.json({ matches: collectMatches(stdout) });
  } catch (err) {
    if (err.code === 1) {
      return res.json({ matches: [] });
    }
    logger.error({ err }, "log search failed");
    next(err);
  }
});

module.exports = router;
