"use strict";

const express = require("express");
const { execFile } = require("child_process");
const { promisify } = require("util");
const { requireUser, requireAdmin } = require("../middleware/auth");
const logger = require("../lib/logger");

const runFile = promisify(execFile);
const router = express.Router();

const AUDIT_ROOT = process.env.AUDIT_LOG_ROOT || "/var/log/app/audit";
const MAX_MATCHES = 200;
const MAX_PATTERN_LENGTH = 120;

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

// GET /operations/audit
// Compliance looks up an actor id or an action name across the rotated audit
// files without shelling into the box.
router.get("/audit", requireUser, requireAdmin, async (req, res, next) => {
  const pattern = String(req.query.q || "").trim();
  const limit = Math.min(Number.parseInt(req.query.limit, 10) || 50, MAX_MATCHES);

  if (pattern.length < 3 || pattern.length > MAX_PATTERN_LENGTH) {
    return res.status(400).json({ error: "Search for between three and 120 characters" });
  }

  try {
    const { stdout } = await runFile(
      "rg",
      ["--json", "--line-number", `--max-count=${limit}`, "--regexp", pattern, "--", AUDIT_ROOT],
      { timeout: 15000, maxBuffer: 16 * 1024 * 1024 }
    );

    res.json({ matches: collectMatches(stdout) });
  } catch (err) {
    if (err.code === 1) {
      return res.json({ matches: [] });
    }
    logger.error({ err }, "audit search failed");
    next(err);
  }
});

module.exports = router;
