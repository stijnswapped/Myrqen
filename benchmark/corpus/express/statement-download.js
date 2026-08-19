"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = express.Router();

const STATEMENT_ROOT = process.env.STATEMENT_ROOT || "/srv/app/statements";

function resolveWithinRoot(root, prefix, name) {
  const candidate = path.resolve(root, prefix, path.basename(name));
  const base = path.resolve(root) + path.sep;
  return candidate.startsWith(base) ? candidate : null;
}

// GET /statements/:statementId/files/:filename
// The billing screen renders the file list from the statement payload and links
// each entry straight back here, so the file name arrives in the path.
router.get("/:statementId/files/:filename", requireUser, async (req, res, next) => {
  const { statementId, filename } = req.params;

  try {
    const { rows } = await pool.query(
      `SELECT s.id, s.storage_prefix
         FROM statements s
        WHERE s.id = $1 AND s.account_id = $2`,
      [statementId, req.user.accountId]
    );

    const statement = rows[0];
    if (!statement) {
      return res.status(404).json({ error: "Statement not found" });
    }

    const filePath = resolveWithinRoot(STATEMENT_ROOT, statement.storage_prefix, filename);
    if (!filePath) {
      return res.status(400).json({ error: "Invalid file name" });
    }

    const stat = await fs.promises.stat(filePath).catch(() => null);
    if (!stat || !stat.isFile()) {
      return res.status(404).json({ error: "File not found" });
    }

    res.set("Content-Type", "application/pdf");
    res.set("Content-Length", String(stat.size));
    res.set("Content-Disposition", `attachment; filename="${path.basename(filePath)}"`);

    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    logger.error({ err, statementId }, "statement stream failed");
    next(err);
  }
});

module.exports = router;
