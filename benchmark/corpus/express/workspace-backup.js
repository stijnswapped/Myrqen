"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const { execFile } = require("child_process");
const { promisify } = require("util");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const logger = require("../lib/logger");

const runFile = promisify(execFile);
const router = express.Router();

const UPLOAD_ROOT = process.env.UPLOAD_ROOT || "/srv/app/uploads";
const BACKUP_ROOT = process.env.BACKUP_ROOT || "/srv/app/backups";
const LABEL_PATTERN = /^[a-z0-9][a-z0-9-]{0,39}$/;

// POST /workspaces/:workspaceId/backups
// Packs every asset a workspace owns into a tarball ops can restore from.
// The label ends up in the file name so two backups can be told apart.
router.post("/:workspaceId/backups", requireUser, async (req, res, next) => {
  const { workspaceId } = req.params;
  const label = String(req.body.label || "backup").trim().toLowerCase();

  if (!LABEL_PATTERN.test(label)) {
    return res.status(400).json({ error: "Label may contain lowercase letters, digits and dashes only" });
  }

  try {
    const { rows } = await pool.query(
      "SELECT id, slug FROM workspaces WHERE id = $1 AND account_id = $2",
      [workspaceId, req.user.accountId]
    );

    const workspace = rows[0];
    if (!workspace) {
      return res.status(404).json({ error: "Workspace not found" });
    }

    const sourceDir = path.join(UPLOAD_ROOT, workspace.slug);
    const archiveName = `${workspace.slug}-${label}-${Date.now()}.tar.gz`;
    const archivePath = path.join(BACKUP_ROOT, archiveName);

    await runFile("tar", ["-czf", archivePath, "-C", sourceDir, "."], {
      cwd: BACKUP_ROOT,
      timeout: 120000,
    });

    const { size } = await fs.promises.stat(archivePath);

    await pool.query(
      "INSERT INTO workspace_backups (workspace_id, archive_name, size_bytes) VALUES ($1, $2, $3)",
      [workspace.id, archiveName, size]
    );

    res.status(201).json({ archive: archiveName, sizeBytes: size });
  } catch (err) {
    logger.error({ err, workspaceId }, "workspace backup failed");
    next(err);
  }
});

module.exports = router;
