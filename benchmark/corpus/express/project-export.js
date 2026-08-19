"use strict";

const express = require("express");
const path = require("path");
const { exec } = require("child_process");
const { promisify } = require("util");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const logger = require("../lib/logger");

const run = promisify(exec);
const router = express.Router();

const UPLOAD_ROOT = process.env.UPLOAD_ROOT || "/srv/app/uploads";
const EXPORT_ROOT = process.env.EXPORT_ROOT || "/srv/app/exports";

// POST /projects/:projectId/exports
// Packs every asset a project owns into a tarball the customer can download.
// The label ends up in the file name so support can tell two exports apart.
router.post("/:projectId/exports", requireUser, async (req, res, next) => {
  const { projectId } = req.params;
  const label = (req.body.label || "export").trim();

  try {
    const { rows } = await pool.query(
      "SELECT id, slug FROM projects WHERE id = $1 AND account_id = $2",
      [projectId, req.user.accountId]
    );

    const project = rows[0];
    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    const sourceDir = path.join(UPLOAD_ROOT, project.slug);
    const archiveName = `${project.slug}-${label}-${Date.now()}.tar.gz`;
    const archivePath = path.join(EXPORT_ROOT, archiveName);

    const { stdout } = await run(
      `tar -czf ${archivePath} -C ${sourceDir} . && du -h ${archivePath} | cut -f1`,
      { cwd: EXPORT_ROOT, timeout: 120000 }
    );

    await pool.query(
      "INSERT INTO project_exports (project_id, archive_name, size_label) VALUES ($1, $2, $3)",
      [project.id, archiveName, stdout.trim()]
    );

    res.status(201).json({ archive: archiveName, size: stdout.trim() });
  } catch (err) {
    logger.error({ err, projectId }, "project export failed");
    next(err);
  }
});

module.exports = router;
