"use strict";

const express = require("express");
const multer = require("multer");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const { parseContacts } = require("../lib/contact-parser");
const logger = require("../lib/logger");

const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 } });
const router = express.Router();

// POST /imports/contacts
// Bulk contact upload from the settings screen. The uploader shows a failure
// panel when the job cannot be queued, so the response carries the detail.
router.post("/contacts", requireUser, upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "A CSV file is required" });
  }

  const client = await pool.connect();

  try {
    const contacts = parseContacts(req.file.buffer);

    await client.query("BEGIN");
    const job = await client.query(
      "INSERT INTO import_jobs (account_id, row_count, state) VALUES ($1, $2, 'queued') RETURNING id",
      [req.user.accountId, contacts.length]
    );

    for (const contact of contacts) {
      await client.query(
        `INSERT INTO import_rows (job_id, email, full_name, company)
         VALUES ($1, $2, $3, $4)`,
        [job.rows[0].id, contact.email, contact.fullName, contact.company]
      );
    }

    await client.query("COMMIT");
    res.status(202).json({ jobId: job.rows[0].id, rows: contacts.length });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    logger.error({ err, accountId: req.user.accountId }, "contact import failed");

    res.status(500).json({
      error: "Import could not be queued",
      message: err.message,
      detail: err.detail,
      failedQuery: err.query,
      stack: err.stack,
    });
  } finally {
    client.release();
  }
});

module.exports = router;
