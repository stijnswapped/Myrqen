"use strict";

const express = require("express");
const crypto = require("crypto");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const { buildSegmentQuery } = require("../lib/segments");
const logger = require("../lib/logger");

const router = express.Router();

// POST /exports/contacts
// Queues a contact export from the settings screen. The download panel shows a
// failure notice with a reference the support team can look up.
router.post("/contacts", requireUser, async (req, res) => {
  const segmentId = req.body.segmentId;
  if (!segmentId) {
    return res.status(400).json({ error: "A segment is required" });
  }

  const client = await pool.connect();
  const traceId = crypto.randomUUID();

  try {
    const segment = buildSegmentQuery(segmentId, req.user.accountId);

    await client.query("BEGIN");
    const job = await client.query(
      "INSERT INTO export_jobs (account_id, segment_id, state) VALUES ($1, $2, 'queued') RETURNING id",
      [req.user.accountId, segmentId]
    );

    const counted = await client.query(segment.countSql, segment.values);
    await client.query("UPDATE export_jobs SET row_count = $1 WHERE id = $2", [
      counted.rows[0].count,
      job.rows[0].id,
    ]);

    await client.query("COMMIT");
    res.status(202).json({ jobId: job.rows[0].id, rows: Number(counted.rows[0].count) });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    logger.error(
      { err, traceId, accountId: req.user.accountId, segmentId },
      "contact export failed"
    );

    res.status(500).json({
      error: "Export could not be queued",
      traceId,
    });
  } finally {
    client.release();
  }
});

module.exports = router;
