"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const mime = require("mime-types");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = express.Router();

const ATTACHMENT_ROOT = process.env.ATTACHMENT_ROOT || "/srv/app/attachments";

// GET /messages/:messageId/attachments/:filename
// The inbox renders the attachment list from the message payload and links each
// entry straight back here, so the file name arrives in the path.
router.get("/:messageId/attachments/:filename", requireUser, async (req, res, next) => {
  const { messageId, filename } = req.params;

  try {
    const { rows } = await pool.query(
      `SELECT m.id, m.storage_prefix
         FROM messages m
         JOIN conversations c ON c.id = m.conversation_id
        WHERE m.id = $1 AND c.account_id = $2`,
      [messageId, req.user.accountId]
    );

    const message = rows[0];
    if (!message) {
      return res.status(404).json({ error: "Message not found" });
    }

    const filePath = path.join(ATTACHMENT_ROOT, message.storage_prefix, filename);

    const stat = await fs.promises.stat(filePath).catch(() => null);
    if (!stat || !stat.isFile()) {
      return res.status(404).json({ error: "Attachment not found" });
    }

    res.set("Content-Type", mime.lookup(filePath) || "application/octet-stream");
    res.set("Content-Length", String(stat.size));
    res.set("Content-Disposition", `attachment; filename="${path.basename(filename)}"`);

    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    logger.error({ err, messageId }, "attachment stream failed");
    next(err);
  }
});

module.exports = router;
