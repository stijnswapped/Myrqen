"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");

const Router = require("@koa/router");
const { koaBody } = require("koa-body");

const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = new Router({ prefix: "/tickets" });

// nginx serves this directory straight off /uploads so the customer can open the
// link in the ticket timeline without going through the app.
const PUBLIC_UPLOAD_DIR = process.env.PUBLIC_UPLOAD_DIR || "/srv/www/public/uploads";

const receiveUpload = koaBody({
  multipart: true,
  formidable: { maxFileSize: 25 * 1024 * 1024, keepExtensions: true },
});

// POST /tickets/:ticketId/attachments
// Agents drag files onto a ticket to share them with the customer.
router.post("/:ticketId/attachments", requireUser, receiveUpload, async (ctx) => {
  const { ticketId } = ctx.params;
  const file = ctx.request.files && ctx.request.files.attachment;

  if (!file) {
    ctx.throw(400, "attachment is required");
  }

  const { rows } = await pool.query(`SELECT id FROM tickets WHERE id = $1 AND org_id = $2`, [
    ticketId,
    ctx.state.user.orgId,
  ]);

  const ticket = rows[0];
  if (!ticket) {
    ctx.throw(404, "Ticket not found");
  }

  const storedName = `${Date.now()}-${path.basename(file.originalFilename)}`;
  const destination = path.join(PUBLIC_UPLOAD_DIR, storedName);

  await fs.copyFile(file.filepath, destination);
  await fs.unlink(file.filepath);

  const inserted = await pool.query(
    `INSERT INTO ticket_attachments
            (ticket_id, uploaded_by, filename, content_type, byte_size, public_path)
          VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, filename, public_path, created_at`,
    [
      ticket.id,
      ctx.state.user.id,
      file.originalFilename,
      file.mimetype,
      file.size,
      `/uploads/${storedName}`,
    ]
  );

  logger.info({ ticketId: ticket.id, attachmentId: inserted.rows[0].id }, "attachment stored");

  ctx.status = 201;
  ctx.body = { attachment: inserted.rows[0] };
});

module.exports = router;
