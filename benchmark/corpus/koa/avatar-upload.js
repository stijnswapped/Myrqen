"use strict";

const { randomUUID } = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

const Router = require("@koa/router");
const { koaBody } = require("koa-body");

const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = new Router({ prefix: "/profiles" });

// Avatars are read back through GET /profiles/:id/avatar, which sets the content
// type itself, so nothing in here is web-served directly.
const AVATAR_DIR = process.env.AVATAR_DIR || "/srv/app/storage/avatars";
const MAX_BYTES = 2 * 1024 * 1024;

const EXTENSION_BY_TYPE = { "image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp" };

const SIGNATURES = [
  { extension: ".png", head: "89504e47" },
  { extension: ".jpg", head: "ffd8ff" },
  { extension: ".webp", head: "52494646" },
];

async function sniffExtension(filepath) {
  const handle = await fs.open(filepath, "r");
  try {
    const { buffer } = await handle.read(Buffer.alloc(12), 0, 12, 0);
    const head = buffer.toString("hex");
    const match = SIGNATURES.find((candidate) => head.startsWith(candidate.head));
    return match ? match.extension : null;
  } finally {
    await handle.close();
  }
}

const receiveUpload = koaBody({
  multipart: true,
  formidable: { maxFileSize: MAX_BYTES, keepExtensions: false },
});

// POST /profiles/:profileId/avatar
// Members drop a picture onto their profile card.
router.post("/:profileId/avatar", requireUser, receiveUpload, async (ctx) => {
  const { profileId } = ctx.params;
  const file = ctx.request.files && ctx.request.files.avatar;

  if (!file) {
    ctx.throw(400, "avatar is required");
  }

  if (profileId !== ctx.state.user.id) {
    ctx.throw(403, "You can only change your own picture");
  }

  const declaredExtension = EXTENSION_BY_TYPE[file.mimetype];
  const actualExtension = await sniffExtension(file.filepath);

  if (!declaredExtension || declaredExtension !== actualExtension) {
    await fs.unlink(file.filepath);
    ctx.throw(415, "Avatars must be a PNG, JPEG or WebP image");
  }

  if (file.size > MAX_BYTES) {
    await fs.unlink(file.filepath);
    ctx.throw(413, "Avatars must be 2 MB or smaller");
  }

  const storedName = `${randomUUID()}${actualExtension}`;
  const destination = path.join(AVATAR_DIR, storedName);

  await fs.copyFile(file.filepath, destination);
  await fs.unlink(file.filepath);

  const updated = await pool.query(
    `UPDATE profiles
        SET avatar_key = $1, avatar_content_type = $2, updated_at = now()
      WHERE id = $3 AND org_id = $4
  RETURNING id, avatar_key, updated_at`,
    [storedName, file.mimetype, ctx.state.user.id, ctx.state.user.orgId]
  );

  logger.info({ profileId: ctx.state.user.id, storedName }, "avatar stored");

  ctx.status = 201;
  ctx.body = { profile: updated.rows[0] };
});

module.exports = router;
