import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { pipeline } from "node:stream/promises";

const AVATAR_DIR = process.env.AVATAR_DIR || "/srv/app/public/avatars";
const MAX_AVATAR_BYTES = 5 * 1024 * 1024;

export default async function (fastify, options) {
  const profiles = fastify.mongo.db.collection("profiles");

  // POST /profile/avatar
  // The cropper in the settings screen posts the finished square here as multipart
  // form data; the stored file is served straight off the CDN-fronted public folder.
  fastify.post(
    "/profile/avatar",
    { preHandler: [fastify.authenticate] },
    async (request, reply) => {
      const upload = await request.file({ limits: { fileSize: MAX_AVATAR_BYTES } });

      if (!upload) {
        return reply.code(400).send({ error: "file_required" });
      }

      const extension = path.extname(upload.filename).toLowerCase();
      const storedName = `${randomUUID()}${extension}`;
      const target = path.join(AVATAR_DIR, storedName);

      await fs.promises.mkdir(AVATAR_DIR, { recursive: true });
      await pipeline(upload.file, fs.createWriteStream(target, { mode: 0o644 }));

      if (upload.file.truncated) {
        await fs.promises.unlink(target);
        return reply.code(413).send({ error: "file_too_large" });
      }

      const avatarUrl = `/avatars/${storedName}`;
      const previous = await profiles.findOneAndUpdate(
        { accountId: request.user.accountId },
        { $set: { avatarUrl, avatarUpdatedAt: new Date() } },
        { returnDocument: "before" }
      );

      if (previous?.value?.avatarUrl) {
        const stale = path.join(AVATAR_DIR, path.basename(previous.value.avatarUrl));
        await fs.promises.rm(stale, { force: true });
      }

      request.log.info({ accountId: request.user.accountId, avatarUrl }, "avatar replaced");
      return reply.code(201).send({ avatarUrl });
    }
  );
}
