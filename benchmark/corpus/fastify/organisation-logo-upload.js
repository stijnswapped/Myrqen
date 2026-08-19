import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

const LOGO_DIR = process.env.LOGO_DIR || "/srv/app/public/logos";
const MAX_LOGO_BYTES = 2 * 1024 * 1024;

const ALLOWED_IMAGE_TYPES = {
  "image/png": ".png",
  "image/jpeg": ".jpg",
  "image/webp": ".webp",
};

const MAGIC_BYTES = {
  "image/png": [0x89, 0x50, 0x4e, 0x47],
  "image/jpeg": [0xff, 0xd8, 0xff],
  "image/webp": [0x52, 0x49, 0x46, 0x46],
};

function hasExpectedHeader(buffer, mimetype) {
  const signature = MAGIC_BYTES[mimetype];
  return signature.every((byte, index) => buffer[index] === byte);
}

export default async function (fastify, options) {
  const organisations = fastify.mongo.db.collection("organisations");

  // POST /organisations/:organisationId/logo
  // Brand settings upload; the stored file is served off the public logo folder.
  fastify.post(
    "/organisations/:organisationId/logo",
    { preHandler: [fastify.authenticate, fastify.requireOrganisationRole("admin")] },
    async (request, reply) => {
      const upload = await request.file({ limits: { fileSize: MAX_LOGO_BYTES } });

      if (!upload) {
        return reply.code(400).send({ error: "file_required" });
      }

      const extension = ALLOWED_IMAGE_TYPES[upload.mimetype];
      if (!extension) {
        return reply.code(415).send({ error: "unsupported_image_type" });
      }

      const contents = await upload.toBuffer();
      if (contents.length === 0 || !hasExpectedHeader(contents, upload.mimetype)) {
        return reply.code(415).send({ error: "unsupported_image_type" });
      }

      const storedName = `${randomUUID()}${extension}`;
      const target = path.join(LOGO_DIR, storedName);

      await fs.promises.mkdir(LOGO_DIR, { recursive: true });
      await fs.promises.writeFile(target, contents, { mode: 0o644 });

      const logoUrl = `/logos/${storedName}`;
      await organisations.updateOne(
        { _id: request.organisation._id },
        { $set: { logoUrl, logoUpdatedAt: new Date() } }
      );

      return reply.code(201).send({ logoUrl });
    }
  );
}
