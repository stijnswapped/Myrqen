import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { pipeline } from "node:stream/promises";
import yauzl from "yauzl";

const PACK_ROOT = process.env.PACK_ROOT || "/srv/app/template-packs";
const MAX_ARCHIVE_BYTES = 20 * 1024 * 1024;
const ARCHIVE_TYPES = new Set(["application/zip", "application/x-zip-compressed"]);

function resolveWithin(destination, entryName) {
  const root = path.resolve(destination);
  const candidate = path.resolve(root, entryName);
  if (candidate !== root && !candidate.startsWith(root + path.sep)) {
    return null;
  }
  return candidate;
}

function unpack(buffer, destination, skipped) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (openError, archive) => {
      if (openError) {
        reject(openError);
        return;
      }

      archive.on("entry", (entry) => {
        const target = resolveWithin(destination, entry.fileName);

        if (!target) {
          skipped.push(entry.fileName);
          archive.readEntry();
          return;
        }

        archive.openReadStream(entry, async (readError, readStream) => {
          if (readError) {
            reject(readError);
            return;
          }
          try {
            await fs.promises.mkdir(path.dirname(target), { recursive: true });
            await pipeline(readStream, fs.createWriteStream(target));
            archive.readEntry();
          } catch (writeError) {
            reject(writeError);
          }
        });
      });

      archive.on("end", resolve);
      archive.on("error", reject);
      archive.readEntry();
    });
  });
}

export default async function (fastify, options) {
  const packs = fastify.mongo.db.collection("template_packs");

  // POST /template-packs/imports
  // Same editor export format as the theme importer, one directory per pack version.
  fastify.post(
    "/template-packs/imports",
    { preHandler: [fastify.authenticate, fastify.requireRole("designer")] },
    async (request, reply) => {
      const upload = await request.file({ limits: { fileSize: MAX_ARCHIVE_BYTES } });

      if (!upload || !ARCHIVE_TYPES.has(upload.mimetype)) {
        return reply.code(415).send({ error: "zip_archive_required" });
      }

      const packId = randomUUID();
      const destination = path.join(PACK_ROOT, packId);
      await fs.promises.mkdir(destination, { recursive: true });

      const skipped = [];
      await unpack(await upload.toBuffer(), destination, skipped);

      await packs.insertOne({
        _id: packId,
        uploadedBy: request.user.accountId,
        directory: destination,
        createdAt: new Date(),
      });

      return reply.code(201).send({ packId, skippedEntries: skipped.length });
    }
  );
}
