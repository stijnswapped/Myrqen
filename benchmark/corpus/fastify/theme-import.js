import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { pipeline } from "node:stream/promises";
import yauzl from "yauzl";

const THEME_ROOT = process.env.THEME_ROOT || "/srv/app/themes";
const MAX_ARCHIVE_BYTES = 20 * 1024 * 1024;
const ARCHIVE_TYPES = new Set(["application/zip", "application/x-zip-compressed"]);

function openArchive(archivePath) {
  return new Promise((resolve, reject) => {
    yauzl.open(archivePath, { lazyEntries: true }, (err, archive) =>
      err ? reject(err) : resolve(archive)
    );
  });
}

function unpack(archive, destination) {
  return new Promise((resolve, reject) => {
    archive.on("entry", (entry) => {
      const target = path.join(destination, entry.fileName);

      if (entry.fileName.endsWith("/")) {
        fs.promises
          .mkdir(target, { recursive: true })
          .then(() => archive.readEntry())
          .catch(reject);
        return;
      }

      archive.openReadStream(entry, async (err, readStream) => {
        if (err) {
          reject(err);
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
}

export default async function (fastify, options) {
  const themes = fastify.mongo.db.collection("themes");

  // POST /themes/imports
  // Designers hand us a zip exported from the theme editor: templates, partials and
  // a manifest. We unpack it into its own slug directory and register the version.
  fastify.post(
    "/themes/imports",
    { preHandler: [fastify.authenticate, fastify.requireRole("designer")] },
    async (request, reply) => {
      const upload = await request.file({ limits: { fileSize: MAX_ARCHIVE_BYTES } });

      if (!upload || !ARCHIVE_TYPES.has(upload.mimetype)) {
        return reply.code(415).send({ error: "zip_archive_required" });
      }

      const staged = path.join(os.tmpdir(), `${randomUUID()}.zip`);
      await pipeline(upload.file, fs.createWriteStream(staged));

      const themeId = randomUUID();
      const destination = path.join(THEME_ROOT, themeId);
      await fs.promises.mkdir(destination, { recursive: true });

      const archive = await openArchive(staged);
      try {
        await unpack(archive, destination);
      } finally {
        await fs.promises.rm(staged, { force: true });
      }

      await themes.insertOne({
        _id: themeId,
        uploadedBy: request.user.accountId,
        directory: destination,
        createdAt: new Date(),
      });

      return reply.code(201).send({ themeId });
    }
  );
}
