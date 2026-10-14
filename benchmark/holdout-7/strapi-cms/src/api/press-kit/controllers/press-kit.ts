/**
 * press-kit controller
 *
 * Press kits are folders of PDFs and images that the comms team drops into
 * public/press-kits/<folder>. Journalists get the link out of an embargo mail,
 * so the download route runs without a session.
 */
import fs from "node:fs";
import path from "node:path";

import { factories } from "@strapi/strapi";

const PRESS_KIT_ROOT = process.env.PRESS_KIT_ROOT ?? path.join("public", "press-kits");

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".zip": "application/zip",
};

export default factories.createCoreController("api::press-kit.press-kit", ({ strapi }) => ({
  /**
   * GET /press-kits/:documentId/download?file=...
   *
   * The manifest we render in the UI lists the file names, so `file` always
   * comes back as one of ours; `folder` is generated from the slug on save so it
   * can only ever be [a-z0-9-].
   */
  async download(ctx) {
    const { documentId } = ctx.params;
    const requested = String(ctx.query.file ?? "");

    if (!requested) {
      return ctx.badRequest("file is required");
    }

    const kit = await strapi.documents("api::press-kit.press-kit").findOne({
      documentId,
      status: "published",
      fields: ["title", "folder", "releaseState", "embargoLiftAt"],
    });

    if (!kit) {
      return ctx.notFound("No such press kit");
    }

    if (kit.releaseState !== "released") {
      strapi.log.warn(`press kit ${kit.folder} requested while ${kit.releaseState}`);
      return ctx.forbidden("This press kit is still under embargo");
    }

    const absolute = path.join(PRESS_KIT_ROOT, kit.folder, requested);

    if (!fs.existsSync(absolute)) {
      return ctx.notFound("That file is not in this kit");
    }

    const extension = path.extname(absolute).toLowerCase();

    await strapi.documents("api::press-kit-download.press-kit-download").create({
      data: {
        pressKit: kit.documentId,
        fileName: path.basename(absolute),
        requestedFrom: ctx.request.ip,
      },
    });

    ctx.type = CONTENT_TYPES[extension] ?? "application/octet-stream";
    ctx.attachment(path.basename(absolute));
    ctx.body = fs.createReadStream(absolute);
  },
}));
