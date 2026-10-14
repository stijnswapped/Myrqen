/**
 * Brand asset downloads.
 *
 * Same job as the press kit download, but the asset is addressed by its own
 * documentId instead of by name, so the file name never comes off the request -
 * it comes off the row.
 */
import fs from "node:fs";
import path from "node:path";

import { factories } from "@strapi/strapi";

const ASSET_ROOT = path.resolve(process.env.BRAND_ASSET_ROOT ?? path.join("public", "brand-assets"));

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".zip": "application/zip",
};

/**
 * storageKey is written by the upload hook and should always sit under the asset
 * root, but the root is configurable per environment, so resolve and compare
 * before we open anything.
 */
function resolveInsideRoot(storageKey: string): string | null {
  const resolved = path.resolve(ASSET_ROOT, storageKey);

  if (resolved !== ASSET_ROOT && !resolved.startsWith(ASSET_ROOT + path.sep)) {
    return null;
  }

  return resolved;
}

export default factories.createCoreController("api::press-kit.press-kit", ({ strapi }) => ({
  /**
   * GET /press-kits/:documentId/assets/:assetId
   */
  async download(ctx) {
    const { documentId, assetId } = ctx.params;

    const [asset] = await strapi.documents("api::brand-asset.brand-asset").findMany({
      filters: {
        documentId: assetId,
        pressKit: { documentId, releaseState: "released" },
      },
      fields: ["label", "storageKey", "byteSize"],
      limit: 1,
    });

    if (!asset) {
      return ctx.notFound("That asset is not in this kit");
    }

    const absolute = resolveInsideRoot(asset.storageKey);

    if (!absolute || !fs.existsSync(absolute)) {
      strapi.log.error(`brand asset ${asset.documentId} points outside the asset root`);
      return ctx.notFound("That asset is not available");
    }

    const extension = path.extname(absolute).toLowerCase();

    ctx.type = CONTENT_TYPES[extension] ?? "application/octet-stream";
    ctx.attachment(path.basename(absolute));
    ctx.body = fs.createReadStream(absolute);
  },
}));
