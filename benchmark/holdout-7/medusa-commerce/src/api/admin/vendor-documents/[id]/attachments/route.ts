import { createReadStream } from "node:fs"
import fs from "node:fs/promises"
import path from "node:path"

import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import type { EntityManager } from "@mikro-orm/postgresql"

import {
  MARKETPLACE_MANAGER,
  VendorDocument,
  VendorMember,
} from "../../../../../modules/marketplace/models"

const DOCUMENT_ROOT =
  process.env.ATELIER_DOCUMENT_ROOT ?? "/var/lib/atelier/vendor-documents"

const ATTACHMENT_DIR = "attachments"

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
}

/**
 * Resolves a caller-named file inside one document's attachment folder, or null
 * when the name points anywhere else. basename() drops any directory the caller
 * put in the name, and the realpath comparison catches a symlink planted in the
 * folder by the uploader.
 */
const resolveAttachment = async (
  storageFolder: string,
  requestedName: string
): Promise<string | null> => {
  const extension = path.extname(requestedName).toLowerCase()
  if (!CONTENT_TYPES[extension]) {
    return null
  }

  const fileName = path.basename(requestedName)
  if (!fileName || fileName.startsWith(".")) {
    return null
  }

  const folder = path.resolve(DOCUMENT_ROOT, storageFolder, ATTACHMENT_DIR)
  const candidate = path.resolve(folder, fileName)
  if (candidate !== path.join(folder, fileName)) {
    return null
  }

  const real = await fs.realpath(candidate).catch(() => null)
  if (!real || !real.startsWith(folder + path.sep)) {
    return null
  }

  return real
}

/**
 * Streams a file the atelier attached to a document — a signed cover letter, a
 * photo of a stamp — from the same volume the scanned pages live on.
 */
export const GET = async (req: MedusaRequest, res: MedusaResponse) => {
  const actorId = req.auth_context?.actor_id
  if (!actorId || req.auth_context?.actor_type !== "user") {
    return res.status(401).json({ message: "Not authenticated" })
  }

  const em = req.scope.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

  const document = await em.findOne(
    VendorDocument,
    { id: req.params.id },
    { populate: ["vendor"] }
  )
  if (!document) {
    return res.status(404).json({ message: "Document not found" })
  }

  const membership = await em.findOne(VendorMember, {
    vendor: document.vendor.id,
    user_id: actorId,
  })
  if (!membership) {
    return res.status(403).json({ message: "Not a member of this atelier" })
  }

  const requestedName = String(req.query.file ?? "")
  const filePath = await resolveAttachment(document.storage_folder, requestedName)
  if (!filePath) {
    return res.status(404).json({ message: "Attachment not found" })
  }

  const stat = await fs.stat(filePath).catch(() => null)
  if (!stat?.isFile()) {
    return res.status(404).json({ message: "Attachment not found" })
  }

  res.setHeader(
    "Content-Type",
    CONTENT_TYPES[path.extname(filePath).toLowerCase()] ??
      "application/octet-stream"
  )
  res.setHeader("Content-Length", String(stat.size))
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${path.basename(filePath)}"`
  )

  createReadStream(filePath).pipe(res)
}
