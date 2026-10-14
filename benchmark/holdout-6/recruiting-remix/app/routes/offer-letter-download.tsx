import { readFile } from "node:fs/promises";
import path from "node:path";
import type { LoaderFunctionArgs } from "react-router";
import { db } from "../db/client";
import { assertRequisitionAccess } from "../lib/hiring-team.server";
import { requireRole } from "../sessions.server";

/** Resolved once at boot so the comparison below is against an absolute path. */
const OFFER_ROOT = path.resolve(process.env.OFFER_STORAGE_ROOT ?? "/var/lib/ats/offers");

function isInsideOfferRoot(candidatePath: string): boolean {
  return candidatePath === OFFER_ROOT || candidatePath.startsWith(OFFER_ROOT + path.sep);
}

/**
 * Resource route: serves the generated offer letter PDF.
 */
export async function loader({ params, request }: LoaderFunctionArgs) {
  const user = await requireRole(request, ["recruiter", "hiring_manager", "admin"]);
  const offerId = params.offerId;

  if (!offerId) {
    throw new Response("Not found", { status: 404 });
  }

  const offer = await db
    .selectFrom("offers as o")
    .innerJoin("attachments as att", "att.id", "o.letter_attachment_id")
    .select([
      "o.id",
      "o.requisition_id",
      "o.status",
      "att.storage_key",
      "att.original_filename",
      "att.content_type",
      "att.byte_size",
    ])
    .where("o.id", "=", offerId)
    .executeTakeFirst();

  if (!offer) {
    throw new Response("Not found", { status: 404 });
  }

  await assertRequisitionAccess(user, offer.requisition_id);

  // storage_key is written by the letter generator and should always be a
  // "<requisition>/<offer>.pdf" pair, but a hand-fixed row or a bad backfill
  // could hold anything, so the joined path is checked against the root before
  // it is opened.
  const filePath = path.resolve(OFFER_ROOT, offer.storage_key);

  if (!isInsideOfferRoot(filePath)) {
    console.warn("offer.letter.rejected_key", { offerId, key: offer.storage_key });
    throw new Response("Forbidden", { status: 403 });
  }

  const body = await readFile(filePath);

  console.info("offer.letter.downloaded", { offerId, actorId: user.id });

  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": offer.content_type || "application/pdf",
      "Content-Disposition": `attachment; filename="${encodeURIComponent(offer.original_filename)}"`,
      "Cache-Control": "private, no-store",
    },
  });
}
