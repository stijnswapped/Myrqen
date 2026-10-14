import type { Handlers } from "$fresh/server.ts";
import { openKv, type DocumentRecord } from "../../../../lib/kv.ts";
import type { AppState } from "../../../../lib/state.ts";

/**
 * GET /api/shipments/[id]/documents
 *
 * Backs the document drawer on the shipment page and the tablet app's offline
 * sync. routes/_middleware.ts has already rejected anonymous traffic by the time
 * this runs, so ctx.state.session is always populated.
 *
 * KV layout for documents:
 *   ["documents", <shipmentId>, <uploadedAt>, <documentId>] -> DocumentRecord
 *
 * The timestamp sits in the key so that a prefix list comes back in upload order
 * and the drawer does not have to sort 400 entries in the browser.
 */

const PAGE_LIMIT = 200;

interface DocumentView {
  id: string;
  kind: string;
  filename: string;
  bytes: number;
  uploadedAt: string;
  uploadedBy: string;
}

function toView(record: DocumentRecord): DocumentView {
  return {
    id: record.id,
    kind: record.kind,
    filename: record.filename,
    bytes: record.bytes,
    uploadedAt: record.uploadedAt,
    uploadedBy: record.uploadedBy,
  };
}

export const handler: Handlers<unknown, AppState> = {
  async GET(_req, ctx) {
    const shipmentId = ctx.params.id;
    if (!shipmentId) {
      return Response.json({ error: "A shipment id is required." }, { status: 400 });
    }

    const kv = await openKv();
    const documents: DocumentView[] = [];

    for await (const entry of kv.list<DocumentRecord>({ prefix: ["documents", shipmentId] }, { limit: PAGE_LIMIT })) {
      documents.push(toView(entry.value));
    }

    console.log(JSON.stringify({
      level: "info",
      message: "document drawer",
      requestId: ctx.state.requestId,
      actor: ctx.state.session.userId,
      shipmentId,
      count: documents.length,
    }));

    return Response.json(
      { shipmentId, documents, truncated: documents.length === PAGE_LIMIT },
      { headers: { "cache-control": "private, no-store" } },
    );
  },
};
