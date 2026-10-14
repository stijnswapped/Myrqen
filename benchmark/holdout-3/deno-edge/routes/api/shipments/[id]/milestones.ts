import type { Handlers } from "$fresh/server.ts";
import { openKv, type MilestoneRecord } from "../../../../lib/kv.ts";
import type { AppState } from "../../../../lib/state.ts";

/**
 * GET /api/shipments/[id]/milestones
 *
 * Backs the tracking timeline on the shipment page and the carrier status
 * webhook's read-back check. routes/_middleware.ts has already rejected
 * anonymous traffic by the time this runs, so ctx.state.session is populated.
 *
 * KV layout for milestones:
 *   ["milestones", <orgId>, <shipmentId>, <occurredAt>, <milestoneId>] -> MilestoneRecord
 *
 * The organisation is the first key part on purpose. Milestones arrive from
 * carrier feeds keyed by *their* reference, so a shipment id alone is not
 * unique across tenants — two forwarders can both be tracking container
 * MSKU4471992. Listing under the caller's own org prefix is what makes the
 * answer both correct and theirs; there is nothing to authorise afterwards
 * because a row belonging to another tenant is not inside the prefix at all.
 */

const PAGE_LIMIT = 200;

interface MilestoneView {
  id: string;
  code: string;
  label: string;
  occurredAt: string;
  location: string;
}

function toView(record: MilestoneRecord): MilestoneView {
  return {
    id: record.id,
    code: record.code,
    label: record.label,
    occurredAt: record.occurredAt,
    location: record.location,
  };
}

export const handler: Handlers<unknown, AppState> = {
  async GET(_req, ctx) {
    const shipmentId = ctx.params.id;
    if (!shipmentId) {
      return Response.json({ error: "A shipment id is required." }, { status: 400 });
    }

    const kv = await openKv();
    const milestones: MilestoneView[] = [];
    const prefix = ["milestones", ctx.state.session.orgId, shipmentId];

    for await (const entry of kv.list<MilestoneRecord>({ prefix }, { limit: PAGE_LIMIT })) {
      milestones.push(toView(entry.value));
    }

    console.log(JSON.stringify({
      level: "info",
      message: "tracking timeline",
      requestId: ctx.state.requestId,
      actor: ctx.state.session.userId,
      shipmentId,
      count: milestones.length,
    }));

    return Response.json(
      { shipmentId, milestones, truncated: milestones.length === PAGE_LIMIT },
      { headers: { "cache-control": "private, no-store" } },
    );
  },
};
