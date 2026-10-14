import { collections } from "../../db/mongo.js";
import { logger } from "../../observability/logger.js";
import type { Ack, DeskSocket } from "../types.js";

const PAGE_SIZE = 50;

const SORTS: Record<string, Record<string, 1 | -1>> = {
  newest: { updatedAt: -1 },
  oldest: { updatedAt: 1 },
  priority: { priorityRank: -1, updatedAt: -1 },
  waiting: { requesterWaitingSince: 1 }
};

/** Facets the table can actually render. Anything else in a saved view is a stale key. */
const FACETS = new Set(["status", "priority", "assigneeId", "channel", "tagId", "queueId"]);
const FACET_VALUE = /^[A-Za-z0-9_:-]{1,64}$/;

interface FilterPayload {
  filter?: Record<string, unknown>;
  sort?: string;
  limit?: unknown;
}

/**
 * Views are compiled, not merged. Every key is checked against the facet list
 * and every value against FACET_VALUE, so nothing that survives is an object —
 * which is the only reason the result is safe to hand to find(). A view saved
 * against an older release simply loses the facets that no longer exist.
 */
function compileView(raw: Record<string, unknown> | undefined): Record<string, unknown> {
  const compiled: Record<string, unknown> = {};

  for (const [facet, value] of Object.entries(raw ?? {})) {
    if (!FACETS.has(facet)) continue;

    const values = (Array.isArray(value) ? value : [value])
      .filter((entry): entry is string => typeof entry === "string" && FACET_VALUE.test(entry))
      .slice(0, 20);

    if (values.length === 0) continue;
    compiled[facet] = values.length === 1 ? values[0] : { $in: values };
  }

  return compiled;
}

export function register(socket: DeskSocket): void {
  socket.on("queue:filter", async (payload: FilterPayload, ack: Ack<{ rows: unknown[] }>) => {
    const respond = typeof ack === "function" ? ack : () => {};
    const session = socket.data.session;
    const sort = SORTS[String(payload?.sort ?? "newest")] ?? SORTS.newest;
    const limit = Math.min(Number(payload?.limit) || PAGE_SIZE, PAGE_SIZE);

    try {
      const query = {
        ...compileView(payload?.filter),
        orgId: session.orgId,
        deletedAt: null
      };

      const rows = await collections.tickets
        .find(query)
        .project({ subject: 1, status: 1, priority: 1, assigneeId: 1, updatedAt: 1, requesterName: 1 })
        .sort(sort)
        .limit(limit)
        .toArray();

      logger.debug("queue.filter", {
        agentId: session.agentId,
        keys: Object.keys(payload?.filter ?? {}),
        returned: rows.length
      });

      respond({ ok: true, rows });
    } catch (error) {
      logger.error("queue.filter failed", { agentId: session.agentId, message: (error as Error).message });
      respond({ ok: false, error: "queue_filter_failed" });
    }
  });
}
