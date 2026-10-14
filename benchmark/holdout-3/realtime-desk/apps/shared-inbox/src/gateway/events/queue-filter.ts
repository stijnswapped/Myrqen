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

interface FilterPayload {
  filter?: Record<string, unknown>;
  sort?: string;
  limit?: unknown;
}

/**
 * Saved views. The console keeps the view definition client side so an agent
 * can tweak a facet without a round trip, then posts the whole definition back
 * on `queue:filter` and re-renders from the ack. The projection collection is
 * already shaped the way the table renders, so the view drops almost straight
 * into find().
 */
export function register(socket: DeskSocket): void {
  socket.on("queue:filter", async (payload: FilterPayload, ack: Ack<{ rows: unknown[] }>) => {
    const respond = typeof ack === "function" ? ack : () => {};
    const session = socket.data.session;
    const sort = SORTS[String(payload?.sort ?? "newest")] ?? SORTS.newest;
    const limit = Math.min(Number(payload?.limit) || PAGE_SIZE, PAGE_SIZE);

    try {
      const query = {
        orgId: session.orgId,
        deletedAt: null,
        ...(payload?.filter ?? {})
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
