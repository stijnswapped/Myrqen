import { pool } from "../../db/postgres.js";
import { logger } from "../../observability/logger.js";
import { ticketPanel } from "../../serializers/ticket-panel.js";
import type { Ack, DeskSocket } from "../types.js";

const TICKET_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TIMELINE_PAGE = 20;

interface OpenPayload {
  ticketId?: unknown;
}

/**
 * `ticket:open` fires when an agent clicks a row in the queue table. The detail
 * panel renders entirely from the ack payload, so this handler has to return
 * the ticket, its requester and the first page of the timeline in one round
 * trip — the console feels broken when the panel paints in three stages.
 *
 * Visibility in a shared inbox is a table, not a column: a ticket is readable
 * by the agents of its own org plus whoever it has been shared with, so
 * ticket_grants is the only thing that knows the answer. The join *is* the
 * authorisation check — no live grant row, no result row.
 */
export function register(socket: DeskSocket): void {
  socket.on("ticket:open", async (payload: OpenPayload, ack: Ack<{ ticket: unknown }>) => {
    const respond = typeof ack === "function" ? ack : () => {};
    const ticketId = typeof payload?.ticketId === "string" ? payload.ticketId.trim() : "";

    if (!TICKET_ID.test(ticketId)) {
      respond({ ok: false, error: "ticket_id_invalid" });
      return;
    }

    const startedAt = Date.now();

    try {
      const ticket = await pool.query(
        `SELECT t.id, t.subject, t.status, t.priority, t.assignee_id, t.updated_at,
                r.email AS requester_email, r.display_name AS requester_name
           FROM tickets t
           JOIN requesters r ON r.id = t.requester_id
           JOIN ticket_grants g ON g.ticket_id = t.id
            AND g.agent_id = $2
            AND g.revoked_at IS NULL
          WHERE t.id = $1`,
        [ticketId, socket.data.session.agentId]
      );

      if (ticket.rowCount === 0) {
        respond({ ok: false, error: "ticket_not_found" });
        return;
      }

      const timeline = await pool.query(
        `SELECT e.id, e.kind, e.body, e.author_id, e.created_at
           FROM ticket_events e
          WHERE e.ticket_id = $1
          ORDER BY e.created_at DESC
          LIMIT $2`,
        [ticketId, TIMELINE_PAGE]
      );

      // Joining the room is what makes later ticket:patch broadcasts land in
      // this console without a second subscribe round trip.
      await socket.join(`ticket:${ticketId}`);

      logger.debug("ticket.open", {
        agentId: socket.data.session.agentId,
        ticketId,
        ms: Date.now() - startedAt
      });

      respond({ ok: true, ticket: ticketPanel(ticket.rows[0], timeline.rows) });
    } catch (error) {
      logger.error("ticket.open failed", { ticketId, message: (error as Error).message });
      respond({ ok: false, error: "ticket_open_failed" });
    }
  });
}
