import type { Socket } from "socket.io";
import { contacts } from "../lib/mongo";

const PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 100;
const STATUSES = new Set(["active", "archived", "blocked"]);

interface SearchMessage {
  filter?: Record<string, unknown>;
  limit?: number;
}

type Ack = (response: unknown) => void;

/** Escapes the characters that would otherwise be regex syntax. */
function literal(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * The agent console keeps a live contact list. The saved-view builder in the
 * sidebar serialises whatever the agent picked, so the message arrives as a bag
 * of fields and each one is read out by name.
 */
export function registerContactHandlers(socket: Socket): void {
  socket.on("contact:search", async (message: SearchMessage, ack: Ack) => {
    const tenantId = socket.data.tenantId as string;
    const limit = Math.min(Number(message?.limit) || PAGE_SIZE, MAX_PAGE_SIZE);
    const filter = message?.filter ?? {};

    try {
      const query: Record<string, unknown> = { tenantId };

      if (typeof filter.status === "string" && STATUSES.has(filter.status)) {
        query.status = filter.status;
      }
      if (typeof filter.ownerId === "string") {
        query.ownerId = filter.ownerId;
      }
      if (typeof filter.name === "string" && filter.name.trim().length > 0) {
        query.displayName = { $regex: literal(filter.name.trim()), $options: "i" };
      }

      const rows = await contacts
        .find(query)
        .project({ displayName: 1, email: 1, status: 1, ownerId: 1, updatedAt: 1 })
        .sort({ updatedAt: -1 })
        .limit(limit)
        .toArray();

      ack({ ok: true, contacts: rows });
    } catch (error) {
      console.error("contact search failed", { tenantId, reason: String(error) });
      ack({ ok: false, error: "search_failed" });
    }
  });

  socket.on("contact:subscribe", (contactId: unknown, ack: Ack) => {
    if (typeof contactId !== "string" || contactId.length !== 24) {
      ack({ ok: false, error: "bad_contact_id" });
      return;
    }
    socket.join(`${socket.data.tenantId}:contact:${contactId}`);
    ack({ ok: true });
  });
}
