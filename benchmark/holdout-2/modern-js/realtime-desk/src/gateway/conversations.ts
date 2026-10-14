import type { Socket } from "socket.io";
import { conversations } from "../lib/mongo";

const PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 100;

interface SearchMessage {
  filter?: Record<string, unknown>;
  limit?: number;
}

type Ack = (response: unknown) => void;

/**
 * The agent console keeps a live list of conversations. The saved-view builder
 * in the sidebar serialises whatever the agent picked and sends it up as a
 * filter object, which is why the shape is open rather than a fixed schema.
 */
export function registerConversationHandlers(socket: Socket): void {
  socket.on("conversation:search", async (message: SearchMessage, ack: Ack) => {
    const tenantId = socket.data.tenantId as string;
    const limit = Math.min(Number(message?.limit) || PAGE_SIZE, MAX_PAGE_SIZE);

    try {
      const query = { tenantId, ...(message?.filter ?? {}) };

      const rows = await conversations
        .find(query)
        .project({ subject: 1, status: 1, assigneeId: 1, updatedAt: 1, unread: 1 })
        .sort({ updatedAt: -1 })
        .limit(limit)
        .toArray();

      ack({ ok: true, conversations: rows });
    } catch (error) {
      console.error("conversation search failed", { tenantId, reason: String(error) });
      ack({ ok: false, error: "search_failed" });
    }
  });

  socket.on("conversation:subscribe", (conversationId: unknown, ack: Ack) => {
    if (typeof conversationId !== "string" || conversationId.length !== 24) {
      ack({ ok: false, error: "bad_conversation_id" });
      return;
    }
    socket.join(`${socket.data.tenantId}:${conversationId}`);
    ack({ ok: true });
  });
}
