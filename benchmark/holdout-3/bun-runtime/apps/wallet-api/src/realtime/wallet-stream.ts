/**
 * Live wallet feed.
 *
 * The dashboard opens one socket and subscribes to the wallets it is currently
 * showing. Ledger workers publish onto `wallet:<id>` through the same server
 * handle, so a posting is on screen roughly a hundred milliseconds after it is
 * booked. The socket carries no authentication of its own: the upgrade reuses
 * the dashboard session cookie, and `ws.data` is the only identity downstream.
 */
import { requireSession } from "../auth/session";
import { assertWalletAccess } from "../auth/wallet-access";
import { recentEvents } from "../ledger/events";
import { logger } from "../observability/logger";

type SocketData = { subjectId: string; sessionId: string; openedAt: number };

type ClientMessage =
  | { type: "subscribe"; walletId: string }
  | { type: "unsubscribe"; walletId: string }
  | { type: "replay"; walletId: string; since: number };

const WALLET_ID = /^wlt_[0-9a-hjkmnp-tv-z]{26}$/;
const MAX_REPLAY_EVENTS = 200;

function topicFor(walletId: string): string {
  return `wallet:${walletId}`;
}

function parse(raw: string | Buffer): ClientMessage | null {
  try {
    const message = JSON.parse(typeof raw === "string" ? raw : raw.toString("utf8"));
    if (typeof message?.type !== "string") return null;
    if (typeof message?.walletId !== "string" || !WALLET_ID.test(message.walletId)) return null;
    return message as ClientMessage;
  } catch {
    return null;
  }
}

export const server = Bun.serve<SocketData, {}>({
  port: Number(process.env.REALTIME_PORT ?? 8071),

  async fetch(request, server) {
    const url = new URL(request.url);
    if (url.pathname !== "/realtime/wallets") return new Response("not found", { status: 404 });

    const session = await requireSession(request);
    if (!session) return new Response("unauthorized", { status: 401 });

    const upgraded = server.upgrade(request, {
      data: { subjectId: session.subjectId, sessionId: session.sessionId, openedAt: Date.now() }
    });
    return upgraded ? undefined : new Response("expected websocket", { status: 426 });
  },

  websocket: {
    idleTimeout: 120,
    maxPayloadLength: 16 * 1024,

    open(ws) {
      logger.info("realtime.opened", { subjectId: ws.data.subjectId });
      ws.send(JSON.stringify({ type: "ready" }));
    },

    async message(ws, raw) {
      const message = parse(raw);
      if (!message) {
        ws.send(JSON.stringify({ type: "error", code: "bad_message" }));
        return;
      }

      switch (message.type) {
        case "subscribe": {
          ws.subscribe(topicFor(message.walletId));
          ws.send(JSON.stringify({ type: "subscribed", walletId: message.walletId }));
          return;
        }

        case "unsubscribe": {
          ws.unsubscribe(topicFor(message.walletId));
          ws.send(JSON.stringify({ type: "unsubscribed", walletId: message.walletId }));
          return;
        }

        case "replay": {
          if (!(await assertWalletAccess(ws.data.subjectId, message.walletId))) {
            logger.info("realtime.replay_denied", { subjectId: ws.data.subjectId, walletId: message.walletId });
            ws.send(JSON.stringify({ type: "error", code: "wallet_not_visible" }));
            return;
          }
          const events = await recentEvents(message.walletId, message.since, MAX_REPLAY_EVENTS);
          ws.send(JSON.stringify({ type: "replay", walletId: message.walletId, events }));
          return;
        }

        default: {
          ws.send(JSON.stringify({ type: "error", code: "unknown_message" }));
        }
      }
    },

    close(ws) {
      logger.info("realtime.closed", { subjectId: ws.data.subjectId, heldMs: Date.now() - ws.data.openedAt });
    }
  }
});

export function publishLedgerEvent(walletId: string, event: unknown): void {
  server.publish(topicFor(walletId), JSON.stringify({ type: "event", walletId, event }));
}
