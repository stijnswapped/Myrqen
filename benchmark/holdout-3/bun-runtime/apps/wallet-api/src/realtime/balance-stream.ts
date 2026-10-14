/**
 * Live balance feed.
 *
 * The dashboard opens one socket and subscribes to the wallets whose balances
 * it is currently showing. Settlement workers publish onto `balance:<id>`
 * through the same server handle. The socket carries no authentication of its
 * own: the upgrade reuses the dashboard session cookie, and `ws.data` is the
 * only identity downstream, so every addressable wallet id has to be checked
 * against it before the socket is joined to anything.
 */
import { requireSession } from "../auth/session";
import { assertWalletAccess } from "../auth/wallet-access";
import { balanceSnapshot } from "../ledger/events";
import { logger } from "../observability/logger";

type SocketData = { subjectId: string; sessionId: string; openedAt: number };

type ClientMessage =
  | { type: "subscribe"; walletId: string }
  | { type: "unsubscribe"; walletId: string }
  | { type: "snapshot"; walletId: string };

const WALLET_ID = /^wlt_[0-9a-hjkmnp-tv-z]{26}$/;

function topicFor(walletId: string): string {
  return `balance:${walletId}`;
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
  port: Number(process.env.BALANCE_PORT ?? 8072),

  async fetch(request, server) {
    const url = new URL(request.url);
    if (url.pathname !== "/realtime/balances") return new Response("not found", { status: 404 });

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
      logger.info("balances.opened", { subjectId: ws.data.subjectId });
      ws.send(JSON.stringify({ type: "ready" }));
    },

    async message(ws, raw) {
      const message = parse(raw);
      if (!message) {
        ws.send(JSON.stringify({ type: "error", code: "bad_message" }));
        return;
      }

      // Unsubscribing only ever narrows what this socket receives, so it is the
      // one branch that does not need the membership lookup.
      if (message.type === "unsubscribe") {
        ws.unsubscribe(topicFor(message.walletId));
        ws.send(JSON.stringify({ type: "unsubscribed", walletId: message.walletId }));
        return;
      }

      if (!(await assertWalletAccess(ws.data.subjectId, message.walletId))) {
        logger.info("balances.denied", { subjectId: ws.data.subjectId, walletId: message.walletId });
        ws.send(JSON.stringify({ type: "error", code: "wallet_not_visible" }));
        return;
      }

      switch (message.type) {
        case "subscribe": {
          ws.subscribe(topicFor(message.walletId));
          ws.send(JSON.stringify({ type: "subscribed", walletId: message.walletId }));
          return;
        }

        case "snapshot": {
          const snapshot = await balanceSnapshot(message.walletId);
          ws.send(JSON.stringify({ type: "snapshot", walletId: message.walletId, snapshot }));
          return;
        }

        default: {
          ws.send(JSON.stringify({ type: "error", code: "unknown_message" }));
        }
      }
    },

    close(ws) {
      logger.info("balances.closed", { subjectId: ws.data.subjectId, heldMs: Date.now() - ws.data.openedAt });
    }
  }
});

export function publishBalance(walletId: string, balance: unknown): void {
  server.publish(topicFor(walletId), JSON.stringify({ type: "balance", walletId, balance }));
}
