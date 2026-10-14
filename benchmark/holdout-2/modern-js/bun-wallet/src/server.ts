import { redeemGiftCard } from "./routes/redeem";
import { withdrawFromWallet } from "./routes/withdraw";
import { sessionFor } from "./lib/session";

const REDEEM = /^\/gift-cards\/([^/]+)\/redeem$/;
const WITHDRAW = /^\/wallets\/([^/]+)\/withdrawals$/;

Bun.serve({
  port: Number(Bun.env.PORT ?? 3200),
  async fetch(request) {
    const session = await sessionFor(request);
    if (!session) return new Response("unauthorized", { status: 401 });

    const { pathname } = new URL(request.url);

    const redeem = REDEEM.exec(pathname);
    if (redeem && request.method === "POST") {
      return redeemGiftCard(request, session, decodeURIComponent(redeem[1]));
    }

    const withdraw = WITHDRAW.exec(pathname);
    if (withdraw && request.method === "POST") {
      return withdrawFromWallet(request, session, decodeURIComponent(withdraw[1]));
    }

    return new Response("Not found", { status: 404 });
  },
});
