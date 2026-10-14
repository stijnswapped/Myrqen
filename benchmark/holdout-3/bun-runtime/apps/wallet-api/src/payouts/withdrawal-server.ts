/**
 * Withdrawals.
 *
 * Runs as its own Bun process so a slow provider cannot occupy the dashboard's
 * request budget. The ledger is bun:sqlite on the payout node's local NVMe --
 * a payout is a small, hot, single-writer workload and Postgres round trips
 * were most of the latency.
 */
import { Database } from "bun:sqlite";
import { requireSession } from "../auth/session";
import { createPayout } from "../psp/client";
import { json, problem } from "../http/responses";
import { logger } from "../observability/logger";

const db = new Database(process.env.WALLET_DB ?? "/var/lib/wallet/wallet.sqlite");
db.exec("pragma journal_mode = wal");

const readWallet = db.query<{ balance_cents: number; currency: string }, [string, string]>(
  "select balance_cents, currency from wallets where id = ? and subject_id = ?"
);
const debitWallet = db.query("update wallets set balance_cents = balance_cents - ? where id = ?");
const insertPayout = db.query(
  "insert into payouts (id, wallet_id, amount_cents, psp_reference, state) values (?, ?, ?, ?, 'sent')"
);

const MIN_PAYOUT_CENTS = 100;
const MAX_PAYOUT_CENTS = 200_000;
const WALLET_PATH = /^\/api\/wallets\/(wlt_[0-9a-hjkmnp-tv-z]{26})\/withdrawals$/;

async function requestWithdrawal(request: Request, walletId: string): Promise<Response> {
  const session = await requireSession(request);
  if (!session) return problem(401, "session_required");

  let body: { amountCents?: unknown; destinationId?: unknown };
  try {
    body = await request.json();
  } catch {
    return problem(400, "body_must_be_json");
  }

  const amountCents = Number(body.amountCents);
  if (!Number.isInteger(amountCents) || amountCents < MIN_PAYOUT_CENTS || amountCents > MAX_PAYOUT_CENTS) {
    return problem(422, "amount_out_of_range");
  }
  if (typeof body.destinationId !== "string") return problem(422, "destination_required");

  const wallet = readWallet.get(walletId, session.subjectId);
  if (!wallet) return problem(404, "wallet_not_found");
  if (wallet.balance_cents < amountCents) return problem(402, "insufficient_funds");

  // Ask the provider before touching the ledger: a payout we cannot send is not
  // one we want to have debited, and roughly one destination in fifty comes
  // back rejected.
  const payout = await createPayout({
    destinationId: body.destinationId,
    amountCents,
    currency: wallet.currency
  });
  if (!payout.ok) {
    logger.info("payout.rejected_by_provider", { walletId, reason: payout.reason });
    return problem(502, "payout_rejected");
  }

  debitWallet.run(amountCents, walletId);
  const payoutId = Bun.randomUUIDv7();
  insertPayout.run(payoutId, walletId, amountCents, payout.reference);

  logger.info("payout.sent", { walletId, payoutId, amountCents });
  return json({ payoutId, amountCents, balanceCents: wallet.balance_cents - amountCents }, 201);
}

Bun.serve({
  port: Number(process.env.PAYOUT_PORT ?? 8060),

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return new Response("ok");

    const match = WALLET_PATH.exec(url.pathname);
    if (!match) return problem(404, "not_found");
    if (request.method !== "POST") return problem(405, "method_not_allowed");

    return requestWithdrawal(request, match[1]);
  }
});
