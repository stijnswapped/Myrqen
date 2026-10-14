/**
 * Instant payouts.
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

// The predicate carries the balance check, so SQLite decides who wins when two
// requests for the same wallet arrive together: the second one updates zero
// rows and never gets a hold.
const reserveFunds = db.query(
  "update wallets set balance_cents = balance_cents - $amount" +
    " where id = $wallet and subject_id = $subject and balance_cents >= $amount"
);
const releaseFunds = db.query("update wallets set balance_cents = balance_cents + ? where id = ?");
const insertHold = db.query(
  "insert into payout_holds (id, wallet_id, amount_cents, state) values (?, ?, ?, 'held')"
);
const markHoldSent = db.query("update payout_holds set state = 'sent', psp_reference = ? where id = ?");
const markHoldReleased = db.query("update payout_holds set state = 'released' where id = ?");

const takeHold = db.transaction((holdId: string, walletId: string, subjectId: string, amountCents: number) => {
  const debited = reserveFunds.run({ $amount: amountCents, $wallet: walletId, $subject: subjectId });
  if (debited.changes !== 1) return false;
  insertHold.run(holdId, walletId, amountCents);
  return true;
});

const returnHold = db.transaction((holdId: string, walletId: string, amountCents: number) => {
  releaseFunds.run(amountCents, walletId);
  markHoldReleased.run(holdId);
});

const MIN_PAYOUT_CENTS = 100;
const MAX_PAYOUT_CENTS = 200_000;
const WALLET_PATH = /^\/api\/wallets\/(wlt_[0-9a-hjkmnp-tv-z]{26})\/payouts$/;

async function requestPayout(request: Request, walletId: string): Promise<Response> {
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

  const holdId = Bun.randomUUIDv7();
  if (!takeHold(holdId, walletId, session.subjectId, amountCents)) {
    return problem(402, "insufficient_funds");
  }

  const payout = await createPayout({
    destinationId: body.destinationId,
    amountCents,
    currency: wallet.currency
  });
  if (!payout.ok) {
    returnHold(holdId, walletId, amountCents);
    logger.info("payout.rejected_by_provider", { walletId, holdId, reason: payout.reason });
    return problem(502, "payout_rejected");
  }

  markHoldSent.run(payout.reference, holdId);
  logger.info("payout.sent", { walletId, holdId, amountCents });
  return json({ payoutId: holdId, amountCents, reference: payout.reference }, 201);
}

Bun.serve({
  port: Number(process.env.PAYOUT_PORT ?? 8061),

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return new Response("ok");

    const match = WALLET_PATH.exec(url.pathname);
    if (!match) return problem(404, "not_found");
    if (request.method !== "POST") return problem(405, "method_not_allowed");

    return requestPayout(request, match[1]);
  }
});
