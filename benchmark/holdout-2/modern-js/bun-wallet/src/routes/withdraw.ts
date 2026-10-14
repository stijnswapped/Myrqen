import { one, query } from "../lib/db";
import type { Session } from "../lib/session";

const MAX_WITHDRAWAL_CENTS = 50_000;

interface WalletRow {
  id: string;
  balance_cents: number;
  status: "active" | "frozen" | "closed";
  currency: string;
}

function json(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * POST /wallets/:walletId/withdrawals
 *
 * Moves part or all of a wallet balance out to the linked payout account. The
 * mobile app retries on a dropped connection, so the client sends an
 * `Idempotency-Key` header we echo back on the receipt.
 */
export async function withdrawFromWallet(request: Request, session: Session, walletId: string): Promise<Response> {
  const body = (await request.json().catch(() => null)) as { amountCents?: number } | null;
  const amountCents = Number(body?.amountCents);

  if (!Number.isInteger(amountCents) || amountCents <= 0 || amountCents > MAX_WITHDRAWAL_CENTS) {
    return json({ error: "amountCents must be a positive integer under the withdrawal cap" }, 400);
  }

  const wallet = await one<WalletRow>(
    `SELECT id, balance_cents, status, currency FROM wallets WHERE id = $1 AND owner_id = $2`,
    [walletId, session.userId],
  );

  // Read once for the message the customer sees; the decision is made by the
  // UPDATE below, which is the only thing allowed to conclude "affordable".
  if (!wallet) return json({ error: "that wallet is not yours" }, 404);
  if (wallet.status !== "active") return json({ error: "that wallet is frozen" }, 409);
  if (wallet.balance_cents < amountCents) {
    return json({ error: "the wallet does not hold that much", balanceCents: wallet.balance_cents }, 422);
  }

  const debited = await query<{ balance_cents: number }>(
    `UPDATE wallets SET balance_cents = balance_cents - $2, updated_at = now()
      WHERE id = $1 AND status = 'active' AND balance_cents >= $2
     RETURNING balance_cents`,
    [wallet.id, amountCents],
  );

  if (debited.rowCount === 0) {
    return json({ error: "the wallet does not hold that much" }, 422);
  }

  await query(
    `INSERT INTO wallet_debits (wallet_id, amount_cents, currency, idempotency_key)
     VALUES ($1, $2, $3, $4) ON CONFLICT (idempotency_key) DO NOTHING`,
    [wallet.id, amountCents, wallet.currency, request.headers.get("idempotency-key")],
  );

  const remainingCents = debited.rows[0].balance_cents;
  console.info("wallet debited", { walletId: wallet.id, amountCents, remainingCents });

  return json({ withdrawnCents: amountCents, remainingCents });
}
