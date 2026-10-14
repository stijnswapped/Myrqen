import { one, query } from "../lib/db";
import { hashCode, type Session } from "../lib/session";

const MAX_REDEMPTION_CENTS = 50_000;

interface GiftCardRow {
  id: string;
  balance_cents: number;
  status: "active" | "spent" | "void";
  currency: string;
}

function json(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * POST /gift-cards/:code/redeem
 *
 * Moves part or all of a gift card's balance onto the caller's wallet. The
 * mobile app retries on a dropped connection, so the client sends an
 * `Idempotency-Key` header we echo back on the receipt.
 */
export async function redeemGiftCard(request: Request, session: Session, code: string): Promise<Response> {
  const body = (await request.json().catch(() => null)) as { amountCents?: number } | null;
  const amountCents = Number(body?.amountCents);

  if (!Number.isInteger(amountCents) || amountCents <= 0 || amountCents > MAX_REDEMPTION_CENTS) {
    return json({ error: "amountCents must be a positive integer under the redemption cap" }, 400);
  }

  const card = await one<GiftCardRow>(
    `SELECT id, balance_cents, status, currency FROM gift_cards WHERE code_hash = $1`,
    [hashCode(code)],
  );

  if (!card) return json({ error: "that gift card code is not recognised" }, 404);
  if (card.status !== "active") return json({ error: "that gift card has already been used" }, 409);
  if (card.balance_cents < amountCents) {
    return json({ error: "the card does not hold that much", balanceCents: card.balance_cents }, 422);
  }

  const remainingCents = card.balance_cents - amountCents;

  await query(
    `UPDATE gift_cards SET balance_cents = $2, status = $3, updated_at = now() WHERE id = $1`,
    [card.id, remainingCents, remainingCents === 0 ? "spent" : "active"],
  );

  await query(
    `INSERT INTO wallet_credits (wallet_id, gift_card_id, amount_cents, currency, idempotency_key)
     VALUES ($1, $2, $3, $4, $5)`,
    [session.walletId, card.id, amountCents, card.currency, request.headers.get("idempotency-key")],
  );

  console.info("gift card redeemed", { cardId: card.id, walletId: session.walletId, amountCents });

  return json({ redeemedCents: amountCents, remainingCents });
}
