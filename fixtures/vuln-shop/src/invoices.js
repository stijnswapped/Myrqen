/**
 * Invoice lookup, deliberately in its own module.
 *
 * The point of this file is the *shape*, not the code. The handler in `server.js`
 * authenticates and then delegates, and the ownership decision that ought to happen
 * lives here — one module boundary away. Myrqen's static pass does not decide whether
 * an ownership check is missing across that boundary, and its coverage output says so:
 * a defect written this way is out of its reach, and exactly what the host agent is for.
 *
 * Nothing about this is contrived. It is how every application above a few hundred
 * lines is laid out: routes delegate to a repository, and the repository is where
 * somebody forgets the tenant predicate.
 */
export const invoices = [
  { reference: "inv-alice-01", userId: 1, total: 4200, card: "4242", address: "1 Alice Street" },
  { reference: "inv-bob-01", userId: 2, total: 1900, card: "4111", address: "2 Bob Avenue" },
  { reference: "inv-root-01", userId: 3, total: 100, card: "5555", address: "3 Root Road" }
];

/**
 * Load an invoice by its reference.
 *
 * The defect: `userId` is never a parameter, so no caller can scope this, and the one
 * caller does not try. Any authenticated customer can read any invoice by reference,
 * including the card fragment and the delivery address.
 */
export function invoiceByReference(reference) {
  return invoices.find((candidate) => candidate.reference === reference);
}

/** The correctly scoped sibling, so the defect above is a slip rather than a design. */
export function invoicesForUser(userId) {
  return invoices.filter((candidate) => candidate.userId === userId);
}

/**
 * Redeem a promotional code against a total.
 *
 * The defect: redemption is not recorded anywhere, so the same code applies as many
 * times as it is sent. No static rule models "this operation should have been
 * idempotent" — the code reads correctly line by line, and the flaw is only visible
 * by doing it twice.
 */
const PROMOTIONS = new Map([["WELCOME10", 10]]);

export function applyPromotion(code, totalCents) {
  const percent = PROMOTIONS.get(code);
  if (percent === undefined) return { applied: false, total: totalCents };
  return { applied: true, total: Math.round(totalCents * (1 - percent / 100)) };
}
