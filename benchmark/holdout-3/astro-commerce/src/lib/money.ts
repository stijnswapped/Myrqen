/** Cents in, cents out. Nothing in this codebase is allowed to hold money in a float. */

export function toCents(value: number): number {
  return Math.round(value * 100);
}

export function formatCents(cents: number, currency = "EUR", locale = "nl-NL"): string {
  return new Intl.NumberFormat(locale, { style: "currency", currency }).format(cents / 100);
}

export function sumLines(lines: ReadonlyArray<{ quantity: number; unitPriceCents: number }>): number {
  return lines.reduce((total, line) => total + line.quantity * line.unitPriceCents, 0);
}
