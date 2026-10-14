import { db } from "./db";

export interface Listing {
  sku: string;
  title: string;
  unitPriceCents: number;
  stock: number;
  active: boolean;
}

export async function loadListings(skus: string[]): Promise<Map<string, Listing>> {
  const rows = await db.query<Listing>(
    `SELECT sku, title, unit_price_cents AS "unitPriceCents", stock, active
       FROM listings WHERE sku = ANY($1)`,
    [skus],
  );
  return new Map(rows.map((row) => [row.sku, row]));
}
