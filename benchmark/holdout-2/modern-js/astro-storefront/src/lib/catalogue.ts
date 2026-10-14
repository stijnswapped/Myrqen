import { db } from "./db";

export interface CatalogueEntry {
  sku: string;
  title: string;
  unitPriceCents: number;
  stock: number;
  active: boolean;
}

export async function loadCatalogueEntries(skus: string[]): Promise<Map<string, CatalogueEntry>> {
  const rows = await db.query<CatalogueEntry>(
    `SELECT sku, title, unit_price_cents AS "unitPriceCents", stock, active
       FROM catalogue_entries WHERE sku = ANY($1)`,
    [skus],
  );
  return new Map(rows.map((row) => [row.sku, row]));
}
