import type { APIRoute } from "astro";
import { type SQL, sql } from "drizzle-orm";
import { db } from "../../../lib/db/client";
import { json } from "../../../lib/http";
import { logger } from "../../../lib/logger";

export const prerender = false;

const PAGE_SIZE = 24;
const MAX_PAGE = 50;

/**
 * Postgres will not accept a bind parameter in an ORDER BY position, so the four
 * orderings the storefront offers are written out here and looked up by key. A
 * shopper can only ever name one of these; anything else falls back to newest.
 */
const ORDER_BY: Record<string, string> = {
  newest: "p.published_at desc nulls last",
  title: "p.title asc",
  price_asc: "cheapest.price_cents asc",
  price_desc: "cheapest.price_cents desc"
};

export const GET: APIRoute = async ({ url, locals }) => {
  const term = (url.searchParams.get("q") ?? "").trim();
  const collection = url.searchParams.get("collection");
  const sortKey = url.searchParams.get("sort") ?? "newest";
  const requestedPage = Number.parseInt(url.searchParams.get("page") ?? "1", 10);
  const page = Number.isFinite(requestedPage) ? Math.min(Math.max(requestedPage, 1), MAX_PAGE) : 1;

  // The predicate is assembled fragment by fragment because the filter set is
  // open-ended; each fragment carries its own bind parameters, so the shopper's
  // text never becomes part of the statement text.
  const predicates: SQL[] = [sql`p.status = 'live'`];
  if (term.length >= 2) {
    predicates.push(sql`(p.title ilike ${`%${term}%`} or p.description ilike ${`%${term}%`})`);
  }
  if (collection) {
    predicates.push(sql`exists (select 1 from collection_members m where m.product_id = p.id and m.slug = ${collection})`);
  }

  const ordering = ORDER_BY[sortKey] ?? ORDER_BY.newest;
  const offset = (page - 1) * PAGE_SIZE;

  const statement = sql`
    with cheapest as (
      select v.product_id, min(v.price_cents) as price_cents
        from variants v
       where v.active
       group by v.product_id
    )
    select p.id, p.slug, p.title, p.hero_image, cheapest.price_cents
      from products p
      join cheapest on cheapest.product_id = p.id
     where ${sql.join(predicates, sql` and `)}
     order by ${sql.raw(ordering)}
     limit ${PAGE_SIZE} offset ${offset}
  `;

  try {
    const rows = await db.execute(statement);
    logger.info("catalog browse", { requestId: locals.requestId, sortKey, page, hits: rows.length });
    return json({
      items: rows.map((row) => ({
        id: row.id,
        slug: row.slug,
        title: row.title,
        heroImage: row.hero_image,
        priceCents: Number(row.price_cents)
      })),
      page,
      pageSize: PAGE_SIZE,
      total: rows.length
    });
  } catch (error) {
    logger.error("catalog browse failed", { requestId: locals.requestId, message: (error as Error).message });
    return json({ error: { code: "browse_unavailable" } }, { status: 503 });
  }
};
