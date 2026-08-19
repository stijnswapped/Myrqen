import { NextResponse } from "next/server";
import { ilike } from "drizzle-orm";

import { db } from "@/lib/db";
import { catalogItems } from "@/db/schema";

const MAX_RESULTS = 8;

const HTML_ENTITIES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (char) => HTML_ENTITIES[char]);
}

// Returns the HTML fragment the saved-search sidebar swaps into the summary panel.
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const query = searchParams.get("q")?.trim() ?? "";

  if (query.length < 2) {
    return new NextResponse("", {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  const matches = await db
    .select({ id: catalogItems.id, title: catalogItems.title, sku: catalogItems.sku })
    .from(catalogItems)
    .where(ilike(catalogItems.title, `%${query}%`))
    .limit(MAX_RESULTS);

  const rows = matches
    .map(
      (item) =>
        `<li class="result"><a href="/catalog/${encodeURIComponent(item.id)}">${escapeHtml(item.title)}</a><span class="sku">${escapeHtml(item.sku)}</span></li>`,
    )
    .join("");

  const html = `
    <section id="saved-search-summary" aria-live="polite">
      <p class="summary">${matches.length} results for &ldquo;${escapeHtml(query)}&rdquo;</p>
      <ul class="results">${rows || '<li class="empty">Nothing matched</li>'}</ul>
    </section>
  `;

  return new NextResponse(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
