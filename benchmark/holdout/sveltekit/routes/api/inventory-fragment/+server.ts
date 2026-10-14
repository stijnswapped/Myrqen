import type { RequestHandler } from "@sveltejs/kit";
import { searchInventory } from "$lib/server/inventory";

const PAGE_SIZE = 20;

function escapeHtml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export const GET: RequestHandler = async ({ url, locals }) => {
  const term = url.searchParams.get("q") ?? "";
  const page = Math.max(1, Number(url.searchParams.get("page") ?? "1") || 1);
  const results = await searchInventory({
    term,
    page,
    pageSize: PAGE_SIZE,
    tenantId: locals.session?.tenantId ?? null
  });

  const rows = results
    .map(
      (item) =>
        `<li class="row" data-sku="${escapeHtml(item.sku)}">` +
        `<a href="/inventory/${escapeHtml(item.slug)}">${escapeHtml(item.title)}</a>` +
        `<span class="stock">${escapeHtml(item.stockLabel)}</span></li>`
    )
    .join("");

  const body = `<section id="inventory-results" data-page="${page}">
  <p class="summary">${results.length} match(es) for &ldquo;${escapeHtml(term)}&rdquo;</p>
  <ul class="rows">${rows}</ul>
</section>`;

  return new Response(body, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }
  });
};
