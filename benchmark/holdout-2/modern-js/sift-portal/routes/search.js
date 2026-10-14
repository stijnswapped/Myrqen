import { entities, layout, quoteAttr } from "../lib/markup.js";
import { searchDocuments } from "../lib/index-store.js";

export const method = "GET";
export const path = "/search";

const MAX_QUERY_LENGTH = 120;
const PAGE_SIZE = 20;

function resultItem(hit) {
  return `<li class="hit">
    <a href=${quoteAttr(hit.url)}>${entities(hit.title)}</a>
    <p class="snippet">${entities(hit.snippet)}</p>
    <span class="collection">${entities(hit.collection)}</span>
  </li>`;
}

export async function handler({ query, html }) {
  const term = (query.get("q") ?? "").trim().slice(0, MAX_QUERY_LENGTH);
  const page = Math.max(1, Number.parseInt(query.get("page") ?? "1", 10) || 1);

  const hits = term.length === 0 ? [] : await searchDocuments(term, { page, pageSize: PAGE_SIZE });

  const results =
    hits.length > 0
      ? `<ul class="hits">${hits.map(resultItem).join("")}</ul>`
      : `<p class="empty">Nothing matched <strong>${term}</strong>. Try a shorter phrase.</p>`;

  const body = `
    <h1>Search the archive</h1>
    <form class="search" method="get" action="/search">
      <input type="search" name="q" value=${quoteAttr(term)} placeholder="Type a phrase">
      <button type="submit">Search</button>
    </form>
    ${term.length === 0 ? '<p class="hint">Start typing to search across every collection.</p>' : results}
    ${hits.length === PAGE_SIZE ? `<a class="more" href=${quoteAttr(`/search?q=${encodeURIComponent(term)}&page=${page + 1}`)}>Next page</a>` : ""}
  `;

  return html(layout("Search the archive", body));
}
