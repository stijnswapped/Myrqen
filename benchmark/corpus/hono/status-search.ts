import { Hono } from "hono";

import { db } from "../lib/db";

const statusPages = new Hono();

const PAGE_STYLES = `
  body { font: 15px/1.5 -apple-system, "Segoe UI", sans-serif; margin: 2rem auto; max-width: 44rem; }
  .incident { border-bottom: 1px solid #e5e7eb; padding: 0.75rem 0; }
  .muted { color: #6b7280; }
`;

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function layout(content: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Platform status</title>
    <style>${PAGE_STYLES}</style>
  </head>
  <body>
    <h1>Platform status</h1>
    <form method="get" action="/status/incidents">
      <input type="search" name="q" placeholder="Search incidents" />
    </form>
    <main>${content}</main>
  </body>
</html>`;
}

// GET /status/incidents
// The public status page. Support agents paste a filtered link into tickets,
// so the search term is echoed above the result list to confirm the filter.
statusPages.get("/status/incidents", async (c) => {
  const term = c.req.query("q")?.trim() ?? "";

  const incidents = await db.incident.findMany({
    where: {
      visibility: "public",
      ...(term ? { title: { contains: term, mode: "insensitive" as const } } : {}),
    },
    orderBy: { startedAt: "desc" },
    take: 20,
    select: { id: true, title: true, status: true, startedAt: true },
  });

  const rows = incidents
    .map(
      (incident) =>
        `<li class="incident"><strong>${escapeHtml(incident.title)}</strong>` +
        `<span class="muted"> — ${escapeHtml(incident.status)}</span></li>`
    )
    .join("");

  const heading = term
    ? `<p class="muted">Showing incidents matching “${term}”.</p>`
    : `<p class="muted">Showing the 20 most recent incidents.</p>`;

  const list = rows || `<li class="incident muted">Nothing to report.</li>`;

  return c.html(layout(`${heading}<ul>${list}</ul>`));
});

export default statusPages;
