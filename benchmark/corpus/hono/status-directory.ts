import { Hono } from "hono";

import { db } from "../lib/db";

const componentPages = new Hono();

const PAGE_STYLES = `
  body { font: 15px/1.5 -apple-system, "Segoe UI", sans-serif; margin: 2rem auto; max-width: 44rem; }
  .component { border-bottom: 1px solid #e5e7eb; padding: 0.75rem 0; }
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
    <title>Component directory</title>
    <style>${PAGE_STYLES}</style>
  </head>
  <body>
    <h1>Component directory</h1>
    <form method="get" action="/status/components">
      <input type="search" name="q" placeholder="Search components" />
    </form>
    <main>${content}</main>
  </body>
</html>`;
}

// GET /status/components
// Public component directory. The search term is echoed above the results so a
// linked filter is obvious to whoever opened the link.
componentPages.get("/status/components", async (c) => {
  const term = c.req.query("q")?.trim() ?? "";

  const components = await db.component.findMany({
    where: {
      visibility: "public",
      ...(term ? { name: { contains: term, mode: "insensitive" as const } } : {}),
    },
    orderBy: { name: "asc" },
    take: 20,
    select: { id: true, name: true, health: true, region: true },
  });

  const rows = components
    .map(
      (component) =>
        `<li class="component"><strong>${escapeHtml(component.name)}</strong>` +
        `<span class="muted"> — ${escapeHtml(component.health)}</span></li>`
    )
    .join("");

  const heading = term
    ? `<p class="muted">Showing components matching “${escapeHtml(term)}”.</p>`
    : `<p class="muted">Showing every public component.</p>`;

  const list = rows || `<li class="component muted">No components match that filter.</li>`;

  return c.html(layout(`${heading}<ul>${list}</ul>`));
});

export default componentPages;
