import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * reflected_cross_site_scripting where the page is assembled in layers.
 *
 * A server-rendered page is almost never a template literal sitting in the
 * argument list of the call that writes it. The handler builds a fragment in one
 * local, embeds that fragment in a page in the next, and hands the page to the
 * project's layout function; the call that reaches the caller then mentions no
 * markup at all. Every pair below is that shape written twice — once with one
 * slot missing its encoder, and once with every slot encoded — because the
 * second file is the one the rule has to stay silent on, and the encoder in both
 * is the project's own, declared in a module the engine never reads.
 *
 * Sources are written inline and named after nothing in any corpus.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-xss-layers-"));
  await fs.writeFile(
    path.join(root, "package.json"),
    `${JSON.stringify({ name: "layered", private: true, type: "module" }, null, 2)}\n`,
    "utf8"
  );
  for (const [relativePath, contents] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, contents, "utf8");
  }
  try {
    return await scan({ repoRoot: root });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const reflected = (result) =>
  result.candidates.filter((candidate) => candidate.category === "reflected_cross_site_scripting");

/** The project's own encoder, in a module the rules never open. */
const MARKUP_MODULE = `
  const REPLACEMENTS = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  export function textNode(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => REPLACEMENTS[character]);
  }
  export function frame(title, body) {
    return \`<!doctype html><html><head><title>\${textNode(title)}</title></head><body>\${body}</body></html>\`;
  }
`;

/* ------------------------------------------------------------------ *
 * A layout helper between the page and the response
 * ------------------------------------------------------------------ */

test("a page handed to a layout helper with one unencoded slot is reported", async () => {
  const result = await scanSource({
    "lib/markup.js": MARKUP_MODULE,
    "web/reports.js": `
      import { frame, textNode } from "../lib/markup.js";
      import { findReports } from "./storage.js";

      export function mount(app) {
        app.get("/reports", async (req, res) => {
          const filter = (req.query.filter ?? "").trim().slice(0, 80);
          const rows = await findReports(filter);
          const listing = rows.length > 0
            ? \`<ul class="rows">\${rows.map((row) => \`<li>\${textNode(row.name)}</li>\`).join("")}</ul>\`
            : \`<p class="empty">No report matches <strong>\${filter}</strong>. Try another word.</p>\`;
          const page = \`<h1>Reports</h1>\${listing}\`;
          res.send(frame("Reports", page));
        });
      }
    `
  });
  const found = reflected(result);
  assert.equal(found.length, 1, "the empty-result message is the one slot with no encoder");
  assert.equal(found[0].route, "GET /reports");
  assert.match(found[0].location.file, /reports\.js$/);
  // The line worth reporting is the slot the author has to change, not the line
  // the response is written on.
  assert.match(found[0].evidence[0].snippet ?? "", /No report matches/);
});

test("the same page with every slot encoded is not reported", async () => {
  const result = await scanSource({
    "lib/markup.js": MARKUP_MODULE,
    "web/reports.js": `
      import { frame, textNode } from "../lib/markup.js";
      import { findReports } from "./storage.js";

      export function mount(app) {
        app.get("/reports", async (req, res) => {
          const filter = (req.query.filter ?? "").trim().slice(0, 80);
          const rows = await findReports(filter);
          const listing = rows.length > 0
            ? \`<ul class="rows">\${rows.map((row) => \`<li>\${textNode(row.name)}</li>\`).join("")}</ul>\`
            : \`<p class="empty">No report matches <strong>\${textNode(filter)}</strong>. Try another word.</p>\`;
          const page = \`<h1>Reports</h1>\${listing}\`;
          res.send(frame("Reports", page));
        });
      }
    `
  });
  assert.deepEqual(reflected(result), [], "the project's own encoder is an encoder");
});

/* ------------------------------------------------------------------ *
 * A hand-rolled router: the handler receives the response helper
 * ------------------------------------------------------------------ */

test("a hand-rolled route module that interpolates the query into its page is reported", async () => {
  const result = await scanSource({
    "lib/markup.js": MARKUP_MODULE,
    "web/tickets.js": `
      import { frame, textNode } from "../lib/markup.js";
      import { findTickets } from "./storage.js";

      export const routes = [{ method: "GET", path: "/tickets", handler: renderTickets }];

      async function renderTickets({ query, html }) {
        const owner = (query.get("owner") ?? "").trim();
        const tickets = await findTickets(owner);
        const listing = tickets.length > 0
          ? \`<ul>\${tickets.map((ticket) => \`<li>\${textNode(ticket.title)}</li>\`).join("")}</ul>\`
          : \`<p>Nothing is assigned to <em>\${owner}</em> right now.</p>\`;
        const page = \`<h1>Tickets</h1>\${listing}\`;
        return html(frame("Tickets", page));
      }
    `
  });
  const found = reflected(result);
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "GET /tickets");
  assert.match(found[0].evidence[0].snippet ?? "", /Nothing is assigned/);
});

test("the same route module encoding the query is not reported", async () => {
  const result = await scanSource({
    "lib/markup.js": MARKUP_MODULE,
    "web/tickets.js": `
      import { frame, textNode } from "../lib/markup.js";
      import { findTickets } from "./storage.js";

      export const routes = [{ method: "GET", path: "/tickets", handler: renderTickets }];

      async function renderTickets({ query, html }) {
        const owner = (query.get("owner") ?? "").trim();
        const tickets = await findTickets(owner);
        const listing = tickets.length > 0
          ? \`<ul>\${tickets.map((ticket) => \`<li>\${textNode(ticket.title)}</li>\`).join("")}</ul>\`
          : \`<p>Nothing is assigned to <em>\${textNode(owner)}</em> right now.</p>\`;
        const page = \`<h1>Tickets</h1>\${listing}\`;
        return html(frame("Tickets", page));
      }
    `
  });
  assert.deepEqual(reflected(result), []);
});

/* ------------------------------------------------------------------ *
 * The document in a local, handed straight to the sink
 * ------------------------------------------------------------------ */

test("a document built in a local and sent without a wrapping helper is reported", async () => {
  const result = await scanSource({
    "web/greeting.js": `
      export function mount(app) {
        app.get("/greeting", (req, res) => {
          const name = String(req.query.name ?? "");
          const page = \`<html><body><h1>Hello \${name}</h1></body></html>\`;
          res.send(page);
        });
      }
    `
  });
  const found = reflected(result);
  assert.equal(found.length, 1, "a local holding the page is still the page");
  assert.equal(found[0].route, "GET /greeting");
});

/* ------------------------------------------------------------------ *
 * Shapes that must stay silent
 * ------------------------------------------------------------------ */

test("a percent-encoded value in a link built behind a layout helper is not reported", async () => {
  const result = await scanSource({
    "lib/markup.js": MARKUP_MODULE,
    "web/pager.js": `
      import { frame } from "../lib/markup.js";

      export function mount(app) {
        app.get("/archive", (req, res) => {
          const term = String(req.query.q ?? "");
          const page = \`<h1>Archive</h1><a class="more" href="/archive?q=\${encodeURIComponent(term)}&page=2">Next page</a>\`;
          res.send(frame("Archive", page));
        });
      }
    `
  });
  assert.deepEqual(reflected(result), [], "percent-encoding leaves nothing that can open a tag");
});

test("a numerically coerced value interpolated behind a layout helper is not reported", async () => {
  const result = await scanSource({
    "lib/markup.js": MARKUP_MODULE,
    "web/paging.js": `
      import { frame } from "../lib/markup.js";

      export function mount(app) {
        app.get("/entries", (req, res) => {
          const page = Number.parseInt(req.query.page ?? "1", 10) || 1;
          const document = \`<h1>Entries</h1><p class="page">Page \${page}</p>\`;
          res.send(frame("Entries", document));
        });
      }
    `
  });
  assert.deepEqual(reflected(result), [], "a number cannot carry markup");
});

test("a page whose only interpolations are server data is not reported", async () => {
  const result = await scanSource({
    "lib/markup.js": MARKUP_MODULE,
    "web/status.js": `
      import { frame } from "../lib/markup.js";
      import { readStatus } from "./storage.js";

      export function mount(app) {
        app.get("/status", async (req, res) => {
          const status = await readStatus();
          const page = \`<h1>Status</h1><p class="state">\${status.state}</p><p class="count">\${status.queued}</p>\`;
          res.send(frame("Status", page));
        });
      }
    `
  });
  assert.deepEqual(reflected(result), []);
});

test("a page that hand-rolls its escaping in the handler is not reported", async () => {
  const result = await scanSource({
    "lib/markup.js": MARKUP_MODULE,
    "web/notes.js": `
      import { frame } from "../lib/markup.js";

      export function mount(app) {
        app.get("/notes", (req, res) => {
          const raw = String(req.query.note ?? "");
          const safe = raw.replace(/[&<>"']/g, (character) => \`&#\${character.charCodeAt(0)};\`);
          const page = \`<h1>Notes</h1><p class="note">\${safe}</p>\`;
          res.send(frame("Notes", page));
        });
      }
    `
  });
  assert.deepEqual(reflected(result), [], "an escaping replace in front of the slot is an escaper");
});

test("a page built from a request value and written to a file is not reported as XSS", async () => {
  const result = await scanSource({
    "lib/markup.js": MARKUP_MODULE,
    "web/export.js": `
      import { createWriteStream } from "node:fs";
      import { frame } from "../lib/markup.js";

      export function mount(app) {
        app.post("/exports", (req, res) => {
          const label = String(req.body.label ?? "");
          const page = \`<h1>Export</h1><p class="label">\${label}</p>\`;
          const stream = createWriteStream("/var/exports/latest.html");
          stream.write(frame("Export", page));
          res.status(202).end();
        });
      }
    `
  });
  assert.deepEqual(reflected(result), [], "a file is not a browser and the finding would name the wrong defect");
});

test("the reported line is the interpolation, not the line the value was read on", async () => {
  const result = await scanSource({
    "lib/markup.js": MARKUP_MODULE,
    "web/lookup.js": `import { frame } from "../lib/markup.js";
import { findMatches } from "./storage.js";

export function mount(app) {
  app.get("/lookup", async (req, res) => {
    const term = (req.query.term ?? "").trim();
    const matches = await findMatches(term);
    const panel = \`<p class="result">Nothing matches <b>\${term}</b>.</p>\`;
    const page = \`<h1>Lookup</h1>\${matches.length > 0 ? "<p>Matches found.</p>" : panel}\`;
    res.send(frame("Lookup", page));
  });
}
`
  });
  const found = reflected(result);
  assert.equal(found.length, 1);
  // The slot on the `panel` line is what the author has to change. Naming the
  // declaration three lines above it sends a reader to a statement that is
  // correct as written.
  assert.equal(found[0].location.line, 8);
  assert.equal(found[0].route, "GET /lookup");
});
