import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * `dom_html_injection`, and the two guard changes that had to land with it.
 *
 * Three things are being pinned here, and the order matters because the second
 * makes the first safe to ship.
 *
 * 1. **The sink family exists at all.** `innerHTML`, `outerHTML`,
 *    `insertAdjacentHTML` and `document.write` appeared nowhere in this engine
 *    until 2026-08-24 — thirty-six rules and none of them could see the commonest
 *    way a browser-side defect is written. No corpus revealed it, which is why
 *    these fixtures are hand-written rather than corpus-derived.
 *
 * 2. **An escaper is recognised by its body, not its name.** Without this, the
 *    rule above reports every correctly escaped assignment in any project that
 *    did not happen to call its escaper `escapeHtml`. Isolated to a single
 *    variable: the same function called `harden` was not a guard, and the handler
 *    using it was reported.
 *
 * 3. **An anchored regular expression is a guard, and only the value it tests.**
 *    Added at the same time, and the pair below is the whole reason it is a pair:
 *    the first version took the *root* identifier, so testing `url.pathname`
 *    disarmed `url` and lost a path traversal through `url.searchParams` two
 *    handlers away.
 *
 * Every source below is written inline and named after nothing in any corpus.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-dom-html-"));
  await fs.writeFile(
    path.join(root, "package.json"),
    `${JSON.stringify({ name: "surface", private: true, type: "module" }, null, 2)}\n`,
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

/** An extension message listener, which is a caller-controlled entry point. */
function listener(body) {
  return `chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {\n${body}\n  sendResponse({ ok: true });\n});\n`;
}

const MANIFEST = `${JSON.stringify({ manifest_version: 3, name: "surface", version: "1.0" }, null, 2)}\n`;

async function domFindings(body) {
  const result = await scanSource({ "manifest.json": MANIFEST, "src/panel.js": listener(body) });
  return result.candidates.filter((candidate) => candidate.ruleId === "dom-html-injection");
}

/* ------------------------------------------------------------------ the sink */

test("an assignment to innerHTML that carries caller text is reported", async () => {
  const found = await domFindings(
    `  const panel = document.querySelector("#panel");\n  panel.innerHTML = "<b>" + message.note + "</b>";`
  );
  assert.equal(found.length, 1);
  assert.equal(found[0].category, "dom_html_injection");
  assert.equal(found[0].severity, "high");
});

test("appending to innerHTML is the same sink", async () => {
  const found = await domFindings(`  const panel = document.querySelector("#panel");\n  panel.innerHTML += message.note;`);
  assert.equal(found.length, 1);
});

test("outerHTML through a template literal is reported", async () => {
  const found = await domFindings(
    "  const panel = document.querySelector(\"#panel\");\n  panel.outerHTML = `<div>${message.note}</div>`;"
  );
  assert.equal(found.length, 1);
});

test("insertAdjacentHTML is reported on its markup argument", async () => {
  const found = await domFindings(
    `  const panel = document.querySelector("#panel");\n  panel.insertAdjacentHTML("beforeend", message.note);`
  );
  assert.equal(found.length, 1);
});

test("document.write is reported", async () => {
  const found = await domFindings(`  document.write("<p>" + message.note + "</p>");`);
  assert.equal(found.length, 1);
});

/* -------------------------------------------------- the shapes that are safe */

test("textContent is the fix, so it is never reported", async () => {
  const found = await domFindings(`  const panel = document.querySelector("#panel");\n  panel.textContent = message.note;`);
  assert.equal(found.length, 0);
});

test("constant markup carries nothing of the caller's", async () => {
  const found = await domFindings(`  const panel = document.querySelector("#panel");\n  panel.innerHTML = "<b>static</b>";`);
  assert.equal(found.length, 0);
});

test("a project's own write() is not document.write", async () => {
  const found = await domFindings(`  const logger = { write: (value) => value };\n  logger.write(message.note);`);
  assert.equal(found.length, 0);
});

/* ------------------------------- the escaper, recognised by body not by name */

test("an escaper named escapeHtml silences the slot", async () => {
  const found = await domFindings(
    `  const escapeHtml = (value) => value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");\n` +
      `  const panel = document.querySelector("#panel");\n  panel.innerHTML = "<b>" + escapeHtml(message.note) + "</b>";`
  );
  assert.equal(found.length, 0);
});

test("the same escaper under a name no list contains still silences the slot", async () => {
  for (const name of ["harden", "toSafeHtml", "fmt"]) {
    const found = await domFindings(
      `  const ${name} = (value) => value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");\n` +
        `  const panel = document.querySelector("#panel");\n  panel.innerHTML = "<b>" + ${name}(message.note) + "</b>";`
    );
    assert.equal(found.length, 0, `${name}() escapes and must be recognised as a guard`);
  }
});

test("a block-bodied escaper is recognised through its return", async () => {
  const found = await domFindings(
    `  function harden(value) {\n    return value.replace(/&/g, "&amp;").replace(/</g, "&lt;");\n  }\n` +
      `  const panel = document.querySelector("#panel");\n  panel.innerHTML = harden(message.note);`
  );
  assert.equal(found.length, 0);
});

test("a partial escaper is not a guard", async () => {
  // Only `&` is neutralised, so `<script>` still reaches the parser intact.
  const found = await domFindings(
    `  const half = (value) => value.replace(/&/g, "&amp;");\n` +
      `  const panel = document.querySelector("#panel");\n  panel.innerHTML = half(message.note);`
  );
  assert.equal(found.length, 1);
});

test("a helper that escapes but returns the raw value is not a guard", async () => {
  const found = await domFindings(
    `  function harden(value) {\n    const shown = value.replace(/&/g, "&amp;").replace(/</g, "&lt;");\n` +
      `    console.log(shown);\n    return value;\n  }\n` +
      `  const panel = document.querySelector("#panel");\n  panel.innerHTML = harden(message.note);`
  );
  assert.equal(found.length, 1);
});

/* ------------------------------------------- the anchored regular expression */

const TRAVERSAL = (guard) => `
import express from "express";
import { readFileSync } from "node:fs";
import { join } from "node:path";
const ROOT = "/srv/pub";
const router = express.Router();
router.get("/files", (request, response) => {
${guard}
  const name = request.query.name;
  return response.send(readFileSync(join(ROOT, name), "utf8"));
});
export default router;
`;

async function traversals(guard) {
  const result = await scanSource({ "src/router.js": TRAVERSAL(guard) });
  return result.candidates.filter((candidate) => candidate.category === "path_traversal");
}

test("an anchored pattern tested on the value is a guard", async () => {
  const found = await traversals(`  if (!/^[a-z0-9-]+$/.test(request.query.name)) return response.status(400).end();
  const checked = request.query.name;
  void checked;`);
  // The tested path is cleared, so the read below is on a constrained value.
  const guarded = await scanSource({
    "src/router.js": `
import express from "express";
import { readFileSync } from "node:fs";
import { join } from "node:path";
const ROOT = "/srv/pub";
const router = express.Router();
router.get("/files", (request, response) => {
  const name = request.query.name;
  if (!/^[a-z0-9-]+$/.test(name)) return response.status(400).end();
  return response.send(readFileSync(join(ROOT, name), "utf8"));
});
export default router;
`
  });
  assert.equal(guarded.candidates.filter((c) => c.category === "path_traversal").length, 0);
  void found;
});

test("an unanchored pattern constrains nothing and is not a guard", async () => {
  const result = await scanSource({
    "src/router.js": `
import express from "express";
import { readFileSync } from "node:fs";
import { join } from "node:path";
const ROOT = "/srv/pub";
const router = express.Router();
router.get("/files", (request, response) => {
  const name = request.query.name;
  if (!/[a-z]/.test(name)) return response.status(400).end();
  return response.send(readFileSync(join(ROOT, name), "utf8"));
});
export default router;
`
  });
  assert.equal(result.candidates.filter((c) => c.category === "path_traversal").length, 1);
});

test("testing one property does not disarm another", async () => {
  // The regression this pins: taking the root identifier cleared `request`
  // wholesale, and the traversal through `request.query.name` disappeared.
  const found = await traversals(`  if (!/^\\/api\\/v1$/.test(request.baseUrl)) return response.status(404).end();`);
  assert.equal(found.length, 1);
});

/* ------------------------- sanitise here, render there ------------------------- */

const QWIK = { dependencies: { "@builder.io/qwik": "^1.12.0", "@builder.io/qwik-city": "^1.12.0", "sanitize-html": "^2.13.0" } };

async function qwikFindings(source) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-loader-"));
  await fs.mkdir(path.join(root, "src/routes/notes"), { recursive: true });
  await fs.writeFile(path.join(root, "src/routes/notes/index.tsx"), source, "utf8");
  await fs.writeFile(
    path.join(root, "package.json"),
    `${JSON.stringify({ name: "surface", private: true, type: "module", ...QWIK }, null, 2)}\n`,
    "utf8"
  );
  try {
    const result = await scan({ repoRoot: root });
    return result.candidates.filter((candidate) => candidate.ruleId === "dangerous-inner-html");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const LOADER = (value) => `
import { component$ } from '@builder.io/qwik';
import { routeLoader$ } from '@builder.io/qwik-city';
import sanitizeHtml from 'sanitize-html';
const OPTIONS = { allowedTags: ['b','i','em','strong'], allowedAttributes: {}, allowedSchemes: [] };
export const useNotes = routeLoader$(async (event) => {
  const rows = await event.platform.db.query('select id, body_html from notes where owner = $1', [event.cookie.get('u')?.value]);
  return rows.map((row) => ({ id: row.id, bodyHtml: ${value} }));
});
export default component$(() => {
  const notes = useNotes();
  return <ul>{notes.value.map((note) => <li key={note.id} dangerouslySetInnerHTML={note.bodyHtml} />)}</ul>;
});
`;

test("a property sanitised in the loader is not reported at the sink", async () => {
  // The shape most real applications are written in: sanitise where the value is
  // loaded, render it somewhere else. The rule reported it, which is the most
  // expensive kind of false positive — a page whose markup had been through
  // `sanitize-html` with `allowedAttributes: {}` and `allowedSchemes: []`.
  assert.equal((await qwikFindings(LOADER("sanitizeHtml(row.body_html, OPTIONS)"))).length, 0);
});

test("the same shape with nothing sanitising it still fires", async () => {
  // What keeps the check above honest. `propertySanitisedInFile` requires *every*
  // assignment of the property to be a sanitiser call, so one raw assignment reports.
  assert.equal((await qwikFindings(LOADER("row.body_html"))).length, 1);
});

test("one raw assignment among sanitised ones still fires", async () => {
  const source = `
import { component$ } from '@builder.io/qwik';
import { routeLoader$ } from '@builder.io/qwik-city';
import sanitizeHtml from 'sanitize-html';
const OPTIONS = { allowedTags: ['b'], allowedAttributes: {}, allowedSchemes: [] };
export const useNotes = routeLoader$(async (event) => {
  const rows = await event.platform.db.query('select id, body_html, draft_html from notes where owner = $1', [event.cookie.get('u')?.value]);
  const safe = rows.map((row) => ({ id: row.id, bodyHtml: sanitizeHtml(row.body_html, OPTIONS) }));
  const drafts = rows.map((row) => ({ id: row.id, bodyHtml: row.draft_html }));
  return [...safe, ...drafts];
});
export default component$(() => {
  const notes = useNotes();
  return <ul>{notes.value.map((note) => <li key={note.id} dangerouslySetInnerHTML={note.bodyHtml} />)}</ul>;
});
`;
  assert.equal((await qwikFindings(source)).length, 1);
});
