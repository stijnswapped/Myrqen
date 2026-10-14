import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import ts from "typescript";

/**
 * The SvelteKit and Remix adapters are driven directly rather than through
 * `entryPointsOf`, so these tests hold whether or not the adapters have been added
 * to the central registry yet, and so a failure points at this file rather than at
 * another framework's adapter.
 *
 * Every case is written as source text here. An adapter that only recognises the
 * benchmark's own fixtures is worthless in a real repository, and a test that reads
 * those fixtures cannot tell the difference.
 */
const dist = fileURLToPath(new URL("../dist/ast/frameworks/sveltekit.js", import.meta.url));

if (!existsSync(dist)) {
  test.skip("the SvelteKit adapter needs a build: run `pnpm --filter @myrqen/scan build` first", () => {});
} else {
  const { sveltekitAdapter, remixAdapter } = await import(dist);

  const SCRIPT_KIND = {
    ".ts": ts.ScriptKind.TS,
    ".tsx": ts.ScriptKind.TSX,
    ".js": ts.ScriptKind.JS,
    ".jsx": ts.ScriptKind.JSX,
    ".mjs": ts.ScriptKind.JS,
    ".cjs": ts.ScriptKind.JS
  };

  function parse(relativePath, text) {
    const extension = relativePath.slice(relativePath.lastIndexOf("."));
    const scriptKind = SCRIPT_KIND[extension] ?? ts.ScriptKind.TS;
    return {
      relativePath,
      absolutePath: `/repo/${relativePath}`,
      text,
      source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.Latest, true, scriptKind),
      language: scriptKind === ts.ScriptKind.JS || scriptKind === ts.ScriptKind.JSX ? "JavaScript" : "TypeScript"
    };
  }

  function detect(adapter, relativePath, text) {
    const file = parse(relativePath, text);
    if (!adapter.applies(file)) return null;
    return adapter.detect(file);
  }

  const addresses = (entries) => entries.map((entry) => `${entry.method} ${entry.path}`);
  const seedNames = (entry) => (entry.seeds ?? []).map((seed) => seed.name).sort();

  /* ------------------------------------------------------------ the route address */

  test("the route comes from the directory, with src and routes stripped", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/link-preview/+server.ts",
      `export async function POST({ request }) { return new Response(await request.text()); }`
    );
    assert.deepEqual(addresses(entries), ["POST /api/link-preview"]);
  });

  test("SvelteKit's bracket syntax is kept exactly as the directory spells it", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/exports/[name]/+server.ts",
      `export const GET = async ({ params }) => new Response(params.name);`
    );
    assert.deepEqual(addresses(entries), ["GET /api/exports/[name]"]);
  });

  test("a rest parameter directory keeps its own spelling too", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/blog/[...rest]/+server.ts",
      `export async function GET({ params }) { return new Response(params.rest); }`
    );
    assert.deepEqual(addresses(entries), ["GET /blog/[...rest]"]);
  });

  test("a group segment in parentheses does not appear in the URL", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/(app)/dashboard/+page.server.ts",
      `export async function load({ url }) { return { q: url.searchParams.get("q") }; }`
    );
    assert.deepEqual(addresses(entries), ["GET /dashboard"]);
  });

  test("a monorepo prefix above src is not part of the route", () => {
    const entries = detect(
      sveltekitAdapter,
      "apps/web/src/routes/api/health/+server.ts",
      `export const GET = async () => new Response("ok");`
    );
    assert.deepEqual(addresses(entries), ["GET /api/health"]);
  });

  test("a routes directory with no src above it still works", () => {
    const entries = detect(
      sveltekitAdapter,
      "routes/api/link-preview/+server.ts",
      `export const POST = async ({ request }) => new Response(await request.text());`
    );
    assert.deepEqual(addresses(entries), ["POST /api/link-preview"]);
  });

  test("a root +server module answers on /", () => {
    const entries = detect(sveltekitAdapter, "src/routes/+server.ts", `export async function GET() { return new Response("hi"); }`);
    assert.deepEqual(addresses(entries), ["GET /"]);
  });

  /* ------------------------------------------------------------ what is not claimed */

  test("a server module outside a routes directory is not claimed", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/lib/server/+server.ts",
      `export async function GET() { return new Response("hi"); }`
    );
    assert.equal(entries, null, "applies() must reject a file that is not under routes/");
  });

  test("an ordinary library module under routes is not claimed", () => {
    const entries = detect(sveltekitAdapter, "src/routes/api/helpers.ts", `export async function GET() {}`);
    assert.equal(entries, null);
  });

  test("a +page.svelte component is not a server module", () => {
    const entries = detect(sveltekitAdapter, "src/routes/blog/+page.ts", `export async function load({ params }) {}`);
    assert.equal(entries, null, "only +server, +page.server and +layout.server run on the server");
  });

  /* ------------------------------------------------------------ method exports */

  test("every HTTP verb export becomes its own entry point", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/items/[id]/+server.ts",
      `
        import { json, type RequestHandler } from "@sveltejs/kit";
        export const GET: RequestHandler = async ({ params }) => json({ id: params.id });
        export const PUT: RequestHandler = async ({ request }) => json(await request.json());
        export async function DELETE({ params }) { return json({ gone: params.id }); }
        export const HEAD = async () => new Response(null);
        const PAGE_SIZE = 20;
        export const config = { runtime: "nodejs20.x" };
      `
    );
    assert.deepEqual(addresses(entries).sort(), [
      "DELETE /api/items/[id]",
      "GET /api/items/[id]",
      "HEAD /api/items/[id]",
      "PUT /api/items/[id]"
    ]);
  });

  test("a fallback export answers any method it did not name", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/proxy/+server.ts",
      `export const fallback = async ({ request }) => new Response(request.method);`
    );
    assert.deepEqual(addresses(entries), ["ANY /api/proxy"]);
  });

  test("a handler wrapped in a satisfies expression is still found", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/items/+server.ts",
      `
        import type { RequestHandler } from "@sveltejs/kit";
        export const GET = (async ({ url }) => new Response(url.href)) satisfies RequestHandler;
      `
    );
    assert.deepEqual(addresses(entries), ["GET /api/items"]);
    assert.ok(entries[0].node, "the handler body must be attached so taint can run over it");
  });

  test("an aliased re-export of a local handler is found", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/items/+server.ts",
      `
        async function handler({ params }) { return new Response(params.id); }
        export { handler as POST };
      `
    );
    assert.deepEqual(addresses(entries), ["POST /api/items"]);
    assert.deepEqual(seedNames(entries[0]), ["params"]);
  });

  test("a CommonJS route module is recognised", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/legacy/+server.js",
      `exports.POST = async ({ request }) => new Response(await request.text());`
    );
    assert.deepEqual(addresses(entries), ["POST /api/legacy"]);
    assert.deepEqual(seedNames(entries[0]), ["request"]);
  });

  /* ------------------------------------------------------------ seeds */

  test("params, url, request and cookies are seeded and locals is not", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/exports/[name]/+server.ts",
      `export const GET = async ({ params, url, request, cookies, locals }) => new Response(params.name);`
    );
    assert.equal(entries.length, 1);
    assert.deepEqual(seedNames(entries[0]), ["cookies", "params", "request", "url"]);
    assert.deepEqual(entries[0].trustedParameters, ["locals"]);
  });

  test("a seed's origin names the event property it came from", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/exports/[name]/+server.ts",
      `export const GET = async ({ params, url }) => new Response(params.name);`
    );
    const origins = Object.fromEntries((entries[0].seeds ?? []).map((seed) => [seed.name, seed.origin]));
    assert.equal(origins.params, "event.params (caller-controlled route parameters)");
    assert.equal(origins.url, "event.url (caller-controlled request URL)");
  });

  test("framework-supplied event keys are never seeded", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/items/+server.ts",
      `export const GET = async ({ platform, setHeaders, fetch, depends, parent, route, isDataRequest }) => new Response("x");`
    );
    assert.equal(entries.length, 1);
    assert.equal(entries[0].seeds, undefined, "seeding a framework-supplied key invents a flow the caller never had");
    assert.equal(entries[0].trustedParameters, undefined);
  });

  test("a renamed destructuring seeds the bound name, not the event key", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/exports/[name]/+server.ts",
      `export const GET = async ({ params: p, locals: ctx }) => new Response(p.name);`
    );
    assert.deepEqual(seedNames(entries[0]), ["p"]);
    assert.deepEqual(entries[0].trustedParameters, ["ctx"]);
  });

  test("an undestructured event is seeded whole with no trusted parameters", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/items/+server.ts",
      `export const GET = async (event) => new Response(event.url.href);`
    );
    assert.deepEqual(entries[0].seeds, [{ name: "event", origin: "event (inbound request)" }]);
    assert.equal(entries[0].trustedParameters, undefined, "the generic model already knows locals is server-attached");
  });

  test("a rest element and a nested pattern are left unseeded", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/api/items/+server.ts",
      `export const GET = async ({ url: { searchParams }, ...rest }) => new Response(searchParams.get("q"));`
    );
    assert.equal(entries[0].seeds, undefined, "a guessed seed manufactures false positives across every data-flow rule");
  });

  /* ------------------------------------------------------------ +page.server.ts */

  test("load is a GET on the page's own route", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/orders/[id]/+page.server.ts",
      `export const load = async ({ params, locals }) => ({ order: await locals.db.find(params.id) });`
    );
    assert.deepEqual(addresses(entries), ["GET /orders/[id]"]);
    assert.deepEqual(seedNames(entries[0]), ["params"]);
  });

  test("named form actions are POSTs on the page route, not on a made-up path", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/session/+page.server.ts",
      `
        import { fail, redirect, type Actions } from "@sveltejs/kit";
        export const actions: Actions = {
          login: async ({ request, cookies }) => {
            const form = await request.formData();
            cookies.set("sid", String(form.get("token")), { path: "/" });
          },
          logout: async ({ cookies, locals }) => {
            cookies.delete("sid", { path: "/" });
          }
        };
      `
    );
    // The action name travels in the query string (`/session?/login`), so the
    // endpoint a reader recognises — and the one a report should name — is the
    // page route. Both actions therefore share it.
    assert.deepEqual(addresses(entries), ["POST /session", "POST /session"]);
    const login = entries.find((entry) => seedNames(entry).includes("request"));
    assert.deepEqual(seedNames(login), ["cookies", "request"]);
    assert.equal(login.kind, "action");
    const logout = entries.find((entry) => !seedNames(entry).includes("request"));
    assert.deepEqual(logout.trustedParameters, ["locals"]);
  });

  test("the default action is addressed as the route itself", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/contact/+page.server.ts",
      `export const actions = { default: async ({ request }) => { await request.formData(); } };`
    );
    assert.deepEqual(addresses(entries), ["POST /contact"]);
  });

  test("a shorthand action resolves to the handler declared above it", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/contact/+page.server.ts",
      `
        const send = async ({ request }) => { await request.formData(); };
        export const actions = { send };
      `
    );
    assert.deepEqual(addresses(entries), ["POST /contact"]);
    assert.deepEqual(seedNames(entries[0]), ["request"], "an unresolved shorthand would leave the body unscanned");
  });

  test("an explicit POST export beside load is claimed too", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/contact/+page.server.ts",
      `
        export const load = async ({ url }) => ({ q: url.searchParams.get("q") });
        export const POST = async ({ request }) => new Response(await request.text());
      `
    );
    assert.deepEqual(addresses(entries).sort(), ["GET /contact", "POST /contact"]);
  });

  test("a layout module contributes only its load", () => {
    const entries = detect(
      sveltekitAdapter,
      "src/routes/(app)/+layout.server.ts",
      `
        export const load = async ({ locals, url }) => ({ user: locals.user, path: url.pathname });
        export const actions = { nope: async () => {} };
      `
    );
    assert.deepEqual(addresses(entries), ["GET /"]);
    assert.deepEqual(seedNames(entries[0]), ["url"]);
  });

  /* ------------------------------------------------------------ Remix / React Router v7 */

  test("a Remix loader and action are found on the flat route path", () => {
    const entries = detect(
      remixAdapter,
      "app/routes/notes.$noteId.tsx",
      `
        import { json } from "@remix-run/node";
        export async function loader({ params, request, context }) {
          return json({ id: params.noteId, url: request.url });
        }
        export async function action({ request }) {
          return json(await request.formData());
        }
      `
    );
    assert.deepEqual(addresses(entries).sort(), ["GET /notes/:noteId", "POST /notes/:noteId"]);
    const loader = entries.find((entry) => entry.method === "GET");
    assert.deepEqual(seedNames(loader), ["params", "request"]);
    assert.deepEqual(loader.trustedParameters, ["context"], "AppLoadContext is the server's own, not the caller's");
  });

  test("a folder route drops the route file name from the path", () => {
    const entries = detect(
      remixAdapter,
      "app/routes/notes.$noteId/route.tsx",
      `
        import { data } from "react-router";
        export const loader = async ({ params }) => data({ id: params.noteId });
      `
    );
    assert.deepEqual(addresses(entries), ["GET /notes/:noteId"]);
  });

  test("an index route answers on the root", () => {
    const entries = detect(
      remixAdapter,
      "app/routes/_index.tsx",
      `
        import { json } from "@remix-run/node";
        export async function loader({ request }) { return json({ url: request.url }); }
      `
    );
    assert.deepEqual(addresses(entries), ["GET /"]);
  });

  test("a splat route becomes a star", () => {
    const entries = detect(
      remixAdapter,
      "app/routes/files.$.tsx",
      `
        import { json } from "@remix-run/node";
        export async function loader({ params }) { return json(params["*"]); }
      `
    );
    assert.deepEqual(addresses(entries), ["GET /files/*"]);
  });

  test("a route path that cannot be derived confidently falls back to /", () => {
    const entries = detect(
      remixAdapter,
      "app/routes/reports.(locale).csv.tsx",
      `
        import { json } from "@remix-run/node";
        export async function loader({ request }) { return json({ url: request.url }); }
      `
    );
    assert.deepEqual(addresses(entries), ["GET /"], "a wrong address is worse than an unknown one");
  });

  test("a file that never imports Remix is not claimed", () => {
    const entries = detect(
      remixAdapter,
      "app/routes/notes.tsx",
      `export async function loader() { return { notes: [] }; }`
    );
    assert.equal(entries, null);
  });

  test("a Remix import alone is not enough without a loader or action", () => {
    const entries = detect(
      remixAdapter,
      "app/components/note-card.tsx",
      `import { Link } from "react-router"; export function NoteCard() { return null; }`
    );
    assert.equal(entries, null);
  });

  test("a SvelteKit route file is never claimed as Remix as well", () => {
    const file = parse(
      "src/routes/api/items/+server.ts",
      `
        import { json } from "@sveltejs/kit";
        import { redirect } from "react-router";
        export const loader = async ({ request }) => json(request.url);
        export const GET = async ({ url }) => json(url.href);
      `
    );
    assert.equal(remixAdapter.applies(file), false, "double-claiming would double every finding's address");
    assert.deepEqual(remixAdapter.detect(file), []);
  });
}
