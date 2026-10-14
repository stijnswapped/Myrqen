import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

/**
 * The Astro adapter, driven directly rather than through `scan()`.
 *
 * Every case is written as source here. A framework adapter that only fires on a
 * fixture it has already seen is worthless in a real repository, and a test that
 * reads the corpus cannot tell the difference.
 *
 * Two things are asserted for every shape, because an entry point that gets one
 * of them wrong is worse than no entry point at all: the address a reader will
 * see in the report, and the seeds the taint model will trust. Every shape is
 * paired with a near miss that must not be claimed, because the cost of claiming
 * a file this framework does not own is a false positive in all thirty-six
 * data-flow rules at once.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const built = path.join(here, "../dist/ast/frameworks/astro.js");

if (!existsSync(built)) {
  test.skip("the astro adapter needs a build: dist/ast/frameworks/astro.js is absent", () => {});
} else {
  const { astroAdapter } = await import(pathToFileURL(built).href);

  const JAVASCRIPT = /\.[cm]?jsx?$/;

  function parsed(relativePath, text) {
    const scriptKind = JAVASCRIPT.test(relativePath) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
    return {
      relativePath,
      absolutePath: `/repo/${relativePath}`,
      text,
      source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.Latest, true, scriptKind),
      language: scriptKind === ts.ScriptKind.JS ? "JavaScript" : "TypeScript"
    };
  }

  /** What the engine would see: nothing at all unless the adapter claims the file. */
  function entriesOf(relativePath, text) {
    const file = parsed(relativePath, text);
    if (!astroAdapter.applies(file)) return [];
    return astroAdapter.detect(file);
  }

  const addresses = (entries) => entries.map((entry) => `${entry.method} ${entry.path}`);
  const seedNames = (entry) => (entry.seeds ?? []).map((seed) => seed.name);
  const origins = (entry) => (entry.seeds ?? []).map((seed) => seed.origin);

  const ENDPOINT = `
    import type { APIRoute } from "astro";
    export const GET: APIRoute = async ({ params, request, url, cookies }) => {
      return new Response(JSON.stringify({ params, url, cookies, request }));
    };
  `;

  /* ------------------------------------------- endpoint addresses from the tree */

  test("the route is the endpoint's own path under src/pages", () => {
    assert.deepEqual(addresses(entriesOf("src/pages/api/link-preview.ts", ENDPOINT)), ["GET /api/link-preview"]);
  });

  test("a monorepo prefix above src/pages is not part of the URL", () => {
    assert.deepEqual(addresses(entriesOf("apps/web/src/pages/api/orders.ts", ENDPOINT)), ["GET /api/orders"]);
  });

  test("a bracket segment is kept exactly as the directory spells it", () => {
    assert.deepEqual(addresses(entriesOf("src/pages/api/orders/[id].ts", ENDPOINT)), ["GET /api/orders/[id]"]);
  });

  test("a rest parameter is kept exactly as the directory spells it", () => {
    assert.deepEqual(addresses(entriesOf("src/pages/files/[...path].ts", ENDPOINT)), ["GET /files/[...path]"]);
  });

  test("index addresses the directory it sits in rather than a segment of its own", () => {
    assert.deepEqual(addresses(entriesOf("src/pages/api/orders/index.ts", ENDPOINT)), ["GET /api/orders"]);
  });

  test("the top-level index is the site root", () => {
    assert.deepEqual(addresses(entriesOf("src/pages/index.ts", ENDPOINT)), ["GET /"]);
  });

  test("an output extension in the file name stays in the URL", () => {
    assert.deepEqual(addresses(entriesOf("src/pages/feed.json.ts", ENDPOINT)), ["GET /feed.json"]);
  });

  test("a JavaScript endpoint is routed the same way a TypeScript one is", () => {
    const source = `export async function POST({ request }) { return new Response(await request.text()); }`;
    assert.deepEqual(addresses(entriesOf("src/pages/api/hook.mjs", source)), ["POST /api/hook"]);
  });

  /* --------------------------------------------------------- endpoint verbs */

  test("every verb export becomes its own entry point", () => {
    const source = `
      import type { APIRoute } from "astro";
      export const GET: APIRoute = async (context) => new Response("");
      export const PUT: APIRoute = async (context) => new Response("");
      export const PATCH: APIRoute = async (context) => new Response("");
      export const DELETE: APIRoute = async (context) => new Response("");
      export const HEAD: APIRoute = async (context) => new Response("");
      export const OPTIONS: APIRoute = async (context) => new Response("");
    `;
    assert.deepEqual(addresses(entriesOf("src/pages/api/thing.ts", source)), [
      "GET /api/thing",
      "PUT /api/thing",
      "PATCH /api/thing",
      "DELETE /api/thing",
      "HEAD /api/thing",
      "OPTIONS /api/thing"
    ]);
  });

  test("ALL answers every verb the module did not export, so it is reported as ANY", () => {
    const source = `
      import type { APIRoute } from "astro";
      export const ALL: APIRoute = async ({ request }) => new Response(await request.text());
    `;
    const found = entriesOf("src/pages/api/proxy.ts", source);
    assert.deepEqual(addresses(found), ["ANY /api/proxy"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("a declared function export is the same endpoint as a const initialiser", () => {
    const source = `export async function POST({ request }) { return new Response(await request.text()); }`;
    const found = entriesOf("src/pages/api/hook.ts", source);
    assert.deepEqual(addresses(found), ["POST /api/hook"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("a renamed re-export is claimed under the verb it is exported as", () => {
    const source = `
      import type { APIRoute } from "astro";
      const handler: APIRoute = async ({ request }) => new Response(await request.text());
      export { handler as POST };
    `;
    const found = entriesOf("src/pages/api/hook.ts", source);
    assert.deepEqual(addresses(found), ["POST /api/hook"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("a CommonJS assignment is the same endpoint written the other way", () => {
    const source = `exports.POST = async function ({ request }) { return new Response(await request.text()); };`;
    const found = entriesOf("src/pages/api/hook.js", source);
    assert.deepEqual(addresses(found), ["POST /api/hook"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("module.exports names the verbs individually", () => {
    const source = `module.exports = { GET: async ({ params }) => new Response(params.id) };`;
    const found = entriesOf("src/pages/api/orders/[id].js", source);
    assert.deepEqual(addresses(found), ["GET /api/orders/[id]"]);
    assert.deepEqual(seedNames(found[0]), ["params"]);
  });

  /* --------------------------------------------------------- endpoint seeds */

  test("the caller-controlled context keys are seeded and named for evidence", () => {
    const found = entriesOf("src/pages/api/link-preview.ts", ENDPOINT);
    assert.deepEqual(seedNames(found[0]), ["params", "request", "url", "cookies"]);
    assert.deepEqual(origins(found[0]), [
      "context.params (caller-controlled route parameters)",
      "context.request (inbound request)",
      "context.url (caller-controlled request URL)",
      "context.cookies (caller-controlled cookies)"
    ]);
  });

  test("locals and redirect are declared trusted rather than left to be guessed at", () => {
    const source = `
      import type { APIRoute } from "astro";
      export const POST: APIRoute = async ({ request, locals, redirect }) => {
        const session = locals.session;
        return redirect(String(session.id));
      };
    `;
    const found = entriesOf("src/pages/api/session.ts", source);
    assert.deepEqual(seedNames(found[0]), ["request"]);
    assert.deepEqual(found[0].trustedParameters, ["locals", "redirect"]);
  });

  test("the server-supplied context keys are never seeded", () => {
    const source = `
      import type { APIRoute } from "astro";
      export const GET: APIRoute = async ({ locals, site, generator, clientAddress, props }) => {
        return new Response(String(site) + generator + clientAddress + props.x + locals.userId);
      };
    `;
    assert.deepEqual(seedNames(entriesOf("src/pages/api/meta.ts", source)[0]), []);
  });

  test("renamed destructuring binds the new name", () => {
    const source = `
      import type { APIRoute } from "astro";
      export const GET: APIRoute = async ({ params: routeParams, locals: ctx }) => new Response(routeParams.id);
    `;
    const found = entriesOf("src/pages/api/orders/[id].ts", source);
    assert.deepEqual(seedNames(found[0]), ["routeParams"]);
    assert.deepEqual(found[0].trustedParameters, ["ctx"]);
  });

  test("a plain identifier parameter is the whole APIContext and is seeded whole", () => {
    const source = `
      import type { APIRoute } from "astro";
      export const GET: APIRoute = async (context) => new Response(context.url.search);
    `;
    const found = entriesOf("src/pages/api/search.ts", source);
    assert.deepEqual(seedNames(found[0]), ["context"]);
    assert.deepEqual(origins(found[0]), ["context (inbound request)"]);
  });

  test("a rest element is not seeded, because which keys it holds cannot be known here", () => {
    const source = `
      import type { APIRoute } from "astro";
      export const GET: APIRoute = async ({ request, ...rest }) => new Response(await request.text());
    `;
    assert.deepEqual(seedNames(entriesOf("src/pages/api/thing.ts", source)[0]), ["request"]);
  });

  test("a type wrapper around the handler does not hide its body", () => {
    const source = `
      import type { APIRoute } from "astro";
      export const GET = (async ({ params }) => new Response(params.id)) satisfies APIRoute;
    `;
    const found = entriesOf("src/pages/api/orders/[id].ts", source);
    assert.deepEqual(addresses(found), ["GET /api/orders/[id]"]);
    assert.deepEqual(seedNames(found[0]), ["params"]);
  });

  test("a single-function wrapper is followed to the handler it wraps", () => {
    const source = `
      import type { APIRoute } from "astro";
      import { withAuth } from "../../lib/auth";
      export const POST: APIRoute = withAuth(async ({ request }) => new Response(await request.text()));
    `;
    const found = entriesOf("src/pages/api/hook.ts", source);
    assert.deepEqual(addresses(found), ["POST /api/hook"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("an ambiguous wrapper keeps the address and refuses to guess at the seeds", () => {
    const source = `
      import type { APIRoute } from "astro";
      import { guard } from "../../lib/guard";
      export const POST: APIRoute = guard(async (context) => new Response(""), (error) => new Response(""));
    `;
    const found = entriesOf("src/pages/api/hook.ts", source);
    assert.deepEqual(addresses(found), ["POST /api/hook"]);
    assert.equal(found[0].seeds, undefined);
    assert.equal(found[0].node, undefined);
  });

  test("a handler imported from elsewhere still contributes its address", () => {
    const source = `
      import { readOrders } from "../../lib/orders";
      export const GET = readOrders;
    `;
    const found = entriesOf("src/pages/api/orders.ts", source);
    assert.deepEqual(addresses(found), ["GET /api/orders"]);
    assert.equal(found[0].seeds, undefined);
  });

  test("a scan rooted below src is placed once the file's imports settle the framework", () => {
    const source = `
      import type { APIRoute } from "astro";
      export const GET: APIRoute = async ({ request }) => new Response(await request.text());
    `;
    assert.deepEqual(addresses(entriesOf("pages/api/ping.ts", source)), ["GET /api/ping"]);
  });

  /* --------------------------------------------------- endpoints NOT claimed */

  test("a verb-named export holding something that is not a handler is not an endpoint", () => {
    const source = `export const ALL = 3;\nexport const prerender = false;`;
    assert.deepEqual(entriesOf("src/pages/api/config.ts", source), []);
  });

  test("an underscore segment is excluded from routing by Astro, so it is not claimed", () => {
    assert.deepEqual(entriesOf("src/pages/_helpers/query.ts", ENDPOINT), []);
    assert.deepEqual(entriesOf("src/pages/api/_internal.ts", ENDPOINT), []);
  });

  test("a .astro file is a page rather than an endpoint", () => {
    assert.deepEqual(entriesOf("src/pages/dashboard.astro", ENDPOINT), []);
  });

  test("a component under src/pages belongs to some other framework's router", () => {
    assert.deepEqual(entriesOf("src/pages/team.tsx", ENDPOINT), []);
  });

  test("a verb export outside src/pages answers no request and is not claimed", () => {
    assert.deepEqual(entriesOf("src/lib/orders.ts", ENDPOINT), []);
    assert.deepEqual(entriesOf("src/components/table.ts", ENDPOINT), []);
  });

  test("a Next.js pages directory is not an Astro route tree", () => {
    const source = `
      import type { NextApiRequest, NextApiResponse } from "next";
      export default async function handler(req: NextApiRequest, res: NextApiResponse) {
        res.status(200).json({ ok: true, method: "GET" });
      }
    `;
    assert.deepEqual(entriesOf("pages/api/users.ts", source), []);
    assert.deepEqual(entriesOf("src/pages/api/users.ts", source), []);
  });

  test("a Nitro route tree is another adapter's business", () => {
    const source = `export default defineEventHandler(async (event) => getQuery(event));`;
    assert.deepEqual(entriesOf("server/api/orders.get.ts", source), []);
  });

  /* ---------------------------------------------------------------- actions */

  const ACTION_SERVER = `
    import { defineAction } from "astro:actions";
    import { z } from "astro:schema";
    export const server = {
      createOrder: defineAction({
        input: z.object({ sku: z.string(), quantity: z.number() }),
        handler: async (input, context) => {
          return { sku: input.sku, tenant: context.locals.tenantId };
        }
      })
    };
  `;

  /*

   * Every address below is `POST /_actions/<dotted name>` rather than the bare name.

   * Astro serves all actions from one endpoint, so that is the URL an action is

   * reachable at — and an address a reader cannot send a request to is not an

   * address. These assertions were `POST <name>` until 2026-08-24; the change was

   * prompted by a held-out corpus whose author, having never read this engine,

   * independently recorded the transport path as the address.

   *

   * `server` is Astro's mandated name for the root object and is never part of an

   * address; an exported group is.

   */

  test("an action is addressed by the key it is bound to under server", () => {
    const found = entriesOf("src/actions/index.ts", ACTION_SERVER);
    assert.deepEqual(addresses(found), ["POST /_actions/createOrder"]);
    assert.equal(found[0].kind, "action");
  });

  test("the action input and the action context are both seeded", () => {
    const found = entriesOf("src/actions/index.ts", ACTION_SERVER);
    assert.deepEqual(seedNames(found[0]), ["input", "context"]);
    assert.deepEqual(origins(found[0]), [
      "input (caller-supplied action input)",
      "context (inbound request)"
    ]);
  });

  test("an action module re-exported by the index is addressed by its own binding", () => {
    const source = `
      import { defineAction } from "astro:actions";
      import { z } from "astro:schema";
      export const placeOrder = defineAction({
        input: z.object({ note: z.string() }),
        handler: async (input) => input.note
      });
    `;
    const found = entriesOf("src/actions/orders.ts", source);
    assert.deepEqual(addresses(found), ["POST /_actions/placeOrder"]);
    assert.deepEqual(seedNames(found[0]), ["input"]);
  });

  test("a nested action group is part of the name the client calls", () => {
    const source = `
      import { defineAction } from "astro:actions";
      export const server = {
        user: {
          create: defineAction({ handler: async (input) => input })
        }
      };
    `;
    assert.deepEqual(addresses(entriesOf("src/actions/index.ts", source)), ["POST /_actions/user.create"]);
  });

  test("a destructured input seeds every binding it names, rest included", () => {
    const source = `
      import { defineAction } from "astro:actions";
      export const server = {
        checkout: defineAction({
          handler: async ({ items, shippingMethod: method, ...extra }) => items.length + method + extra
        })
      };
    `;
    const found = entriesOf("src/actions/index.ts", source);
    assert.deepEqual(seedNames(found[0]), ["items", "method", "extra"]);
    assert.deepEqual(origins(found[0]), [
      "input.items (caller-supplied action input)",
      "input.shippingMethod (caller-supplied action input)",
      "input (caller-supplied action input)"
    ]);
  });

  test("a form action still receives the submission as its first argument", () => {
    const source = `
      import { defineAction } from "astro:actions";
      import { z } from "astro:schema";
      export const server = {
        subscribe: defineAction({
          accept: "form",
          input: z.object({ email: z.string() }),
          handler: async (form, context) => form.email + context.locals.userId
        })
      };
    `;
    const found = entriesOf("src/actions/index.ts", source);
    assert.deepEqual(addresses(found), ["POST /_actions/subscribe"]);
    assert.deepEqual(seedNames(found[0]), ["form", "context"]);
  });

  test("an action handler written as a method is the same handler", () => {
    const source = `
      import { defineAction } from "astro:actions";
      export const server = {
        ping: defineAction({
          async handler(input, context) {
            return input.value + context.request.url;
          }
        })
      };
    `;
    const found = entriesOf("src/actions/index.ts", source);
    assert.deepEqual(addresses(found), ["POST /_actions/ping"]);
    assert.deepEqual(seedNames(found[0]), ["input", "context"]);
  });

  test("a destructured action context keeps locals out of the caller's half", () => {
    const source = `
      import { defineAction } from "astro:actions";
      export const server = {
        ping: defineAction({ handler: async (input, { request, cookies, locals }) => input })
      };
    `;
    const found = entriesOf("src/actions/index.ts", source);
    assert.deepEqual(seedNames(found[0]), ["input", "request", "cookies"]);
    assert.deepEqual(found[0].trustedParameters, ["locals"]);
  });

  test("an action defined outside src/actions is claimed on the strength of its import", () => {
    const source = `
      import { defineAction } from "astro:actions";
      export const archive = defineAction({ handler: async (input) => input.id });
    `;
    assert.deepEqual(addresses(entriesOf("src/server/archive.ts", source)), ["POST /_actions/archive"]);
  });

  test("a shorthand handler property is resolved to the function declared above it", () => {
    const source = `
      import { defineAction } from "astro:actions";
      const handler = async (input, context) => input.sku + context.request.url;
      export const server = { reserve: defineAction({ handler }) };
    `;
    const found = entriesOf("src/actions/index.ts", source);
    assert.deepEqual(addresses(found), ["POST /_actions/reserve"]);
    assert.deepEqual(seedNames(found[0]), ["input", "context"]);
  });

  test("a call with no handler is not an action, whatever directory it sits in", () => {
    const source = `
      import { defineAction } from "../store/actions";
      export const setFilter = defineAction({ type: "SET_FILTER", payload: (value) => value });
    `;
    assert.deepEqual(entriesOf("src/actions/filters.ts", source), []);
  });

  test("a defineAction from somewhere other than Astro is not an Astro action", () => {
    const source = `
      import { defineAction } from "../../lib/store";
      export const archive = defineAction({ handler: async (input) => input.id });
    `;
    assert.deepEqual(entriesOf("src/store/archive.ts", source), []);
  });

  /* ------------------------------------------------------------- middleware */

  test("middleware is where every request first meets application code", () => {
    const source = `
      import { defineMiddleware } from "astro:middleware";
      export const onRequest = defineMiddleware(async (context, next) => {
        context.locals.session = await resolve(context.request);
        return next();
      });
    `;
    const found = entriesOf("src/middleware.ts", source);
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["context"]);
  });

  test("a bare onRequest export is the same middleware without the helper", () => {
    const source = `
      export async function onRequest({ request, locals }, next) {
        locals.trace = request.headers.get("x-trace");
        return next();
      }
    `;
    const found = entriesOf("src/middleware.ts", source);
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
    assert.deepEqual(found[0].trustedParameters, ["locals"]);
  });

  test("a wrapped middleware is reported once rather than twice", () => {
    const source = `
      import { defineMiddleware } from "astro:middleware";
      export const onRequest = defineMiddleware(async ({ request }, next) => next());
    `;
    assert.equal(entriesOf("src/middleware/index.ts", source).length, 1);
  });

  test("a Next.js middleware module at the same path is not claimed", () => {
    const source = `
      import { NextResponse } from "next/server";
      export function middleware(request) {
        return NextResponse.next();
      }
      export const config = { matcher: ["/dashboard/:path*"] };
    `;
    assert.deepEqual(entriesOf("src/middleware.ts", source), []);
  });

  test("an onRequest hook that belongs to another framework is not Astro middleware", () => {
    const source = `
      import fastify from "fastify";
      const app = fastify();
      app.addHook("onRequest", async (request, reply) => {
        request.startedAt = Date.now();
      });
    `;
    assert.deepEqual(entriesOf("src/server/hooks.ts", source), []);
  });
}
