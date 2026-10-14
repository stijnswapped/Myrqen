import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

/**
 * Every case is written inline and none of it is copied from the benchmark
 * corpus: an adapter that only recognises a known fixture is worthless in a real
 * repository, so these use their own names, routes and export styles.
 *
 * The adapter is driven directly rather than through `entryPointsOf`, so the
 * assertions hold whether or not the registry has been wired up yet.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(here, "..", "dist", "ast", "frameworks", "serverless.js");

if (!existsSync(dist)) {
  test.skip("serverless adapter (build packages/scan first: npm run build -w @myrqen/scan)", () => {});
} else {
  const { serverlessAdapter } = await import(dist);

  const parse = (source, relativePath = "src/handler.ts") => {
    const scriptKind = relativePath.endsWith(".ts") ? ts.ScriptKind.TS : ts.ScriptKind.JS;
    return {
      relativePath,
      absolutePath: `/repo/${relativePath}`,
      text: source,
      source: ts.createSourceFile(relativePath, source, ts.ScriptTarget.Latest, true, scriptKind),
      language: scriptKind === ts.ScriptKind.TS ? "TypeScript" : "JavaScript"
    };
  };

  /** What the engine would end up with: nothing at all when `applies` says no. */
  const entryPoints = (source, relativePath) => {
    const file = parse(source, relativePath);
    if (!serverlessAdapter.applies(file)) return [];
    return serverlessAdapter.detect(file);
  };

  const seedNames = (entry) => (entry.seeds ?? []).map((seed) => seed.name);

  /* ---------------- AWS Lambda and API Gateway ---------------- */

  test("a CommonJS Lambda seeds the event and refuses to trust the context", () => {
    const [entry, ...rest] = entryPoints(
      `
      exports.handler = async (event, context) => {
        const token = event.queryStringParameters.token;
        return { statusCode: 200, body: token + context.awsRequestId };
      };
      `,
      "functions/redeem.js"
    );
    assert.equal(rest.length, 0, "one exported handler is one entry point");
    assert.equal(entry.framework, "serverless");
    assert.equal(entry.kind, "http");
    assert.deepEqual(seedNames(entry), ["event"]);
    assert.equal(entry.seeds[0].origin, "event (inbound API Gateway request)");
    assert.deepEqual(entry.trustedParameters, ["context"]);
  });

  test("the event is seeded under whatever name the author chose", () => {
    const [entry] = entryPoints(`
      export const handler = async (apiEvent) => {
        return { statusCode: 200, body: apiEvent.pathParameters.id };
      };
    `);
    assert.deepEqual(seedNames(entry), ["apiEvent"], "the generic model only knows the name 'event'");
  });

  test("the verb and path are read from the handler's own comparisons", () => {
    const [entry] = entryPoints(`
      import type { APIGatewayProxyEvent } from "aws-lambda";
      export async function handler(event: APIGatewayProxyEvent, context) {
        if (event.httpMethod !== "POST") return { statusCode: 405 };
        if (event.path === "/ledger/entries") return write(event.body);
        return { statusCode: 404 };
      }
    `);
    assert.equal(entry.method, "POST");
    assert.equal(entry.path, "/ledger/entries");
  });

  test("the HTTP API v2 payload shape is read too", () => {
    const [entry] = entryPoints(`
      module.exports.lambdaHandler = async function (event, context) {
        if (event.requestContext.http.method === "delete" && event.rawPath === "/v2/keys") {
          return remove(event.rawQueryString);
        }
      };
    `, "src/keys.js");
    assert.equal(entry.method, "DELETE");
    assert.equal(entry.path, "/v2/keys");
  });

  test("a handler with no address to read admits it rather than inventing one", () => {
    const [entry] = entryPoints(`
      export const handler = async (event, context) => {
        return { statusCode: 200, body: JSON.stringify(event.headers) };
      };
    `);
    assert.equal(entry.method, "ANY");
    assert.equal(entry.path, "/", "a Lambda genuinely has no path in its own source");
  });

  test("a destructured event seeds each property it binds", () => {
    const [entry] = entryPoints(`
      export const handler = async ({ pathParameters, body }) => {
        return save(pathParameters.id, body);
      };
    `);
    assert.deepEqual(seedNames(entry).sort(), ["body", "pathParameters"]);
    assert.equal(
      entry.seeds.find((seed) => seed.name === "body").origin,
      "event.body (inbound API Gateway request)"
    );
  });

  test("an event-source handler is left to the adapter that names its queue", () => {
    assert.deepEqual(
      entryPoints(`
        exports.handler = async (event, context) => {
          for (const record of event.Records) await ingest(JSON.parse(record.body));
        };
      `, "src/ingest.js"),
      [],
      "the queue adapter already declares this handler, and one handler is one entry point"
    );
  });

  test("an exported binding named handler is not a Lambda on its own", () => {
    assert.deepEqual(
      entryPoints(`
        export const handler = (element) => {
          element.classList.toggle("open");
        };
      `, "src/ui/toggle.js"),
      [],
      "every export named handler in the world would otherwise become an API Gateway route"
    );
  });

  test("a scheduled handler taking no arguments claims no route", () => {
    assert.deepEqual(
      entryPoints(`
        import { S3Client } from "@aws-sdk/client-s3";
        export const handler = async () => {
          await new S3Client({}).send(rotate());
        };
      `),
      [],
      "there is no caller data to seed and no address to report"
    );
  });

  /* ---------------- Cloudflare Workers and edge ---------------- */

  test("a module Worker seeds the request and trusts the bindings", () => {
    const [entry, ...rest] = entryPoints(`
      export default {
        async fetch(request, env, ctx) {
          const url = new URL(request.url);
          if (url.pathname === "/receipts" && request.method === "POST") {
            return store(await request.text(), env.LEDGER);
          }
          return new Response("no", { status: 404 });
        }
      };
    `, "worker/index.ts");
    assert.equal(rest.length, 0);
    assert.equal(entry.method, "POST");
    assert.equal(entry.path, "/receipts");
    assert.deepEqual(seedNames(entry), ["request"]);
    assert.equal(entry.seeds[0].origin, "request (inbound request)");
    assert.deepEqual(entry.trustedParameters, ["env", "ctx"], "env holds secrets, not caller data");
  });

  test("a service-worker fetch listener is an entry point", () => {
    const [entry] = entryPoints(`
      addEventListener("fetch", (event) => {
        event.respondWith(handle(event.request));
      });
    `, "worker/legacy.js");
    assert.equal(entry.kind, "http");
    assert.deepEqual(seedNames(entry), ["event"]);
    assert.equal(entry.seeds[0].origin, "event.request (inbound request)");
  });

  test("a Netlify edge function takes its path from the config it exports", () => {
    const [entry] = entryPoints(`
      export default async (request, context) => {
        return new Response(await lookup(new URL(request.url).searchParams.get("q")));
      };
      export const config = { path: "/search" };
    `, "netlify/edge-functions/search.ts");
    assert.equal(entry.path, "/search");
    assert.deepEqual(seedNames(entry), ["request"]);
    assert.deepEqual(entry.trustedParameters, ["context"], "Netlify's context is the platform's, not the caller's");
  });

  test("a single-argument edge default export is recognised without a config", () => {
    const [entry] = entryPoints(`
      export const runtime = "edge";
      export default async function handler(request) {
        const url = new URL(request.url);
        if (url.pathname === "/og") return render(url.searchParams.get("title"));
        return new Response(null, { status: 404 });
      }
    `, "api/og.ts");
    assert.equal(entry.path, "/og");
    assert.deepEqual(seedNames(entry), ["request"]);
  });

  test("a Next.js pages/api default export is left to its own adapter", () => {
    assert.deepEqual(
      entryPoints(`
        export const config = { runtime: "edge" };
        export default async function handler(request) {
          return new Response(request.url);
        }
      `, "pages/api/hello.ts"),
      [],
      "claiming it here would report the same handler twice"
    );
  });

  /* ---------------- itty-router ---------------- */

  test("an itty route seeds the request its handler receives", () => {
    const entries = entryPoints(`
      import { Router } from "itty-router";
      const router = Router({ base: "/api" });
      router.post("/webhooks/ledger", async (request, env, ctx) => {
        return record(await request.json(), env.DB);
      });
      export default { fetch: router.handle };
    `, "worker/router.ts");
    const entry = entries.find((candidate) => candidate.path === "/api/webhooks/ledger");
    assert.ok(entry, `expected the itty route, saw ${JSON.stringify(entries.map((e) => e.path))}`);
    assert.equal(entry.method, "POST");
    assert.deepEqual(seedNames(entry), ["request"]);
    assert.deepEqual(entry.trustedParameters, ["env", "ctx"]);
  });

  test("a route on a receiver no itty factory produced is not claimed", () => {
    assert.deepEqual(
      entryPoints(`
        const router = express.Router();
        router.get("/reports", (req, res) => res.json(list()));
        export const handler = router;
      `, "src/reports.js"),
      [],
      "the Express-shaped discovery already owns this and knows nothing about env"
    );
  });

  /* ---------------- Azure Functions ---------------- */

  test("the Azure v4 model reports one entry point per declared method", () => {
    const entries = entryPoints(`
      import { app } from "@azure/functions";
      app.http("submitClaim", {
        methods: ["POST", "PUT"],
        route: "claims/{id}",
        authLevel: "anonymous",
        handler: async (request, context) => {
          context.log("claim");
          return { body: await request.text() };
        }
      });
    `, "src/functions/claims.ts");
    assert.deepEqual(entries.map((entry) => entry.method).sort(), ["POST", "PUT"]);
    assert.equal(entries[0].path, "/claims/{id}");
    assert.deepEqual(seedNames(entries[0]), ["request"]);
    assert.deepEqual(entries[0].trustedParameters, ["context"], "InvocationContext is the runtime's");
  });

  test("the Azure v3 model seeds the second parameter, not the first", () => {
    const [entry] = entryPoints(`
      module.exports = async function (context, req) {
        context.res = { body: await lookup(req.query.account) };
      };
    `, "GetAccount/index.js");
    assert.deepEqual(seedNames(entry), ["req"]);
    assert.equal(entry.seeds[0].origin, "req (inbound HTTP request)");
    assert.deepEqual(entry.trustedParameters, ["context"], "context is named like caller data and is not");
  });

  /* ---------------- Google Cloud Functions ---------------- */

  test("a functions-framework HTTP function is addressed by its registered name", () => {
    const [entry] = entryPoints(`
      const functions = require("@google-cloud/functions-framework");
      functions.http("receiveHook", (req, res) => {
        res.send(render(req.query.template));
      });
    `, "index.js");
    assert.equal(entry.path, "/receiveHook");
    assert.deepEqual(seedNames(entry), ["req"]);
  });

  /* ---------------- claiming ---------------- */

  test("a handler matching two families is claimed once", () => {
    const entries = entryPoints(`
      import { S3Client } from "@aws-sdk/client-s3";
      export default async function handler(event) {
        return new Response(JSON.stringify(event.queryStringParameters));
      }
    `, "src/proxy.ts");
    assert.equal(entries.length, 1, "two entry points would contradict each other on trusted parameters");
    assert.deepEqual(seedNames(entries[0]), ["event"]);
  });
}
