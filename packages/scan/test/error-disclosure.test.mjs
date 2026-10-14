import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * verbose_error_response across the frameworks that never write to a `res`.
 *
 * A Nitro route throws `createError`, a SvelteKit endpoint returns `json(...)`,
 * a Worker returns `new Response(...)`, a NestJS controller throws an exception
 * the framework serialises, and an Express error middleware writes the body the
 * old way. Each pair below is a handler that hands the caught exception to the
 * caller and the same handler written correctly, because the second one is what
 * the rule has to stay silent on.
 *
 * Sources are written inline and named after nothing in any corpus.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-disclosure-"));
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

const disclosures = (result) =>
  result.candidates.filter((candidate) => candidate.category === "verbose_error_response");

/* ------------------------------------------------------------------ *
 * Nitro and h3: the response is a thrown createError
 * ------------------------------------------------------------------ */

test("a Nitro handler that attaches the driver error to createError is reported", async () => {
  const result = await scanSource({
    "server/api/batches/[id]/state.get.ts": `
      import { createError, defineEventHandler, getRouterParam, isError } from "h3";
      import { pool } from "../../../utils/pool";

      export default defineEventHandler(async (event) => {
        const id = getRouterParam(event, "id");
        try {
          const result = await pool.query("select * from batches where id = $1", [id]);
          return result.rows[0];
        } catch (err) {
          if (isError(err)) throw err;
          const failure = err;
          throw createError({
            statusCode: 500,
            statusMessage: "batch state unavailable",
            data: { message: failure.message, code: failure.code, detail: failure.detail, stack: failure.stack }
          });
        }
      });
    `
  });
  const found = disclosures(result);
  assert.equal(found.length, 1, "the data object of the thrown error is the response body");
  assert.equal(found[0].route, "GET /api/batches/[id]/state");
});

test("the same Nitro handler logging the driver error and returning a reference is not reported", async () => {
  const result = await scanSource({
    "server/api/batches/[id]/state.get.ts": `
      import { createError, defineEventHandler, getRouterParam, isError } from "h3";
      import { pool } from "../../../utils/pool";
      import { logger } from "../../../utils/logger";

      export default defineEventHandler(async (event) => {
        const id = getRouterParam(event, "id");
        try {
          const result = await pool.query("select * from batches where id = $1", [id]);
          return result.rows[0];
        } catch (err) {
          if (isError(err)) throw err;
          const failure = err;
          logger.error({ err: failure, code: failure.code, detail: failure.detail, batchId: id }, "batch state failed");
          throw createError({
            statusCode: 500,
            statusMessage: "batch state unavailable",
            data: { reference: event.context.requestId ?? null }
          });
        }
      });
    `
  });
  assert.deepEqual(disclosures(result), []);
});

test("a Nitro handler that returns the exception message in its own body is reported", async () => {
  const result = await scanSource({
    "server/api/batches/rebuild.post.ts": `
      import { defineEventHandler, readBody } from "h3";
      import { rebuild } from "../../utils/rebuild";

      export default defineEventHandler(async (event) => {
        const body = await readBody(event);
        try {
          return { ok: true, rebuilt: await rebuild(body.batchId) };
        } catch (err) {
          return { ok: false, error: err.message, where: err.detail };
        }
      });
    `
  });
  assert.equal(disclosures(result).length, 1, "what the handler returns is what the caller receives");
});

/* ------------------------------------------------------------------ *
 * SvelteKit and Workers: the response is a returned value
 * ------------------------------------------------------------------ */

test("a SvelteKit endpoint that returns String(error) as the body is reported", async () => {
  const result = await scanSource({
    "src/routes/api/ledger-export/+server.ts": `
      import { json } from "@sveltejs/kit";
      import { buildExport } from "$lib/server/exports";

      export const POST = async ({ request }) => {
        const payload = await request.json();
        try {
          return json({ export: await buildExport(payload) });
        } catch (error) {
          return json({ error: String(error) }, { status: 500 });
        }
      };
    `
  });
  assert.equal(disclosures(result).length, 1);
});

test("a SvelteKit endpoint that quotes a validation message on a 400 is not reported", async () => {
  const result = await scanSource({
    "src/routes/api/ledger-export/+server.ts": `
      import { json } from "@sveltejs/kit";
      import { parseExportRequest } from "$lib/server/schema";
      import { buildExport } from "$lib/server/exports";

      export const POST = async ({ request }) => {
        const payload = await request.json();
        try {
          return json({ export: await buildExport(parseExportRequest(payload)) });
        } catch (error) {
          return json({ error: error.message }, { status: 400 });
        }
      };
    `
  });
  assert.deepEqual(
    disclosures(result),
    [],
    "a 4xx explaining the caller's own request is the handler doing its job"
  );
});

test("a Worker that serialises the error into a Response body is reported", async () => {
  const result = await scanSource({
    "src/worker.ts": `
      export default {
        async fetch(request, env) {
          try {
            const body = await request.json();
            return new Response(JSON.stringify(await env.STORE.put(body.key, body.value)));
          } catch (err) {
            return new Response(JSON.stringify({ error: err.message, stack: err.stack }), { status: 500 });
          }
        }
      };
    `
  });
  assert.equal(disclosures(result).length, 1);
});

/* ------------------------------------------------------------------ *
 * NestJS: the response is a thrown exception
 * ------------------------------------------------------------------ */

test("a NestJS controller that constructs its exception from the caught error is reported", async () => {
  const result = await scanSource({
    "src/statements.controller.ts": `
      import { Controller, Get, Param, InternalServerErrorException } from "@nestjs/common";
      import { StatementsService } from "./statements.service";

      @Controller("statements")
      export class StatementsController {
        constructor(private readonly statements: StatementsService) {}

        @Get(":id")
        async findOne(@Param("id") id: string) {
          try {
            return await this.statements.findOne(id);
          } catch (err) {
            throw new InternalServerErrorException({ message: err.message, detail: err.detail });
          }
        }
      }
    `
  });
  assert.equal(disclosures(result).length, 1);
});

/* ------------------------------------------------------------------ *
 * The shapes that must stay silent
 * ------------------------------------------------------------------ */

test("a handler that logs the exception and answers with a correlation id is not reported", async () => {
  const result = await scanSource({
    "src/exports.js": `
      const express = require("express");
      const { randomUUID } = require("node:crypto");
      const logger = require("../lib/logger");
      const router = express.Router();

      router.post("/exports", async (req, res) => {
        const incidentId = randomUUID();
        try {
          res.status(202).json({ queued: true });
        } catch (err) {
          logger.error({ err, incidentId, accountId: req.user.accountId }, "export failed");
          res.status(500).json({ error: "Export could not be queued", incidentId });
        }
      });

      module.exports = router;
    `
  });
  assert.deepEqual(disclosures(result), []);
});

test("an exception handed to the framework's error channel rather than to the caller is not reported", async () => {
  const result = await scanSource({
    "src/reports.js": `
      const express = require("express");
      const router = express.Router();

      router.get("/reports/:id", async (req, res, next) => {
        try {
          res.json(await load(req.params.id));
        } catch (err) {
          next(err);
        }
      });

      module.exports = router;
    `
  });
  assert.deepEqual(disclosures(result), [], "next(err) hands the error to a middleware, not to the caller");
});

test("a catch block that rethrows without shaping a body is not reported", async () => {
  const result = await scanSource({
    "src/jobs.js": `
      const { Worker } = require("bullmq");
      const logger = require("../lib/logger");

      const worker = new Worker("sync", async (job) => {
        try {
          return { written: await sync(job.data.accountId) };
        } catch (err) {
          logger.error({ jobId: job.id, err: { message: err.message, code: err.code } }, "sync failed");
          throw err;
        }
      });

      module.exports = { worker };
    `
  });
  assert.deepEqual(disclosures(result), []);
});

test("a catch block that branches on the error code but answers with a fixed sentence is not reported", async () => {
  const result = await scanSource({
    "src/invites.js": `
      const express = require("express");
      const router = express.Router();

      router.post("/invites", async (req, res) => {
        try {
          res.status(201).json(await invite(req.body.email));
        } catch (err) {
          res.status(err.code === "23505" ? 409 : 500).json({
            error: err.code === "23505" ? "That address is already invited" : "Invite could not be created"
          });
        }
      });

      module.exports = router;
    `
  });
  assert.deepEqual(disclosures(result), [], "the exception is tested, never disclosed");
});

test("a payload passed through a project's own redaction helper is not reported", async () => {
  const result = await scanSource({
    "src/billing.js": `
      const express = require("express");
      const { toClientError } = require("../lib/errors");
      const router = express.Router();

      router.post("/charges", async (req, res) => {
        try {
          res.status(201).json(await charge(req.body));
        } catch (err) {
          res.status(500).json(toClientError(err));
        }
      });

      module.exports = router;
    `
  });
  assert.deepEqual(
    disclosures(result),
    [],
    "what a helper does with the exception is not visible here, and guessing reports the fix as the defect"
  );
});

/* ------------------------------------------------------------------ *
 * Shapes the walk has to follow to see the response at all
 * ------------------------------------------------------------------ */

test("a body built one statement before the response call is reported", async () => {
  const result = await scanSource({
    "src/imports.js": `
      const express = require("express");
      const router = express.Router();

      router.post("/imports", async (req, res) => {
        try {
          res.status(202).json({ queued: true });
        } catch (err) {
          const body = { error: "Import failed", message: err.message, failedQuery: err.query };
          res.status(500).json(body);
        }
      });

      module.exports = router;
    `
  });
  assert.equal(disclosures(result).length, 1);
});

test("an Express error middleware that returns the exception is reported once", async () => {
  const result = await scanSource({
    "src/app.js": `
      const express = require("express");
      const app = express();

      app.use((err, req, res, next) => {
        res.status(500).json({ error: "Unhandled failure", message: err.message, stack: err.stack });
      });

      module.exports = app;
    `
  });
  assert.equal(disclosures(result).length, 1, "one escape is one finding, whichever pass sees it first");
});

test("a rejection handler that answers with the rejection reason is reported", async () => {
  const result = await scanSource({
    "src/webhooks.js": `
      const express = require("express");
      const router = express.Router();

      router.post("/webhooks/replay", (req, res) => {
        replay(req.body.eventId)
          .then((outcome) => res.json({ outcome }))
          .catch((err) => res.status(500).json({ error: err.message, detail: err.detail }));
      });

      module.exports = router;
    `
  });
  assert.equal(disclosures(result).length, 1);
});

/* ------------------------------------------------------------------ *
 * debug_endpoint_exposure: the private-by-convention prefix
 * ------------------------------------------------------------------ */

const diagnostics = (result) =>
  result.candidates.filter((candidate) => candidate.category === "debug_endpoint_exposure");

test("a diagnostic route hidden behind an underscore prefix is still a public route", async () => {
  const result = await scanSource({
    "server/api/_internal/config.get.ts": `
      import { defineEventHandler } from "h3";
      import { pool } from "../../utils/pool";

      export default defineEventHandler(async () => {
        const migrations = await pool.query("select * from schema_migrations order by version desc limit 5");
        return {
          databaseUrl: process.env.DATABASE_URL,
          queueUrl: process.env.REDIS_URL,
          commit: process.env.GIT_COMMIT,
          migrations: migrations.rows
        };
      });
    `
  });
  assert.equal(diagnostics(result).length, 1, "the underscore is a naming convention, not an access control");
  assert.equal(diagnostics(result)[0].severity, "high", "the payload carries connection strings");
});

test("the same underscore-prefixed route answering only with liveness is not reported", async () => {
  const result = await scanSource({
    "server/api/_internal/ping.get.ts": `
      import { defineEventHandler } from "h3";

      export default defineEventHandler(async () => {
        return { ok: true };
      });
    `
  });
  assert.deepEqual(diagnostics(result), [], "a liveness answer discloses nothing");
});

test("an exception message sent as the whole body is reported", async () => {
  const result = await scanSource({
    "src/renderer.js": `
      const express = require("express");
      const router = express.Router();

      router.get("/renders/:id", async (req, res) => {
        try {
          res.send(await render(req.params.id));
        } catch (err) {
          res.status(500).send(err.message);
        }
      });

      module.exports = router;
    `
  });
  assert.equal(disclosures(result).length, 1, "a bare string body is still the response body");
});

test("an exception field read only to choose a status is not reported", async () => {
  const result = await scanSource({
    "src/renderer.js": `
      const express = require("express");
      const router = express.Router();

      router.get("/renders/:id", async (req, res) => {
        try {
          res.send(await render(req.params.id));
        } catch (err) {
          res.status(err.code === "ENOENT" ? 404 : 500).send("Render unavailable");
        }
      });

      module.exports = router;
    `
  });
  assert.deepEqual(disclosures(result), [], "the exception picked the status, it did not reach the body");
});

test("a diagnostic-looking route gated by role middleware at its registration is not reported", async () => {
  const handler = `(req, res) => {
      res.json({ hostname: require("node:os").hostname(), uptime: process.uptime() });
    }`;
  const open = await scanSource({
    "src/ops.js": `const express = require("express");\nconst router = express.Router();\nrouter.get("/trace", ${handler});\nmodule.exports = router;\n`
  });
  assert.equal(open.candidates.filter((candidate) => candidate.category === "debug_endpoint_exposure").length, 1);

  const gated = await scanSource({
    "src/ops.js": `const express = require("express");\nconst { requireUser, requireRole } = require("./auth");\nconst router = express.Router();\nrouter.get("/trace", requireUser, requireRole("operator"), ${handler});\nmodule.exports = router;\n`
  });
  assert.equal(gated.candidates.filter((candidate) => candidate.category === "debug_endpoint_exposure").length, 0);
});
