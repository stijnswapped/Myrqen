import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * Unit tests for the object-level authorization rule.
 *
 * Every case is written as source here, never as a reference to a corpus or fixture
 * file: a rule that only fires on a file it has seen before is worthless in a real
 * repository, and a test that reads the benchmark cannot detect that it has become
 * one. The shapes, names and routes deliberately differ from anything the corpus
 * contains.
 *
 * The pairs are the point. For each shape the vulnerable form is asserted to fire
 * and the corrected form of the *same* code is asserted to stay silent, because a
 * rule that cannot tell them apart is a rule nobody will leave switched on.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-records-"));
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

const bola = (result) =>
  result.candidates.filter((candidate) => candidate.category === "broken_object_level_authorization");

/* ------------------------------------------------ raw SQL with a bound identifier */

test("a row selected by a bound path parameter alone is reported", async () => {
  const result = await scanSource({
    "src/tickets.js": `
      const express = require("express");
      const { pool } = require("../lib/db");
      const { requireUser } = require("../middleware/auth");
      const router = express.Router();

      router.get("/:ticketId", requireUser, async (req, res) => {
        const { ticketId } = req.params;
        const { rows } = await pool.query(
          "SELECT id, subject, body, reporter_email, tenant_id FROM tickets WHERE id = $1",
          [ticketId]
        );
        if (!rows[0]) return res.status(404).json({ error: "not found" });
        res.json({ ticket: rows[0] });
      });

      module.exports = router;
    `
  });
  const found = bola(result);
  assert.equal(found.length, 1, "the unscoped select is a finding");
  assert.equal(found[0].severity, "high");
  assert.equal(found[0].route, "GET /:ticketId");
});

test("the same select with the subject in the WHERE clause is not reported", async () => {
  const result = await scanSource({
    "src/tickets.js": `
      const express = require("express");
      const { pool } = require("../lib/db");
      const { requireUser } = require("../middleware/auth");
      const router = express.Router();

      router.get("/:ticketId", requireUser, async (req, res) => {
        const { ticketId } = req.params;
        const { rows } = await pool.query(
          "SELECT id, subject, body, reporter_email FROM tickets WHERE id = $1 AND tenant_id = $2",
          [ticketId, req.user.tenantId]
        );
        if (!rows[0]) return res.status(404).json({ error: "not found" });
        res.json({ ticket: rows[0] });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(bola(result), []);
});

test("an owner column in the SELECT list is not mistaken for a check", async () => {
  const result = await scanSource({
    "src/notes.js": `
      const express = require("express");
      const { pool } = require("../lib/db");
      const { requireUser } = require("../middleware/auth");
      const router = express.Router();

      router.get("/:noteId", requireUser, async (req, res) => {
        const { rows } = await pool.query(
          "SELECT id, title, account_id, created_by FROM notes WHERE id = $1",
          [req.params.noteId]
        );
        res.json({ note: rows[0] });
      });

      module.exports = router;
    `
  });
  assert.equal(bola(result).length, 1, "a projection names the owner column without constraining it");
});

/* -------------------------------------------------------------- ORM object filter */

test("an ORM lookup by identifier alone is reported", async () => {
  const result = await scanSource({
    "src/folders.ts": `
      import { Hono } from "hono";
      import { db } from "../lib/db";
      import { requireSession } from "../middleware/session";

      const folders = new Hono();
      folders.use("*", requireSession);

      folders.get("/folders/:id", async (c) => {
        const id = c.req.param("id");
        const folder = await db.folder.findUnique({
          where: { id },
          select: { id: true, name: true, teamId: true, contents: true }
        });
        if (!folder) return c.json({ error: "not found" }, 404);
        return c.json({ folder });
      });

      export default folders;
    `
  });
  const found = bola(result);
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "GET /folders/:id");
});

test("a select projection naming the owner field does not excuse the lookup", async () => {
  const result = await scanSource({
    "src/folders.ts": `
      import { Hono } from "hono";
      import { db } from "../lib/db";
      import { requireSession } from "../middleware/session";

      const folders = new Hono();
      folders.use("*", requireSession);

      folders.get("/folders/:id", async (c) => {
        const viewer = c.get("viewer");
        const folder = await db.folder.findFirst({
          where: { id: c.req.param("id"), teamId: viewer.teamId },
          select: { id: true, name: true, teamId: true, contents: true }
        });
        return c.json({ folder });
      });

      export default folders;
    `
  });
  assert.deepEqual(bola(result), [], "the corrected form of the same handler must stay silent");
});

/* ------------------------------------------------------------- query-builder chain */

test("a builder update filtered only by identifier is reported as critical", async () => {
  const result = await scanSource({
    "app/actions/rename-folder.ts": `
      "use server";
      import { eq } from "drizzle-orm";
      import { cookies } from "next/headers";
      import { db } from "@/lib/db";
      import { folders } from "@/db/schema";
      import { getSessionByToken } from "@/lib/session";

      export async function renameFolder(formData: FormData) {
        const jar = await cookies();
        const session = await getSessionByToken(jar.get("sid")?.value ?? "");
        if (!session) return { ok: false as const };

        const folderId = String(formData.get("folderId") ?? "");
        const name = String(formData.get("name") ?? "").trim();

        const [updated] = await db
          .update(folders)
          .set({ name, updatedAt: new Date() })
          .where(eq(folders.id, folderId))
          .returning({ id: folders.id, teamId: folders.teamId });

        return { ok: true as const, folder: updated };
      }
    `
  });
  const found = bola(result);
  assert.equal(found.length, 1, "a write reachable by any identifier is the worst form of this defect");
  assert.equal(found[0].severity, "critical");
});

test("the same builder update with a tenant predicate is not reported", async () => {
  const result = await scanSource({
    "app/actions/rename-folder.ts": `
      "use server";
      import { and, eq } from "drizzle-orm";
      import { cookies } from "next/headers";
      import { db } from "@/lib/db";
      import { folders } from "@/db/schema";
      import { getSessionByToken } from "@/lib/session";

      export async function renameFolder(formData: FormData) {
        const jar = await cookies();
        const session = await getSessionByToken(jar.get("sid")?.value ?? "");
        if (!session) return { ok: false as const };

        const folderId = String(formData.get("folderId") ?? "");
        const name = String(formData.get("name") ?? "").trim();

        const [updated] = await db
          .update(folders)
          .set({ name, updatedAt: new Date() })
          .where(and(eq(folders.id, folderId), eq(folders.teamId, session.teamId)))
          .returning({ id: folders.id });

        return { ok: true as const, folder: updated };
      }
    `
  });
  assert.deepEqual(bola(result), []);
});

/* ----------------------------------------------------------------- document filter */

test("a document filter on the caller's identifier is reported", async () => {
  const result = await scanSource({
    "src/threads.js": `
      import { threads } from "./store.js";
      export async function handler(request, response) {
        const viewer = currentUser(request);
        if (!viewer) return response.end("401");
        const thread = await threads.findOne({ _id: request.params.threadId });
        return response.end(JSON.stringify(thread));
      }
      function currentUser(request) { return request.headers.authorization ? { id: 1 } : null; }
    `
  });
  assert.equal(bola(result).length, 1);
});

/* --------------------------------- an in-memory collection searched by a predicate */

test("an in-memory record searched by a caller-chosen id is reported", async () => {
  const result = await scanSource({
    "src/api.js": `
      import http from "node:http";
      import { bookings, sessions, people } from "./store.js";

      function json(response, status, body) {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(body));
      }

      function currentUser(request) {
        const record = sessions.get(request.headers.cookie ?? "");
        return record ? people.find((person) => person.id === record.personId) : null;
      }

      const server = http.createServer((request, response) => {
        const url = new URL(request.url ?? "/", "http://127.0.0.1");
        if (request.method === "GET" && /^\\/api\\/bookings\\/\\d+$/.test(url.pathname)) {
          const user = currentUser(request);
          if (!user) return json(response, 401, { error: "sign in first" });
          const id = Number(url.pathname.split("/").pop());
          const booking = bookings.find((candidate) => candidate.id === id);
          if (!booking) return json(response, 404, { error: "not found" });
          return json(response, 200, booking);
        }
        return json(response, 404, {});
      });

      export default server;
    `
  });
  const found = bola(result);
  assert.equal(found.length, 1, "a record held in memory is still somebody's record");
  assert.equal(found[0].route, "GET /api/bookings/:id");
  assert.match(found[0].evidence[0].snippet ?? "", /bookings\.find/);
});

test("numeric coercion of an identifier does not make the record the caller's", async () => {
  const result = await scanSource({
    "src/api.js": `
      import http from "node:http";
      import { bookings } from "./store.js";
      const server = http.createServer((request, response) => {
        const url = new URL(request.url ?? "/", "http://127.0.0.1");
        const viewer = currentUser(request);
        if (!viewer) return response.end("401");
        const id = parseInt(url.searchParams.get("id") ?? "", 10);
        const booking = bookings.find((candidate) => candidate.id === id);
        return response.end(JSON.stringify(booking));
      });
      function currentUser(request) { return request.headers.cookie ? { id: 1 } : null; }
      export default server;
    `
  });
  assert.equal(
    bola(result).length,
    1,
    "Number() removes the ability to inject text, not the caller's choice of which row to read"
  );
});

test("a collection already scoped to the caller may be searched by identifier", async () => {
  const result = await scanSource({
    "src/page.tsx": `
      import { listProjectsForUser } from "@/lib/projects";
      import { requireViewer } from "@/lib/session";

      export default async function ProjectPage({ params }: { params: Promise<{ id: string }> }) {
        const { id } = await params;
        const viewer = await requireViewer();
        const projects = await listProjectsForUser(db, viewer.userId);
        const project = projects.find((candidate) => candidate.id === id);
        if (!project) return null;
        return <h1>{project.name}</h1>;
      }
    `
  });
  assert.deepEqual(bola(result), [], "the list never held another account's rows, so picking one out cannot cross an account");
});

/* --------------------------------------------- a dispatcher with mixed-quality routes */

test("a correctly scoped route below does not excuse the unscoped route above it", async () => {
  const result = await scanSource({
    "src/dispatch.js": `
      import http from "node:http";
      import { bookings } from "./store.js";

      function json(response, status, body) {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(body));
      }

      const server = http.createServer((request, response) => {
        const url = new URL(request.url ?? "/", "http://127.0.0.1");
        const route = request.method + " " + url.pathname;
        const user = currentUser(request);
        if (!user) return json(response, 401, { error: "sign in first" });

        if (request.method === "GET" && /^\\/api\\/bookings\\/\\d+$/.test(url.pathname)) {
          const id = Number(url.pathname.split("/").pop());
          const booking = bookings.find((candidate) => candidate.id === id);
          if (!booking) return json(response, 404, { error: "not found" });
          return json(response, 200, booking);
        }

        if (route === "GET /api/bookings") {
          return json(response, 200, bookings.filter((booking) => booking.userId === user.id));
        }

        return json(response, 404, {});
      });

      function currentUser(request) { return request.headers.cookie ? { id: 1 } : null; }
      export default server;
    `
  });
  const found = bola(result);
  assert.equal(
    found.length,
    1,
    "at most one branch of a dispatcher runs, so the list route's ownership filter is not evidence about the detail route"
  );
  assert.equal(found[0].route, "GET /api/bookings/:id");
});

test("an ownership comparison on the same route does suppress the finding", async () => {
  const result = await scanSource({
    "src/dispatch.js": `
      import http from "node:http";
      import { bookings } from "./store.js";

      function json(response, status, body) {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(body));
      }

      const server = http.createServer((request, response) => {
        const url = new URL(request.url ?? "/", "http://127.0.0.1");
        const user = currentUser(request);
        if (!user) return json(response, 401, { error: "sign in first" });

        if (request.method === "GET" && /^\\/api\\/bookings\\/\\d+$/.test(url.pathname)) {
          const id = Number(url.pathname.split("/").pop());
          const booking = bookings.find((candidate) => candidate.id === id);
          if (!booking) return json(response, 404, { error: "not found" });
          if (booking.userId !== user.id) return json(response, 404, { error: "not found" });
          return json(response, 200, booking);
        }

        return json(response, 404, {});
      });

      function currentUser(request) { return request.headers.cookie ? { id: 1 } : null; }
      export default server;
    `
  });
  assert.deepEqual(bola(result), [], "a check after the lookup, on this route, is the fix");
});

/* --------------------------------------------------------------- what must stay quiet */

test("an identifier that came back out of the store is not the caller's choice", async () => {
  const result = await scanSource({
    "src/devices.ts": `
      import { protectedProcedure, router } from "../trpc";
      import { z } from "zod";

      export const devicesRouter = router({
        rename: protectedProcedure
          .input(z.object({ deviceId: z.string().uuid(), label: z.string().min(1) }))
          .mutation(async ({ ctx, input }) => {
            const device = await ctx.db.device.findFirst({
              where: { id: input.deviceId, userId: ctx.session.userId },
              select: { id: true }
            });
            if (!device) throw new Error("not found");

            const updated = await ctx.db.device.update({
              where: { id: device.id },
              data: { label: input.label },
              select: { id: true, label: true }
            });
            return { device: updated };
          })
      });
    `
  });
  assert.deepEqual(bola(result), [], "the second statement reuses an id already proven to be the caller's");
});

test("a row read only to price a purchase is not reported", async () => {
  const result = await scanSource({
    "app/actions/buy.ts": `
      "use server";
      import { eq } from "drizzle-orm";
      import { cookies } from "next/headers";
      import { db } from "@/lib/db";
      import { catalogue, orders } from "@/db/schema";
      import { getSessionByToken } from "@/lib/session";

      export async function buy(formData: FormData) {
        const jar = await cookies();
        const session = await getSessionByToken(jar.get("sid")?.value ?? "");
        if (!session) return { ok: false as const };

        const itemId = String(formData.get("itemId") ?? "");
        const item = await db.query.catalogue.findFirst({
          where: eq(catalogue.id, itemId),
          columns: { id: true, priceCents: true, currency: true }
        });
        if (!item) return { ok: false as const };

        await db.insert(orders).values({
          userId: session.userId,
          totalCents: item.priceCents,
          currency: item.currency
        });
        return { ok: true as const };
      }
    `
  });
  assert.deepEqual(bola(result), [], "the row never reaches the caller and is not written to");
});

test("a route that declares an object-level guard is not reported", async () => {
  const result = await scanSource({
    "src/members.js": `
      export default async function (fastify) {
        fastify.patch(
          "/teams/:teamId/members/:memberId",
          { preHandler: [fastify.authenticate, fastify.requireTeamRole("manager")] },
          async (request, reply) => {
            const { teamId, memberId } = request.params;
            const { rows } = await fastify.pg.query(
              "UPDATE team_members SET role = $1 WHERE team_id = $2 AND id = $3 RETURNING id, role",
              [request.body.role, teamId, memberId]
            );
            if (rows.length === 0) return reply.code(404).send({ error: "not_found" });
            return reply.send({ member: rows[0] });
          }
        );
      }
    `
  });
  assert.deepEqual(bola(result), [], "requireTeamRole authorises the object outside the query; requireUser would not");
});

test("resolving a session cookie to its user is authentication, not a broken check", async () => {
  const result = await scanSource({
    "src/auth.js": `
      import { people, sessions } from "./store.js";
      export function currentUser(request) {
        const cookie = request.headers.cookie ?? "";
        const match = /(?:^|;\\s*)sid=([^;]+)/.exec(cookie);
        if (!match) return null;
        const record = sessions.get(match[1]);
        if (!record) return null;
        return people.find((person) => person.id === record.personId) ?? null;
      }
      export function handler(request, response) {
        const user = currentUser(request);
        response.end(JSON.stringify({ signedIn: Boolean(user) }));
      }
    `
  });
  assert.deepEqual(bola(result), [], "a helper the file calls itself returns to the next line, not to the caller");
});

test("an anonymous endpoint is left to the rule that owns unauthenticated access", async () => {
  const result = await scanSource({
    "src/public.js": `
      import { articles } from "./store.js";
      export async function handler(request, response) {
        const article = await articles.findOne({ id: request.params.articleId });
        return response.end(JSON.stringify(article));
      }
    `
  });
  assert.deepEqual(bola(result), [], "with no identity there is no ownership relationship to get wrong");
});

test("the finding names the endpoint, the fix and how to confirm it", async () => {
  const result = await scanSource({
    "src/tickets.js": `
      const express = require("express");
      const { pool } = require("../lib/db");
      const { requireUser } = require("../middleware/auth");
      const router = express.Router();
      router.get("/:ticketId", requireUser, async (req, res) => {
        const { rows } = await pool.query(
          "SELECT id, subject, tenant_id FROM tickets WHERE id = $1",
          [req.params.ticketId]
        );
        res.json({ ticket: rows[0] });
      });
      module.exports = router;
    `
  });
  const [found] = bola(result);
  assert.ok(found, "the finding exists");
  assert.equal(found.verification, "strong_evidence");
  assert.ok(found.evidence.length >= 2, "the predicate is quoted alongside the source");
  assert.match(found.evidence[1].description, /tenant_id|id = \$1/);
  assert.match(found.remediation, /predicate|404/);
  assert.match(found.verificationPlan, /two accounts/i);
  assert.ok(found.taxonomy.includes("CWE-639"));
});
