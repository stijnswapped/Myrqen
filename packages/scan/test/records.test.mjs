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

/* ------------------------------------------- decorator-routed controllers and ORMs */

/*
 * A controller that never mentions the request is the shape this rule was blindest
 * to. Nest hands the caller's data over as an ordinary string parameter, hides the
 * store behind an injected member, and establishes identity in a class decorator, so
 * every signal the Express-shaped reading depended on is absent while the defect is
 * exactly the same. Each pair below differs only in whether the subject is part of
 * the predicate.
 */

test("a repository lookup by a decorated path parameter alone is reported", async () => {
  const result = await scanSource({
    "src/shipments.controller.ts": `
      import { Controller, Get, Param, UseGuards } from "@nestjs/common";
      import { InjectRepository } from "@nestjs/typeorm";
      import { Repository } from "typeorm";
      import { CurrentUser } from "../auth/current-user.decorator";
      import { SessionGuard } from "../auth/session.guard";
      import { Shipment } from "./shipment.entity";

      @UseGuards(SessionGuard)
      @Controller("logistics/shipments")
      export class ShipmentsController {
        constructor(@InjectRepository(Shipment) private readonly shipments: Repository<Shipment>) {}

        @Get(":ref/label")
        async label(@CurrentUser() operator: { id: string }, @Param("ref") ref: string) {
          const shipment = await this.shipments.findOneBy({ id: ref });
          return { carrier: shipment.carrier, label: shipment.labelSvg, printedBy: operator.id };
        }
      }
    `
  });
  const found = bola(result);
  assert.equal(found.length, 1, "the subject is available and is not part of the lookup");
  assert.equal(found[0].route, "GET /logistics/shipments/:ref/label");
  assert.match(found[0].title, /shipments/);
});

test("the same repository lookup carrying the subject's tenant is not reported", async () => {
  const result = await scanSource({
    "src/consignments.controller.ts": `
      import { Controller, Get, Param, UseGuards } from "@nestjs/common";
      import { InjectRepository } from "@nestjs/typeorm";
      import { Repository } from "typeorm";
      import { CurrentUser } from "../auth/current-user.decorator";
      import { SessionGuard } from "../auth/session.guard";
      import { Shipment } from "./shipment.entity";

      @UseGuards(SessionGuard)
      @Controller("logistics/consignments")
      export class ConsignmentsController {
        constructor(@InjectRepository(Shipment) private readonly shipments: Repository<Shipment>) {}

        @Get(":ref/label")
        async label(@CurrentUser() operator: { id: string; tenantId: string }, @Param("ref") ref: string) {
          const shipment = await this.shipments.findOneBy({ id: ref, tenantId: operator.tenantId });
          return { carrier: shipment.carrier, label: shipment.labelSvg, printedBy: operator.id };
        }
      }
    `
  });
  assert.deepEqual(bola(result), []);
});

test("a filtered read whose filter pins the primary key is reported", async () => {
  const result = await scanSource({
    "src/tickets.controller.ts": `
      import { Controller, Get, Param, Req, UseGuards } from "@nestjs/common";
      import { InjectRepository } from "@nestjs/typeorm";
      import { Repository } from "typeorm";
      import { SessionGuard } from "../auth/session.guard";
      import { Ticket } from "./ticket.entity";

      @UseGuards(SessionGuard)
      @Controller("desk/tickets")
      export class TicketsController {
        constructor(@InjectRepository(Ticket) private readonly tickets: Repository<Ticket>) {}

        @Get(":ticketId/transcript")
        async transcript(@Req() req: { user: { id: string } }, @Param("ticketId") ticketId: string) {
          const rows = await this.tickets.find({ where: { id: ticketId }, relations: { messages: true } });
          return { viewer: req.user.id, transcript: rows[0] };
        }
      }
    `
  });
  assert.equal(bola(result).length, 1, "the plural method still returns exactly the row the caller named");
});

test("a scope the caller was proved to belong to is not a finding", async () => {
  const result = await scanSource({
    "src/site-tickets.controller.ts": `
      import { Controller, Get, NotFoundException, Param, Req, UseGuards } from "@nestjs/common";
      import { InjectRepository } from "@nestjs/typeorm";
      import { Repository } from "typeorm";
      import { SessionGuard } from "../auth/session.guard";
      import { Enrolment } from "./enrolment.entity";
      import { Ticket } from "./ticket.entity";

      @UseGuards(SessionGuard)
      @Controller("desk/sites/:siteId/tickets")
      export class SiteTicketsController {
        constructor(
          @InjectRepository(Ticket) private readonly tickets: Repository<Ticket>,
          @InjectRepository(Enrolment) private readonly enrolments: Repository<Enrolment>
        ) {}

        @Get(":ticketId/transcript")
        async transcript(
          @Req() req: { user: { id: string } },
          @Param("siteId") siteId: string,
          @Param("ticketId") ticketId: string
        ) {
          const enrolment = await this.enrolments.findOneBy({ siteId, userId: req.user.id });
          if (!enrolment) throw new NotFoundException("no such site");
          const rows = await this.tickets.find({ where: { id: ticketId, siteId }, relations: { messages: true } });
          return { viewer: req.user.id, transcript: rows[0] };
        }
      }
    `
  });
  assert.deepEqual(
    bola(result),
    [],
    "every value in the predicate came from the URL, and the membership read proved the caller is in that site"
  );
});

test("a query-builder chain that constrains only the primary key is reported", async () => {
  const result = await scanSource({
    "src/manifests.controller.ts": `
      import { Controller, Get, Param, Req, UseGuards } from "@nestjs/common";
      import { InjectRepository } from "@nestjs/typeorm";
      import { Repository } from "typeorm";
      import { SessionGuard } from "../auth/session.guard";
      import { Manifest } from "./manifest.entity";

      @UseGuards(SessionGuard)
      @Controller("freight/manifests")
      export class ManifestsController {
        constructor(@InjectRepository(Manifest) private readonly manifests: Repository<Manifest>) {}

        @Get(":manifestId")
        async detail(@Req() req: { user: { id: string; carrierId: string } }, @Param("manifestId") manifestId: string) {
          const manifest = await this.manifests
            .createQueryBuilder("m")
            .where("m.id = :manifestId", { manifestId })
            .getOne();
          return { viewer: req.user.id, manifest };
        }
      }
    `
  });
  const found = bola(result);
  assert.equal(found.length, 1, "the conditions live in the chain, not in the call that runs it");
  assert.match(found[0].title, /manifests/, "the finding names the table, not the builder link it hangs off");
});

test("the same chain with an andWhere on the owner column is not reported", async () => {
  const result = await scanSource({
    "src/waybills.controller.ts": `
      import { Controller, Get, Param, Req, UseGuards } from "@nestjs/common";
      import { InjectRepository } from "@nestjs/typeorm";
      import { Repository } from "typeorm";
      import { SessionGuard } from "../auth/session.guard";
      import { Manifest } from "./manifest.entity";

      @UseGuards(SessionGuard)
      @Controller("freight/waybills")
      export class WaybillsController {
        constructor(@InjectRepository(Manifest) private readonly waybills: Repository<Manifest>) {}

        @Get(":waybillId")
        async detail(@Req() req: { user: { id: string; carrierId: string } }, @Param("waybillId") waybillId: string) {
          const waybill = await this.waybills
            .createQueryBuilder("w")
            .where("w.id = :waybillId", { waybillId })
            .andWhere("w.customerId = :customerId", { customerId: req.user.carrierId })
            .getOne();
          return { viewer: req.user.id, waybill };
        }
      }
    `
  });
  assert.deepEqual(bola(result), []);
});

test("an array searched with a callback is still not a store query", async () => {
  const result = await scanSource({
    "src/catalogue.controller.ts": `
      import { Controller, Get, Param, Req, UseGuards } from "@nestjs/common";
      import { SessionGuard } from "../auth/session.guard";
      import { PRICE_BANDS } from "./price-bands";

      @UseGuards(SessionGuard)
      @Controller("catalogue")
      export class CatalogueController {
        @Get("bands/:bandId")
        async band(@Req() req: { user: { id: string } }, @Param("bandId") bandId: string) {
          const band = PRICE_BANDS.find({ id: bandId });
          return { viewer: req.user.id, band };
        }
      }
    `
  });
  assert.deepEqual(bola(result), [], "a module constant is not a store, whatever the method is called");
});

/* ---------------------------------------- a fluent query builder (Drizzle, Kysely) */

/*
 * `db.select().from(t).where(eq(t.id, id))` names no method this rule used to
 * know: the table arrives through `.from`, the filter through `.where`, and the
 * terminal link is whichever modifier was written last. Keying on the terminal
 * name switched the rule off for most of the TypeScript ORM population.
 */

test("a fluent builder select filtered by the path parameter alone is reported", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "kilnworks", version: "1.0.0", type: "module" }),
    "src/pages/api/firings/[id]/schedule.ts": `import type { APIRoute } from "astro";
import { eq } from "drizzle-orm";
import { db } from "../../../../lib/db/client";
import { firings } from "../../../../lib/db/schema";

export const prerender = false;

export const GET: APIRoute = async ({ params, locals }) => {
  const potter = locals.potter!;

  const [firing] = await db.select().from(firings).where(eq(firings.id, params.id)).limit(1);
  if (!firing) return new Response("not found", { status: 404 });

  return new Response(JSON.stringify({ firing, viewer: potter.id }), { status: 200 });
};
`
  });
  const found = bola(result);
  assert.equal(found.length, 1, JSON.stringify(found.map((c) => c.location)));
  assert.match(found[0].affected?.route ?? found[0].location.file, /firings/);
});

test("the same builder select with an owner predicate stays silent", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "kilnworks", version: "1.0.0", type: "module" }),
    "src/pages/api/firings/[id]/kiln.ts": `import type { APIRoute } from "astro";
import { and, eq } from "drizzle-orm";
import { db } from "../../../../lib/db/client";
import { firings } from "../../../../lib/db/schema";

export const prerender = false;

export const GET: APIRoute = async ({ params, locals }) => {
  const potter = locals.potter!;

  const [firing] = await db
    .select()
    .from(firings)
    .where(and(eq(firings.id, params.id), eq(firings.potterId, potter.id)))
    .limit(1);
  if (!firing) return new Response("not found", { status: 404 });

  return new Response(JSON.stringify({ firing }), { status: 200 });
};
`
  });
  assert.deepEqual(bola(result).map((c) => c.location.line), []);
});

test("one builder chain produces one finding, not one per link", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "kilnworks", version: "1.0.0", type: "module" }),
    "src/pages/api/glazes/[id]/batch.ts": `import type { APIRoute } from "astro";
import { eq } from "drizzle-orm";
import { db } from "../../../../lib/db/client";
import { glazeBatches } from "../../../../lib/db/schema";

export const prerender = false;

export const PATCH: APIRoute = async ({ params, request, locals }) => {
  const potter = locals.potter!;
  const body = await request.json();

  const [updated] = await db
    .update(glazeBatches)
    .set({ notes: body.notes })
    .where(eq(glazeBatches.id, params.id))
    .returning();

  return new Response(JSON.stringify({ updated, viewer: potter.id }), { status: 200 });
};
`
  });
  const found = bola(result);
  assert.equal(found.length, 1, JSON.stringify(found.map((c) => c.location)));
});

test("an array method chain is not mistaken for a query builder", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "kilnworks", version: "1.0.0", type: "module" }),
    "src/pages/api/glazes/index.ts": `import type { APIRoute } from "astro";

const CATALOGUE = [
  { id: "celadon", cone: 10 },
  { id: "tenmoku", cone: 10 },
  { id: "shino", cone: 9 }
];

export const prerender = false;

export const GET: APIRoute = async ({ url }) => {
  const cone = Number(url.searchParams.get("cone") ?? "10");
  const rows = CATALOGUE.filter((entry) => entry.cone === cone)
    .map((entry) => entry.id)
    .slice(0, 20);
  return new Response(JSON.stringify({ rows }), { status: 200 });
};
`
  });
  assert.deepEqual(bola(result).map((c) => c.location.line), []);
});

/* ------------------------------------- column-and-value builder conditions (Knex) */

/*
 * Knex spells the commonest filter in Node as `where("id", value)`, with a
 * three-argument `where("id", "=", value)` beside it, and names its table by
 * calling the store itself rather than through `.from(…)`. None of those three
 * shapes is an object literal or a `:placeholder` fragment, so all of them used to
 * walk past the predicate reader and switch this rule off silently — for Knex, and
 * for Adonis Lucid, which is built on it.
 *
 * These are shape tests, not corpus tests: no benchmark case uses this form, which
 * is exactly why the gap survived four held-out corpora.
 */

test("a row addressed by a two-argument builder condition is reported", async () => {
  const result = await scanSource({
    "src/statements.js": `
      const express = require("express");
      const knex = require("../lib/knex");
      const { requireSession } = require("../middleware/session");
      const router = express.Router();

      router.get("/:statementId", requireSession, async (req, res) => {
        // the session middleware has already run, so the reader is authenticated
        const statement = await knex("statements").where("id", req.params.statementId).first();
        if (!statement) return res.status(404).json({ error: "no such statement" });
        res.json({ statement });
      });

      module.exports = router;
    `
  });
  assert.equal(bola(result).length, 1);
});

test("a two-argument condition that also names the owner column stays silent", async () => {
  const result = await scanSource({
    "src/statements.js": `
      const express = require("express");
      const knex = require("../lib/knex");
      const { requireSession } = require("../middleware/session");
      const router = express.Router();

      router.get("/:statementId", requireSession, async (req, res) => {
        const statement = await knex("statements")
          .where("id", req.params.statementId)
          .where("account_id", req.session.accountId)
          .first();
        if (!statement) return res.status(404).json({ error: "no such statement" });
        res.json({ statement });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(bola(result), []);
});

test("a three-argument equality condition is reported", async () => {
  const result = await scanSource({
    "src/shipments.js": `
      const express = require("express");
      const db = require("../lib/db");
      const { requireSession } = require("../middleware/session");
      const router = express.Router();

      router.get("/:shipmentId", requireSession, async (req, res) => {
        const shipment = await db.from("shipments").where("id", "=", req.params.shipmentId).first();
        res.json({ shipment });
      });

      module.exports = router;
    `
  });
  assert.equal(bola(result).length, 1);
});

test("a keyset page boundary is not read as a record address", async () => {
  const result = await scanSource({
    "src/shipments.js": `
      const express = require("express");
      const db = require("../lib/db");
      const { requireSession } = require("../middleware/session");
      const router = express.Router();

      // A cursor names where the page starts, not which row belongs to whom.
      router.get("/", requireSession, async (req, res) => {
        const page = await db.from("shipments")
          .where("id", ">", req.query.cursor)
          .where("account_id", req.session.accountId)
          .limit(20);
        res.json({ page });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(bola(result), []);
});

test("a SQL fragment condition is still read with its bindings, not as a column", async () => {
  const result = await scanSource({
    "src/manifests.ts": `
      import { Router } from "express";
      import { repository } from "../lib/orm";
      import { requireSession } from "../middleware/session";

      export const router = Router();

      router.get("/:manifestId", requireSession, async (req, res) => {
        const manifest = await repository
          .createQueryBuilder("m")
          .where("m.id = :manifestId", { manifestId: req.params.manifestId })
          .getOne();
        res.json({ manifest });
      });
    `
  });
  assert.equal(bola(result).length, 1);
});

/* --------------------------------- a row addressed by its business reference */

/*
 * `PRIMARY_KEY_COLUMN` admits `id`, `_id`, `uuid`, `guid`, `pk`, `objectid` and
 * nothing else, so a row addressed by the reference printed on the document was not
 * addressed at all and this rule never ran. holdout-6 lost an object-ownership case
 * to it, on a Drizzle query keyed by `consignments.reference`.
 *
 * Recognised by shape rather than by adding nouns to a list: a read that returns a
 * single row, whose only non-owner condition is one caller-supplied value, addresses
 * a record. The negatives below are the three ways that can fail to hold.
 */

test("a single row addressed by a business reference is reported", async () => {
  const result = await scanSource({
    "src/consignments.js": `
      const express = require("express");
      const { db } = require("../lib/db");
      const { requireSession } = require("../middleware/session");
      const router = express.Router();

      router.get("/:reference", requireSession, async (req, res) => {
        // The desk user is authenticated; their branch never enters the predicate.
        const desk = req.session.forwarderId;
        const consignment = await db.select().from(consignments)
          .where(eq(consignments.reference, req.params.reference))
          .limit(1);
        if (!consignment) return res.status(404).json({ error: "not found" });
        res.json({ consignment, desk });
      });

      module.exports = router;
    `
  });
  assert.equal(bola(result).length, 1);
});

test("the same read scoped to the caller's own branch stays silent", async () => {
  const result = await scanSource({
    "src/consignments.js": `
      const express = require("express");
      const { db } = require("../lib/db");
      const { requireSession } = require("../middleware/session");
      const router = express.Router();

      router.get("/:reference", requireSession, async (req, res) => {
        const consignment = await db.select().from(consignments)
          .where(and(eq(consignments.reference, req.params.reference), eq(consignments.forwarderId, req.session.forwarderId)))
          .limit(1);
        if (!consignment) return res.status(404).json({ error: "not found" });
        res.json({ consignment });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(bola(result), []);
});

test("a listing filtered by one caller value is not a record address", async () => {
  // No `limit(1)` and no single-row method: this returns many rows, and reporting it
  // would report every search endpoint in every application.
  const result = await scanSource({
    "src/consignments.js": `
      const express = require("express");
      const { db } = require("../lib/db");
      const { requireSession } = require("../middleware/session");
      const router = express.Router();

      router.get("/", requireSession, async (req, res) => {
        const rows = await db.select().from(consignments)
          .where(eq(consignments.destinationPort, req.query.port));
        res.json({ rows });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(bola(result), []);
});

test("a single row addressed by a value the caller did not choose stays silent", async () => {
  const result = await scanSource({
    "src/consignments.js": `
      const express = require("express");
      const { db } = require("../lib/db");
      const { requireSession } = require("../middleware/session");
      const router = express.Router();

      router.get("/current", requireSession, async (req, res) => {
        const consignment = await db.select().from(consignments)
          .where(eq(consignments.reference, req.session.activeConsignmentReference))
          .limit(1);
        res.json({ consignment });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(bola(result), []);
});

test("two caller-supplied conditions are a filter, not an address", async () => {
  // One condition is what makes a value *the* address. Two is a query.
  const result = await scanSource({
    "src/consignments.js": `
      const express = require("express");
      const { db } = require("../lib/db");
      const { requireSession } = require("../middleware/session");
      const router = express.Router();

      router.get("/lookup", requireSession, async (req, res) => {
        const consignment = await db.select().from(consignments)
          .where(and(eq(consignments.originPort, req.query.from), eq(consignments.destinationPort, req.query.to)))
          .limit(1);
        res.json({ consignment });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(bola(result), []);
});

/* ------------------- a predicate names an owner by its columns, not its text */

/*
 * `namesOwner` used to be `OWNER_COLUMN.test(predicateText)`, so a predicate named an
 * owner whenever the *characters* of an owner column appeared anywhere in it — including
 * inside a value the caller supplied. Combined with `predicateIsScoped`, which treats a
 * predicate that names an owner but resolves no owner value as scoped, that excused the
 * application letting the caller nominate whose data to read.
 */
const visibility = (viewer) => `const Router = require("@koa/router");
const { Asset } = require("../models/asset");
const router = new Router({ prefix: "/api/assets" });

router.get("/:assetId", requireUser, async (ctx) => {
  const assetId = ctx.params.assetId;
  const asset = await Asset.findOne({ _id: assetId, $or: Asset.visibilityFilter(${viewer}) }).lean();
  ctx.body = { asset };
});

module.exports = router;
`;

test("a visibility filter fed from the session scopes the lookup", async () => {
  const result = await scanSource({ "src/assets.js": visibility("ctx.state.user.id") });
  assert.deepEqual(bola(result), []);
});

test("a visibility filter the caller names is not a scope, however it is spelled", async () => {
  // `viewerId` matches the owner-column pattern. That it appears in the predicate's
  // text is exactly the coincidence the old test mistook for a guard.
  const result = await scanSource({ "src/assets.js": visibility("ctx.request.body.viewerId") });
  assert.equal(bola(result).length, 1);
});

/* ------------------------------------------- a membership lookup is an ownership check */

const seats = (predicate) => `import { and, eq } from "drizzle-orm";
import { db } from "../lib/db";
import { memberships, workspaces } from "../lib/schema";
import { getSessionByToken } from "../lib/session";

export async function changeSeats(formData: FormData) {
  const session = await getSessionByToken("token");
  if (!session) return { ok: false as const };

  const workspaceId = String(formData.get("workspaceId") ?? "");
  const seatLimit = Number(formData.get("seatLimit") ?? 0);

  const membership = await db.query.memberships.findFirst({
    where: ${predicate},
    columns: { id: true, role: true },
  });
  if (!membership) return { ok: false as const };

  const [updated] = await db
    .update(workspaces)
    .set({ seatLimit })
    .where(eq(workspaces.id, workspaceId))
    .returning({ id: workspaces.id, seatLimit: workspaces.seatLimit });

  return { ok: true as const, updated };
}
`;

test("a membership row proving the caller belongs to the workspace is an ownership check", async () => {
  const result = await scanSource({
    "src/seats.ts": seats("and(eq(memberships.workspaceId, workspaceId), eq(memberships.userId, session.userId))")
  });
  assert.deepEqual(bola(result), []);
});

test("a membership lookup that does not constrain the caller proves nothing", async () => {
  // The workspace is named, the caller is not: this returns somebody's membership,
  // not necessarily the caller's.
  const result = await scanSource({
    "src/seats.ts": seats("eq(memberships.workspaceId, workspaceId)")
  });
  assert.equal(bola(result).length, 1);
});

test("a membership lookup that does not constrain the subject proves nothing", async () => {
  // The caller is named and the workspace is not, so the row says the caller is a
  // member of something — not of the workspace being modified.
  const result = await scanSource({
    "src/seats.ts": seats("eq(memberships.userId, session.userId)")
  });
  assert.equal(bola(result).length, 1);
});

/* --------------------------------- input that arrives through a free function (h3) */

/*
 * The adapters have always declared `accessorFunctions` — "free functions that return
 * caller data when called with this entry point's request object". The taint model reads
 * them; this rule's scope did not, so a value acquired as `getRouterParam(event, "id")`
 * was not the caller's while `event.context.params.id` was, in otherwise identical code.
 * Path traversal and injection were found in h3 handlers all along, which is what made
 * the gap invisible: the framework was clearly supported.
 */

const H3_PACKAGE = JSON.stringify({
  name: "letting-portal",
  version: "1.0.0",
  private: true,
  type: "module",
  dependencies: { nuxt: "^3.13.0", "drizzle-orm": "^0.33.0" }
});

const H3_SUPPORT = {
  "server/db/schema.ts": `export const agreements = { id: "id", holderId: "holderId", depositCents: "depositCents" } as any;
export const eq = (a: unknown, b: unknown) => ({ a, b }) as any;
export const and = (...a: unknown[]) => ({ a }) as any;
`,
  "server/db/client.ts": `export const store = {
  select: (_: unknown) => store,
  from: (_: unknown) => store,
  where: (_: unknown) => store,
  limit: (_: number) => [] as any[]
} as any;
`,
  "server/utils/session.ts": `export function requireSession(event: unknown) { return { holderId: "h-1" }; }\n`
};

const h3Handler = (predicate) => `import { and, eq, agreements } from '../../db/schema'
import { store } from '../../db/client'
import { requireSession } from '../../utils/session'

export default defineEventHandler(async (event) => {
  const session = requireSession(event)
  const agreementId = getRouterParam(event, 'id')
  const [agreement] = await store
    .select({ id: agreements.id, depositCents: agreements.depositCents })
    .from(agreements)
    .where(${predicate})
    .limit(1)
  return { agreement }
})
`;

test("a value read through an h3 accessor function is the caller's", async () => {
  const result = await scanSource({
    "package.json": H3_PACKAGE,
    ...H3_SUPPORT,
    "server/api/agreements/[id]/deposit.get.ts": h3Handler("eq(agreements.id, agreementId)")
  });
  assert.equal(bola(result).length, 1, "the unscoped lookup is reported although the id arrived through a call");
});

test("the same handler is silent when the predicate also names the holder", async () => {
  const result = await scanSource({
    "package.json": H3_PACKAGE,
    ...H3_SUPPORT,
    "server/api/agreements/[id]/deposit.get.ts": h3Handler(
      "and(eq(agreements.id, agreementId), eq(agreements.holderId, session.holderId))"
    )
  });
  assert.deepEqual(bola(result), [], "the identity is in the predicate, so the row cannot belong to anybody else");
});

/* ------------------------------------- the row was not returned, it keyed the write */

const TRANSFER_PACKAGE = JSON.stringify({
  name: "pass-desk",
  version: "1.0.0",
  private: true,
  type: "module",
  dependencies: { express: "^5.0.0", "@prisma/client": "^5.19.0" }
});

const TRANSFER_SUPPORT = {
  "src/lib/db.ts": `export const prisma = {
  pass: { findUnique: async (_: unknown) => ({ id: "p", ownerId: "h", state: "ISSUED" }) as any, update: async (_: unknown) => null as any },
  account: { upsert: async (_: unknown) => ({ id: "a" }) as any }
} as any;
`,
  "src/middleware/auth.ts": `export function currentUser(request: unknown) { return { accountId: "a-1" }; }\n`
};

const transferHandler = (guard) => `import express from 'express'
import { prisma } from '../lib/db'
import { currentUser } from '../middleware/auth'

export const router = express.Router()

router.post('/api/passes/:passId/hand-over', async (req, res) => {
  const viewer = currentUser(req)

  const pass = await prisma.pass.findUnique({
    where: { id: req.params.passId },
    select: { id: true, state: true, ownerId: true }
  })
  if (!pass) return res.status(404).json({ error: 'not_found' })
  if (pass.state !== 'ISSUED') return res.status(409).json({ error: 'not_transferable' })
${guard}
  const recipient = await prisma.account.upsert({
    where: { email: String(req.body.recipientEmail).toLowerCase() },
    create: { email: String(req.body.recipientEmail).toLowerCase() },
    update: {},
    select: { id: true }
  })
  if (recipient.id === pass.ownerId) return res.status(409).json({ error: 'already_theirs' })

  await prisma.pass.update({ where: { id: pass.id }, data: { ownerId: recipient.id } })
  return res.json({ ok: true })
})
`;

test("a row that never reaches the response but chooses which row is written is reported", async () => {
  const result = await scanSource({
    "package.json": TRANSFER_PACKAGE,
    ...TRANSFER_SUPPORT,
    "src/routes/passes.ts": transferHandler("")
  });
  assert.equal(bola(result).length, 1, "the read fixes which pass the update lands on, so it is the decision");
  // The handler does contain `recipient.id === pass.ownerId`, which reads exactly like an
  // ownership comparison. It is a duplicate-transfer check: `recipient` is fetched by an
  // address out of the request body, so the caller picks both sides and it can never fail
  // for the pass they are taking. Suppressing on it is what made this case silent.
});

test("the same handler is silent when the pass's owner is compared to the caller", async () => {
  const result = await scanSource({
    "package.json": TRANSFER_PACKAGE,
    ...TRANSFER_SUPPORT,
    "src/routes/passes.ts": transferHandler(
      "  if (pass.ownerId !== viewer.accountId) return res.status(403).json({ error: 'not_yours' })\n"
    )
  });
  assert.deepEqual(bola(result), [], "the row's owner is compared to the established identity and the handler stops");
});

/* ------------------------------------------------------- Kysely's builder vocabulary */

/*
 * `isFluentBuilderLookup` named Kysely in its own docstring as one of the two builders it
 * existed for, and `BUILDER_TABLE_LINK` did not contain `selectFrom`. Every Kysely chain
 * therefore read as a builder that names no table and was declined, and a chain ending in
 * `executeTakeFirst()` read as a listing rather than a single-row read — and a listing
 * filtered by one caller value is deliberately not this rule's finding.
 */

const KYSELY_PACKAGE = JSON.stringify({
  name: "hiring-desk",
  version: "1.0.0",
  private: true,
  type: "module",
  dependencies: { "@remix-run/node": "^2.12.0", kysely: "^0.27.4" }
});

const KYSELY_SUPPORT = {
  "app/db/client.ts": `export const db = {
  selectFrom: (_: string) => db,
  innerJoin: (..._a: unknown[]) => db,
  select: (_: unknown) => db,
  where: (..._a: unknown[]) => db,
  executeTakeFirst: async () => null as any
} as any;
`,
  "app/auth/session.ts": `export async function requireUser(request: unknown) { return { id: "u-1" }; }\n`
};

const kyselyLoader = (predicates) => `import type { LoaderFunctionArgs } from '@remix-run/node'
import { db } from '../db/client'
import { requireUser } from '../auth/session'

export async function loader({ params, request }: LoaderFunctionArgs) {
  const user = await requireUser(request)
  const noteId = params.noteId as string
  const note = await db
    .selectFrom('interview_notes as n')
    .select(['n.id', 'n.body', 'n.interviewer_user_id'])
${predicates}
    .executeTakeFirst()
  if (!note) throw new Response('Not found', { status: 404 })
  return { note }
}
`;

test("a Kysely chain that filters on the path parameter alone is reported", async () => {
  const result = await scanSource({
    "package.json": KYSELY_PACKAGE,
    ...KYSELY_SUPPORT,
    "app/routes/note-detail.tsx": kyselyLoader("    .where('n.id', '=', noteId)")
  });
  assert.equal(bola(result).length, 1, "the alias-prefixed column and executeTakeFirst are Kysely's own spelling");
});

test("the same Kysely chain is silent when it also filters on the interviewer", async () => {
  const result = await scanSource({
    "package.json": KYSELY_PACKAGE,
    ...KYSELY_SUPPORT,
    "app/routes/note-detail.tsx": kyselyLoader(
      "    .where('n.id', '=', noteId)\n    .where('n.interviewer_user_id', '=', user.id)"
    )
  });
  assert.deepEqual(bola(result), [], "the second predicate ties the row to the signed-in interviewer");
});

/* --------------------------------------------- a document store has no `where` */

/*
 * `db.collection("children").doc(childId).get()` names the collection, then names the
 * document, and both are arguments rather than properties. There is no filter object
 * anywhere in the chain, so the predicate model found nothing and object-level
 * authorization was structurally unreachable for the two most widely deployed document
 * databases there are.
 */

const DOC_PACKAGE = JSON.stringify({
  name: "enrolment-desk",
  version: "1.0.0",
  private: true,
  type: "module",
  dependencies: { "firebase-admin": "^12.5.0" }
});

const DOC_SUPPORT = {
  "src/lib/firestore.ts": `export const store = {
  collection: (_name: string) => store,
  doc: (_id: string) => store,
  get: async () => ({ exists: true, data: () => ({}) as any }),
  set: async (_value: unknown) => undefined
} as any;
`,
  "src/lib/session.ts": `export function currentUser(request: unknown) { return { uid: "u-1" }; }\n`
};

const docHandler = (guard) => `import express from "express";
import { store } from "../lib/firestore";
import { currentUser } from "../lib/session";

export const router = express.Router();

router.get("/api/enrolments/:enrolmentId", async (req, res) => {
  const viewer = currentUser(req);
  const enrolmentId = req.params.enrolmentId;

  const snapshot = await store.collection("enrolments").doc(enrolmentId).get();
  if (!snapshot.exists) return res.status(404).json({ error: "not found" });
  const enrolment = snapshot.data();
${guard}
  return res.json({ enrolment });
});
`;

test("a document addressed positionally by a caller-supplied key is reported", async () => {
  const result = await scanSource({
    "package.json": DOC_PACKAGE,
    ...DOC_SUPPORT,
    "src/enrolments.ts": docHandler("")
  });
  assert.equal(bola(result).length, 1, "the collection and the document are both arguments, and there is no where");
});

test("the same read is silent when the document's owner is compared to the caller", async () => {
  const result = await scanSource({
    "package.json": DOC_PACKAGE,
    ...DOC_SUPPORT,
    "src/enrolments.ts": docHandler("  if (enrolment.ownerId !== viewer.uid) return res.status(403).json({ error: \"forbidden\" });\n")
  });
  assert.deepEqual(bola(result), []);
});

test("a document addressed by a constant is not a finding", async () => {
  const result = await scanSource({
    "package.json": DOC_PACKAGE,
    ...DOC_SUPPORT,
    "src/rates.ts": `import express from "express";
import { store } from "../lib/firestore";
import { currentUser } from "../lib/session";

export const router = express.Router();

router.get("/api/rates", async (req, res) => {
  const viewer = currentUser(req);
  const snapshot = await store.collection("settings").doc("exchange-rates").get();
  return res.json({ rates: snapshot.data(), viewer: viewer.uid });
});
`
  });
  assert.deepEqual(bola(result), [], "the caller chose nothing, so there is no boundary to cross");
});

/* ---------------------------------- the request container, and what it does not own */

test("the authenticated subject on the request container is not caller data", async () => {
  // `auth_context` is Medusa's spelling, `authContext` is somebody else's, and neither is
  // the string `auth`. Getting this wrong promotes the identity itself to attacker data
  // and reports a correctly scoped query — the worst failure this rule has.
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "registry", version: "1.0.0", private: true, type: "module" }),
    "src/lib/db.ts": `export const em = { findOne: async (_entity: unknown, _where: unknown) => ({ id: "r" }) as any } as any;
export const Registry = class {};
`,
    "src/registry.ts": `import { em, Registry } from "./lib/db";

declare function route(options: { path: string }, handler: (req: any, res: any) => Promise<unknown>): unknown;

export const detail = route({ path: "/store/registries/:id" }, async (req, res) => {
  const customerId = req.auth_context?.actor_id;
  if (!customerId) return res.status(401).json({ message: "no" });
  const registry = await em.findOne(Registry, { id: req.params.id, customer_id: customerId });
  return { registry };
});
`
  });
  assert.deepEqual(bola(result), [], "the predicate is scoped by an owner column whose value is the session's");
});
