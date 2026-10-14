import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { parseFile } from "../dist/ast/parse.js";
import { discoverRoutes } from "../dist/ast/routes.js";
import * as accessRules from "../dist/rules/access.js";
// Loading the engine registers the framework adapters. A decorator-routed
// controller, a queue processor, and an edge worker have no entry point without
// them, and with no entry point the rules below have nothing to judge.
import "../dist/index.js";

/**
 * The access rules are driven directly rather than through `scan()`, so these
 * tests hold whether or not the rules are registered in the engine's rule list
 * yet, and so a failure points at this file rather than at another rule.
 *
 * Every case is written as source here. None of them references the benchmark
 * corpus: a rule that only fires on a fixture it has seen is worthless in a real
 * repository, and a test that reads the fixture cannot detect that.
 */
async function runAccess(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-access-"));
  const candidates = [];
  try {
    for (const [relativePath, contents] of Object.entries(files)) {
      const target = path.join(root, relativePath);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, contents, "utf8");
    }
    for (const relativePath of Object.keys(files)) {
      const parsed = await parseFile(root, path.join(root, relativePath));
      if ("error" in parsed) throw new Error(`${relativePath}: ${parsed.error}`);
      const context = {
        file: parsed,
        routes: discoverRoutes(parsed),
        report: (candidate) => candidates.push(candidate)
      };
      for (const rule of Object.values(accessRules)) rule.run(context);
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
  return candidates;
}

const categories = (candidates) => candidates.map((candidate) => candidate.category);
const of = (candidates, category) => candidates.filter((candidate) => candidate.category === category);

/* ------------------------------------------------------------ missing_authentication */

test("an unauthenticated route handler beside an authenticated one is reported", async () => {
  const found = await runAccess({
    "app/api/rosters/[groupId]/entries/route.ts": `
      import { readSession } from "@/lib/session";
      import { cookies } from "next/headers";
      import { store } from "@/lib/store";

      export async function GET(request: Request, { params }) {
        const jar = await cookies();
        const session = await readSession(jar.get("sid")?.value ?? "");
        if (!session) return Response.json({ error: "no" }, { status: 401 });
        return Response.json(await store.entry.findMany({ where: { userId: session.userId } }));
      }

      export async function POST(request: Request, { params }) {
        const payload = await request.json();
        await store.entry.create({ data: { groupId: payload.groupId, userId: payload.userId, tag: payload.tag } });
        return Response.json({ ok: true }, { status: 201 });
      }
    `
  });
  const hits = of(found, "missing_authentication");
  assert.equal(hits.length, 1, "only the handler without an identity check is reported");
  assert.match(hits[0].route, /^POST \//);
  assert.equal(hits[0].severity, "critical");
});

test("a route handler file where every method authenticates is quiet", async () => {
  const found = await runAccess({
    "app/api/rosters/[groupId]/entries/route.ts": `
      import { readSession } from "@/lib/session";
      import { cookies } from "next/headers";
      import { store } from "@/lib/store";

      async function current() {
        const jar = await cookies();
        return readSession(jar.get("sid")?.value ?? "");
      }

      export async function GET() {
        const session = await current();
        if (!session) return Response.json({ error: "no" }, { status: 401 });
        return Response.json(await store.entry.findMany({ where: { userId: session.userId } }));
      }

      export async function POST(request: Request) {
        const session = await current();
        if (!session) return Response.json({ error: "no" }, { status: 401 });
        const payload = await request.json();
        await store.entry.create({ data: { userId: session.userId, tag: payload.tag } });
        return Response.json({ ok: true }, { status: 201 });
      }
    `
  });
  assert.deepEqual(categories(found), [], "a shared session helper is still an identity check");
});

test("a module where nothing is authenticated is treated as a public API", async () => {
  const found = await runAccess({
    "app/api/catalogue/route.ts": `
      import { store } from "@/lib/store";

      export async function GET(request: Request) {
        const term = new URL(request.url).searchParams.get("q") ?? "";
        return Response.json(await store.product.findMany({ where: { name: { contains: term } } }));
      }

      export async function POST(request: Request) {
        const body = await request.json();
        await store.pageView.create({ data: { productId: body.productId, at: new Date() } });
        return Response.json({ ok: true });
      }
    `
  });
  assert.deepEqual(
    categories(found).filter((category) => category === "missing_authentication"),
    [],
    "without an authenticated sibling there is no evidence the surface should be authenticated"
  );
});

test("a server action that writes a per-user row without a session is reported", async () => {
  const found = await runAccess({
    "app/actions/nickname.ts": `
      "use server";
      import { cookies } from "next/headers";
      import { readSession } from "@/lib/session";
      import { store } from "@/lib/store";

      export async function saveNickname(formData: FormData) {
        const userId = String(formData.get("userId") ?? "");
        const nickname = String(formData.get("nickname") ?? "");
        await store.member.update({ where: { userId }, data: { nickname } });
      }

      export async function clearNickname() {
        const jar = await cookies();
        const session = await readSession(jar.get("sid")?.value ?? "");
        if (!session) return { ok: false };
        await store.member.update({ where: { userId: session.userId }, data: { nickname: null } });
        return { ok: true };
      }
    `
  });
  const hits = of(found, "missing_authentication");
  assert.equal(hits.length, 1);
  assert.match(hits[0].summary, /server action/i, "the finding explains why an action is a network endpoint");
});

test("a public tRPC mutation among protected siblings is reported", async () => {
  const found = await runAccess({
    "src/handsets-router.ts": `
      import { z } from "zod";
      import { protectedProcedure, publicProcedure, router } from "../trpc";

      export const handsetsRouter = router({
        list: protectedProcedure.query(async ({ ctx }) =>
          ctx.db.handset.findMany({ where: { userId: ctx.session.userId } })
        ),
        forget: publicProcedure
          .input(z.object({ handsetId: z.string().uuid() }))
          .mutation(async ({ ctx, input }) => {
            const handset = await ctx.db.handset.findUnique({ where: { id: input.handsetId }, select: { id: true, userId: true } });
            if (!handset) return { forgotten: false };
            await ctx.db.handset.delete({ where: { id: handset.id } });
            return { forgotten: true };
          })
      });
    `
  });
  const hits = of(found, "missing_authentication");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].route, "handsets.forget", "a procedure is addressed by its dotted path, not an HTTP route");
});

test("a Zod input schema is not mistaken for an authentication check", async () => {
  const found = await runAccess({
    "src/handsets-router.ts": `
      import { z } from "zod";
      import { protectedProcedure, router } from "../trpc";

      export const handsetsRouter = router({
        list: protectedProcedure.query(async ({ ctx }) =>
          ctx.db.handset.findMany({ where: { userId: ctx.session.userId } })
        ),
        forget: protectedProcedure
          .input(z.object({ handsetId: z.string().uuid() }))
          .mutation(async ({ ctx, input }) => {
            const handset = await ctx.db.handset.findFirst({
              where: { id: input.handsetId, userId: ctx.session.userId },
              select: { id: true }
            });
            if (!handset) return { forgotten: false };
            await ctx.db.handset.delete({ where: { id: handset.id } });
            return { forgotten: true };
          })
      });
    `
  });
  assert.deepEqual(categories(found), [], "every procedure here is protected and tenant-scoped");
});

test("a sign-in handler is not reported for having no session of its own", async () => {
  const found = await runAccess({
    "src/access-routes.js": `
      const router = require("express").Router();
      const bcrypt = require("bcryptjs");
      const { requireUser } = require("../middleware/auth");
      const db = require("../lib/db");

      router.post("/tokens", async (req, res) => {
        const account = await db.account.findOne({ email: req.body.email });
        if (!account || !(await bcrypt.compare(req.body.password, account.passwordHash))) {
          return res.status(401).json({ error: "invalid" });
        }
        const session = await db.session.insertOne({ accountId: account._id });
        res.cookie("sid", session._id, { httpOnly: true, sameSite: "lax" });
        res.status(201).json({ ok: true });
      });

      router.get("/tokens/current", requireUser, async (req, res) => {
        res.json(await db.session.findOne({ accountId: req.user.accountId }));
      });

      module.exports = router;
    `
  });
  assert.deepEqual(
    categories(found).filter((category) => category === "missing_authentication"),
    [],
    "establishing a session cannot require one"
  );
});

test("a webhook receiver that writes without checking its signature is reported", async () => {
  const found = await runAccess({
    "src/receivers/billing-events.ts": `
      import { Router } from "itty-router";

      const router = Router();
      const encoder = new TextEncoder();

      async function digestMatches(secret: string, raw: string, header: string | null) {
        if (!header || !secret) return false;
        const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
        return crypto.subtle.verify("HMAC", key, encoder.encode(header), encoder.encode(raw));
      }

      router.post("/receivers/invoices", async (request: Request, env) => {
        const raw = await request.text();
        if (!(await digestMatches(env.INVOICE_SECRET, raw, request.headers.get("x-sign")))) {
          return new Response("rejected", { status: 401 });
        }
        const event = JSON.parse(raw);
        await env.DB.prepare("insert into invoice_events (id, account_id) values (?1, ?2)").bind(event.id, event.accountId).run();
        return Response.json({ received: true });
      });

      router.post("/receivers/wallet", async (request: Request, env) => {
        const raw = await request.text();
        const event = JSON.parse(raw);
        await env.DB.prepare("update accounts set credit_cents = credit_cents + ?1 where id = ?2")
          .bind(Number(event.creditCents), event.accountId)
          .run();
        return Response.json({ applied: true });
      });

      export default { fetch: router.handle };
    `
  });
  const hits = of(found, "missing_authentication");
  assert.equal(hits.length, 1, "the sibling verifies its signature, so the omission is an omission");
  assert.equal(hits[0].route, "POST /receivers/wallet");
  assert.equal(hits[0].severity, "critical");
});

test("webhook receivers that all verify their signature are quiet", async () => {
  const found = await runAccess({
    "src/receivers/billing-events.ts": `
      import { Router } from "itty-router";

      const router = Router();
      const encoder = new TextEncoder();

      async function digestMatches(secret: string, raw: string, header: string | null) {
        if (!header || !secret) return false;
        const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
        return crypto.subtle.verify("HMAC", key, encoder.encode(header), encoder.encode(raw));
      }

      router.post("/receivers/invoices", async (request: Request, env) => {
        const raw = await request.text();
        if (!(await digestMatches(env.INVOICE_SECRET, raw, request.headers.get("x-sign")))) {
          return new Response("rejected", { status: 401 });
        }
        const event = JSON.parse(raw);
        await env.DB.prepare("insert into invoice_events (id, account_id) values (?1, ?2)").bind(event.id, event.accountId).run();
        return Response.json({ received: true });
      });

      router.post("/receivers/wallet", async (request: Request, env) => {
        const raw = await request.text();
        if (!(await digestMatches(env.WALLET_SECRET, raw, request.headers.get("x-sign")))) {
          return new Response("rejected", { status: 401 });
        }
        const event = JSON.parse(raw);
        await env.DB.prepare("update accounts set credit_cents = credit_cents + ?1 where id = ?2")
          .bind(Number(event.creditCents), event.accountId)
          .run();
        return Response.json({ applied: true });
      });

      export default { fetch: router.handle };
    `
  });
  assert.deepEqual(categories(found), [], "both receivers recompute the issuer's signature before writing");
});

/* ------------------------------------------------------------------ mass_assignment */

test("the request body spread into an update is reported", async () => {
  const found = await runAccess({
    "src/crew-routes.js": `
      const router = require("express").Router();
      const knex = require("../lib/knex");
      const { requireUser, requireCrewLead } = require("../middleware/auth");

      router.patch("/:crewId/people/:personId", requireUser, requireCrewLead, async (req, res) => {
        const patch = { ...req.body, updated_at: knex.fn.now() };
        delete patch.id;
        const [person] = await knex("crew_people")
          .where({ id: req.params.personId })
          .update(patch)
          .returning(["id", "display_name", "role", "updated_at"]);
        res.json({ person });
      });

      module.exports = router;
    `
  });
  const hits = of(found, "mass_assignment");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high");
  assert.match(hits[0].summary, /role/, "the reachable privileged column is named");
  assert.match(hits[0].summary, /denylist/, "deleting keys is described as a denylist, not a fix");
});

test("named field-by-field assignment is quiet even with the same route and columns", async () => {
  const found = await runAccess({
    "src/crew-routes.js": `
      const router = require("express").Router();
      const knex = require("../lib/knex");
      const { requireUser, requireCrewLead } = require("../middleware/auth");
      const SEATS = new Set(["full", "light"]);

      router.patch("/:crewId/people/:personId", requireUser, requireCrewLead, async (req, res) => {
        const body = req.body || {};
        const patch = { updated_at: knex.fn.now() };
        if (typeof body.displayName === "string") patch.display_name = body.displayName.trim();
        if (typeof body.seat === "string" && SEATS.has(body.seat)) patch.seat = body.seat;
        const [person] = await knex("crew_people")
          .where({ id: req.params.personId })
          .update(patch)
          .returning(["id", "display_name", "role", "updated_at"]);
        res.json({ person });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(categories(found), [], "an allowlist of named columns is the safe form");
});

test("every posted form field spread into an update is reported", async () => {
  const found = await runAccess({
    "app/actions/crew-settings.ts": `
      "use server";
      import { cookies } from "next/headers";
      import { eq } from "drizzle-orm";
      import { readSession } from "@/lib/session";
      import { db } from "@/lib/db";
      import { crewMembers } from "@/db/schema";

      export async function saveCrewSettings(formData: FormData) {
        const jar = await cookies();
        const session = await readSession(jar.get("sid")?.value ?? "");
        if (!session) return { ok: false as const };
        const patch = Object.fromEntries(formData) as Record<string, string>;
        delete patch.intent;
        await db.update(crewMembers).set({ ...patch, updatedAt: new Date() }).where(eq(crewMembers.userId, session.userId));
        return { ok: true as const };
      }
    `
  });
  const hits = of(found, "mass_assignment");
  assert.equal(hits.length, 1);
  // The summary must name where the payload came from. Since FormData parameters
  // became a recognised taint source the origin is stated as the binding itself,
  // which is more useful to a reader than the phrase this test first expected.
  assert.match(hits[0].summary, /formData|form data|Object\.fromEntries/, "the origin of the spread is named");
});

test("conditional spreads of named fields are quiet", async () => {
  const found = await runAccess({
    "src/settings-router.ts": `
      import { z } from "zod";
      import { protectedProcedure, router } from "../trpc";

      const patchSchema = z
        .object({ displayName: z.string().optional(), locale: z.enum(["en", "nl"]).optional() })
        .strict();

      export const settingsRouter = router({
        update: protectedProcedure.input(z.object({ patch: patchSchema })).mutation(async ({ ctx, input }) => {
          const { displayName, locale } = input.patch;
          return ctx.db.user.update({
            where: { id: ctx.session.userId },
            data: {
              ...(displayName !== undefined ? { displayName } : {}),
              ...(locale !== undefined ? { locale } : {}),
              updatedAt: new Date()
            },
            select: { id: true, displayName: true, locale: true }
          });
        })
      });
    `
  });
  assert.deepEqual(categories(found), [], "a spread of an object literal names its own fields");
});

test("an allowlist copied into a payload before the spread is quiet", async () => {
  const found = await runAccess({
    "src/profile-resolvers.js": `
      const prisma = require("../lib/prisma");
      const SELF_EDITABLE = ["contactName", "phone"];

      const resolvers = {
        Mutation: {
          updateContact: async (_parent, { input }, context) => {
            const viewer = requireViewer(context);
            const data = {};
            for (const field of SELF_EDITABLE) {
              if (input[field] !== undefined) data[field] = input[field];
            }
            return prisma.account.update({
              where: { id: viewer.accountId },
              data: { ...data, updatedAt: new Date() },
              select: { id: true, contactName: true, phone: true, supportTier: true }
            });
          }
        }
      };

      function requireViewer(context) {
        if (!context.viewer) throw new Error("unauthenticated");
        return context.viewer;
      }

      module.exports = { resolvers };
    `
  });
  assert.deepEqual(categories(found), [], "the spread carries only the fields the allowlist copied in");
});

test("caller-supplied fields copied onto a stored record are reported", async () => {
  const found = await runAccess({
    "src/settings/listener-profile.controller.ts": `
      import { Body, Controller, Patch, Req, UseGuards } from "@nestjs/common";
      import { InjectRepository } from "@nestjs/typeorm";
      import { Repository } from "typeorm";
      import { JwtAuthGuard } from "../auth/jwt-auth.guard";
      import { ListenerProfile } from "./listener-profile.entity";

      @UseGuards(JwtAuthGuard)
      @Controller("listeners/me")
      export class ListenerProfileController {
        constructor(@InjectRepository(ListenerProfile) private readonly profiles: Repository<ListenerProfile>) {}

        @Patch()
        async update(@Req() req, @Body() attributes: Partial<ListenerProfile>) {
          const profile = await this.profiles.findOneByOrFail({ id: req.user.id });
          Object.assign(profile, attributes);
          profile.updatedAt = new Date();
          return this.profiles.save(profile);
        }
      }
    `
  });
  const hits = of(found, "mass_assignment");
  assert.equal(hits.length, 1, "Object.assign copies whatever keys the caller sent");
  assert.match(hits[0].summary, /Object\.assign/);
});

test("copying only permitted fields onto the same record is quiet", async () => {
  const found = await runAccess({
    "src/settings/listener-profile.controller.ts": `
      import { Body, Controller, Patch, Req, UseGuards } from "@nestjs/common";
      import { InjectRepository } from "@nestjs/typeorm";
      import { Repository } from "typeorm";
      import { JwtAuthGuard } from "../auth/jwt-auth.guard";
      import { ListenerProfile } from "./listener-profile.entity";

      const WRITABLE = ["displayName", "locale", "timezone"] as const;

      @UseGuards(JwtAuthGuard)
      @Controller("listeners/me")
      export class ListenerProfileController {
        constructor(@InjectRepository(ListenerProfile) private readonly profiles: Repository<ListenerProfile>) {}

        @Patch()
        async update(@Req() req, @Body() attributes: Partial<ListenerProfile>) {
          const profile = await this.profiles.findOneByOrFail({ id: req.user.id });
          for (const field of WRITABLE) {
            if (field in attributes) Object.assign(profile, { [field]: attributes[field] });
          }
          profile.updatedAt = new Date();
          return this.profiles.save(profile);
        }
      }
    `
  });
  assert.deepEqual(categories(found), [], "the copy names the field it sets on every iteration");
});

test("caller fields copied onto a record that is never stored are quiet", async () => {
  const found = await runAccess({
    "src/settings/listener-preview.controller.ts": `
      import { Body, Controller, Post, Req, UseGuards } from "@nestjs/common";
      import { JwtAuthGuard } from "../auth/jwt-auth.guard";

      const DEFAULTS = { displayName: "", locale: "en" };

      @UseGuards(JwtAuthGuard)
      @Controller("listeners/me/preview")
      export class ListenerPreviewController {
        @Post()
        async preview(@Req() req, @Body() attributes: Record<string, unknown>) {
          const view = { ...DEFAULTS };
          Object.assign(view, attributes);
          return { preview: view, viewer: req.user.id };
        }
      }
    `
  });
  assert.deepEqual(categories(found), [], "a view model that never reaches storage over-writes no row");
});

/* --------------------------------------------- broken_function_level_authorization */

test("a role change with no authorization comparison is reported", async () => {
  const found = await runAccess({
    "src/crew-roles.js": `
      const Router = require("@koa/router");
      const { pool } = require("../lib/db");
      const { requireUser } = require("../middleware/auth");

      const router = new Router({ prefix: "/crews" });
      const ASSIGNABLE = new Set(["member", "lead"]);

      router.put("/:crewId/people/:userId/role", requireUser, async (ctx) => {
        const { role } = ctx.request.body || {};
        if (!ASSIGNABLE.has(role)) ctx.throw(400, "Unknown role");
        const { rows } = await pool.query(
          \`UPDATE crew_people SET role = $1, updated_at = now() WHERE crew_id = $2 AND user_id = $3 RETURNING user_id, role\`,
          [role, ctx.params.crewId, ctx.params.userId]
        );
        ctx.body = { person: rows[0] };
      });

      module.exports = router;
    `
  });
  const hits = of(found, "broken_function_level_authorization");
  assert.equal(hits.length, 1, "validating the submitted role is not an authorization check");
  assert.equal(hits[0].severity, "critical");
  assert.match(hits[0].title, /role/);
});

test("the same role change is quiet when the caller's own role is tested", async () => {
  const found = await runAccess({
    "src/crew-roles.js": `
      const Router = require("@koa/router");
      const { pool } = require("../lib/db");
      const { requireUser } = require("../middleware/auth");

      const router = new Router({ prefix: "/crews" });
      const ASSIGNABLE = new Set(["member", "lead"]);
      const MANAGERS = new Set(["lead"]);

      router.put("/:crewId/people/:userId/role", requireUser, async (ctx) => {
        const { role } = ctx.request.body || {};
        if (!ASSIGNABLE.has(role)) ctx.throw(400, "Unknown role");
        if (!MANAGERS.has(ctx.state.crew.role)) ctx.throw(403, "Only crew leads can change roles");
        const { rows } = await pool.query(
          \`UPDATE crew_people SET role = $1, updated_at = now() WHERE crew_id = $2 AND user_id = $3 RETURNING user_id, role\`,
          [role, ctx.params.crewId, ctx.params.userId]
        );
        ctx.body = { person: rows[0] };
      });

      module.exports = router;
    `
  });
  assert.deepEqual(categories(found), [], "the caller's own role is compared against a fixed set");
});

test("a role-requiring middleware is recognised on the route registration", async () => {
  const found = await runAccess({
    "src/plugin.js": `
      export default async function (fastify) {
        fastify.patch(
          "/pods/:podId/people/:personId",
          { preHandler: [fastify.authenticate, fastify.requirePodRole("owner")] },
          async (request, reply) => {
            const { rows } = await fastify.pg.query(
              \`UPDATE pod_people SET role = $1, updated_at = now() WHERE pod_id = $2 AND id = $3 RETURNING id, role\`,
              [request.body.role, request.params.podId, request.params.personId]
            );
            return reply.send({ person: rows[0] });
          }
        );
      }
    `
  });
  assert.deepEqual(categories(found), [], "the authorization decision is made by the route's own middleware");
});

test("a role that is selected and never compared is reported", async () => {
  const found = await runAccess({
    "app/actions/pod-plan.ts": `
      "use server";
      import { cookies } from "next/headers";
      import { and, eq } from "drizzle-orm";
      import { readSession } from "@/lib/session";
      import { db } from "@/lib/db";
      import { memberships, pods } from "@/db/schema";

      export async function changePodPlan(formData: FormData) {
        const jar = await cookies();
        const session = await readSession(jar.get("sid")?.value ?? "");
        if (!session) return { ok: false as const };
        const podId = String(formData.get("podId") ?? "");
        const plan = String(formData.get("plan") ?? "");

        const membership = await db.query.memberships.findFirst({
          where: and(eq(memberships.podId, podId), eq(memberships.userId, session.userId)),
          columns: { id: true, role: true }
        });
        if (!membership) return { ok: false as const };

        await db.update(pods).set({ plan, updatedAt: new Date() }).where(eq(pods.id, podId));
        return { ok: true as const };
      }
    `
  });
  const hits = of(found, "broken_function_level_authorization");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high", "a plan change is serious without being a handover of control");
  assert.ok(
    hits[0].evidence.some((item) => /never compared/.test(item.description)),
    "the unused role selection is quoted as evidence"
  );
});

test("the same plan change is quiet when the selected role is compared", async () => {
  const found = await runAccess({
    "app/actions/pod-plan.ts": `
      "use server";
      import { cookies } from "next/headers";
      import { and, eq } from "drizzle-orm";
      import { readSession } from "@/lib/session";
      import { db } from "@/lib/db";
      import { memberships, pods } from "@/db/schema";

      const BILLING_ROLES = new Set(["owner", "billing_admin"]);

      export async function changePodPlan(formData: FormData) {
        const jar = await cookies();
        const session = await readSession(jar.get("sid")?.value ?? "");
        if (!session) return { ok: false as const };
        const podId = String(formData.get("podId") ?? "");
        const plan = String(formData.get("plan") ?? "");

        const membership = await db.query.memberships.findFirst({
          where: and(eq(memberships.podId, podId), eq(memberships.userId, session.userId)),
          columns: { id: true, role: true }
        });
        if (!membership) return { ok: false as const };
        if (!BILLING_ROLES.has(membership.role)) return { ok: false as const, message: "Not permitted" };

        await db.update(pods).set({ plan, updatedAt: new Date() }).where(eq(pods.id, podId));
        return { ok: true as const };
      }
    `
  });
  assert.deepEqual(categories(found), [], "the role is loaded and then actually used");
});

test("creating an invitation that carries a role is not a privilege escalation", async () => {
  const found = await runAccess({
    "app/api/pods/[podId]/invites/route.ts": `
      import { cookies } from "next/headers";
      import { readSession } from "@/lib/session";
      import { db } from "@/lib/db";
      import { invitations } from "@/db/schema";

      export async function POST(request: Request, { params }) {
        const jar = await cookies();
        const session = await readSession(jar.get("sid")?.value ?? "");
        if (!session) return Response.json({ error: "no" }, { status: 401 });
        const { podId } = await params;
        if (session.podId !== podId) return Response.json({ error: "not found" }, { status: 404 });
        const body = await request.json();
        const [invitation] = await db
          .insert(invitations)
          .values({ podId, email: body.email, role: body.role, invitedBy: session.userId })
          .returning({ id: invitations.id, role: invitations.role });
        return Response.json({ invitation }, { status: 201 });
      }
    `
  });
  assert.deepEqual(
    categories(found),
    [],
    "an insert of a new row is how invitations work; escalation is changing an existing row's role"
  );
});

test("a privileged route reached through hand-rolled dispatch is judged like a registered one", async () => {
  const found = await runAccess({
    "src/server.js": `
      import http from "node:http";
      import { operators, tickets } from "./store.js";

      function json(response, status, body) {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(body));
      }

      function currentUser(request) {
        const token = request.headers.authorization ?? "";
        return token ? tickets.session(token) : null;
      }

      const server = http.createServer(async (request, response) => {
        const url = new URL(request.url ?? "/", "http://127.0.0.1");
        const route = \`\${request.method} \${url.pathname}\`;

        if (route === "GET /api/tickets") {
          const user = currentUser(request);
          if (!user) return json(response, 401, { error: "sign in first" });
          return json(response, 200, tickets.forUser(user.id));
        }

        if (route === "GET /api/admin/operators") {
          const user = currentUser(request);
          if (!user) return json(response, 401, { error: "sign in first" });
          return json(response, 200, operators);
        }

        return json(response, 404, { error: "not found" });
      });

      server.listen(4010);
    `
  });
  const hits = of(found, "broken_function_level_authorization");
  assert.equal(hits.length, 1, "only the administrative branch is reported");
  assert.equal(hits[0].route, "GET /api/admin/operators", "the finding is attributed to the dispatched route");
  assert.equal(hits[0].severity, "high");
  assert.match(hits[0].summary, /dispatcher/i, "the finding says there is no middleware layer holding the check");
});

test("a privileged route that answers with a constant is not reported", async () => {
  const found = await runAccess({
    "src/server.js": `
      import http from "node:http";

      const LAYOUTS = ["weekly-digest", "invoice-reminder", "seat-limit"];

      const server = http.createServer(async (request, response) => {
        const url = new URL(request.url ?? "/", "http://127.0.0.1");
        const route = \`\${request.method} \${url.pathname}\`;

        if (route === "GET /admin/layouts") {
          response.writeHead(200, { "content-type": "application/json" });
          response.end(JSON.stringify({ layouts: LAYOUTS }));
          return;
        }

        response.writeHead(404, { "content-type": "text/plain" });
        response.end("not found");
      });

      server.listen(4010);
    `
  });
  assert.deepEqual(
    categories(found),
    [],
    "a hardcoded list of names is configuration, not the state an authorization check would protect"
  );
});

test("a privileged dispatched route whose helper checks a role is not reported", async () => {
  const found = await runAccess({
    "src/server.js": `
      import http from "node:http";
      import { operators } from "./store.js";
      import { authenticate } from "./auth.js";

      async function listOperators(request, response) {
        const actor = await authenticate(request);
        if (!actor || !actor.roles.includes("staff")) {
          response.writeHead(403, { "content-type": "text/plain" });
          response.end("forbidden");
          return;
        }
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify(operators));
      }

      const server = http.createServer(async (request, response) => {
        const url = new URL(request.url ?? "/", "http://127.0.0.1");
        const route = \`\${request.method} \${url.pathname}\`;

        if (route === "GET /api/admin/operators") {
          await listOperators(request, response);
          return;
        }

        response.writeHead(404, { "content-type": "text/plain" });
        response.end("not found");
      });

      server.listen(4010);
    `
  });
  assert.deepEqual(categories(found), [], "the branch delegates to a helper that compares the caller's roles");
});

test("a decorator-routed role change with no required-role decorator is reported", async () => {
  const found = await runAccess({
    "src/squads/squad-members.controller.ts": `
      import { Body, Controller, Delete, Param, Patch, Req, UseGuards } from "@nestjs/common";
      import { JwtAuthGuard } from "../auth/jwt-auth.guard";
      import { Roles } from "../auth/roles.decorator";
      import { TierGuard } from "../auth/tier.guard";
      import { PrismaService } from "../prisma/prisma.service";

      @UseGuards(JwtAuthGuard, TierGuard)
      @Controller("squads/:squadId/members")
      export class SquadMembersController {
        constructor(private readonly prisma: PrismaService) {}

        @Roles("captain")
        @Delete(":memberId")
        async drop(@Req() req, @Param("memberId") memberId: string) {
          await this.prisma.squadMembership.delete({ where: { id: memberId } });
          return { dropped: memberId };
        }

        @Patch(":memberId/tier")
        async retier(@Req() req, @Param("memberId") memberId: string, @Body() body: { tier: string }) {
          const updated = await this.prisma.squadMembership.update({
            where: { id: memberId },
            data: { tier: body.tier, tierChangedBy: req.user.id }
          });
          return { id: updated.id, tier: updated.tier };
        }
      }
    `
  });
  const hits = of(found, "broken_function_level_authorization");
  assert.equal(hits.length, 1, "a guard that reads metadata nobody declared admits everyone");
  assert.equal(hits[0].route, "PATCH /squads/:squadId/members/:memberId/tier");
  assert.equal(hits[0].severity, "high");
});

test("the same decorator-routed change is quiet when the method declares its required role", async () => {
  const found = await runAccess({
    "src/squads/squad-members.controller.ts": `
      import { Body, Controller, Param, Patch, Req, UseGuards } from "@nestjs/common";
      import { JwtAuthGuard } from "../auth/jwt-auth.guard";
      import { Roles } from "../auth/roles.decorator";
      import { TierGuard } from "../auth/tier.guard";
      import { PrismaService } from "../prisma/prisma.service";

      @UseGuards(JwtAuthGuard, TierGuard)
      @Controller("squads/:squadId/members")
      export class SquadMembersController {
        constructor(private readonly prisma: PrismaService) {}

        @Roles("captain")
        @Patch(":memberId/tier")
        async retier(@Req() req, @Param("memberId") memberId: string, @Body() body: { tier: string }) {
          const updated = await this.prisma.squadMembership.update({
            where: { id: memberId },
            data: { tier: body.tier, tierChangedBy: req.user.id }
          });
          return { id: updated.id, tier: updated.tier };
        }
      }
    `
  });
  assert.deepEqual(categories(found), [], "the required role is declared on the method the guard protects");
});

test("a route decorator whose path segment reads like a privilege is not an authorization check", async () => {
  const found = await runAccess({
    "src/squads/squad-roles.controller.ts": `
      import { Body, Controller, Param, Patch, Req, UseGuards } from "@nestjs/common";
      import { JwtAuthGuard } from "../auth/jwt-auth.guard";
      import { PrismaService } from "../prisma/prisma.service";

      @UseGuards(JwtAuthGuard)
      @Controller("squads/:squadId")
      export class SquadRolesController {
        constructor(private readonly prisma: PrismaService) {}

        @Patch("roles/:memberId")
        async retier(@Req() req, @Param("memberId") memberId: string, @Body() body: { tier: string }) {
          const updated = await this.prisma.squadMembership.update({
            where: { id: memberId },
            data: { tier: body.tier, tierChangedBy: req.user.id }
          });
          return { id: updated.id, tier: updated.tier };
        }
      }
    `
  });
  const hits = of(found, "broken_function_level_authorization");
  assert.equal(hits.length, 1, "`@Patch(\"roles/:memberId\")` is an address, not a required role");
});

test("a rank comparison between two roles is recognised as the authorization decision", async () => {
  const found = await runAccess({
    "src/pods.js": `
      const express = require("express");
      const { pool } = require("../lib/db");
      const { requireUser } = require("../middleware/auth");

      const router = express.Router();
      const RANK = { guest: 0, crew: 1, captain: 2 };

      router.patch("/pods/:podId/people/:personId/rank", requireUser, async (req, res) => {
        const target = await pool.query("select role from pod_people where id = $1", [req.params.personId]);
        if (RANK[req.session.role] <= RANK[target.rows[0].role]) {
          return res.status(403).json({ error: "outranked" });
        }
        await pool.query("UPDATE pod_people SET role = $1 WHERE id = $2", [req.body.role, req.params.personId]);
        res.json({ ok: true });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(categories(found), [], "the caller's rank is compared against the target's before the write");
});

/* ----------------------------------------------------------- missing_csrf_protection */

test("a cookie-authenticated state change with a cross-site cookie and no token is reported", async () => {
  const found = await runAccess({
    "app/api/ops/[verb]/route.ts": `
      import { cookies } from "next/headers";
      import { eq } from "drizzle-orm";
      import { readSession } from "@/lib/session";
      import { db } from "@/lib/db";
      import { pods } from "@/db/schema";

      const SESSION_COOKIE = "sid";
      const COOKIE_OPTIONS = { httpOnly: true, secure: true, sameSite: "none" as const, path: "/" };

      async function renamePod(session, form: FormData) {
        return db.update(pods).set({ name: String(form.get("name") ?? "") }).where(eq(pods.id, session.podId));
      }

      const VERBS = { "pod.rename": renamePod };

      export async function POST(request: Request, { params }) {
        const { verb } = await params;
        const handler = VERBS[verb];
        if (!handler) return Response.json({ error: "unknown" }, { status: 404 });
        const jar = await cookies();
        const session = await readSession(jar.get(SESSION_COOKIE)?.value ?? "");
        if (!session) return Response.json({ error: "no" }, { status: 401 });
        const form = await request.formData();
        const result = await handler(session, form);
        const response = Response.json({ ok: true, result });
        response.cookies.set(SESSION_COOKIE, session.token, COOKIE_OPTIONS);
        return response;
      }
    `
  });
  const hits = of(found, "missing_csrf_protection");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high", "a form-encoded body needs no preflight, so a plain form works");
  assert.match(hits[0].summary, /server actions do not have this exposure/i, "the framework distinction is explained");
});

test("the same dispatcher is quiet when it checks the origin", async () => {
  const found = await runAccess({
    "app/api/ops/[verb]/route.ts": `
      import { cookies } from "next/headers";
      import { eq } from "drizzle-orm";
      import { readSession } from "@/lib/session";
      import { db } from "@/lib/db";
      import { pods } from "@/db/schema";

      const SESSION_COOKIE = "sid";
      const COOKIE_OPTIONS = { httpOnly: true, secure: true, sameSite: "none" as const, path: "/" };
      const ALLOWED_ORIGINS = new Set(["https://app.example", "https://portal.example"]);

      async function renamePod(session, form: FormData) {
        return db.update(pods).set({ name: String(form.get("name") ?? "") }).where(eq(pods.id, session.podId));
      }

      const VERBS = { "pod.rename": renamePod };

      export async function POST(request: Request, { params }) {
        const { verb } = await params;
        const handler = VERBS[verb];
        if (!handler) return Response.json({ error: "unknown" }, { status: 404 });
        const origin = request.headers.get("origin");
        if (!origin || !ALLOWED_ORIGINS.has(origin)) return Response.json({ error: "origin" }, { status: 403 });
        const jar = await cookies();
        const session = await readSession(jar.get(SESSION_COOKIE)?.value ?? "");
        if (!session) return Response.json({ error: "no" }, { status: 401 });
        const form = await request.formData();
        const result = await handler(session, form);
        const response = Response.json({ ok: true, result });
        response.cookies.set(SESSION_COOKIE, session.token, COOKIE_OPTIONS);
        return response;
      }
    `
  });
  assert.deepEqual(
    categories(found).filter((category) => category === "missing_csrf_protection"),
    [],
    "an origin allowlist is the check this rule looks for"
  );
});

test("a cookie-authenticated state change with a same-site cookie is quiet", async () => {
  const found = await runAccess({
    "app/api/pods/[podId]/notes/route.ts": `
      import { cookies } from "next/headers";
      import { readSession } from "@/lib/session";
      import { db } from "@/lib/db";
      import { notes } from "@/db/schema";

      const COOKIE_OPTIONS = { httpOnly: true, secure: true, sameSite: "lax" as const, path: "/" };

      export async function POST(request: Request) {
        const jar = await cookies();
        const session = await readSession(jar.get("sid")?.value ?? "");
        if (!session) return Response.json({ error: "no" }, { status: 401 });
        const form = await request.formData();
        await db.insert(notes).values({ userId: session.userId, body: String(form.get("body") ?? "") });
        const response = Response.json({ ok: true });
        response.cookies.set("sid", session.token, COOKIE_OPTIONS);
        return response;
      }
    `
  });
  assert.deepEqual(
    categories(found).filter((category) => category === "missing_csrf_protection"),
    [],
    "a SameSite=Lax cookie is not attached to a cross-site form submission at all"
  );
});

/* ------------------------------------------------------------- sensitive_data_in_logs */

test("logging the whole request body is reported", async () => {
  const found = await runAccess({
    "src/instruments.js": `
      const { randomUUID } = require("node:crypto");

      const cardSchema = {
        body: {
          type: "object",
          properties: { cardNumber: { type: "string" }, securityCode: { type: "string" } }
        }
      };

      export default async function (fastify) {
        fastify.post("/instruments", { preHandler: [fastify.authenticate], schema: cardSchema }, async (request, reply) => {
          const correlationId = randomUUID();
          request.log.info({ correlationId, accountId: request.user.accountId, body: request.body }, "intake received");
          const token = await fastify.processor.tokenise({ number: request.body.cardNumber });
          return reply.code(201).send({ token: token.id });
        });
      }
    `
  });
  const hits = of(found, "sensitive_data_in_logs");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high", "the module's own schema shows credential fields inside the logged object");
  assert.match(hits[0].summary, /cardNumber/, "the fields that end up in the log are named");
});

test("logging named non-sensitive fields and a truncation is quiet", async () => {
  const found = await runAccess({
    "src/instruments.js": `
      const { randomUUID } = require("node:crypto");

      export default async function (fastify) {
        fastify.post("/instruments", { preHandler: [fastify.authenticate] }, async (request, reply) => {
          const correlationId = randomUUID();
          request.log.info(
            {
              correlationId,
              accountId: request.user.accountId,
              country: request.body.country,
              cardLast4: request.body.cardNumber.slice(-4)
            },
            "intake received"
          );
          const token = await fastify.processor.tokenise({ number: request.body.cardNumber });
          return reply.code(201).send({ token: token.id });
        });
      }
    `
  });
  assert.deepEqual(
    categories(found).filter((category) => category === "sensitive_data_in_logs"),
    [],
    "a correlation id, named scalars, and a truncation reveal nothing"
  );
});

test("logging a field whose name says it is a credential is reported", async () => {
  const found = await runAccess({
    "src/exchange.js": `
      const logger = require("../lib/logger");

      export async function exchange(req, res) {
        logger.debug({ traceId: req.id, refreshToken: req.body.refreshToken }, "exchanging token");
        res.json({ ok: true });
      }
    `
  });
  const hits = of(found, "sensitive_data_in_logs");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high");
});

test("a queue payload the module reads a token out of is reported when logged whole", async () => {
  const found = await runAccess({
    "workers/inbox-refresh.js": `
      "use strict";

      const { Worker } = require("bullmq");
      const { connection } = require("../lib/redis");
      const { logger } = require("../lib/logger");
      const { openInbox, pullSince } = require("../lib/inbox");

      const worker = new Worker(
        "inbox-refresh",
        async (task) => {
          try {
            const client = await openInbox(task.data.provider, {
              accessToken: task.data.accessToken,
              refreshToken: task.data.refreshToken
            });
            const pulled = await pullSince(client, task.data.since);
            logger.info({ taskId: task.id, tenant: task.data.tenantId, pulled }, "inbox refresh complete");
            return { pulled };
          } catch (err) {
            logger.error({ taskId: task.id, err, task: task.data }, "inbox refresh failed");
            throw err;
          }
        },
        { connection }
      );

      module.exports = { worker };
    `
  });
  const hits = of(found, "sensitive_data_in_logs");
  assert.equal(hits.length, 1, "the failure branch logs the payload the access token lives in");
  assert.match(hits[0].summary, /task\.data/);
  assert.match(hits[0].summary, /accessToken/);
  assert.equal(hits[0].severity, "medium");
});

test("logging identifiers and counts off the same payload is quiet", async () => {
  const found = await runAccess({
    "workers/inbox-refresh.js": `
      "use strict";

      const { Worker } = require("bullmq");
      const { connection } = require("../lib/redis");
      const { logger } = require("../lib/logger");
      const { openInbox, pullSince } = require("../lib/inbox");

      const worker = new Worker(
        "inbox-refresh",
        async (task) => {
          try {
            const client = await openInbox(task.data.provider, {
              accessToken: task.data.accessToken,
              refreshToken: task.data.refreshToken
            });
            const pulled = await pullSince(client, task.data.since);
            logger.info({ taskId: task.id, tenant: task.data.tenantId, pulled }, "inbox refresh complete");
            return { pulled };
          } catch (err) {
            logger.error(
              { taskId: task.id, tenant: task.data.tenantId, reason: err.code },
              "inbox refresh failed"
            );
            throw err;
          }
        },
        { connection }
      );

      module.exports = { worker };
    `
  });
  assert.deepEqual(categories(found), [], "an id, a tenant and an error code carry no credential");
});

/* -------------------------------------------------- secret_exposed_to_client_bundle */

test("a public-prefixed service credential is reported", async () => {
  const found = await runAccess({
    "app/(dash)/panels/uploader.tsx": `
      "use client";
      import { useState } from "react";

      const ENDPOINT = "https://warehouse.example/v1/ingest";
      const KEY = process.env.NEXT_PUBLIC_WAREHOUSE_SERVICE_KEY ?? "";

      export function Uploader() {
        const [state, setState] = useState("idle");
        async function send(file: File) {
          await fetch(ENDPOINT, { method: "POST", headers: { authorization: \`Bearer \${KEY}\` }, body: file });
          setState("done");
        }
        return <input type="file" onChange={(event) => event.target.files && send(event.target.files[0])} />;
      }
    `
  });
  const hits = of(found, "secret_exposed_to_client_bundle");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "critical");
  assert.match(hits[0].remediation, /short-lived/, "the fix is a scoped token minted on the server");
});

test("a publishable key and a server-only variable are quiet", async () => {
  const found = await runAccess({
    "app/(dash)/panels/checkout.tsx": `
      "use client";
      const PUBLISHABLE = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY ?? "";
      const SITE = process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY ?? "";
      const ENDPOINT = process.env.NEXT_PUBLIC_API_URL ?? "";

      export function Checkout() {
        return <span data-key={PUBLISHABLE} data-site={SITE} data-api={ENDPOINT} />;
      }
    `,
    "app/(dash)/panels/panel.tsx": `
      import { mintUploadToken } from "@/lib/warehouse";

      export default async function Panel({ datasetId }: { datasetId: string }) {
        const token = await mintUploadToken({ serviceKey: process.env.WAREHOUSE_SERVICE_KEY, datasetId });
        return <span data-token={token} />;
      }
    `
  });
  assert.deepEqual(
    categories(found).filter((category) => category === "secret_exposed_to_client_bundle"),
    [],
    "a publishable key is meant to be public and a server-only variable never reaches the bundle"
  );
});

/* ------------------------------------------------ sign-off without authorization */

test("a server function that signs off a record with only a session check is reported", async () => {
  const found = await runAccess({
    "app/server/change-orders.ts": `
      import { createServerFn } from "@tanstack/start";
      import { z } from "zod";
      import { db } from "../lib/db";
      import { requireSession } from "../lib/session";

      const schema = z.object({ changeOrderId: z.string().uuid() });

      export const approveChangeOrder = createServerFn({ method: "POST" })
        .validator((input: unknown) => schema.parse(input))
        .handler(async ({ data }) => {
          const session = await requireSession();

          const order = await db.changeOrder.findUnique({
            where: { id: data.changeOrderId },
            select: { id: true, tenantId: true, raisedById: true, totalCents: true }
          });
          if (!order || order.tenantId !== session.tenantId) throw new Error("gone");

          return db.changeOrder.update({
            where: { id: order.id },
            data: { status: "approved", approvedById: session.userId, approvedAt: new Date() },
            select: { id: true, status: true }
          });
        });
    `
  });
  const hits = of(found, "broken_function_level_authorization");
  assert.equal(hits.length, 1);
  assert.match(hits[0].title, /approveChangeOrder/, "the finding is addressed by the name a client imports");
  assert.ok(
    hits[0].route === undefined || !hits[0].route.includes("/"),
    "a server function is addressed by the name a client imports, never by an invented URL path"
  );
  assert.match(hits[0].summary, /approved state/);
});

test("the same sign-off is quiet when the handler requires an approving role", async () => {
  const found = await runAccess({
    "app/server/change-orders.ts": `
      import { createServerFn } from "@tanstack/start";
      import { z } from "zod";
      import { db } from "../lib/db";
      import { requireRole } from "../lib/authz";
      import { requireSession } from "../lib/session";

      const schema = z.object({ changeOrderId: z.string().uuid() });

      export const approveChangeOrder = createServerFn({ method: "POST" })
        .validator((input: unknown) => schema.parse(input))
        .handler(async ({ data }) => {
          const session = await requireSession();
          requireRole(session, "approver", "finance");

          const order = await db.changeOrder.findUnique({
            where: { id: data.changeOrderId },
            select: { id: true, tenantId: true, raisedById: true }
          });
          if (!order || order.tenantId !== session.tenantId) throw new Error("gone");

          return db.changeOrder.update({
            where: { id: order.id },
            data: { status: "approved", approvedById: session.userId, approvedAt: new Date() },
            select: { id: true, status: true }
          });
        });
    `
  });
  assert.deepEqual(
    of(found, "broken_function_level_authorization"),
    [],
    "the role the operation needs is compared before the write"
  );
});

test("a sign-off narrowed to the caller's own row is quiet", async () => {
  const found = await runAccess({
    "app/server/consents.ts": `
      import { createServerFn } from "@tanstack/start";
      import { db } from "../lib/db";
      import { requireSession } from "../lib/session";

      export const grantConsent = createServerFn({ method: "POST" })
        .handler(async ({ data }) => {
          const session = await requireSession();
          return db.consentGrant.update({
            where: { id: data.grantId, userId: session.userId },
            data: { status: "approved", approvedAt: new Date() },
            select: { id: true }
          });
        });
    `
  });
  assert.deepEqual(
    of(found, "broken_function_level_authorization"),
    [],
    "a subject approving their own row escalates nothing"
  );
});

test("a sign-off that refuses the requester as approver is quiet", async () => {
  const found = await runAccess({
    "app/server/claims.ts": `
      import { createServerFn } from "@tanstack/start";
      import { db } from "../lib/db";
      import { requireSession } from "../lib/session";

      export const approveClaim = createServerFn({ method: "POST" })
        .handler(async ({ data }) => {
          const session = await requireSession();
          const claim = await db.claim.findUnique({
            where: { id: data.claimId },
            select: { id: true, submittedById: true }
          });
          if (!claim) throw new Error("gone");
          if (claim.submittedById === session.userId) throw new Error("cannot approve your own claim");

          return db.claim.update({
            where: { id: claim.id },
            data: { status: "approved", approvedById: session.userId },
            select: { id: true }
          });
        });
    `
  });
  assert.deepEqual(
    of(found, "broken_function_level_authorization"),
    [],
    "separation of duties is the control an approval workflow turns on"
  );
});

test("a raw-SQL sign-off is recognised from the state the statement writes", async () => {
  const found = await runAccess({
    "src/routes/invoices.js": `
      const express = require("express");
      const { pool } = require("../db");
      const { requireSession } = require("../session");

      const router = express.Router();

      router.post("/invoices/:id/approve", async (request, response) => {
        const session = await requireSession(request);
        await pool.query(
          "UPDATE invoices SET status = 'approved', approved_by = $2, approved_at = now() WHERE id = $1",
          [request.params.id, session.userId]
        );
        response.json({ ok: true });
      });

      module.exports = router;
    `
  });
  const hits = of(found, "broken_function_level_authorization");
  assert.equal(hits.length, 1, "the column names never say `role`, and the statement is still a sign-off");
  assert.match(hits[0].reasoning, /approved state/);
});

test("creating a record that is already approved is not a sign-off", async () => {
  const found = await runAccess({
    "app/server/imports.ts": `
      import { createServerFn } from "@tanstack/start";
      import { db } from "../lib/db";
      import { requireSession } from "../lib/session";

      export const recordAutoApproval = createServerFn({ method: "POST" })
        .handler(async ({ data }) => {
          const session = await requireSession();
          return db.approvalRecord.create({
            data: { subjectId: data.subjectId, status: "approved", approvedById: session.userId },
            select: { id: true }
          });
        });
    `
  });
  assert.deepEqual(
    of(found, "broken_function_level_authorization"),
    [],
    "a row that comes into existence approved changes no earlier decision"
  );
});

/* --------------------------------- unauthenticated external extension channels */

const COMPANION_WORKER = `
  const API = "https://api.example.com";

  async function readToken() {
    const { linkedToken } = await chrome.storage.local.get("linkedToken");
    if (!linkedToken) throw new Error("not_linked");
    return linkedToken;
  }

  async function call(path) {
    const response = await fetch(API + path, {
      headers: { authorization: "Bearer " + (await readToken()) }
    });
    return response.json();
  }

  const commands = {
    listVaults: () => call("/v1/vaults"),
    vaultSecrets: ({ vaultId }) => call("/v1/vaults/" + encodeURIComponent(vaultId) + "/secrets")
  };

  function run(message) {
    const command = commands[message && message.kind];
    if (!command) return Promise.reject(new Error("unknown_command"));
    return command(message);
  }
`;

test("an external extension listener that lends the worker's token is reported", async () => {
  const found = await runAccess({
    "background/service-worker.js": `${COMPANION_WORKER}
      chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
        run(message).then(
          (result) => sendResponse({ ok: true, result }),
          (error) => sendResponse({ ok: false, error: error.message })
        );
        return true;
      });

      chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
        run(message).then((result) => sendResponse({ ok: true, result }));
        return true;
      });
    `
  });
  const hits = of(found, "missing_authentication");
  assert.equal(hits.length, 1, "only the channel a web page can address is reported");
  assert.match(hits[0].title, /onMessageExternal/);
  assert.match(hits[0].summary, /onMessage\b/, "the internal sibling is named as the boundary this one is not");
  assert.equal(hits[0].verification, "strong_evidence");
});

test("the same worker is quiet when the external listener checks the sender's origin", async () => {
  const found = await runAccess({
    "background/service-worker.js": `${COMPANION_WORKER}
      const CONSOLE_ORIGIN = "https://app.example.com";

      chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
        if (sender.origin !== CONSOLE_ORIGIN) {
          sendResponse({ ok: false, error: "forbidden_origin" });
          return false;
        }
        run(message).then((result) => sendResponse({ ok: true, result }));
        return true;
      });

      chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
        run(message).then((result) => sendResponse({ ok: true, result }));
        return true;
      });
    `
  });
  assert.deepEqual(
    of(found, "missing_authentication"),
    [],
    "the browser-filled sender is compared against an allow list, which is the whole of authentication here"
  );
});

test("an internal-only extension worker with no sender check is quiet", async () => {
  const found = await runAccess({
    "background/service-worker.js": `${COMPANION_WORKER}
      chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
        run(message).then((result) => sendResponse({ ok: true, result }));
        return true;
      });
    `
  });
  assert.deepEqual(
    of(found, "missing_authentication"),
    [],
    "runtime.onMessage is reachable only from the extension's own scripts, which need no sender check"
  );
});

test("an external listener that reaches no privileged capability is quiet", async () => {
  const found = await runAccess({
    "background/service-worker.js": `
      chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
        sendResponse({ ok: true, version: chrome.runtime.getManifest().version });
        return true;
      });
    `
  });
  assert.deepEqual(
    of(found, "missing_authentication"),
    [],
    "answering with the extension's own version lends nothing the page did not already have"
  );
});

/* ------------------------------------------- missing_authentication: webhook receivers */

/*
 * A webhook receiver is unauthenticated by design in exactly one sense — no session
 * reaches it — and is emphatically not open by design: the issuer signs the payload so
 * the receiver can refuse everybody else.
 *
 * Three separate gates used to suppress this whole class, each of them correct for a
 * session-authenticated route and wrong for a receiver: a module needed two endpoints, it
 * needed one that already authenticated, and the handler had to touch a record belonging
 * to an identifiable subject. A webhook module usually holds exactly one receiver, which
 * authenticates nothing and writes rows keyed by a carrier reference, so it failed all
 * three. A fourth gate then exempted it for "establishing a session", because handling a
 * shared signing secret has the vocabulary of a credential exchange.
 */

const WEBHOOK_HELPERS = `
  import crypto from "node:crypto";
  export const SIGNING_SECRETS: Record<string, string> = {
    northline: process.env.NORTHLINE_SECRET ?? "",
    tidewater: process.env.TIDEWATER_SECRET ?? ""
  };
  export function expectedSignature(secret: string, body: string): Buffer {
    return crypto.createHmac("sha256", secret).update(body).digest();
  }
`;

test("a lone webhook receiver whose signature check is optional is reported as a candidate", async () => {
  const found = await runAccess({
    "src/lib/signing.ts": WEBHOOK_HELPERS,
    "src/webhooks/carrier-status.ts": `
      import crypto from "node:crypto";
      import express from "express";
      import { SIGNING_SECRETS, expectedSignature } from "../lib/signing";
      import { db } from "../lib/db";

      export const router = express.Router();

      router.post("/api/webhooks/carrier-status", async (req, res) => {
        const raw = JSON.stringify(req.body);
        const carrierCode = req.body.carrierCode;
        const signature = req.header("x-carrier-signature");
        const secret = SIGNING_SECRETS[carrierCode];
        // Carriers that have finished onboarding sign their callbacks.
        if (signature && secret) {
          const expected = expectedSignature(secret, raw);
          if (!crypto.timingSafeEqual(Buffer.from(signature, "hex"), expected)) {
            return res.status(401).json({ error: "bad signature" });
          }
        }
        await db.update("consignments", { status: req.body.status }, { reference: req.body.reference });
        return res.json({ ok: true });
      });
    `
  });
  const reported = of(found, "missing_authentication");
  assert.equal(reported.length, 1, `expected one finding, got ${JSON.stringify(categories(found))}`);
  // Nothing in the module verifies a signature unconditionally, so middleware outside
  // this file cannot be ruled out and the finding is a question rather than a claim.
  assert.equal(reported[0].verification, "needs_review");
  assert.match(reported[0].title, /unsigned event body/);
});

test("a lone webhook receiver that verifies before writing is silent", async () => {
  const found = await runAccess({
    "src/lib/signing.ts": WEBHOOK_HELPERS,
    "src/webhooks/carrier-milestones.ts": `
      import crypto from "node:crypto";
      import express from "express";
      import { SIGNING_SECRETS, expectedSignature } from "../lib/signing";
      import { db } from "../lib/db";

      export const router = express.Router();

      router.post("/api/webhooks/carrier-milestones", async (req, res) => {
        const raw = JSON.stringify(req.body);
        const signature = req.header("x-carrier-signature");
        if (!signature) return res.status(401).json({ error: "unsigned" });
        const secret = SIGNING_SECRETS[req.body.carrierCode];
        if (!secret) return res.status(401).json({ error: "unknown carrier" });
        const expected = expectedSignature(secret, raw);
        if (!crypto.timingSafeEqual(Buffer.from(signature, "hex"), expected)) {
          return res.status(401).json({ error: "bad signature" });
        }
        await db.update("consignments", { milestone: req.body.milestone }, { reference: req.body.reference });
        return res.json({ ok: true });
      });
    `
  });
  assert.deepEqual(of(found, "missing_authentication"), []);
});

test("a receiver is recognised from its module path when neither name nor route says webhook", async () => {
  const found = await runAccess({
    "src/webhooks/inbound.ts": `
      import express from "express";
      import { db } from "../lib/db";

      export const router = express.Router();

      router.post("/api/carrier/events", async (req, res) => {
        await db.update("consignments", { status: req.body.status }, { reference: req.body.reference });
        return res.json({ ok: true });
      });
    `
  });
  assert.equal(of(found, "missing_authentication").length, 1);
});

test("a receiver that only reads, and writes nothing, is not reported", async () => {
  const found = await runAccess({
    "src/webhooks/carrier-status.ts": `
      import express from "express";
      import { db } from "../lib/db";

      export const router = express.Router();

      router.post("/api/webhooks/carrier-status", async (req, res) => {
        const row = await db.select("consignments", { reference: req.body.reference });
        return res.json({ known: Boolean(row) });
      });
    `
  });
  assert.deepEqual(of(found, "missing_authentication"), []);
});

test("a verified sibling in the same module states the finding as established rather than as a question", async () => {
  const found = await runAccess({
    "src/lib/signing.ts": WEBHOOK_HELPERS,
    "src/webhooks/carrier.ts": `
      import crypto from "node:crypto";
      import express from "express";
      import { SIGNING_SECRETS, expectedSignature } from "../lib/signing";
      import { db } from "../lib/db";

      export const router = express.Router();

      router.post("/api/webhooks/carrier-milestones", async (req, res) => {
        const signature = req.header("x-carrier-signature");
        if (!signature) return res.status(401).json({ error: "unsigned" });
        const secret = SIGNING_SECRETS[req.body.carrierCode];
        if (!secret) return res.status(401).json({ error: "unknown carrier" });
        const expected = expectedSignature(secret, JSON.stringify(req.body));
        if (!crypto.timingSafeEqual(Buffer.from(signature, "hex"), expected)) {
          return res.status(401).json({ error: "bad signature" });
        }
        await db.update("consignments", { milestone: req.body.milestone }, { reference: req.body.reference });
        return res.json({ ok: true });
      });

      router.post("/api/webhooks/carrier-status", async (req, res) => {
        await db.update("consignments", { status: req.body.status }, { reference: req.body.reference });
        return res.json({ ok: true });
      });
    `
  });
  const reported = of(found, "missing_authentication");
  assert.equal(reported.length, 1, `expected one finding, got ${reported.length}`);
  assert.equal(reported[0].verification, "strong_evidence");
  // The example a reader is sent to must be the verifying receiver, not a session route.
  assert.match(reported[0].reasoning, /verify their signature/);
});
