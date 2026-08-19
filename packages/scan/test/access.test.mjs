import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { parseFile } from "../dist/ast/parse.js";
import { discoverRoutes } from "../dist/ast/routes.js";
import * as accessRules from "../dist/rules/access.js";

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
