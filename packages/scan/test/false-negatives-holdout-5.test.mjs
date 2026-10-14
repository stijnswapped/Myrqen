import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * The false negatives holdout-5 found, each pinned as a pair.
 *
 * Every one was a real defect this engine said nothing about, and none of them was
 * missed for want of an idea: the rule existed, understood the shape, and was
 * switched off by something incidental — an import, a credential that was not a
 * session, a `??`, a repository named after its rows, a URL parsed on its own line,
 * a data layer that owns its pool.
 *
 * The negative half of each pair is the load-bearing half. A rule can be made to
 * fire on anything; what these assert is that it still refuses the corrected form.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-fn5-"));
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

const has = (result, category) => result.candidates.some((candidate) => candidate.category === category);
const PKG = (deps) => JSON.stringify({ name: "case", version: "1.0.0", private: true, dependencies: deps });

/* ------------------------- an import is not a guard (the widest of these by far) */

const twoHandlers = (imports) => `import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
${imports}

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const session = await requireSession();
  const { id } = await context.params;
  const document = await prisma.document.findUnique({ where: { id }, select: { id: true, body: true, workspaceId: true } });
  if (!document) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json({ document });
}
`;

test("importing an authorization helper does not excuse a handler that never calls it", async () => {
  const result = await scanSource({
    "package.json": PKG({ next: "^15.0.0", "@prisma/client": "^5.14.0" }),
    "src/app/api/documents/[id]/route.ts": twoHandlers(`import { requireMembership, requireSession } from "@/lib/auth";`)
  });
  assert.ok(has(result, "broken_object_level_authorization"));
});

test("a membership check the handler actually performs still excuses it", async () => {
  const result = await scanSource({
    "package.json": PKG({ next: "^15.0.0", "@prisma/client": "^5.14.0" }),
    "src/app/api/documents/[id]/route.ts": `import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireMembership, requireSession } from "@/lib/auth";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const session = await requireSession();
  const { id } = await context.params;
  const document = await prisma.document.findUnique({ where: { id }, select: { id: true, body: true, workspaceId: true } });
  if (!document) return NextResponse.json({ error: "not found" }, { status: 404 });
  const membership = await requireMembership(session.user.id, document.workspaceId);
  if (!membership) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json({ document });
}
`
  });
  assert.ok(!has(result, "broken_object_level_authorization"));
});

/* --------------------------- an API key is an identity, and a scope is not a guard */

const metered = (binding) => `import { Hono } from "hono";
const app = new Hono<{ Bindings: { DB: D1Database } }>();
app.get("/v1/quota/:customerId", async (c) => {
  const key = requireApiKey(c);
  requireScope(key, "quota:read");
  const customerId = c.req.param("customerId");
  const result = await c.env.DB.prepare("SELECT metric, used_units FROM quotas WHERE customer_id = ?1").bind(${binding}).all();
  const rows = result.results ?? [];
  return c.json({ rows });
});
export default app;
`;

test("an API-key service has an identity, and a scope check is not an ownership check", async () => {
  const result = await scanSource({
    "package.json": PKG({ hono: "^4.4.0" }),
    "src/quota.ts": metered("customerId")
  });
  assert.ok(has(result, "broken_object_level_authorization"));
});

test("the same query bound to the key's own account is scoped", async () => {
  const result = await scanSource({
    "package.json": PKG({ hono: "^4.4.0" }),
    "src/quota.ts": metered("key.accountId")
  });
  assert.ok(!has(result, "broken_object_level_authorization"));
});

/* ------------------------------ a repository named after what it holds */

const nestController = (write) => `import { Controller, Patch, Body, Param, Req } from "@nestjs/common";
import { Repository } from "typeorm";

@Controller("subscriptions")
export class SubscriptionsController {
  constructor(private readonly subscriptions: Repository<Subscription>) {}

  @Patch(":id")
  async change(@Param("id") id: string, @Body() patch: PlanChangeDto, @Req() req: any) {
    const subscription = await this.subscriptions.findOneOrFail({ where: { id, orgId: req.user.orgId } });
${write}
    await this.subscriptions.save(updated);
    return updated;
  }
}
`;

test("a payload merged into an injected repository is a database write", async () => {
  const result = await scanSource({
    "package.json": PKG({ "@nestjs/common": "^10.3.0", typeorm: "^0.3.20" }),
    "src/subscriptions.controller.ts": nestController(
      `    const updated = this.subscriptions.merge(subscription, { ...patch, planCode: subscription.planCode });`
    )
  });
  assert.ok(has(result, "mass_assignment"));
});

test("fields copied across explicitly are not a mass assignment", async () => {
  const result = await scanSource({
    "package.json": PKG({ "@nestjs/common": "^10.3.0", typeorm: "^0.3.20" }),
    "src/subscriptions.controller.ts": nestController(
      `    const updated = this.subscriptions.merge(subscription, { seats: patch.seats, notes: patch.notes });`
    )
  });
  assert.ok(!has(result, "mass_assignment"));
});

/* ------------------------- the query string of a Web-standard handler */

const search = (source, statement) => `import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(request: Request) {
  ${source}
  const rows = await prisma.$queryRawUnsafe(${statement});
  return NextResponse.json({ rows });
}
`;

test("search params bound to a local name are still the caller's data", async () => {
  const result = await scanSource({
    "package.json": PKG({ next: "^15.0.0", "@prisma/client": "^5.14.0" }),
    "src/app/api/search/route.ts": search(
      `const params = new URL(request.url).searchParams;
  const sort = params.get("sort") ?? "rank";`,
      "`SELECT id FROM \"Document\" ORDER BY ${sort}`"
    )
  });
  assert.ok(has(result, "sql_injection"));
});

test("a URL parsed from configuration is not the caller's data", async () => {
  const result = await scanSource({
    "package.json": PKG({ next: "^15.0.0", "@prisma/client": "^5.14.0" }),
    "src/app/api/search/route.ts": search(
      `const params = new URL(process.env.BASE_URL ?? "").searchParams;
  const sort = params.get("sort") ?? "rank";`,
      "`SELECT id FROM \"Document\" ORDER BY ${sort}`"
    )
  });
  assert.ok(!has(result, "sql_injection"));
});

/* --------------------------------- a data layer that owns its own pool */

const wrapped = (call) => `import type { FastifyInstance } from "fastify";
import { query } from "../db/pool.js";

export async function routes(fastify: FastifyInstance) {
  fastify.get("/api/reports", { schema: {} }, async (request) => {
    const sort = request.query.sort ?? "settled_at";
    const result = await ${call};
    return { rows: result.rows };
  });
}
`;

test("a project's own query helper is a SQL sink when it is handed a statement", async () => {
  const result = await scanSource({
    "package.json": PKG({ fastify: "^4.28.0", pg: "^8.11.5" }),
    "src/reports.ts": wrapped("query(`SELECT id FROM settlements ORDER BY ${sort} desc`)")
  });
  assert.ok(has(result, "sql_injection"));
});

test("the same helper handed a bound statement is not a finding", async () => {
  const result = await scanSource({
    "package.json": PKG({ fastify: "^4.28.0", pg: "^8.11.5" }),
    "src/reports.ts": wrapped('query("SELECT id FROM settlements WHERE merchant_id = $1", [getSession(request).merchantId])')
  });
  assert.ok(!has(result, "sql_injection"));
});

test("a same-named helper that is not given a statement is not a SQL sink", async () => {
  const result = await scanSource({
    "package.json": PKG({ fastify: "^4.28.0", pg: "^8.11.5" }),
    "src/reports.ts": wrapped("query(`#settlement-grid-${sort}`)")
  });
  assert.ok(!has(result, "sql_injection"));
});
