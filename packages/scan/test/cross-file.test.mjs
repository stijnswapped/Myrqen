import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";
import { resolveRelative } from "../dist/ast/call-sites.js";

/**
 * One call boundary, across a file, and the guard that keeps it honest.
 *
 * A layered application puts the caller's value in a plain function parameter one module
 * away. The service file has no entry point, so it has no seeds, so nothing in it is
 * caller-controlled and every rule judging a sink inside it stays silent — three of
 * holdout-6's misses are that shape.
 *
 * The pairs below are the point. Each positive has a negative that must stay silent,
 * because the whole risk of crossing a boundary is inventing a flow: an earlier attempt
 * at widening taint immediately reported a validated executable path in this project's
 * own source, and was closed by requiring *observed* taint rather than *inferred*.
 */
async function scanFiles(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-xfile-"));
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
const PKG = JSON.stringify({
  name: "layered",
  version: "1.0.0",
  private: true,
  dependencies: { "@nestjs/common": "^10.3.0", typeorm: "^0.3.20" }
});

const SERVICE = `import { Injectable, NotFoundException } from "@nestjs/common";
import { Repository } from "typeorm";
import type { AuthenticatedUser } from "../auth/guard";

@Injectable()
export class InvoicesService {
  constructor(private readonly invoices: Repository<Invoice>) {}

  async getInvoiceDetail(invoiceId: string, actor: AuthenticatedUser): Promise<Invoice> {
    const invoice = await this.invoices.findOne({ where: { id: invoiceId } });
    if (!invoice) throw new NotFoundException();
    return invoice;
  }
}
`;

const controller = (call) => `import { Controller, Get, Param } from "@nestjs/common";
import { InvoicesService } from "./invoices.service";
import { CurrentUser, type AuthenticatedUser } from "../auth/guard";

@Controller("api/invoices")
export class InvoicesController {
  constructor(private readonly invoices: InvoicesService) {}

  @Get(":invoiceId")
  async detail(@Param("invoiceId") invoiceId: string, @CurrentUser() actor: AuthenticatedUser) {
    return ${call};
  }
}
`;

const GUARD = `export interface AuthenticatedUser { id: string; organisationId: string }
export const CurrentUser = () => (target: unknown, key: string, index: number) => undefined;
`;

test("a service reached from a controller is analysed with the caller's value", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/auth/guard.ts": GUARD,
    "src/invoices/invoices.service.ts": SERVICE,
    "src/invoices/invoices.controller.ts": controller("this.invoices.getInvoiceDetail(invoiceId, actor)")
  });
  assert.ok(
    has(result, "broken_object_level_authorization"),
    "the unscoped lookup in the service is reached through the controller's call"
  );
});

test("the same service is silent when nothing hands it caller data", async () => {
  // The controller passes a value it chose itself. The service is byte-identical, so
  // this is the whole difference between an observation and an assumption.
  const result = await scanFiles({
    "package.json": PKG,
    "src/auth/guard.ts": GUARD,
    "src/invoices/invoices.service.ts": SERVICE,
    "src/invoices/invoices.controller.ts": controller('this.invoices.getInvoiceDetail("fixed-internal-id", actor)')
  });
  assert.ok(!has(result, "broken_object_level_authorization"));
});

test("a service nobody calls is silent", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/auth/guard.ts": GUARD,
    "src/invoices/invoices.service.ts": SERVICE
  });
  assert.ok(!has(result, "broken_object_level_authorization"));
});

test("the authenticated subject handed across a boundary is not the caller's data", async () => {
  // `session` really is derived from the request, and the taint model is right to say so
  // for its own purposes. Recording it as a caller-controlled parameter would tell every
  // rule downstream that the identity is attacker-chosen, which unscopes every predicate
  // built from it — the correctly scoped query becomes the reported defect.
  const result = await scanFiles({
    "package.json": JSON.stringify({ name: "w", version: "1.0.0", private: true, dependencies: { pg: "^8.11.5" } }),
    "src/db.ts": `export async function one<T>(sql: string, values: unknown[]): Promise<T | null> {
  return null as T | null;
}
`,
    "src/wallet.ts": `import { one } from "./db";

export async function readWallet(session: { userId: string }, walletId: string) {
  return one(\`SELECT id, balance_cents FROM wallets WHERE id = $1 AND owner_id = $2\`, [walletId, session.userId]);
}
`,
    "src/route.ts": `import { readWallet } from "./wallet";

export async function GET(request: Request) {
  const session = await resolveSession(request);
  const walletId = new URL(request.url).searchParams.get("walletId") ?? "";
  const wallet = await readWallet(session, walletId);
  return Response.json({ wallet });
}
`
  });
  assert.ok(
    !has(result, "broken_object_level_authorization"),
    "the query is scoped by owner_id against the session, so nothing is wrong here"
  );
});

/* ----------------------------------------------------------- module resolution */

test("a relative specifier resolves against the files actually discovered", async () => {
  const known = new Set(["src/invoices/invoices.service.ts", "src/lib/db/index.ts", "src/util.js"]);
  assert.equal(
    resolveRelative("src/invoices/invoices.controller.ts", "./invoices.service", known),
    "src/invoices/invoices.service.ts"
  );
  // TypeScript source is written importing `.js`; the file on disk is `.ts`.
  assert.equal(resolveRelative("src/a.ts", "./util.js", known), "src/util.js");
  assert.equal(resolveRelative("src/routes/x.ts", "../lib/db", known), "src/lib/db/index.ts");
});

test("a specifier pointing outside the project resolves to nothing", async () => {
  const known = new Set(["src/a.ts"]);
  // A bare specifier is a dependency, and a call into a dependency is not a call into
  // code this scan can see.
  assert.equal(resolveRelative("src/a.ts", "typeorm", known), null);
  assert.equal(resolveRelative("src/a.ts", "@nestjs/common", known), null);
  assert.equal(resolveRelative("src/a.ts", "./missing", known), null);
  // Escaping the root is refused rather than normalised to something plausible.
  assert.equal(resolveRelative("src/a.ts", "../../../etc/passwd", known), null);
});

/* ------------------------------------------------------- utilities versus services */

const UTILITY = `import fs from "node:fs/promises";

export async function readIfPresent(target: string): Promise<string | null> {
  try {
    return await fs.readFile(target, "utf8");
  } catch {
    return null;
  }
}
`;

const caller = (index) => `import { readIfPresent } from "./util";

export async function GET${index}(request: Request) {
  const name = new URL(request.url).searchParams.get("name") ?? "";
  return Response.json({ body: await readIfPresent("/srv/docs/" + name) });
}
`;

test("a helper reached from one place is reported where it is reported", async () => {
  const result = await scanFiles({
    "package.json": JSON.stringify({ name: "u", version: "1.0.0", private: true }),
    "src/util.ts": UTILITY,
    "src/a.ts": caller(1)
  });
  assert.ok(has(result, "path_traversal"));
});

test("a helper everything calls is a utility, and a finding on it is a finding about none of its callers", async () => {
  // Same helper, same argument shape, reached from four routes. Attributing one finding
  // to the wrapper asserts something about all of them at once: false for most, and
  // unhelpful for the rest, because the defect is at whichever call site failed to
  // validate. Measured on this project's own source, where seeding without this reported
  // a one-line `fs.readFile` wrapper.
  const result = await scanFiles({
    "package.json": JSON.stringify({ name: "u", version: "1.0.0", private: true }),
    "src/util.ts": UTILITY,
    "src/a.ts": caller(1),
    "src/b.ts": caller(2),
    "src/c.ts": caller(3),
    "src/d.ts": caller(4)
  });
  const onTheUtility = result.candidates.filter((candidate) => candidate.location.file === "src/util.ts");
  assert.deepEqual(onTheUtility, [], "the wrapper is not where a caller's failure to validate belongs");
});

test("an aliased specifier resolves against the file set, and refuses to guess", async () => {
  // `@/lib/prisma` is the Next.js default and `~/server/…` is Nuxt's. Reading `paths` out
  // of a tsconfig would be more machinery for a worse answer — the mapping can be several
  // entries deep, `baseUrl` shifts it, monorepos nest configs, and none of that changes
  // which file is meant.
  const known = new Set(["src/lib/prisma.ts", "src/lib/db/index.ts", "server/utils/session.ts"]);
  assert.equal(resolveRelative("src/app/api/x/route.ts", "@/lib/prisma", known), "src/lib/prisma.ts");
  assert.equal(resolveRelative("src/app/api/x/route.ts", "@/lib/db", known), "src/lib/db/index.ts");
  assert.equal(resolveRelative("server/api/y.ts", "~/server/utils/session", known), "server/utils/session.ts");

  // A scoped package is not an alias: the slash has to come directly after the `@`.
  assert.equal(resolveRelative("src/a.ts", "@nestjs/common", known), null);
  assert.equal(resolveRelative("src/a.ts", "@/lib/missing", known), null);
});

test("an ambiguous alias resolves to nothing rather than to the wrong file", async () => {
  // Inventing an edge between the wrong two modules is worse than having no edge: it
  // would attribute a finding to a file that never received the value.
  const ambiguous = new Set(["src/lib/db.ts", "packages/api/lib/db.ts"]);
  assert.equal(resolveRelative("src/a.ts", "@/lib/db", ambiguous), null);
});

/*
 * The other two classes a layered application hides.
 *
 * Object-level authorization is covered above, and it was the class the call-site index
 * was built for. These two come along with it and were never pinned: the observed
 * parameter is seeded inside `analyzeFunction`, which is what every data-flow rule
 * consults, so `sql_injection` and `mass_assignment` reach a service method without
 * either rule file knowing the index exists. Untested, that is indistinguishable from
 * luck, and the next change to the seeding would take both away silently.
 */

const nestService = (body) => `import { Injectable } from "@nestjs/common";
import { DataSource, Repository } from "typeorm";

@Injectable()
export class LedgerService {
  constructor(
    private readonly connection: DataSource,
    private readonly entries: Repository<Entry>
  ) {}

${body}
}
`;

const nestController = (decorator, signature, call) => `import { Body, Controller, Param, Query } from "@nestjs/common";
import { LedgerService } from "./ledger.service";

@Controller("api/ledger")
export class LedgerController {
  constructor(private readonly ledger: LedgerService) {}

  ${decorator}
  async handle(${signature}) {
    return ${call};
  }
}
`;

test("a raw statement built inside a delegated service is reported", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/ledger/ledger.service.ts": nestService(
      `  async searchByNarrative(term: string): Promise<unknown[]> {
    return await this.connection.query("select id from entries where narrative like '%" + term + "%'");
  }`
    ),
    "src/ledger/ledger.controller.ts": nestController(
      `@Query("term") @Get("search")`,
      `@Query("term") term: string`,
      "this.ledger.searchByNarrative(term)"
    )
  });
  assert.ok(has(result, "sql_injection"), "the concatenated statement is reached through the controller's call");
});

test("the same service is silent when the statement is parameterised", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/ledger/ledger.service.ts": nestService(
      `  async searchByNarrative(term: string): Promise<unknown[]> {
    return await this.connection.query("select id from entries where narrative like $1", ["%" + term + "%"]);
  }`
    ),
    "src/ledger/ledger.controller.ts": nestController(
      `@Query("term") @Get("search")`,
      `@Query("term") term: string`,
      "this.ledger.searchByNarrative(term)"
    )
  });
  assert.ok(!has(result, "sql_injection"), "a bound parameter carries the value, so the statement is fixed text");
});

test("a caller-supplied object spread inside a delegated service is reported", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/ledger/ledger.service.ts": nestService(
      `  async applyChanges(entryId: string, patch: Record<string, unknown>): Promise<void> {
    await this.entries.update({ id: entryId }, { ...patch });
  }`
    ),
    "src/ledger/ledger.controller.ts": nestController(
      `@Patch(":entryId")`,
      `@Param("entryId") entryId: string, @Body() body: Record<string, unknown>`,
      "this.ledger.applyChanges(entryId, body)"
    )
  });
  assert.ok(has(result, "mass_assignment"), "the spread of the caller's body is reached through the controller");
});

test("the same service is silent when it names the columns it will write", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/ledger/ledger.service.ts": nestService(
      `  async applyChanges(entryId: string, patch: Record<string, unknown>): Promise<void> {
    await this.entries.update({ id: entryId }, { narrative: String(patch.narrative), reference: String(patch.reference) });
  }`
    ),
    "src/ledger/ledger.controller.ts": nestController(
      `@Patch(":entryId")`,
      `@Param("entryId") entryId: string, @Body() body: Record<string, unknown>`,
      "this.ledger.applyChanges(entryId, body)"
    )
  });
  assert.ok(!has(result, "mass_assignment"), "an explicit column list cannot be widened by the caller");
});

/* ------------------------------------ D28: provenance of an authenticated principal */

/*
 * The vocabulary fix landed first and works only for the ~40 names in `IDENTITY_EVIDENCE`.
 * These two cases use a name that is deliberately *not* on that list, so they fail until the
 * engine can answer the question by shape: does this helper's return value derive from a
 * server-owned property of the request, whatever the helper is called?
 *
 * The pair is the point. If only the positive existed, deleting the traversal rule would
 * pass it.
 */

const ORG_CONTEXT = `import type { Request } from "express";

export interface OrgContext {
  actorId: string;
  workspaceSlug: string;
}

/** Resolves the workspace from the authenticated principal, never from the wire. */
export function establishOrgContext(req: Request): OrgContext {
  const principal = (req as any).user;
  if (!principal) {
    throw new Error("unauthenticated");
  }
  return { actorId: principal.id, workspaceSlug: principal.workspace };
}
`;

const ORG_CONTEXT_FROM_HEADER = ORG_CONTEXT.replace(
  "const principal = (req as any).user;",
  "const principal = { id: req.headers[\"x-actor\"], workspace: req.headers[\"x-workspace\"] };"
);

const STORE = `import path from "node:path";

const ROOT = "/srv/workspaces";

export function resolveInWorkspace(workspaceSlug: string, leaf: string) {
  return path.join(ROOT, workspaceSlug, leaf);
}
`;

const ROUTE = `import express from "express";
import { establishOrgContext } from "../lib/org-context";
import { resolveInWorkspace } from "../lib/store";

const LEAF = /^[A-Za-z0-9._-]+$/;

export const router = express.Router();
router.get("/workspace/exports/:leaf", (req, res) => {
  const { workspaceSlug } = establishOrgContext(req);
  const leaf = String(req.params.leaf);
  if (!LEAF.test(leaf) || leaf.includes("..")) {
    res.status(400).end();
    return;
  }
  res.sendFile(resolveInWorkspace(workspaceSlug, leaf));
});
`;

test("a workspace resolved from req.user is not a caller-chosen path segment", async () => {
  const result = await scanFiles({
    "package.json": JSON.stringify({ name: "org", version: "1.0.0", private: true, dependencies: { express: "^4.19.0" } }),
    "src/lib/org-context.ts": ORG_CONTEXT,
    "src/lib/store.ts": STORE,
    "src/routes/exports.ts": ROUTE
  });
  assert.equal(has(result, "path_traversal"), false, "the principal decides the workspace, not the caller");
});

test("the same workspace taken off a header is still caller-chosen", async () => {
  const result = await scanFiles({
    "package.json": JSON.stringify({ name: "org", version: "1.0.0", private: true, dependencies: { express: "^4.19.0" } }),
    "src/lib/org-context.ts": ORG_CONTEXT_FROM_HEADER,
    "src/lib/store.ts": STORE,
    "src/routes/exports.ts": ROUTE
  });
  assert.equal(has(result, "path_traversal"), true, "a header-supplied workspace must still report");
});
