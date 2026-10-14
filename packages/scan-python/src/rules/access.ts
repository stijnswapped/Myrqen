import type { Expr, FunctionDef } from "../syntax/ast.js";
import { calleeTail, childExprs, constString, dotted, exprsIn, stmtExprs, walkExpr, walkStmts } from "../syntax/ast.js";
import type { Project, PyModule } from "../project/modules.js";
import type { RouteInfo } from "../project/frameworks.js";
import { routeLabelAt } from "../project/methods.js";
import type { Lookup } from "../analysis/lookups.js";
import type { CallTarget } from "../analysis/engine.js";
import { OWNER_COLUMN } from "../analysis/lookups.js";
import type { PyCandidate } from "../types.js";

/**
 * Who may ask.
 *
 * Both rules reason about a route relative to its neighbours rather than in
 * isolation, because "this endpoint needs a login" is not something the code of
 * one endpoint can say — it is what the endpoints around it say:
 *
 *  - missing authentication: a route with no identity check in a file whose
 *    other routes all have one, that reads or changes stored data, and whose
 *    path does not name a deliberately public operation (login, health, webhook);
 *  - object-level authorization: an authenticated route that fetches a record
 *    by an identifier the caller chose, and never mentions the caller again —
 *    no owner filter, no ownership comparison, no role check.
 */

const PUBLIC_ROUTE =
  /(login|logout|log_in|log_out|sign_?in|sign_?out|sign_?up|signup|register|health|healthz|ready|readiness|live|liveness|status|ping|version|public|webhook|callback|oauth|openid|sso|reset|forgot|recover|verify|confirm|activate|docs|openapi|swagger|redoc|static|robots|favicon|metrics|token|refresh|csrf|invite|unsubscribe|track|pixel|landing|well-known|\.well_known|feed|rss|sitemap|catalog|catalogue|pricing|plans|about|contact|terms|privacy|legal|faq|share|preview|embed)/i;

const DATA_CALL =
  /^(execute|executemany|query|get|get_or_404|first_or_404|filter|filter_by|where|all|first|one|one_or_none|scalars|scalar|scalar_one|scalar_one_or_none|fetchone|fetchall|fetchmany|fetch|fetchrow|insert|insert_one|update|update_one|delete|delete_one|find|find_one|aggregate|commit|add|merge|save|create|bulk_create|send_file|send_from_directory)$/;

/** A read that is worth protecting even without an identifier in the path. */
const SENSITIVE_READ =
  /(export|download|statement|invoice|payment|billing|payout|account|profile|address|order|message|inbox|conversation|document|attachment|file|report|history|transaction|card|wallet|tax|payroll|salary|medical|patient|customer|member|user|admin|internal|private|setting|token|key|secret|audit|log|backup|dump|credential|session|personal|contact|ledger|balance)/i;

/** Records that are usually public by design when read: a user's own profile row. */
const PROFILE_MODEL = /^(users?|members?|profiles?|authors?|people|persons?|followers?|following)$/i;

const ADMIN_EVIDENCE = /(admin|staff|superuser|super_user|role|permission|scope|operator|internal|service_account)/i;

const CATALOGUE_MODEL =
  /^(products?|catalog(ue)?s?|categor(y|ies)|articles?|posts?|pages?|countr(y|ies)|currenc(y|ies)|plans?|tags?|faqs?|docs?|blogs?|regions?|languages?|settings?|configs?|features?|brands?|manufacturers?|cit(y|ies)|timezones?|announcements?|news|events?|courses?|lessons?|books?|movies?|recipes?|skus?|items?_?types?|statuses|locales?)$/i;

export interface AccessContext {
  project: Project;
  report: (candidate: PyCandidate) => void;
  /** The project function a call in a handler reached, when the engine resolved it. */
  callTarget?: (call: Expr) => CallTarget | undefined;
}

function routeLabel(route: RouteInfo): string {
  return `${route.methods[0]} ${route.path}`;
}

/* ------------------------------------------------- missing authentication */

export function missingAuthentication(context: AccessContext, routes: RouteInfo[]): void {
  const byModule = new Map<PyModule, RouteInfo[]>();
  for (const route of routes) {
    const list = byModule.get(route.module) ?? [];
    list.push(route);
    byModule.set(route.module, list);
  }
  for (const [module, list] of byModule) {
    // Deliberately public operations (login, health, webhooks) are neither
    // siblings nor suspects: they do not set the module's convention.
    const handlers = [...new Set(list.map((route) => route.fn))].filter((fn) => {
      const route = list.find((candidate) => candidate.fn === fn)!;
      return !PUBLIC_ROUTE.test(route.path) && !PUBLIC_ROUTE.test(fn.name);
    });
    const authenticated = handlers.filter((fn) => list.find((route) => route.fn === fn)?.authenticated);
    const open = handlers.filter((fn) => !list.find((route) => route.fn === fn)?.authenticated);
    if (authenticated.length < 2 || open.length === 0) continue;
    if (authenticated.length / handlers.length < 0.6) continue;
    for (const fn of open) {
      const route = list.find((candidate) => candidate.fn === fn)!;
      if (route.optionalAuth) continue;
      const mutating = route.methods.some((method) => method !== "GET" && method !== "HEAD" && method !== "OPTIONS");
      const touches = touchesData(fn) || mutating;
      if (!touches) continue;
      // A read with no sign of personal or privileged data is usually public by
      // design (an article, a tag list, a blog index), whatever its siblings do.
      if (!mutating && !SENSITIVE_READ.test(route.path) && !SENSITIVE_READ.test(fn.name)) continue;
      const siblings = authenticated
        .map((sibling) => list.find((candidate) => candidate.fn === sibling)!)
        .slice(0, 3)
        .map((sibling) => `${routeLabel(sibling)} (${sibling.authEvidence})`);
      const severity = mutating || route.pathParams.size > 0 ? "high" : "medium";
      context.report({
        ruleId: "py-missing-authentication",
        category: "missing_authentication",
        title: `${routeLabel(route)} has no authentication while its sibling routes require it`,
        severity,
        verification: "needs_review",
        summary: `${fn.name} serves ${routeLabel(route)} with no identity check — no authentication dependency, decorator or hook — while ${authenticated.length} of the ${handlers.length} routes in ${module.relativePath} require one. It ${mutating ? "changes" : "reads"} stored data.`,
        impact: `Anyone who can reach the service can ${mutating ? "perform this operation" : "read what this endpoint returns"} without signing in.`,
        remediation:
          route.framework === "fastapi"
            ? "Add the same authentication dependency the sibling routes use (a `Depends(get_current_user)` parameter, or `dependencies=[...]` on the router so no route can be added without it)."
            : "Add the same decorator the sibling views use (`@login_required`), or move the check into a `before_request` hook on the blueprint so every view is covered.",
        verificationPlan: `Request ${routeLabel(route)} with no session and confirm a 401 or 403; then repeat with a valid session and confirm it works.`,
        taxonomy: ["CWE-306", "CWE-862", "OWASP-A01"],
        location: { file: module.relativePath, line: route.line, endLine: fn.defLine, container: fn.name },
        route: routeLabel(route),
        evidence: [
          {
            kind: "source",
            description: `Sibling routes in the same module require authentication: ${siblings.join("; ")}. This route has no equivalent.`,
            location: `${module.relativePath}:${route.line}`
          }
        ],
        reasoning: `${authenticated.length}/${handlers.length} handlers in the module are authenticated; this one is not, is not named as a public operation, and ${mutating ? "is a state-changing method" : "reads stored data"}.`
      });
    }
  }
}

function touchesData(fn: FunctionDef): boolean {
  let found = false;
  for (const expr of exprsIn(fn.body)) {
    walkExpr(expr, (inner) => {
      if (found || inner.k !== "call") return;
      const tail = calleeTail(inner);
      const receiver = inner.func.k === "attr" ? dotted(inner.func.value) ?? "" : "";
      // Anywhere in the receiver chain: `Payment.query.order_by(...).all()`.
      if (tail && DATA_CALL.test(tail) && /(^|\.)(session|db|cursor|conn|connection|repo|collection|query|objects|table|engine|store|tx)(\.|\(|$)/i.test(receiver)) found = true;
      if (tail && /^(select|insert|update|delete|text)$/.test(tail) && inner.func.k === "name") found = true;
      // A module-level data helper: `query("SELECT …")`, `execute(...)`, `fetch_all(...)`.
      if (tail && inner.func.k === "name" && /^(query|execute|fetch_?(one|all|many|rows?)?|run_query|db_\w+)$/.test(tail)) found = true;
      if (tail && /^(open|send_file|FileResponse|send_from_directory)$/.test(tail)) found = true;
    });
  }
  return found;
}

/* ----------------------------------------- object-level authorization */

export function objectLevelAuthorization(context: AccessContext, route: RouteInfo, lookups: Lookup[], siblings: RouteInfo[] = [route]): void {
  if (lookups.length === 0 || !route.authenticated) return;
  if (route.authEvidence && ADMIN_EVIDENCE.test(route.authEvidence)) return;
  const subjects = route.subjects.length > 0 ? route.subjects : route.framework === "flask" ? ["current_user", "g.user", "session"] : [];
  if (subjects.length === 0) return;
  const scope: OwnershipScope = { context, lookups, seen: new Set([route.fn]), flaskGlobals: route.framework === "flask" };
  if (establishesOwnership(scope, route.module, route.fn, subjects, 0)) return;

  const reading = route.methods.every((method) => method === "GET" || method === "HEAD");
  const lookup = lookups.find(
    (candidate) =>
      isOwnedModel(context.project, candidate.module ?? route.module, candidate.model) &&
      !(reading && PROFILE_MODEL.test((candidate.model ?? "").split(".").pop() ?? ""))
  );
  if (!lookup) return;
  const where = lookup.module ?? route.module;
  const label = routeLabelAt(siblings, lookup.siteLine ?? lookup.span.line) ?? routeLabel(route);
  const through = lookup.path && lookup.path.length > 0 ? ` (in ${lookup.path.map((fn) => fn.name).join(" → ")}, called from the handler)` : "";
  context.report({
    ruleId: "py-object-level-authorization",
    category: "broken_object_level_authorization",
    title: `${label} returns ${lookup.model ?? "a record"} by caller-chosen id without checking who owns it`,
    severity: "high",
    verification: "needs_review",
    summary: `${route.fn.name} fetches ${lookup.model ?? "a record"} through ${lookup.via}${through} using an identifier from the request. The handler is authenticated (${route.authEvidence}), but the signed-in subject (${subjects.join(", ")}) is never compared with the record's owner or used to scope the query.`,
    impact: `Any signed-in user can ${route.methods[0] === "GET" ? "read" : "act on"} another user's ${lookup.model ?? "record"} by changing the identifier in the request.`,
    remediation:
      "Scope the lookup to the caller — filter on the owner column (`where(Model.id == id, Model.owner_id == current_user.id)`) — or compare the fetched record's owner with the caller and answer 404 when they differ.",
    verificationPlan: `Sign in as two different users, create a record as the first, and request it through ${label} as the second; the response must be 404 or 403.`,
    taxonomy: ["CWE-639", "CWE-284", "OWASP-A01"],
    location: { file: where.relativePath, line: lookup.span.line, endLine: lookup.span.endLine, container: lookup.path?.at(-1)?.name ?? route.fn.name },
    route: label,
    evidence: [
      {
        kind: "source",
        description: `The record is resolved from a request identifier at ${where.relativePath}:${lookup.span.line}; nothing in the handler${through ? " or the functions it passes the request to" : ""} compares ${subjects.join(" or ")} or an owner column with it.`,
        location: `${where.relativePath}:${lookup.span.line}`
      }
    ],
    reasoning: `Authenticated route; lookup ${lookup.via} keyed on a path or query value; no reference to the subject or to an ownership column anywhere in the handler.`
  });
}

/**
 * Calls that record who did something rather than decide whether they may:
 * `record_event("invoice.voided", actor_id=current_user.id)`. The subject named
 * there scopes nothing, so it is not evidence of an ownership check.
 */
const RECORDING_CALL =
  /(^|\.)(record_\w+|audit\w*|log_\w+|track\w*|emit\w*|publish\w*|notify\w*|send_(event|notification|email|mail)|(logger|logging|log|current_app\.logger|app\.logger|statsd|metrics|analytics)\.\w+|print)$/;

interface OwnershipScope {
  context: AccessContext;
  lookups: Lookup[];
  seen: Set<FunctionDef>;
  /** Flask's signed-in user is a global (`current_user`, `g.user`) a helper can read itself. */
  flaskGlobals: boolean;
}

const MAX_HELPER_DEPTH = 3;

/** A reference to the signed-in subject: the subject, or one attribute of it (`user.id`). */
function subjectRef(expr: Expr, subjects: readonly string[]): string | null {
  const name = dotted(expr);
  if (!name) return null;
  for (const subject of subjects) {
    if (name === subject) return subject;
    if (name.startsWith(`${subject}.`) && name.slice(subject.length + 1).split(".").length === 1) return subject;
  }
  return null;
}

/**
 * A test that asks whether someone is signed in, or whether the caller has some
 * attribute at all (`current_user.patient_id is None`), rather than whom a record
 * belongs to or whether the caller holds a privileged role. Every reference to the
 * subject in it has to be of that kind.
 */
function isPresenceCheck(test: Expr, subjects: readonly string[]): boolean {
  const presenceRef = (expr: Expr): boolean => {
    if (expr.k === "call" && expr.args.length === 0 && expr.func.k === "attr") return presenceRef(expr.func);
    const subject = subjectRef(expr, subjects);
    if (!subject) return false;
    const attr = expr.k === "attr" && dotted(expr) !== subject ? expr.attr : "";
    return !ADMIN_EVIDENCE.test(attr);
  };
  switch (test.k) {
    case "not":
      return isPresenceCheck(test.operand, subjects);
    case "boolop":
      return isPresenceCheck(test.left, subjects) && isPresenceCheck(test.right, subjects);
    case "compare": {
      if (!/^(is|is not|==|!=)$/.test(test.op)) return false;
      const isNone = (expr: Expr) => expr.k === "const" && expr.value === null;
      return (isNone(test.right) && presenceRef(test.left)) || (isNone(test.left) && presenceRef(test.right));
    }
    default:
      return presenceRef(test);
  }
}

/**
 * The expressions of a function that could decide access, and the project calls whose
 * callee decides it on the function's behalf.
 *
 * Left out: the arguments of a recording call (`record_event(..., actor_id=user.id)`),
 * stamping the caller on a record (`invoice.voided_by = user.id`), and presence checks
 * (`if current_user.patient_id is None: abort(403)`). A subject handed to a project
 * function is not itself a check: what the function does with it is.
 */
function decidingParts(fn: FunctionDef, subjects: readonly string[], scope: OwnershipScope): { exprs: Expr[]; calls: Array<{ call: Extract<Expr, { k: "call" }>; target: CallTarget; passed: string[] }> } {
  const exprs: Expr[] = [];
  const calls: Array<{ call: Extract<Expr, { k: "call" }>; target: CallTarget; passed: string[] }> = [];
  const visit = (expr: Expr) => {
    if (expr.k === "call" && RECORDING_CALL.test(dotted(expr.func) ?? "")) return;
    const target = expr.k === "call" ? scope.context.callTarget?.(expr) : undefined;
    if (expr.k === "call" && target) {
      const offset = target.bound && target.fn.params[0] && /^(self|cls)$/.test(target.fn.params[0].name) ? 1 : 0;
      const passed: string[] = [];
      expr.args.forEach((arg, index) => {
        const param = target.fn.params[index + offset];
        if (param && param.kind === "normal" && subjectRef(arg, subjects)) passed.push(param.name);
        else visit(arg);
      });
      for (const kw of expr.kwargs) {
        if (kw.name && OWNER_COLUMN.test(kw.name)) exprs.push(expr);
        if (kw.name && target.fn.params.some((param) => param.name === kw.name) && subjectRef(kw.value, subjects)) passed.push(kw.name);
        else visit(kw.value);
      }
      exprs.push(expr.func);
      if (expr.func.k === "attr") visit(expr.func.value);
      calls.push({ call: expr, target, passed });
      return;
    }
    exprs.push(expr);
    for (const child of childExprs(expr)) visit(child);
  };
  walkStmts(fn.body, (stmt) => {
    // `invoice.voided_by = current_user.id` records the caller on the record; it checks
    // nothing. Assigning an ownership column (`order.user_id = …`) still counts.
    if (stmt.k === "assign" && stmt.value && stmt.targets.every((target) => target.k === "attr" && !OWNER_COLUMN.test(target.attr))) {
      for (const target of stmt.targets) visit(target);
      return;
    }
    if (stmt.k === "if") {
      for (const branch of stmt.branches) if (branch.test && !isPresenceCheck(branch.test, subjects)) visit(branch.test);
      return;
    }
    if (stmt.k === "assert" && isPresenceCheck(stmt.test, subjects)) return;
    for (const root of stmtExprs(stmt)) visit(root);
  });
  return { exprs, calls };
}

/**
 * Does this function — or a project function it hands the request to — scope the
 * record to the signed-in subject, compare an owner with it, or name an ownership
 * column where it could decide access?
 *
 * A helper is consulted when it receives the subject, when it builds the query the
 * lookup runs on (`_visible_results().filter_by(id=…)`), or when the lookup itself is
 * inside it. In a helper the subject is the parameter it was passed in, and, in Flask,
 * the signed-in user it can read for itself.
 */
function establishesOwnership(scope: OwnershipScope, module: PyModule, fn: FunctionDef, subjects: readonly string[], depth: number): boolean {
  const { exprs, calls } = decidingParts(fn, subjects, scope);
  if (mentionsSubjectOrOwner(exprs, subjects)) return true;
  if (depth >= MAX_HELPER_DEPTH) return false;
  for (const { call, target, passed } of calls) {
    if (scope.seen.has(target.fn)) continue;
    const buildsLookup = scope.lookups.some(
      (lookup) =>
        (lookup.path ?? []).includes(target.fn) ||
        ((lookup.module ?? module) === module && call.span.from >= lookup.span.from && call.span.to <= lookup.span.to)
    );
    if (passed.length === 0 && !buildsLookup) continue;
    const globals = scope.flaskGlobals ? flaskGlobalSubjects(target.module) : [];
    scope.seen.add(target.fn);
    const found = establishesOwnership(scope, target.module, target.fn, [...passed, ...globals], depth + 1);
    scope.seen.delete(target.fn);
    if (found) return true;
  }
  return false;
}

/** The signed-in user as a Flask helper module can read it. */
function flaskGlobalSubjects(module: PyModule): string[] {
  const out = ["current_user", "g.user"];
  const session = module.imports.get("session");
  if (session && /^(flask|quart)$/.test(session.module)) out.push("session");
  return out;
}

/** Does any of these expressions use the signed-in subject, or name an ownership column, where it could decide access? */
function mentionsSubjectOrOwner(exprs: readonly Expr[], subjects: readonly string[]): boolean {
  let found = false;
  const subjectRoots = new Set(subjects.map((subject) => subject.split(".")[0]!));
  // decidingParts already lists every sub-expression, so each node is checked on its own.
  for (const inner of exprs) {
    if (found) break;
    const name = dotted(inner);
    if (name) {
      // `token_auth.current_user()`, `get_jwt_identity()`: the caller, however it is spelled.
      if (/(^|\.)(current_user|current_identity|get_jwt_identity|get_current_user)(\(\))?(\.|$)/.test(name)) found = true;
      for (const subject of subjects) {
        if (name === subject || name.startsWith(`${subject}.`)) found = true;
      }
      if (inner.k === "name" && subjectRoots.has(inner.id) && !subjects.some((s) => s.includes("."))) found = true;
    }
    if (inner.k === "attr" && OWNER_COLUMN.test(inner.attr)) found = true;
    if (inner.k === "call") {
      for (const kw of inner.kwargs) if (kw.name && OWNER_COLUMN.test(kw.name)) found = true;
      const callee = dotted(inner.func) ?? "";
      if (/(^|\.)(get_jwt_identity|current_identity|get_current_user|authorize|check_owner|ensure_owner|assert_owner|require_owner|can_access|has_access|check_access|check_permission|has_permission)$/.test(callee)) found = true;
    }
    const text = constString(inner as Expr);
    // In SQL text only the predicate scopes anything; a selected column does not.
    if (text && /\bwhere\b[\s\S]*\b(user_id|owner_id|account_id|tenant_id|customer_id|org_id|created_by|author_id)\b/i.test(text)) found = true;
  }
  return found;
}

/**
 * Whether a model is the kind of thing a user owns.
 *
 * Positive evidence first: the project's own model declares an ownership column,
 * or some code in the project filters it by one. Without the model's source, the
 * name decides, and catalogue-shaped names (products, articles, countries) are
 * assumed shared.
 */
function isOwnedModel(project: Project, module: PyModule, model: string | null): boolean {
  if (!model) return true;
  const tail = model.split(".").pop() ?? model;
  const symbol = project.resolve(module, tail);
  if (symbol?.kind === "class") {
    for (const stmt of symbol.cls.body) {
      if (stmt.k === "assign") {
        for (const target of stmt.targets) if (target.k === "name" && OWNER_COLUMN.test(target.id)) return true;
      }
    }
    if (referencesOwnerColumn(project, tail)) return true;
    return !CATALOGUE_MODEL.test(tail);
  }
  if (referencesOwnerColumn(project, tail)) return true;
  return !CATALOGUE_MODEL.test(tail);
}

function referencesOwnerColumn(project: Project, model: string): boolean {
  const pattern = new RegExp(`\\b${model}\\.(${OWNER_COLUMN.source.replace(/^\^\(|\)\$$/g, "")})\\b`);
  return project.modules.some((module) => pattern.test(module.text));
}
