import type { Expr, FunctionDef, Span, Stmt } from "../syntax/ast.js";
import { constString, dotted, isTrue, keyword, stmtBlocks, stmtExprs, walkExpr } from "../syntax/ast.js";
import type { Project, PyModule } from "../project/modules.js";
import type { FrameworkModel } from "../project/frameworks.js";
import { routeLabelAt, siblingRoutes } from "../project/methods.js";
import type { PyCandidate } from "../types.js";
import { classifyCredential, shannonEntropy } from "./credentials.js";

/**
 * Configuration defects: what the code says about itself rather than what data
 * flows through it. No taint is involved, so each rule demands a literal — a
 * hard-coded string, a literal `True` — and stays silent on any value read from
 * the environment, which is the remediation for all three.
 */

export interface ConfigContext {
  project: Project;
  frameworks: FrameworkModel;
  report: (candidate: PyCandidate) => void;
}

const SECRET_BINDING_NAME =
  /(secret|password|passwd|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|client[_-]?secret|session[_-]?key|credential|auth[_-]?token|signing[_-]?key|encryption[_-]?key|jwt[_-]?key|dsn|connection[_-]?string)/i;
const NOT_A_SECRET_NAME =
  /(_url|_uri|_endpoint|_path|_file|_name|_header|_field|_length|_len|_ttl|_expiry|_expires?|_expire_minutes|_minutes|_seconds|_algorithm|_alg|_prefix|_type|_param|_cookie|_label|_id|_ids|_count|_lifetime|_age|_scheme|_location|_dir|_env|_var|_key_name|_policy|_hash_rounds|_rounds|_regex|_pattern|_min_length|_max_length|_reset_url|_format)$/i;
const PLACEHOLDER_VALUE =
  /^(|x{3,}|\.{3,}|<[^>]+>|\{\{.*\}\}|\$\{.*\}|change[-_ ]?me|replace[-_ ]?me|your[-_ ].*|example|dummy|placeholder|todo|test|fake|sample|redacted|null|undefined|none|localhost)$/i;
const SELF_DESCRIBING_VALUE =
  /(password|passphrase|secret|token|apikey|api[-_]key|credential|changeme|change[-_]me|example|sample|dummy|fixture|seed|placeholder|redacted|insecure|not[-_]?for[-_]?prod|dev[-_]?only|development|localdev|testing)/i;
const LOOPBACK_CONNECTION =
  /^[a-z0-9+.-]{2,20}:\/\/[^\s:@/]{1,64}:[^\s@/]+@(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1|0\.0\.0\.0|host\.docker\.internal|(?:db|database|postgres|postgresql|mysql|mariadb|redis|mongo|mongodb)(?::\d+)?)(?::\d+)?(?:[/?#]|$)/i;

const SESSION_COOKIE_NAME = /(sess|\bsid\b|_sid|auth|token|jwt|login|identity|refresh|access|remember|impersonat|device)/i;
const NON_SENSITIVE_COOKIE =
  /(csrf|xsrf|theme|locale|lang|\btz\b|timezone|consent|banner|colou?r|layout|sidebar|font|currency|dismiss|tour|variant|utm|ab[_-]?test|preview|cookie[_-]?notice)/i;

/* ------------------------------------------------------------ helpers */

function location(module: PyModule, span: Span, container?: string): PyCandidate["location"] {
  return { file: module.relativePath, line: span.line, endLine: span.endLine, ...(container ? { container } : {}) };
}

/** Every statement in the module with the function that encloses it, if any. */
function statementsWithOwner(body: Stmt[], owner: FunctionDef | null, visit: (stmt: Stmt, owner: FunctionDef | null, inClass: string | null) => void, inClass: string | null = null): void {
  for (const stmt of body) {
    visit(stmt, owner, inClass);
    if (stmt.k === "funcdef") statementsWithOwner(stmt.body, stmt, visit, inClass);
    else if (stmt.k === "classdef") statementsWithOwner(stmt.body, owner, visit, stmt.name);
    else for (const block of stmtBlocks(stmt)) statementsWithOwner(block, owner, visit, inClass);
  }
}

function routeOf(context: ConfigContext, fn: FunctionDef | null, line?: number): string | undefined {
  if (!fn) return undefined;
  const route = context.frameworks.routeOf(fn);
  return route ? routeLabelAt(siblingRoutes(context.frameworks.routes, route), line) : undefined;
}

/* -------------------------------------------------------------- secrets */

export function hardcodedSecrets(context: ConfigContext, module: PyModule): void {
  const reported = new Set<number>();
  const consider = (valueExpr: Expr, names: string[], how: string, owner: FunctionDef | null) => {
    const value = constString(valueExpr)?.trim();
    if (value === undefined || value === null) return;
    if (value.length < 8 || value.length > 4096) return;
    if (PLACEHOLDER_VALUE.test(value) || LOOPBACK_CONNECTION.test(value)) return;
    const shape = classifyCredential(value);
    if (!shape && SELF_DESCRIBING_VALUE.test(value)) return;
    const named = names.find((name) => SECRET_BINDING_NAME.test(name) && !NOT_A_SECRET_NAME.test(name));
    let label: string;
    let live: boolean;
    let reasoning: string;
    if (shape) {
      label = shape.label;
      live = shape.live;
      reasoning = `The literal matches the documented shape of a ${shape.label}${how ? ` and ${how}` : ""}.`;
    } else if (named && value.length >= 12 && shannonEntropy(value) >= 3.4 && !/\s/.test(value) && !/^[A-Z][A-Z0-9_]+$/.test(value) && !/^(https?:)?\/\//.test(value)) {
      label = `credential assigned to ${named}`;
      live = value.length >= 24 && shannonEntropy(value) >= 3.5;
      reasoning = `The literal ${how || "is bound to a secret-named binding"}, is ${value.length} characters with entropy ${shannonEntropy(value).toFixed(2)}, and contains no whitespace.`;
    } else {
      return;
    }
    if (reported.has(valueExpr.span.line)) return;
    reported.add(valueExpr.span.line);
    const route = routeOf(context, owner, valueExpr.span.line);
    context.report({
      ruleId: "py-hardcoded-secret",
      category: "hardcoded_secret",
      title: `Credential in source: ${label}`,
      severity: live ? "high" : "medium",
      verification: "strong_evidence",
      summary: `A ${label} is present as a literal in ${module.relativePath}${how ? `, where it ${how}` : ""}. Anyone who can read the repository, its history, a CI log or a build artifact holds the credential.`,
      impact:
        "The credential has to be treated as compromised, because publication cannot be undone by deleting the line. For a Flask or JWT signing key that means anyone holding it can forge sessions and tokens for any user.",
      remediation:
        "Rotate the credential first — the old value is burned. Then read the new one from the environment or a secret manager, fail at startup when it is absent rather than falling back to a literal, and purge the value from git history.",
      verificationPlan:
        "Confirm the rotated credential is loaded from configuration at runtime and the application refuses to start without it; search the tree and history for the old value.",
      taxonomy: ["CWE-798", "CWE-259", "OWASP-A07"],
      location: location(module, valueExpr.span, owner?.name),
      ...(route ? { route } : {}),
      evidence: [
        {
          kind: "source",
          description: `A ${label} appears as a literal. The value is deliberately not reproduced in this report.`,
          location: `${module.relativePath}:${valueExpr.span.line}`
        }
      ],
      reasoning
    });
  };

  statementsWithOwner(module.ast.body, null, (stmt, owner) => {
    if (stmt.k === "assign" && stmt.value) {
      for (const target of stmt.targets) {
        const name = target.k === "name" ? target.id : target.k === "attr" ? target.attr : target.k === "subscript" ? constString(target.index) : null;
        if (name) consider(stmt.value, [name], target.k === "subscript" ? `is assigned to ${dotted(target.value) ?? "a mapping"}["${name}"]` : "", owner);
      }
      // `secret_key: str = "..."` on a settings class.
    }
    for (const root of stmtExprs(stmt)) {
      walkExpr(root, (expr) => {
        if (expr.k === "dict") {
          for (const entry of expr.entries) {
            const key = constString(entry.key);
            if (key) consider(entry.value, [key], "", owner);
          }
        }
        if (expr.k !== "call") return;
        const name = dotted(expr.func) ?? "";
        // os.environ.get("JWT_SECRET", "literal") — the fallback is live the moment the variable is unset.
        if (/(^|\.)(environ\.get|getenv|environ\.setdefault)$/.test(name) || /^(config|env|env\.str)$/.test(name)) {
          const variable = constString(expr.args[0]) ?? "";
          const fallback = expr.args[1] ?? keyword(expr, "default");
          if (fallback) consider(fallback, [variable], `serves as the default when ${variable || "the variable"} is unset`, owner);
          return;
        }
        // app.config.update(SECRET_KEY="..."), Settings(secret_key="...")
        for (const kw of expr.kwargs) if (kw.name) consider(kw.value, [kw.name], "", owner);
        // jwt.encode(payload, "literal"), jwt.decode(token, "literal")
        if (/(^|\.)jwt\.(encode|decode)$|^(encode|decode)$/.test(name) && expr.args[1]) consider(expr.args[1], ["signing_key"], `is the key passed to ${name}()`, owner);
      });
    }
  });
}

/* ----------------------------------------------------------- debug mode */

/** A configuration class for a developer's machine or the test suite, not for production. */
const DEVELOPMENT_CLASS = /(dev|test|local|debug)/i;

export function debugMode(context: ConfigContext, module: PyModule): void {
  statementsWithOwner(module.ast.body, null, (stmt, owner, inClass) => {
    if (inClass && DEVELOPMENT_CLASS.test(inClass)) return;
    const report = (span: Span, what: string, severity: "high" | "medium", reasoning: string) =>
      context.report({
        ruleId: "py-debug-mode",
        category: "debug_endpoint_exposure",
        title: `Debug mode is enabled: ${what}`,
        severity,
        verification: "strong_evidence",
        summary: `${what} turns on the framework's debug mode in code that is not conditional on the environment. In Flask that enables the Werkzeug debugger, whose console executes Python for anyone who can reach an error page; in FastAPI it returns full tracebacks to the caller.`,
        impact:
          "The Werkzeug debugger is remote code execution once its PIN is guessed or derived from disclosed host details; tracebacks disclose source, paths, configuration and sometimes secrets.",
        remediation:
          "Read the setting from the environment with a production default of off (`debug=os.environ.get(\"FLASK_DEBUG\") == \"1\"`), and run production behind a WSGI/ASGI server (gunicorn, uvicorn) rather than the development server.",
        verificationPlan: "Trigger an error on the running service and confirm the response is a generic 500 page with no traceback or debugger console.",
        taxonomy: ["CWE-489", "CWE-215", "OWASP-A05"],
        location: location(module, span, owner?.name),
        evidence: [{ kind: "configuration", description: `${what} at ${module.relativePath}:${span.line}.`, location: `${module.relativePath}:${span.line}` }],
        reasoning
      });

    if (stmt.k === "assign" && stmt.value && isTrue(stmt.value)) {
      for (const target of stmt.targets) {
        const name = dotted(target) ?? "";
        if (/(^|\.)(app|application)\.debug$/.test(name)) report(stmt.span, `${name} = True`, "medium", "The application object's debug attribute is set to a literal True.");
        if (target.k === "subscript" && /config$/.test(dotted(target.value) ?? "") && constString(target.index) === "DEBUG") {
          report(stmt.span, `${dotted(target.value)}["DEBUG"] = True`, "medium", "The application configuration sets DEBUG to a literal True.");
        }
      }
    }
    for (const root of stmtExprs(stmt)) {
      walkExpr(root, (expr) => {
        if (expr.k !== "call") return;
        const qualified = context.project.qualified(module, expr.func) ?? "";
        const name = dotted(expr.func) ?? "";
        if (/(^|\.)run$/.test(name) && expr.func.k === "attr" && isTrue(keyword(expr, "debug"))) {
          const receiver = dotted(expr.func.value) ?? "";
          const isUvicorn = /^uvicorn\.run$/.test(qualified);
          if (!isUvicorn && !isFlaskApp(context, module, expr.func.value) && !/^(app|application)$/.test(receiver)) return;
          const host = constString(keyword(expr, "host"));
          const exposed = host === "0.0.0.0" || host === "::";
          report(
            expr.span,
            `${name}(debug=True${exposed ? `, host="${host}"` : ""})`,
            exposed ? "high" : "medium",
            `The development server is started with debug=True${exposed ? " and bound to every interface" : ""}.`
          );
          return;
        }
        if (/(^|\.)FastAPI$/.test(qualified) && isTrue(keyword(expr, "debug"))) {
          report(expr.span, "FastAPI(debug=True)", "medium", "The FastAPI application is constructed with debug=True, so unhandled errors return tracebacks.");
          return;
        }
        if (/(^|\.)DebuggedApplication$/.test(qualified) && isTrue(keyword(expr, "evalex"))) {
          report(expr.span, "DebuggedApplication(evalex=True)", "high", "The Werkzeug debugger middleware is installed with its interactive console enabled.");
          return;
        }
        if (/config\.update$/.test(name) && isTrue(keyword(expr, "DEBUG"))) {
          report(expr.span, `${name}(DEBUG=True)`, "medium", "The application configuration sets DEBUG to a literal True.");
        }
      });
    }
  });
}

function isFlaskApp(context: ConfigContext, module: PyModule, expr: Expr): boolean {
  if (expr.k !== "name") return false;
  const value = context.project.constantValue(module, expr.id);
  if (!value || value.expr.k !== "call") return false;
  const qualified = context.project.qualified(value.module, value.expr.func) ?? dotted(value.expr.func) ?? "";
  return /(^|\.)(Flask|Quart|APIFlask)$/.test(qualified) || /(^|\.)create_app$/.test(qualified);
}

/* -------------------------------------------------------------- cookies */

export function insecureCookies(context: ConfigContext, module: PyModule): void {
  const flaskModule = [...module.imports.values()].some((binding) => /^(flask|quart|werkzeug)/.test(binding.module));
  statementsWithOwner(module.ast.body, null, (stmt, owner, inClass) => {
    for (const root of stmtExprs(stmt)) {
      walkExpr(root, (expr) => {
        if (expr.k !== "call" || expr.func.k !== "attr") return;
        const name = dotted(expr.func) ?? "";
        if (expr.func.attr === "set_cookie") {
          const cookieName = cookieNameOf(context, module, expr.args[0] ?? keyword(expr, "key"));
          if (!cookieName || !SESSION_COOKIE_NAME.test(cookieName) || NON_SENSITIVE_COOKIE.test(cookieName)) return;
          // Flags passed through `**mapping` count when the mapping can be read; when it
          // cannot, the flags are unknown and nothing is claimed about them.
          const flags = cookieKeywords(context, module, owner, expr);
          if (!flags) return;
          const route = owner ? context.frameworks.routeOf(owner) : undefined;
          const isFlask = route ? route.framework === "flask" : flaskModule;
          const missing: string[] = [];
          const httponly = flags.get("httponly");
          const secure = flags.get("secure");
          const samesite = flags.get("samesite");
          if (!httponly || isLiteralFalse(httponly)) missing.push("HttpOnly");
          if (!secure || isLiteralFalse(secure)) missing.push("Secure");
          // Flask's default is no SameSite attribute; Starlette's is Lax.
          if ((isFlask && !samesite) || (samesite && (samesite.k === "const" || constString(samesite)?.toLowerCase() === "none") && !isTrue(secure))) {
            missing.push("SameSite");
          }
          if (missing.length === 0) return;
          reportCookie(context, module, expr.span, owner, `the ${cookieName} cookie`, missing, `${name}("${cookieName}", …)`);
          return;
        }
        // Starlette's signed-cookie sessions: `add_middleware(SessionMiddleware, https_only=False)`.
        const sessionMiddleware =
          (/(^|\.)add_middleware$/.test(name) || /(^|\.)Middleware$/.test(name)) && expr.args.some((arg) => /(^|\.)SessionMiddleware$/.test(dotted(arg) ?? ""));
        if (sessionMiddleware) {
          const missing: string[] = [];
          const httpsOnly = keyword(expr, "https_only");
          if (isLiteralFalse(httpsOnly)) missing.push("Secure");
          if (/^none$/i.test(constString(keyword(expr, "same_site")) ?? "") && !isTrue(httpsOnly)) missing.push("SameSite");
          if (missing.length > 0) reportCookie(context, module, expr.span, owner, "the session cookie", missing, "SessionMiddleware(…)");
          return;
        }
        if (/config\.(update|from_mapping)$/.test(name)) {
          const missing: string[] = [];
          if (isLiteralFalse(keyword(expr, "SESSION_COOKIE_HTTPONLY"))) missing.push("HttpOnly");
          if (isLiteralFalse(keyword(expr, "SESSION_COOKIE_SECURE"))) missing.push("Secure");
          if (missing.length > 0) reportCookie(context, module, expr.span, owner, "the Flask session cookie", missing, `${name}(…)`);
        }
      });
    }
    // `class DevelopmentConfig: SESSION_COOKIE_SECURE = False` is the setting for a local
    // server on plain HTTP, exactly as `DEBUG = True` is there (see debugMode).
    if (stmt.k === "assign" && stmt.value && isLiteralFalse(stmt.value) && !(inClass && DEVELOPMENT_CLASS.test(inClass))) {
      for (const target of stmt.targets) {
        const key = target.k === "subscript" ? constString(target.index) : target.k === "name" ? target.id : null;
        if (key === "SESSION_COOKIE_HTTPONLY" || key === "SESSION_COOKIE_SECURE") {
          reportCookie(context, module, stmt.span, owner, "the Flask session cookie", [key === "SESSION_COOKIE_HTTPONLY" ? "HttpOnly" : "Secure"], `${key} = False`);
        }
      }
    }
  });
}

/** A cookie's name: a literal, or a constant the project binds to one (`SESSION_COOKIE = "sid"`). */
function cookieNameOf(context: ConfigContext, module: PyModule, expr: Expr | undefined): string | null {
  if (!expr) return null;
  const literal = constString(expr);
  if (literal !== null) return literal;
  if (expr.k === "name") {
    const bound = context.project.constantValue(module, expr.id);
    return bound ? constString(bound.expr) : null;
  }
  if (expr.k === "attr") {
    const owner = context.project.resolveExpr(module, expr.value);
    if (owner?.kind !== "module") return null;
    const bound = context.project.constantValue(owner.module, expr.attr);
    return bound ? constString(bound.expr) : null;
  }
  return null;
}

/**
 * The keyword arguments of a `set_cookie` call, with `**mapping` expanded when the
 * mapping is a literal the project binds (a module constant or a local assignment).
 * Null when a mapping cannot be read, because its flags are then unknown.
 */
function cookieKeywords(context: ConfigContext, module: PyModule, owner: FunctionDef | null, call: Extract<Expr, { k: "call" }>): Map<string, Expr> | null {
  const flags = new Map<string, Expr>();
  for (const kw of call.kwargs) {
    if (kw.name) {
      flags.set(kw.name, kw.value);
      continue;
    }
    const entries = mappingEntries(context, module, owner, kw.value, call.span.line);
    if (!entries) return null;
    for (const [name, value] of entries) if (!flags.has(name)) flags.set(name, value);
  }
  return flags;
}

function mappingEntries(context: ConfigContext, module: PyModule, owner: FunctionDef | null, expr: Expr, beforeLine: number): Map<string, Expr> | null {
  const literal = (value: Expr): Map<string, Expr> | null => {
    if (value.k === "dict") {
      const out = new Map<string, Expr>();
      for (const entry of value.entries) {
        const key = constString(entry.key);
        if (key === null) return null;
        out.set(key, entry.value);
      }
      return out;
    }
    if (value.k === "call" && dotted(value.func) === "dict" && value.args.length === 0) {
      const out = new Map<string, Expr>();
      for (const kw of value.kwargs) {
        if (!kw.name) return null;
        out.set(kw.name, kw.value);
      }
      return out;
    }
    return null;
  };
  const direct = literal(expr);
  if (direct) return direct;
  if (expr.k !== "name") return null;
  if (owner) {
    let local: Expr | null = null;
    statementsWithOwner(owner.body, owner, (stmt) => {
      if (stmt.k === "assign" && stmt.value && stmt.span.line < beforeLine && stmt.targets.some((target) => target.k === "name" && target.id === expr.id)) local = stmt.value;
    });
    if (local) return literal(local);
  }
  const bound = context.project.constantValue(module, expr.id);
  return bound ? literal(bound.expr) : null;
}

function isLiteralFalse(expr: Expr | undefined): boolean {
  return Boolean(expr && expr.k === "const" && expr.value === false);
}

function reportCookie(context: ConfigContext, module: PyModule, span: Span, owner: FunctionDef | null, what: string, missing: string[], call: string): void {
  const route = routeOf(context, owner, span.line);
  context.report({
    ruleId: "py-insecure-cookie",
    category: "insecure_cookie_configuration",
    title: `${capitalise(what)} is set without ${missing.join(", ")}`,
    severity: "medium",
    verification: "strong_evidence",
    summary: `${call} writes ${what} without ${missing.join(", ")}. A session or authentication cookie without HttpOnly is readable by any script on the page, without Secure it is sent over plain HTTP, and without SameSite it rides along on cross-site requests.`,
    impact: "Session theft through any XSS on the origin or any unencrypted hop, and cross-site request forgery against cookie-authenticated actions.",
    remediation: "Set `httponly=True`, `secure=True` and `samesite=\"Lax\"` (or `\"Strict\"`) on every session or token cookie, or configure the framework's session cookie flags globally.",
    verificationPlan: "Sign in on the running service and confirm the Set-Cookie header carries HttpOnly, Secure and SameSite.",
    taxonomy: ["CWE-1004", "CWE-614", "OWASP-A05"],
    location: location(module, span, owner?.name),
    ...(route ? { route } : {}),
    evidence: [{ kind: "configuration", description: `${call} omits ${missing.join(", ")}.`, location: `${module.relativePath}:${span.line}` }],
    reasoning: `The cookie name marks it as a session or credential cookie and the call sets no ${missing.join(", ")} flag (or sets it to False).`
  });
}

function capitalise(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
