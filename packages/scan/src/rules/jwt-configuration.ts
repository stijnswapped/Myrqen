import ts from "typescript";
import { calleeName, calleeTail, collect, expressionName, walk } from "../ast/helpers.js";
import { routeOf } from "./attribution.js";
import { declarationFor } from "./browser-sources.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * How a JSON Web Token is signed and checked, as distinct from *whether* it is.
 *
 * `jwt-verification-bypass` owns the absence of a check: decode used as verify, a key
 * taken from the token, `algorithms` missing or listing `none`. Four configuration
 * defects survive a check that is present, and none of them was read anywhere:
 *
 *  1. **A guessable signing key.** `jwt.sign(claims, "secret")`, or
 *     `process.env.JWT_SECRET || "changeme"`. `credential-literal` deliberately
 *     ignores placeholder-looking and short values, because as committed credentials
 *     they authenticate to nothing — but as an HMAC key they are exactly what an
 *     attacker tries first, and a token signed with one can be forged offline.
 *  2. **Tokens issued unsigned**: `algorithm: "none"` on sign, `alg: "none"` in a jose
 *     protected header.
 *  3. **An `algorithms` list held in a constant that includes `none`**, which the other
 *     rule reads as text at the call and so counts as pinned.
 *  4. **`ignoreExpiration: true`**, which makes a stolen token valid forever.
 */
const JWT_MODULES = /^(?:jsonwebtoken|jose|jwt-simple|njwt|fast-jwt|@nestjs\/jwt|@tsndr\/cloudflare-worker-jwt|hono\/jwt|@hono\/jwt)$/;

/** Values an attacker tries first against an HMAC key, and the shapes of a placeholder. */
const GUESSABLE_KEY =
  /^(?:secret|secretkey|secret[-_]?key|jwt[-_]?secret|jwtsecret|mysecret|my[-_]?secret|supersecret|super[-_]?secret|changeme|change[-_]?me|password|passw0rd|keyboard cat|shhhhh+|test|testing|dev|development|default|key|token|example|your[-_ ].*|replace[-_ ]?me|xxx+|123456\d*|abc123|qwerty|s3cr3t)$/i;
const SELF_DESCRIBING = /(?:secret|password|changeme|example|sample|dummy|placeholder|your[-_ ]|replace|default|dev[-_]?key|test[-_]?key|insecure|not[-_]?secure)/i;

export const jwtConfiguration: Rule = {
  id: "jwt-configuration",
  category: "jwt_verification_bypass",
  describes: "JSON Web Tokens signed with a guessable key, issued unsigned, or accepted after expiry",
  run(context: RuleContext) {
    const bindings = jwtBindings(context);
    if (bindings.size === 0 && !/\bjwt\b|JwtModule|jwtService|SignJWT|jwtVerify/i.test(context.file.text)) return;
    const reported = new Set<string>();
    const report = (key: string, emit: () => void): void => {
      if (reported.has(key)) return;
      reported.add(key);
      emit();
    };

    for (const call of collect(context.file.source, ts.isCallExpression)) {
      const tail = calleeTail(call);
      const name = calleeName(call);
      const isJwt = isJwtCall(call, bindings);

      // jsonwebtoken / jwt-simple / hono: sign(payload, key, options), verify(token, key, options)
      if (isJwt && (tail === "sign" || tail === "verify" || tail === "encode" || tail === "decode") && call.arguments.length >= 2) {
        const keyArgument = call.arguments[1]!;
        const options = optionsObject(call.arguments[2]);
        if (options) checkOptions(context, call, options, tail, name, report);
        // An unsigned token has no key worth judging; that finding is the one to read.
        if (options && (stringProperty(options, "algorithm") ?? "").toLowerCase() === "none") continue;
        // jwt-simple's decode(token, key, noVerify) verifies; only its key is of interest.
        checkKey(context, call, keyArgument, `${name}()`, report);
        continue;
      }

      // jose: jwtVerify(token, key, options); new SignJWT(...)....sign(key)
      if (tail === "jwtVerify" && call.arguments[1]) {
        checkKey(context, call, call.arguments[1], "jwtVerify()", report);
        const options = optionsObject(call.arguments[2]);
        if (options) checkOptions(context, call, options, "verify", "jwtVerify", report);
        continue;
      }
      if (tail === "sign" && call.arguments.length === 1 && isSignJwtChain(call)) {
        checkKey(context, call, call.arguments[0]!, "SignJWT.sign()", report);
        continue;
      }
      if (tail === "setProtectedHeader" && call.arguments[0]) {
        const header = optionsObject(call.arguments[0]);
        const alg = header ? stringProperty(header, "alg") : null;
        if (alg && alg.toLowerCase() === "none") unsignedIssue(context, call, "setProtectedHeader({ alg: \"none\" })", report);
        continue;
      }

      // NestJS JwtModule.register({ secret }) / jwtService.sign(payload, { secret })
      if ((/^JwtModule\.register(?:Async)?$/.test(name) || (/jwtService$/i.test(receiverName(call)) && (tail === "sign" || tail === "signAsync" || tail === "verify" || tail === "verifyAsync")))) {
        for (const argument of call.arguments) {
          const options = optionsObject(argument);
          if (!options) continue;
          const secret = property(options, "secret") ?? property(options, "privateKey");
          if (secret) checkKey(context, call, secret, `${name}() secret`, report);
          checkOptions(context, call, options, tail.startsWith("verify") ? "verify" : "sign", name, report);
          const signOptions = property(options, "signOptions");
          if (signOptions && ts.isObjectLiteralExpression(signOptions)) checkOptions(context, call, signOptions, "sign", name, report);
          const verifyOptions = property(options, "verifyOptions");
          if (verifyOptions && ts.isObjectLiteralExpression(verifyOptions)) checkOptions(context, call, verifyOptions, "verify", name, report);
        }
        continue;
      }

      // fast-jwt: createSigner({ key }), createVerifier({ key })
      if ((tail === "createSigner" || tail === "createVerifier") && call.arguments[0]) {
        const options = optionsObject(call.arguments[0]);
        const key = options ? property(options, "key") : null;
        if (key) checkKey(context, call, key, `${tail}() key`, report);
        if (options) checkOptions(context, call, options, tail === "createSigner" ? "sign" : "verify", tail, report);
      }
    }
  }
};

type Reporter = (key: string, emit: () => void) => void;

function checkKey(context: RuleContext, call: ts.CallExpression, keyArgument: ts.Expression, sink: string, report: Reporter): void {
  const resolved = literalKey(keyArgument, 0);
  if (!resolved) return;
  const { value, fallback, inline } = resolved;
  const guessable = isGuessable(value);
  // A strong-looking key bound to a name is `credential-literal`'s finding; only an
  // inline one, which that rule cannot attribute to a secret, is reported here.
  if (!guessable && (!inline || fallback)) return;
  const line = locationOf(context, call).line;
  report(`key:${line}`, () => {
    const severity = fallback ? "medium" : "high";
    context.report({
      ruleId: "jwt-configuration",
      category: "jwt_weak_secret",
      title: guessable
        ? `Tokens are signed or checked with a guessable key in ${sink}`
        : `Tokens are signed or checked with a key written into the source in ${sink}`,
      severity,
      verification: fallback ? "needs_review" : "strong_evidence",
      summary: `${sink} uses a key that ${fallback ? "falls back to a literal when the environment variable is unset" : "is a literal in the source"}${
        guessable ? ", and the literal is one an attacker tries first" : ""
      }. Anyone who knows the key can mint a token for any subject and any role, and this one ${guessable ? "is guessable" : "is readable by everyone with the source"}.`,
      impact:
        "Forged tokens pass verification: an attacker signs claims of their choosing — another user's id, an administrator role — and the application accepts them as genuine. No interaction with the application is needed to produce them.",
      remediation: fallback
        ? "Remove the fallback and fail at startup when the key is missing. Use a randomly generated key of at least 256 bits held in a secret store, and rotate it, since the fallback value must be assumed known."
        : "Load the key from a secret store or environment variable, generated randomly with at least 256 bits of entropy (or use an asymmetric key pair), and rotate it: a key that was ever committed must be assumed known.",
      verificationPlan: fallback
        ? "Confirm whether the environment variable is set in every deployed environment. Where it is not, sign a token with the fallback value and confirm the application rejects it."
        : "Sign a token for a test identity with the literal key using any JWT library and present it to an authenticated endpoint; it must be rejected.",
      taxonomy: ["CWE-1391", "CWE-798", "CWE-321", "OWASP-A02", "OWASP-A07"],
      location: locationOf(context, call),
      ...routeOf(context, call),
      // No snippet: the line holds the key, and a key is never reproduced in a report.
      evidence: [
        {
          kind: "source",
          description: `${sink} is given a key that resolves to a ${guessable ? "guessable " : ""}literal${fallback ? " behind an environment fallback" : ""}. The value is deliberately not reproduced in this report.`,
          location: `${context.file.relativePath}:${line}`
        }
      ],
      reasoning: `The key argument resolves to a string literal${fallback ? " used when the environment variable is absent" : ""}; ${guessable ? "its value matches a placeholder or common-key shape" : "it is written inline at the call"}.`
    });
  });
}

function checkOptions(
  context: RuleContext,
  call: ts.CallExpression,
  options: ts.ObjectLiteralExpression,
  mode: string,
  name: string,
  report: Reporter
): void {
  const line = locationOf(context, call).line;
  if (mode === "sign" || mode === "encode") {
    const algorithm = stringProperty(options, "algorithm");
    if (algorithm && algorithm.toLowerCase() === "none") unsignedIssue(context, call, `${name}() with algorithm "none"`, report);
  }
  if (mode === "verify" || mode === "decode") {
    const ignore = property(options, "ignoreExpiration");
    if (ignore && ignore.kind === ts.SyntaxKind.TrueKeyword) {
      report(`exp:${line}`, () =>
        context.report({
          ruleId: "jwt-configuration",
          category: "jwt_verification_bypass",
          title: `${name}() accepts tokens after they expire`,
          severity: "medium",
          verification: "strong_evidence",
          summary: `\`ignoreExpiration: true\` tells ${name}() to accept a token whose \`exp\` has passed. A token that leaks — from a log, a browser, a proxy — therefore stays valid for as long as its signing key does.`,
          impact: "A stolen or logged token grants access indefinitely, and logging out or waiting for expiry does not end the session.",
          remediation: "Remove `ignoreExpiration`, issue tokens with a short `expiresIn`, and if long sessions are needed use a refresh token that can be revoked.",
          verificationPlan: "Sign a token for a test identity with an `exp` in the past, using the application's own signing path in a test environment, and confirm the endpoint rejects it.",
          taxonomy: ["CWE-613", "CWE-347", "OWASP-A07"],
          location: locationOf(context, call),
          ...routeOf(context, call),
          evidence: [sourceEvidence(context, call, "The verification options switch the expiry check off.")],
          reasoning: "The options object passed to the verify call sets ignoreExpiration to the literal true."
        })
      );
    }
    const algorithms = property(options, "algorithms");
    // A constant list is the shape the other rule reads as text and cannot see into.
    if (algorithms && ts.isIdentifier(algorithms)) {
      const resolved = resolveConstant(algorithms);
      if (resolved && ts.isArrayLiteralExpression(resolved) && resolved.elements.some((element) => ts.isStringLiteralLike(element) && element.text.toLowerCase() === "none")) {
        report(`none:${line}`, () =>
          context.report({
            ruleId: "jwt-configuration",
            category: "jwt_verification_bypass",
            title: `${name}() accepts unsigned tokens through its algorithm list`,
            severity: "critical",
            verification: "strong_evidence",
            summary: `The \`algorithms\` list passed to ${name}() is the constant \`${algorithms.text}\`, and that constant includes \`none\`. A token with \`alg: none\` carries no signature at all, so this check accepts claims anybody wrote.`,
            impact: "Anyone can present a token naming any subject and any role, with no key, and it is accepted as authenticated.",
            remediation: `Remove \`none\` from \`${algorithms.text}\` and list only the algorithm your keys are issued with, for example \`["HS256"]\` or \`["RS256"]\`.`,
            verificationPlan: "Present a token with header `{\"alg\":\"none\"}`, a chosen subject, and an empty signature to an authenticated endpoint, and confirm it is rejected.",
            taxonomy: ["CWE-347", "CWE-327", "OWASP-A02", "OWASP-A07"],
            location: locationOf(context, call),
            ...routeOf(context, call),
            evidence: [sourceEvidence(context, call, `The algorithm allowlist resolves to a constant that contains "none".`)],
            reasoning: `The algorithms option is the identifier ${algorithms.text}, which resolves to an array literal containing "none".`
          })
        );
      }
    }
  }
}

function unsignedIssue(context: RuleContext, call: ts.CallExpression, sink: string, report: Reporter): void {
  const line = locationOf(context, call).line;
  report(`unsigned:${line}`, () =>
    context.report({
      ruleId: "jwt-configuration",
      category: "jwt_verification_bypass",
      title: `Tokens are issued without a signature by ${sink}`,
      severity: "high",
      verification: "strong_evidence",
      summary: `${sink} produces tokens with no signature. Any verifier that accepts them accepts claims anybody could have written, and a verifier that rejects them means this path issues tokens nothing can check.`,
      impact: "If any consumer of these tokens accepts `alg: none` — and one configured to accept what this issuer produces must — an attacker mints tokens for any identity without a key.",
      remediation: "Sign with a real algorithm — HS256 with a randomly generated secret, or RS256/ES256 with a key pair — and pin that algorithm on every verifier.",
      verificationPlan: "Obtain a token from this path and decode its header; confirm `alg` is not `none`, and that the verifying endpoint rejects a token whose signature has been removed.",
      taxonomy: ["CWE-347", "CWE-327", "OWASP-A02"],
      location: locationOf(context, call),
      ...routeOf(context, call),
      evidence: [sourceEvidence(context, call, "The signing options select the `none` algorithm.")],
      reasoning: "The algorithm for signing is the literal \"none\"."
    })
  );
}

/** Is this value one an attacker would try against an HMAC key? */
function isGuessable(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 16) return true;
  if (GUESSABLE_KEY.test(trimmed)) return true;
  if (SELF_DESCRIBING.test(trimmed)) return true;
  return entropy(trimmed) < 3.0;
}

function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/**
 * The literal a key argument resolves to, following constants, `TextEncoder.encode`,
 * `Buffer.from`, and an environment read with a literal default.
 */
function literalKey(node: ts.Expression, depth: number): { value: string; fallback: boolean; inline: boolean } | null {
  if (depth > 5) return null;
  let current = node;
  while (ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isNonNullExpression(current)) current = current.expression;
  if (ts.isStringLiteralLike(current)) return { value: current.text, fallback: false, inline: depth === 0 };
  if (ts.isBinaryExpression(current) && [ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken].includes(current.operatorToken.kind)) {
    if (!/process\.env|import\.meta\.env|Deno\.env|Bun\.env|env\./.test(current.left.getText())) return null;
    const right = literalKey(current.right, depth + 1);
    return right ? { ...right, fallback: true } : null;
  }
  if (ts.isCallExpression(current)) {
    const tail = calleeTail(current);
    if ((tail === "encode" || tail === "from") && current.arguments[0]) {
      const inner = literalKey(current.arguments[0], depth + 1);
      return inner ? { ...inner, inline: inner.inline && depth === 0 } : null;
    }
    return null;
  }
  if (ts.isIdentifier(current)) {
    const resolved = resolveConstant(current);
    if (!resolved) return null;
    const inner = literalKey(resolved, depth + 1);
    return inner ? { ...inner, inline: false } : null;
  }
  return null;
}

/** A `const` initialiser for this name, in its own scope or the module's. */
function resolveConstant(identifier: ts.Identifier): ts.Expression | null {
  const declaration = declarationFor(identifier);
  if (!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer) return null;
  const list = declaration.parent;
  if (!ts.isVariableDeclarationList(list) || !(list.flags & ts.NodeFlags.Const)) return null;
  return declaration.initializer;
}

function optionsObject(node: ts.Expression | undefined): ts.ObjectLiteralExpression | null {
  if (!node) return null;
  if (ts.isObjectLiteralExpression(node)) return node;
  if (ts.isIdentifier(node)) {
    const resolved = resolveConstant(node);
    return resolved && ts.isObjectLiteralExpression(resolved) ? resolved : null;
  }
  return null;
}

function property(object: ts.ObjectLiteralExpression, key: string): ts.Expression | null {
  for (const element of object.properties) {
    if (ts.isPropertyAssignment(element) && element.name.getText().replace(/["']/g, "") === key) return element.initializer;
    if (ts.isShorthandPropertyAssignment(element) && element.name.text === key) return element.name;
  }
  return null;
}

function stringProperty(object: ts.ObjectLiteralExpression, key: string): string | null {
  const value = property(object, key);
  if (!value) return null;
  if (ts.isStringLiteralLike(value)) return value.text;
  if (ts.isIdentifier(value)) {
    const resolved = resolveConstant(value);
    if (resolved && ts.isStringLiteralLike(resolved)) return resolved.text;
  }
  return null;
}

function receiverName(call: ts.CallExpression): string {
  return ts.isPropertyAccessExpression(call.expression) ? expressionName(call.expression.expression) : "";
}

function isSignJwtChain(call: ts.CallExpression): boolean {
  let found = false;
  walk(call.expression, (node) => {
    if (ts.isNewExpression(node) && expressionName(node.expression) === "SignJWT") found = true;
  });
  return found;
}

function isJwtCall(call: ts.CallExpression, bindings: Set<string>): boolean {
  if (!ts.isPropertyAccessExpression(call.expression)) return bindings.has(calleeName(call));
  const receiver = expressionName(call.expression.expression);
  return bindings.has(receiver) || /^(?:jwt|jsonwebtoken|JWT)$/.test(receiver);
}

function jwtBindings(context: RuleContext): Set<string> {
  const names = new Set<string>();
  walk(context.file.source, (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier) && JWT_MODULES.test(node.moduleSpecifier.text)) {
      const clause = node.importClause;
      if (!clause) return;
      if (clause.name) names.add(clause.name.text);
      if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) names.add(clause.namedBindings.name.text);
      if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
        for (const element of clause.namedBindings.elements) names.add(element.name.text);
      }
      return;
    }
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isCallExpression(node.initializer) && calleeName(node.initializer) === "require") {
      const specifier = node.initializer.arguments[0];
      if (!specifier || !ts.isStringLiteralLike(specifier) || !JWT_MODULES.test(specifier.text)) return;
      if (ts.isIdentifier(node.name)) names.add(node.name.text);
      if (ts.isObjectBindingPattern(node.name)) {
        for (const element of node.name.elements) if (ts.isIdentifier(element.name)) names.add(element.name.text);
      }
    }
  });
  return names;
}
