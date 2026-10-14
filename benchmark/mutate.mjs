#!/usr/bin/env node
/**
 * Semantics-preserving source mutation, for measuring whether a rule is
 * structural or lexical.
 *
 * Recall 1.000 on a corpus says a rule fires on that corpus. It does not say
 * whether it fired because of the shape of the code or because of the words in
 * it, and those two are indistinguishable from inside — which is the same
 * problem `docs/12-release/HOLDOUT-PROTOCOL.md` exists to solve for corpora,
 * one level down. A corpus written in ordinary English variable names cannot
 * tell a taint rule from a vocabulary match.
 *
 * So: rename every locally-bound identifier to an opaque token and score again.
 * The gap is the part of the score that was vocabulary. Measured 2026-08-23 on
 * the development corpus: recall 1.000 as authored, 0.699 renamed, with 20 of 73
 * cases producing no candidate at all.
 *
 * What is preserved, because a mutant that changes the program proves nothing:
 * line count, imports, exports, property names, object keys (a shorthand
 * `{ status }` is expanded to `{ status: renamed }` rather than rewritten), array
 * binding elements, type references, and a list of framework identifiers whose
 * names are part of the contract with the framework rather than the author's
 * choice. Verified across all four corpora to introduce no new parse diagnostic.
 *
 * Two honest caveats. A route whose *name* is an identifier — a tRPC router, a
 * path parameter — legitimately changes when that identifier is renamed, so a
 * mutated corpus must be scored route-blind or those cases will read as engine
 * failures when they are the mutant's doing. And a local declaration shadowing a
 * global that is also referenced unshadowed elsewhere in the same file would be
 * renamed in both places; no case in any corpus does this, and KEEP covers the
 * globals it would matter for.
 */
import ts from "typescript";

const KEEP = new Set([
  "req","res","request","reply","response","next","ctx","context","event","socket","ws","params","query","body","headers","url","session","user","db","sql","fetch","console","process","Buffer","JSON","Math","Object","Array","String","Number","Boolean","Promise","Error","module","exports","require","globalThis","window","document","chrome","browser","Deno","Bun","__dirname","__filename"
]);

export function mutateRename(source, fileName) {
  const kind = /\.tsx?$/.test(fileName) ? (fileName.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
             : (fileName.endsWith(".jsx") ? ts.ScriptKind.JSX : ts.ScriptKind.JS);
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, kind);

  // Pass 1: which names are locally bound and safe to rename?
  const declared = new Set();
  const imported = new Set();
  const exportedNames = new Set();
  const collect = (node) => {
    if (ts.isImportDeclaration(node) || ts.isImportEqualsDeclaration(node)) {
      node.forEachChild(function walkImport(n) {
        if (ts.isIdentifier(n)) imported.add(n.text);
        n.forEachChild(walkImport);
      });
    }
    if (ts.isExportSpecifier(node) || ts.isExportAssignment(node)) {
      node.forEachChild(function walkExport(n) {
        if (ts.isIdentifier(n)) exportedNames.add(n.text);
        n.forEachChild(walkExport);
      });
    }
    // Declared bindings: variables, parameters, binding elements.
    if ((ts.isVariableDeclaration(node) || ts.isParameter(node) || ts.isBindingElement(node))) {
      const collectBinding = (name) => {
        if (ts.isIdentifier(name)) declared.add(name.text);
        else if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
          for (const el of name.elements) if (ts.isBindingElement(el)) collectBinding(el.name);
        }
      };
      if (node.name) collectBinding(node.name);
    }
    /*
     * An exported `const` keeps its name, and this used to miss it.
     *
     * `export function` and `export class` were protected; `export const GET =` was
     * not, because it is a `VariableDeclaration` and lands in `declared` above. So the
     * mutant renamed `GET` to `q0z` and destroyed entry-point discovery outright —
     * which is not vocabulary dependence, it is the harness breaking the input. The
     * line count is unchanged, so the "moved a line" bail-out does not catch it, and
     * route-blind scoring turns the loss into "no candidate in range", indistinguishable
     * from the thing this harness exists to measure.
     *
     * Affected 25 files across the corpora — 13 in holdout-3 alone, which is also the
     * corpus reporting the smallest delta. The measurement was confounded in both
     * directions at once.
     */
    if (ts.isVariableStatement(node) && node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) {
      for (const declaration of node.declarationList.declarations) {
        const collectExported = (name) => {
          if (ts.isIdentifier(name)) exportedNames.add(name.text);
          else if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
            for (const el of name.elements) if (ts.isBindingElement(el)) collectExported(el.name);
          }
        };
        if (declaration.name) collectExported(declaration.name);
      }
    }
    // A function or class that is exported keeps its name.
    if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) && node.name) {
      const isExported = node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
      if (isExported) exportedNames.add(node.name.text);
      else declared.add(node.name.text);
    }
    node.forEachChild(collect);
  };
  collect(sf);

  const renamable = new Set([...declared].filter((n) => !KEEP.has(n) && !imported.has(n) && !exportedNames.has(n) && n.length > 1));
  if (renamable.size === 0) return { source, renamed: 0 };

  const map = new Map([...renamable].sort().map((n, i) => [n, `q${i}z`]));

  // Pass 2: text edits at AST positions.
  const edits = [];
  const visit = (node) => {
    if (ts.isIdentifier(node) && map.has(node.text)) {
      const parent = node.parent;
      let skip = false;
      // Inside a type annotation an identifier names a type, not the binding.
      for (let p = parent; p; p = p.parent) { if (ts.isTypeNode(p) || ts.isTypeAliasDeclaration(p) || ts.isInterfaceDeclaration(p)) { skip = true; break; } }
      // `obj.status` — the property, not the binding.
      if (parent && ts.isPropertyAccessExpression(parent) && parent.name === node) skip = true;
      // `{ status: value }` — the key.
      if (parent && ts.isPropertyAssignment(parent) && parent.name === node) skip = true;
      // `{ status }` in an object literal is a key AND a reference: expand it.
      if (parent && ts.isShorthandPropertyAssignment(parent) && parent.name === node) {
        edits.push({ start: node.getStart(sf), end: node.getEnd(), text: `${node.text}: ${map.get(node.text)}` });
        skip = true;
      }
      // `const { status } = req` — the source property name must stay, so the
      // shorthand is expanded to `status: newName`. An ARRAY binding element has
      // no key, so it is a plain rename; expanding it would be a syntax error.
      if (parent && ts.isBindingElement(parent) && parent.name === node && !parent.propertyName) {
        if (parent.parent && ts.isObjectBindingPattern(parent.parent)) {
          edits.push({ start: node.getStart(sf), end: node.getEnd(), text: `${node.text}: ${map.get(node.text)}` });
          skip = true;
        }
      }
      if (parent && ts.isBindingElement(parent) && parent.propertyName === node) skip = true;
      // Method / member / enum / import-export names.
      if (parent && (ts.isMethodDeclaration(parent) || ts.isPropertySignature(parent) || ts.isPropertyDeclaration(parent) || ts.isEnumMember(parent) || ts.isImportSpecifier(parent) || ts.isExportSpecifier(parent) || ts.isMethodSignature(parent)) && parent.name === node) skip = true;
      // JSX attribute names and element names.
      if (parent && (ts.isJsxAttribute(parent) || ts.isJsxOpeningElement(parent) || ts.isJsxClosingElement(parent) || ts.isJsxSelfClosingElement(parent))) skip = true;
      // Qualified names / labels.
      if (parent && (ts.isQualifiedName(parent) || ts.isLabeledStatement(parent) || ts.isBreakOrContinueStatement(parent))) skip = true;
      if (!skip) edits.push({ start: node.getStart(sf), end: node.getEnd(), text: map.get(node.text) });
    }
    node.forEachChild(visit);
  };
  visit(sf);

  edits.sort((a, b) => b.start - a.start);
  let out = source;
  let last = Infinity;
  for (const e of edits) {
    if (e.end > last) continue; // overlapping edit, skip defensively
    out = out.slice(0, e.start) + e.text + out.slice(e.end);
    last = e.start;
  }
  return { source: out, renamed: map.size };
}

/**
 * Property names a real application cannot choose, so renaming them proves nothing.
 *
 * This is a list of names, which is the thing the harness exists to punish — and it is
 * defensible for exactly one reason: these names are fixed by a framework, a driver or
 * the language. `req.params` is spelled `params` in every Express application ever
 * written, so a rule that keys on it is not making a bet about the author's vocabulary.
 * `invoice.merchantId` is entirely the author's choice, and a rule that keys on *that*
 * is making a bet it will lose.
 *
 * Method names are excluded wholesale (see `mutateProperties`) rather than listed here,
 * because `.map`, `.findFirst` and `.json` are all method surface and none of them is
 * domain vocabulary.
 */
const FRAMEWORK_PROPERTY = new Set([
  // Request and response surface.
  "params", "query", "body", "headers", "cookies", "session", "locals", "state", "url",
  "method", "path", "pathname", "search", "searchParams", "hostname", "host", "ip",
  "protocol", "originalUrl", "baseUrl", "status", "statusCode", "statusText", "statusMessage",
  "req", "res", "request", "response", "context", "ctx", "event", "next", "env", "platform",
  // Identity a framework or middleware attaches.
  "user", "auth", "identity", "principal", "viewer", "actor", "claims", "payload", "sub",
  // Driver and ORM surface.
  "rows", "results", "rowCount", "affectedRows", "insertId", "data", "where", "select",
  "include", "omit", "orderBy", "take", "skip", "cursor", "limit", "offset", "returning",
  // Language and stdlib surface.
  "length", "name", "message", "stack", "cause", "size", "value", "done", "type",
  "constructor", "prototype", "__proto__", "default", "current", "buffer", "byteLength"
]);

/**
 * Rename the *data* property names an author chose, consistently across one file.
 *
 * `mutateRename` above is blind to this entire surface. It preserves object-literal
 * keys and property-access names deliberately — a shorthand `{ status }` is expanded
 * rather than rewritten — because renaming them inconsistently would change the
 * program. The consequence is that the column vocabularies are never tested at all:
 * `OWNER_COLUMN` is the most-referenced constant in `packages/scan` and no mutation
 * has ever touched a single name in it, because `userId` lives in
 * `where: { userId: … }` and in `row.userId`, and both are preserved.
 *
 * So this renames them *consistently* — every read and every key for a given name
 * together — which keeps the file internally coherent. It is not runnable against a
 * real database afterwards, and it does not need to be: nothing here executes, and the
 * ground truth is stated in line numbers rather than in names.
 *
 * Deliberately left alone: anything in `FRAMEWORK_PROPERTY`, and any property used as
 * a call callee. A method name is framework or library surface, never the author's
 * domain vocabulary, and renaming `.findFirst` would measure whether the engine knows
 * Prisma rather than whether it knows what an owner column is.
 */
export function mutateProperties(source, fileName) {
  const kind = /\.tsx?$/.test(fileName)
    ? (fileName.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
    : (fileName.endsWith(".jsx") ? ts.ScriptKind.JSX : ts.ScriptKind.JS);
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, kind);

  const candidates = new Set();
  const calleeNames = new Set();

  const collect = (node) => {
    if (ts.isPropertyAccessExpression(node)) {
      const isCallee = node.parent && ts.isCallExpression(node.parent) && node.parent.expression === node;
      if (isCallee) calleeNames.add(node.name.text);
      else candidates.add(node.name.text);
    }
    if (ts.isPropertyAssignment(node) && ts.isIdentifier(node.name)) candidates.add(node.name.text);
    if (ts.isShorthandPropertyAssignment(node)) candidates.add(node.name.text);
    if (ts.isBindingElement(node) && node.propertyName && ts.isIdentifier(node.propertyName)) {
      candidates.add(node.propertyName.text);
    }
    node.forEachChild(collect);
  };
  collect(sf);

  const map = new Map();
  let index = 0;
  for (const name of [...candidates].sort()) {
    if (FRAMEWORK_PROPERTY.has(name) || calleeNames.has(name) || name.length <= 1) continue;
    map.set(name, `p${index++}k`);
  }
  if (map.size === 0) return { source, renamed: 0 };

  const edits = [];
  const rewrite = (node) => {
    if (ts.isPropertyAccessExpression(node) && map.has(node.name.text)) {
      const isCallee = node.parent && ts.isCallExpression(node.parent) && node.parent.expression === node;
      if (!isCallee) {
        edits.push({ start: node.name.getStart(sf), end: node.name.getEnd(), text: map.get(node.name.text) });
      }
    }
    if (ts.isPropertyAssignment(node) && ts.isIdentifier(node.name) && map.has(node.name.text)) {
      edits.push({ start: node.name.getStart(sf), end: node.name.getEnd(), text: map.get(node.name.text) });
    }
    // `{ userId }` is a key and a reference at once, so it expands rather than swaps.
    if (ts.isShorthandPropertyAssignment(node) && map.has(node.name.text)) {
      edits.push({
        start: node.name.getStart(sf),
        end: node.name.getEnd(),
        text: `${map.get(node.name.text)}: ${node.name.text}`
      });
    }
    // `const { userId: local } = row` — rename the source key, keep the local binding.
    if (ts.isBindingElement(node) && node.propertyName && ts.isIdentifier(node.propertyName) && map.has(node.propertyName.text)) {
      edits.push({
        start: node.propertyName.getStart(sf),
        end: node.propertyName.getEnd(),
        text: map.get(node.propertyName.text)
      });
    }
    node.forEachChild(rewrite);
  };
  rewrite(sf);

  edits.sort((a, b) => b.start - a.start);
  let out = source;
  for (const edit of edits) out = out.slice(0, edit.start) + edit.text + out.slice(edit.end);
  return { source: out, renamed: map.size };
}
