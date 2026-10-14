/**
 * Which function a call reaches.
 *
 * The question every inter-procedural step asks first. Answered for the shapes a layered
 * JavaScript or TypeScript application actually uses to hand a value from a handler to
 * the code that does something with it:
 *
 *  - a function in lexical scope, however it is declared, honouring shadowing;
 *  - an imported function, a namespace member, a CommonJS module member;
 *  - `this.method()` inside a class or an object literal;
 *  - `this.member.method()` where the member is an injected or constructed instance of a
 *    class this project declares — typed constructor parameters, typed or initialised
 *    property declarations, and `this.member = new C()` in the constructor;
 *  - `local.method()` where the local holds `new C()` or an object literal;
 *  - `new C(...)`, which reaches the constructor;
 *  - a method on an exported singleton (`export const svc = new Svc()`) or an exported
 *    object of functions.
 *
 * **Anything else resolves to nothing.** A value passed around, a computed property, a
 * method on a library object: guessing which function those reach is exactly the inference
 * that turns a call graph into a source of invented flows. A call that does not resolve is
 * one this engine does not follow, which is the behaviour every call had before this
 * existed.
 */
import ts from "typescript";
import type { ParsedFile } from "../ast/parse.js";
import type { Definition, ModuleGraph } from "./modules.js";

/** A function a call reaches. */
export interface CallTarget {
  file: ParsedFile;
  /** A function-like node with a body: declaration, expression, arrow, method, or constructor. */
  fn: ts.FunctionLikeDeclaration;
}

export type Invocation = ts.CallExpression | ts.NewExpression;

function unwrap(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 6; depth += 1) {
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isTypeAssertionExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

/** Is this a function-like node with a body a call can land in? */
export function isCallableBody(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return (
    (ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isConstructorDeclaration(node)) &&
    node.body !== undefined
  );
}

function isClassLike(node: ts.Node): node is ts.ClassLikeDeclaration {
  return ts.isClassDeclaration(node) || ts.isClassExpression(node);
}

function asTarget(definition: Definition | null): CallTarget | null {
  if (!definition) return null;
  return isCallableBody(definition.node) ? { file: definition.file, fn: definition.node } : null;
}

function constructorOf(file: ParsedFile, declaration: ts.ClassLikeDeclaration): CallTarget | null {
  for (const member of declaration.members) {
    if (ts.isConstructorDeclaration(member) && member.body) return { file, fn: member };
  }
  return null;
}

/* ------------------------------------------------------------------ lexical scope */

/** What a scope-introducing node declares directly, by name. */
interface ScopeEntry {
  /** A function or an initialiser, or `null` when the name is a parameter (opaque). */
  value: ts.Node | null;
}

const scopeTables = new WeakMap<ts.Node, Map<string, ScopeEntry>>();

function addBinding(table: Map<string, ScopeEntry>, name: ts.BindingName, value: ts.Node | null): void {
  if (ts.isIdentifier(name)) {
    if (!table.has(name.text)) table.set(name.text, { value });
    return;
  }
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    addBinding(table, element.name, null);
  }
}

function declarationsOf(container: ts.Node): Map<string, ScopeEntry> {
  const cached = scopeTables.get(container);
  if (cached) return cached;
  const table = new Map<string, ScopeEntry>();
  if (ts.isFunctionLike(container)) {
    for (const parameter of (container as ts.SignatureDeclaration).parameters) addBinding(table, parameter.name, null);
  }
  const statements: readonly ts.Statement[] | undefined = ts.isSourceFile(container) || ts.isBlock(container)
    ? container.statements
    : ts.isFunctionLike(container) && (container as ts.FunctionLikeDeclaration).body && ts.isBlock((container as ts.FunctionLikeDeclaration).body!)
      ? ((container as ts.FunctionLikeDeclaration).body as ts.Block).statements
      : undefined;
  for (const statement of statements ?? []) {
    if (ts.isFunctionDeclaration(statement) && statement.name) table.set(statement.name.text, { value: statement });
    else if (ts.isClassDeclaration(statement) && statement.name) table.set(statement.name.text, { value: statement });
    else if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        addBinding(table, declaration.name, declaration.initializer ? unwrap(declaration.initializer) : null);
      }
    }
  }
  scopeTables.set(container, table);
  return table;
}

/**
 * The innermost binding of `name` visible at `site`, or `undefined` when the name is not
 * declared anywhere in this file (so it is a global or an import).
 *
 * `null` in the result means "declared, but as something this resolver cannot see
 * through" — a parameter, a destructured binding — and that shadows an import of the same
 * name, which is the whole reason to look lexically first.
 */
function lexicalBinding(site: ts.Node, name: string, graph?: ModuleGraph, file?: ParsedFile): ScopeEntry | undefined {
  let current: ts.Node | undefined = site.parent;
  while (current) {
    if (ts.isSourceFile(current) || ts.isBlock(current) || ts.isFunctionLike(current)) {
      const entry = declarationsOf(current).get(name);
      if (entry) {
        // A module-level `require` is an import, and the module graph is what reads it.
        if (ts.isSourceFile(current) && graph && file && graph.importOf(file, name)) return undefined;
        return entry;
      }
    }
    current = current.parent;
  }
  return undefined;
}

/* ------------------------------------------------------------------ receivers */

function enclosingClass(node: ts.Node): ts.ClassLikeDeclaration | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (isClassLike(current)) return current;
    // An arrow keeps `this`; a function expression or declaration rebinds it.
    if (ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current)) {
      // A method's own body is not a function expression, so this only stops at a
      // `function () {}` nested inside a method — whose `this` is not the instance.
      return undefined;
    }
    current = current.parent;
  }
  return undefined;
}

function enclosingObjectLiteral(node: ts.Node): ts.ObjectLiteralExpression | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isMethodDeclaration(current) && ts.isObjectLiteralExpression(current.parent)) return current.parent;
    if (ts.isFunctionExpression(current) && ts.isPropertyAssignment(current.parent) && ts.isObjectLiteralExpression(current.parent.parent)) {
      return current.parent.parent;
    }
    if (ts.isFunctionDeclaration(current) || ts.isClassDeclaration(current) || ts.isClassExpression(current)) return undefined;
    current = current.parent;
  }
  return undefined;
}

/** The name of the class a type annotation refers to, without generic arguments. */
function typeName(type: ts.TypeNode | undefined): string | null {
  if (!type || !ts.isTypeReferenceNode(type)) return null;
  return ts.isIdentifier(type.typeName) ? type.typeName.text : null;
}

/** Resolve a class name visible from `site` in `file`. */
function classNamed(graph: ModuleGraph, file: ParsedFile, site: ts.Node, name: string): Definition | null {
  const local = lexicalBinding(site, name, graph, file);
  if (local?.value && isClassLike(local.value)) return { file, node: local.value };
  if (local && !local.value) return null;
  const resolved = graph.resolveLocal(file, name);
  return resolved && isClassLike(resolved.node) ? resolved : null;
}

/** What `this.member` holds in this class, as a class definition. */
function memberClass(graph: ModuleGraph, file: ParsedFile, declaration: ts.ClassLikeDeclaration, member: string): Definition | null {
  for (const element of declaration.members) {
    if (ts.isPropertyDeclaration(element) && element.name && ts.isIdentifier(element.name) && element.name.text === member) {
      const declared = typeName(element.type);
      if (declared) {
        const resolved = classNamed(graph, file, element, declared);
        if (resolved) return resolved;
      }
      const initializer = element.initializer ? unwrap(element.initializer) : null;
      if (initializer && ts.isNewExpression(initializer) && ts.isIdentifier(initializer.expression)) {
        return classNamed(graph, file, element, initializer.expression.text);
      }
    }
    if (!ts.isConstructorDeclaration(element)) continue;
    for (const parameter of element.parameters) {
      if (!ts.isIdentifier(parameter.name)) continue;
      const declared = typeName(parameter.type);
      // A parameter property (`private readonly orders: OrdersService`) declares the member.
      const isProperty = Boolean(ts.getModifiers(parameter)?.length);
      if (isProperty && parameter.name.text === member && declared) {
        const resolved = classNamed(graph, file, parameter, declared);
        if (resolved) return resolved;
      }
    }
    // `this.store = new Store()` or `this.orders = orders` in the constructor body.
    for (const statement of element.body?.statements ?? []) {
      if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)) continue;
      const assignment = statement.expression;
      if (assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
      const left = assignment.left;
      if (!ts.isPropertyAccessExpression(left) || left.expression.kind !== ts.SyntaxKind.ThisKeyword || left.name.text !== member) continue;
      const right = unwrap(assignment.right);
      if (ts.isNewExpression(right) && ts.isIdentifier(right.expression)) {
        return classNamed(graph, file, statement, right.expression.text);
      }
      if (ts.isIdentifier(right)) {
        const parameter = element.parameters.find((p) => ts.isIdentifier(p.name) && p.name.text === right.text);
        const declared = typeName(parameter?.type);
        if (declared) return classNamed(graph, file, statement, declared);
      }
    }
  }
  return null;
}

/** What a local identifier holds, as something `memberOf` understands. */
function receiverDefinition(graph: ModuleGraph, file: ParsedFile, site: ts.Node, name: string, depth = 0): Definition | null {
  if (depth > 4) return null;
  const local = lexicalBinding(site, name, graph, file);
  if (local === undefined) return graph.resolveLocal(file, name);
  if (local.value === null) {
    // A typed parameter: `function handle(orders: OrdersService)`.
    const parameter = findParameter(site, name);
    const declared = typeName(parameter?.type);
    return declared ? classNamed(graph, file, site, declared) : null;
  }
  const value = local.value;
  if (ts.isIdentifier(value)) return receiverDefinition(graph, file, value, value.text, depth + 1);
  if (ts.isNewExpression(value) || ts.isObjectLiteralExpression(value) || isClassLike(value)) return { file, node: value };
  return null;
}

function findParameter(site: ts.Node, name: string): ts.ParameterDeclaration | undefined {
  let current: ts.Node | undefined = site.parent;
  while (current) {
    if (ts.isFunctionLike(current)) {
      const found = (current as ts.SignatureDeclaration).parameters.find((p) => ts.isIdentifier(p.name) && p.name.text === name);
      if (found) return found;
    }
    current = current.parent;
  }
  return undefined;
}

/* ------------------------------------------------------------------ resolution */

const resolvedCache = new WeakMap<ts.Node, CallTarget | null>();

export function resolveCall(graph: ModuleGraph, file: ParsedFile, call: Invocation): CallTarget | null {
  if (resolvedCache.has(call)) return resolvedCache.get(call) ?? null;
  let result: CallTarget | null = null;
  try {
    result = resolveUncached(graph, file, call);
  } catch {
    result = null;
  }
  resolvedCache.set(call, result);
  return result;
}

function resolveUncached(graph: ModuleGraph, file: ParsedFile, call: Invocation): CallTarget | null {
  const callee = unwrap(call.expression);

  if (ts.isNewExpression(call)) {
    if (!ts.isIdentifier(callee)) return null;
    const declaration = classNamed(graph, file, call, callee.text);
    return declaration && isClassLike(declaration.node) ? constructorOf(declaration.file, declaration.node) : null;
  }

  if (ts.isIdentifier(callee)) {
    const local = lexicalBinding(call, callee.text, graph, file);
    if (local !== undefined) {
      if (local.value === null) return null;
      if (isCallableBody(local.value)) return { file, fn: local.value };
      if (ts.isIdentifier(local.value)) return asTarget(graph.localDefinition(file, local.value.text));
      return null;
    }
    return asTarget(graph.resolveLocal(file, callee.text));
  }

  if (!ts.isPropertyAccessExpression(callee) || ts.isPrivateIdentifier(callee.name)) return null;
  const method = callee.name.text;
  const receiver = unwrap(callee.expression);

  // `this.method()`
  if (receiver.kind === ts.SyntaxKind.ThisKeyword) {
    const declaration = enclosingClass(call);
    if (declaration) return asTarget(graph.memberOf({ file, node: declaration }, method));
    const object = enclosingObjectLiteral(call);
    return object ? asTarget(graph.memberOf({ file, node: object }, method)) : null;
  }

  // `this.member.method()`
  if (ts.isPropertyAccessExpression(receiver) && receiver.expression.kind === ts.SyntaxKind.ThisKeyword) {
    const declaration = enclosingClass(call);
    if (!declaration) return null;
    const held = memberClass(graph, file, declaration, receiver.name.text);
    return held ? asTarget(graph.memberOf(held, method)) : null;
  }

  // `local.method()`, `imported.method()`, `ns.method()`, `Class.staticMethod()`
  if (ts.isIdentifier(receiver)) {
    const definition = receiverDefinition(graph, file, call, receiver.text);
    return definition ? asTarget(graph.memberOf(definition, method)) : null;
  }
  return null;
}
