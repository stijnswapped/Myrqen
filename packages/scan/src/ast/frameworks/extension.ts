import ts from "typescript";
import { collect, expressionName, literalTextOf, walk } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";
import { functionOf, stringArgument, type EntryPoint, type FrameworkAdapter, type TaintSeed } from "../entrypoints.js";

/**
 * Browser extension background pages and service workers.
 *
 * The privileged half of an extension is a genuine attack surface and it looks
 * like nothing else the engine recognises. There is no route, no verb, no request
 * object and no export a runtime picks up by name — only a listener registered on
 * an event object, receiving a plain value somebody else chose. `chrome.` calls
 * therefore produce no entry point, no entry point produces no request parameter,
 * and every data-flow rule stays silent over a worker that holds the user's OAuth
 * token, carries host permissions for every site the user visits, and hands the
 * result of an arbitrary API call back to whoever asked.
 *
 * Three trust boundaries meet in one file and they are not the same boundary,
 * which is the reason this adapter names them separately in the report.
 * `runtime.onMessage` is reachable from the extension's own content scripts and
 * from other extensions; `runtime.onMessageExternal` is reachable from *web
 * pages* — any page at all when the manifest's `externally_connectable` is
 * broad — and is the most exposed listener an extension can register; a
 * `webRequest` listener sees every request the browser makes on behalf of every
 * page. A reader who is told which one a finding sits behind can judge it; a
 * reader told only "a message handler" cannot.
 */

const FRAMEWORK = "extension";

/* ------------------------------------------------------------------------- *
 * Reaching the extension namespace
 *
 * `chrome` in Chromium, `browser` in Firefox and under the polyfill, and in
 * cross-browser code a local alias for whichever of the two exists. All three
 * spellings address the identical API, so all three have to resolve to the same
 * path or the same worker is recognised in Chrome and invisible in Firefox.
 * ------------------------------------------------------------------------- */

const NAMESPACES = new Set(["chrome", "browser"]);

/** Objects the namespace is routinely reached through inside a worker. */
const HOST_OBJECTS = new Set(["globalThis", "self", "window"]);

/**
 * Namespace members that belong to the extension API and to nothing else.
 *
 * The gate exists because `browser` is also what half the Playwright and
 * Puppeteer code in the world calls its browser handle. `browser.contexts()`
 * resolves through the same syntax as `browser.runtime`, and without this list a
 * test file would be claimed as an extension worker.
 */
const EXTENSION_MEMBERS = new Set([
  "runtime",
  "webRequest",
  "tabs",
  "storage",
  "scripting",
  "declarativeNetRequest",
  "extension",
  "action",
  "browserAction",
  "pageAction",
  "cookies",
  "windows",
  "permissions",
  "alarms",
  "notifications",
  "contextMenus",
  "downloads",
  "identity",
  "webNavigation",
  "management",
  "bookmarks",
  "history",
  "i18n"
]);

/**
 * The API path an expression addresses — `chrome.runtime.onMessage` becomes
 * `runtime.onMessage` — or null when it addresses something else entirely.
 */
function namespacePath(expression: ts.Expression, aliases: ReadonlyMap<string, string>): string | null {
  const dotted = expressionName(expression);
  if (!dotted) return null;
  const segments = dotted.split(".");
  const start = HOST_OBJECTS.has(segments[0]!) ? 1 : 0;
  const head = segments[start];
  if (head === undefined) return null;
  if (NAMESPACES.has(head)) return segments.slice(start + 1).join(".");
  // An alias stands for the namespace itself, so it can only be the whole head:
  // `globalThis.api` is somebody's own object, not `chrome`.
  if (start !== 0) return null;
  const prefix = aliases.get(head);
  if (prefix === undefined) return null;
  return [prefix, segments.slice(1).join(".")].filter((part) => part.length > 0).join(".");
}

/** `chrome`, `globalThis.browser ?? globalThis.chrome`, `chrome.runtime` — one base, three spellings. */
function namespaceBase(expression: ts.Expression, aliases: ReadonlyMap<string, string>): string | null {
  if (ts.isParenthesizedExpression(expression)) return namespaceBase(expression.expression, aliases);
  if (ts.isBinaryExpression(expression)) {
    const operator = expression.operatorToken.kind;
    // `browser ?? chrome` and `chrome || browser` are the two ways every
    // cross-browser extension picks its namespace, and both hands are the API.
    if (operator !== ts.SyntaxKind.QuestionQuestionToken && operator !== ts.SyntaxKind.BarBarToken) return null;
    return namespaceBase(expression.left, aliases) ?? namespaceBase(expression.right, aliases);
  }
  return namespacePath(expression, aliases);
}

/**
 * Local names bound to the namespace or to a part of it.
 *
 * Declarations are visited in source order, so an alias derived from an earlier
 * one resolves by the time it is read. Without this a worker written the
 * cross-browser way — `const api = globalThis.browser ?? globalThis.chrome` and
 * then `api.runtime.onMessage.addListener(...)` — has no `chrome.` anywhere near
 * its listeners and is not recognised at all.
 */
function namespaceAliases(file: ParsedFile): Map<string, string> {
  const aliases = new Map<string, string>();
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!declaration.initializer) continue;
    const base = namespaceBase(declaration.initializer, aliases);
    if (base === null) continue;
    if (ts.isIdentifier(declaration.name)) {
      aliases.set(declaration.name.text, base);
      continue;
    }
    // `const { runtime } = chrome` binds a name that stands for `chrome.runtime`.
    if (!ts.isObjectBindingPattern(declaration.name)) continue;
    for (const element of declaration.name.elements) {
      const property = element.propertyName ?? element.name;
      if (!ts.isIdentifier(property) || !ts.isIdentifier(element.name)) continue;
      aliases.set(element.name.text, [base, property.text].filter((part) => part.length > 0).join("."));
    }
  }
  return aliases;
}

/** Does this file reach a real extension API, rather than merely name a variable `browser`? */
function usesExtensionApi(file: ParsedFile, aliases: ReadonlyMap<string, string>): boolean {
  for (const access of collect(file.source, ts.isPropertyAccessExpression)) {
    const path = namespacePath(access, aliases);
    if (path === null) continue;
    if (EXTENSION_MEMBERS.has(path.split(".")[0]!)) return true;
  }
  return false;
}

/* ------------------------------------------------------------------------- *
 * The channels
 * ------------------------------------------------------------------------- */

/**
 * How a payload is described in evidence, per channel.
 *
 * The wording is the finding's statement of who the attacker is, so the three
 * boundaries are worded apart. A reader who sees "another extension" knows the
 * caller had to be installed; a reader who sees "a web page" knows any site the
 * user visits can reach this listener, and that is a different conversation.
 */
const FROM_CONTENT_SCRIPT = "sent by a content script or another extension";
const FROM_WEB_PAGE = "sent by a web page or another extension";
const FROM_USER_SCRIPT = "sent by a user script";

/** Events whose listener receives the message directly as its first argument. */
const MESSAGE_EVENTS = new Map<string, string>([
  ["runtime.onMessage", FROM_CONTENT_SCRIPT],
  ["runtime.onMessageExternal", FROM_WEB_PAGE],
  ["runtime.onUserScriptMessage", FROM_USER_SCRIPT]
]);

/**
 * Events whose listener receives a `Port`, and whose messages arrive one level
 * further in at `port.onMessage`.
 */
const CONNECT_EVENTS = new Map<string, string>([
  ["runtime.onConnect", FROM_CONTENT_SCRIPT],
  ["runtime.onConnectExternal", FROM_WEB_PAGE],
  ["runtime.onUserScriptConnect", FROM_USER_SCRIPT]
]);

/**
 * The `webRequest` events, all of which hand the listener one `details` object.
 *
 * Every one of them is fed by whatever page the user happens to be visiting: the
 * URL, the method and the headers in `details` were chosen by that page, and a
 * background worker that reads them holds host permissions the page does not.
 * The whole family is listed rather than only `onBeforeRequest`, because the
 * blocking rewrite that turns an intercepted URL into a request of the
 * extension's own is written just as often on `onBeforeSendHeaders` or
 * `onHeadersReceived`.
 */
const WEB_REQUEST_EVENTS = new Set([
  "webRequest.onBeforeRequest",
  "webRequest.onBeforeSendHeaders",
  "webRequest.onSendHeaders",
  "webRequest.onHeadersReceived",
  "webRequest.onAuthRequired",
  "webRequest.onBeforeRedirect",
  "webRequest.onResponseStarted",
  "webRequest.onCompleted",
  "webRequest.onErrorOccurred"
]);

/* ------------------------------------------------------------------------- *
 * Handlers and their parameters
 * ------------------------------------------------------------------------- */

/** Every identifier a binding pattern introduces, rest and nested elements included. */
function boundNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  const names: string[] = [];
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...boundNames(element.name));
  }
  return names;
}

/**
 * The parameters a caller actually fills in.
 *
 * A TypeScript `this` parameter occupies a slot in the AST and none at the call
 * site. Counting it would shift every position by one, which here means seeding
 * `sender` as the message and calling the message trusted — the exact inversion
 * this adapter exists to prevent.
 */
function callerParameters(fn: ts.Node | undefined): readonly ts.ParameterDeclaration[] {
  const parameters = (fn as ts.FunctionLikeDeclaration | undefined)?.parameters ?? [];
  const first = parameters[0];
  if (first && ts.isIdentifier(first.name) && first.name.text === "this") return parameters.slice(1);
  return parameters;
}

/**
 * The function a listener argument denotes.
 *
 * A named handler — `chrome.runtime.onMessage.addListener(handleMessage)` — is
 * where the interesting code usually lives, and only declarations in this same
 * file are followed: an imported name could be anything, and a seed bound to the
 * wrong function is worse than no seed at all.
 */
function handlerOf(file: ParsedFile, argument: ts.Node | undefined): ts.Node | undefined {
  const inline = functionOf(argument);
  if (inline) return inline;
  if (!argument || !ts.isIdentifier(argument)) return undefined;
  for (const declaration of collect(file.source, ts.isFunctionDeclaration)) {
    if (declaration.name?.text === argument.text && declaration.body) return declaration;
  }
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== argument.text) continue;
    const resolved = functionOf(declaration.initializer);
    if (resolved) return resolved;
  }
  return undefined;
}

/**
 * The bindings that hold the message.
 *
 * An identifier parameter is the message whole. A destructured one has no root
 * to name, so each bound field is seeded on its own — `({ type, payload })` is
 * how a dispatching worker is usually written, and a seed on an object that
 * never exists as a binding would reach nothing.
 */
function messageSeeds(fn: ts.Node | undefined, origin: string): TaintSeed[] {
  const parameter = callerParameters(fn)[0];
  if (!parameter) return [];
  if (ts.isIdentifier(parameter.name)) return [{ name: parameter.name.text, origin: `${parameter.name.text} (${origin})` }];
  if (!ts.isObjectBindingPattern(parameter.name)) return [];
  return boundNames(parameter.name).map((name) => ({ name, origin: `${name} (a field of a message ${origin})` }));
}

/** Parameter names at the given positions, for the arguments the browser fills in. */
function trustedAt(fn: ts.Node | undefined, ...indices: number[]): string[] {
  const parameters = callerParameters(fn);
  const names: string[] = [];
  for (const index of indices) {
    const parameter = parameters[index];
    if (parameter) names.push(...boundNames(parameter.name));
  }
  return names;
}

/* ------------------------------------------------------------------------- *
 * The address
 * ------------------------------------------------------------------------- */

/** Properties a message handler conventionally dispatches on. */
const DISPATCH_PROPERTIES = new Set(["type", "action", "command", "cmd", "kind", "op"]);

/** The expressions in this handler that name the message's dispatch field. */
function dispatchNames(fn: ts.Node | undefined): Set<string> {
  const names = new Set<string>();
  const parameter = callerParameters(fn)[0];
  if (!parameter) return names;
  if (ts.isIdentifier(parameter.name)) {
    for (const property of DISPATCH_PROPERTIES) names.add(`${parameter.name.text}.${property}`);
    return names;
  }
  if (!ts.isObjectBindingPattern(parameter.name)) return names;
  for (const element of parameter.name.elements) {
    const property = element.propertyName ?? element.name;
    if (!ts.isIdentifier(property) || !DISPATCH_PROPERTIES.has(property.text)) continue;
    if (ts.isIdentifier(element.name)) names.add(element.name.text);
  }
  return names;
}

function isEquality(kind: ts.SyntaxKind): boolean {
  return (
    kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
    kind === ts.SyntaxKind.EqualsEqualsToken ||
    kind === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
    kind === ts.SyntaxKind.ExclamationEqualsToken
  );
}

/**
 * The one message type this handler answers, when it answers exactly one.
 *
 * A worker that guards itself with `if (message.type !== "syncTokens") return`
 * has stated its own address, and that literal is what a reader will search the
 * source for. A worker that switches over eight cases has no single address —
 * naming the first case would send the reader to the wrong branch — so it keeps
 * the channel name instead.
 */
function dispatchedType(fn: ts.Node | undefined): string | null {
  if (!fn) return null;
  const names = dispatchNames(fn);
  if (names.size === 0) return null;

  const literals = new Set<string>();
  walk(fn, (node) => {
    if (ts.isBinaryExpression(node) && isEquality(node.operatorToken.kind)) {
      for (const [accessed, other] of [
        [node.left, node.right],
        [node.right, node.left]
      ] as const) {
        if (!names.has(expressionName(accessed))) continue;
        const literal = literalTextOf(other);
        if (literal !== null && literal.length > 0) literals.add(literal);
      }
      return;
    }
    if (!ts.isSwitchStatement(node)) return;
    if (!names.has(expressionName(node.expression))) return;
    for (const clause of node.caseBlock.clauses) {
      if (!ts.isCaseClause(clause)) continue;
      const literal = literalTextOf(clause.expression);
      if (literal !== null && literal.length > 0) literals.add(literal);
    }
  });

  return literals.size === 1 ? [...literals][0]! : null;
}

function entryPoint(
  file: ParsedFile,
  site: ts.Node,
  path: string,
  fn: ts.Node | undefined,
  seeds: TaintSeed[],
  trustedParameters: string[]
): EntryPoint {
  return {
    framework: FRAMEWORK,
    kind: "ipc",
    method: "MESSAGE",
    path,
    line: lineOf(file, site),
    ...(fn ? { node: fn } : {}),
    ...(seeds.length > 0 ? { seeds } : {}),
    ...(trustedParameters.length > 0 ? { trustedParameters } : {})
  };
}

/* ------------------------------------------------------------------------- *
 * The shapes
 * ------------------------------------------------------------------------- */

interface Registration {
  call: ts.CallExpression;
  /** The API path the listener was registered on, such as `runtime.onMessage`. */
  path: string;
}

/** Every `X.addListener(...)` in this file whose receiver resolves to the extension API. */
function registrations(file: ParsedFile, aliases: ReadonlyMap<string, string>): Registration[] {
  const found: Registration[] = [];
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    if (call.expression.name.text !== "addListener") continue;
    const path = namespacePath(call.expression.expression, aliases);
    if (path === null || path.length === 0) continue;
    found.push({ call, path });
  }
  return found;
}

/**
 * `runtime.onMessage` and its two siblings.
 *
 * The parameter positions are fixed by the API and are the whole point of
 * declaring them here. The first is the message and is entirely the sender's.
 * The second is `sender`, which the *browser* fills in — `sender.id`,
 * `sender.origin`, `sender.url` and `sender.tab` are all set by the browser from
 * what it knows about the sending context rather than from anything the sender
 * claimed, which is precisely why comparing `sender.origin` against an expected
 * origin is a real check and not a self-attestation. Treating it as attacker
 * data would report every correctly written listener as broken. The third is
 * `sendResponse`, a callback the handler calls to answer; it carries no inbound
 * value at all.
 */
function messageEntryPoints(file: ParsedFile, found: Registration[]): EntryPoint[] {
  const entries: EntryPoint[] = [];
  for (const { call, path } of found) {
    const origin = MESSAGE_EVENTS.get(path);
    if (origin === undefined) continue;
    const handler = handlerOf(file, call.arguments[0]);
    entries.push(
      entryPoint(file, call, dispatchedType(handler) ?? path, handler, messageSeeds(handler, origin), trustedAt(handler, 1, 2))
    );
  }
  return entries;
}

/**
 * `runtime.onConnect` and its siblings, whose messages arrive through the port.
 *
 * The connect listener itself receives no payload — a `Port` is an object with
 * `postMessage`, `disconnect` and a browser-filled `sender` — so the entry point
 * that matters is the `port.onMessage` listener registered inside it, and the
 * port is required to be *this* handler's own parameter. A `port.onMessage`
 * listener attached to a port the extension opened itself with
 * `runtime.connect()` is the other end of the pipe and is deliberately not
 * claimed here.
 *
 * When no inner listener can be located — the port is stored in a map and
 * subscribed elsewhere, or the handler is imported — the connect registration is
 * still emitted, with no seeds, so the report can at least name the surface.
 */
function connectEntryPoints(file: ParsedFile, found: Registration[]): EntryPoint[] {
  const entries: EntryPoint[] = [];
  for (const { call, path } of found) {
    const origin = CONNECT_EVENTS.get(path);
    if (origin === undefined) continue;

    const connectHandler = handlerOf(file, call.arguments[0]);
    const portParameter = callerParameters(connectHandler)[0];
    const portName = portParameter && ts.isIdentifier(portParameter.name) ? portParameter.name.text : null;

    const inner: EntryPoint[] = [];
    if (connectHandler && portName) {
      for (const candidate of collect(connectHandler, ts.isCallExpression)) {
        if (!ts.isPropertyAccessExpression(candidate.expression)) continue;
        if (candidate.expression.name.text !== "addListener") continue;
        if (expressionName(candidate.expression.expression) !== `${portName}.onMessage`) continue;
        const handler = handlerOf(file, candidate.arguments[0]);
        inner.push(
          entryPoint(
            file,
            candidate,
            dispatchedType(handler) ?? "port.onMessage",
            handler,
            messageSeeds(handler, origin),
            // The second argument is the `Port` itself, handed back so the
            // listener can answer on the same channel.
            trustedAt(handler, 1)
          )
        );
      }
    }

    if (inner.length > 0) {
      entries.push(...inner);
      continue;
    }
    entries.push(entryPoint(file, call, path, connectHandler, [], portName ? [portName] : []));
  }
  return entries;
}

/**
 * `webRequest` interception.
 *
 * The listener's first argument is the `details` record for a request the
 * browser is about to make on behalf of whatever page the user is looking at, so
 * its URL, method and headers are chosen by that page. The remaining arguments
 * of the registration are the URL filter and the option list, which are the
 * extension's own configuration and are not handlers.
 */
function webRequestEntryPoints(file: ParsedFile, found: Registration[]): EntryPoint[] {
  const entries: EntryPoint[] = [];
  for (const { call, path } of found) {
    if (!WEB_REQUEST_EVENTS.has(path)) continue;
    const handler = handlerOf(file, call.arguments[0]);
    const parameter = callerParameters(handler)[0];

    let seeds: TaintSeed[] = [];
    if (parameter && ts.isIdentifier(parameter.name)) {
      seeds = [{ name: parameter.name.text, origin: `${parameter.name.text} (details of an intercepted network request)` }];
    } else if (parameter && ts.isObjectBindingPattern(parameter.name)) {
      seeds = boundNames(parameter.name).map((name) => ({
        name,
        origin: `${name} (a field of an intercepted network request)`
      }));
    }

    entries.push(entryPoint(file, call, path, handler, seeds, []));
  }
  return entries;
}

/* ------------------------------------------------------------------------- *
 * A plain service worker's own message event
 * ------------------------------------------------------------------------- */

/** The channel name for `self.addEventListener("message", ...)`. */
const WORKER_CHANNEL = "serviceWorker.onMessage";

/** Is this expression `self` / `globalThis` / `window`, the worker's global? */
function isWorkerGlobal(expression: ts.Expression): boolean {
  return ts.isIdentifier(expression) && HOST_OBJECTS.has(expression.text);
}

/**
 * The bindings a worker reads out of the message event.
 *
 * The first parameter here is a `MessageEvent` and is *not* the message: the
 * payload is `event.data`, while `event.origin` and `event.source` are filled in
 * by the browser and are exactly what a correct handler compares before trusting
 * anything. Seeding the parameter would therefore put attacker control on the
 * check itself, so only the bindings that actually read `.data` are seeded — a
 * destructured `({ data })`, or a local declared from `event.data`. A handler
 * that reads `event.data` inline is left to the engine's generic request-parameter
 * model, which already recognises `.data` on a parameter named `event`.
 */
function workerMessageSeeds(fn: ts.Node): TaintSeed[] {
  const parameter = callerParameters(fn)[0];
  if (!parameter) return [];

  if (ts.isObjectBindingPattern(parameter.name)) {
    const seeds: TaintSeed[] = [];
    for (const element of parameter.name.elements) {
      const property = element.propertyName ?? element.name;
      if (!ts.isIdentifier(property) || property.text !== "data") continue;
      for (const name of boundNames(element.name)) {
        seeds.push({ name, origin: `${name} (the payload posted to this service worker)` });
      }
    }
    return seeds;
  }

  if (!ts.isIdentifier(parameter.name)) return [];
  const event = parameter.name.text;
  const seeds: TaintSeed[] = [];
  for (const declaration of collect(fn, ts.isVariableDeclaration)) {
    if (!declaration.initializer) continue;
    if (expressionName(declaration.initializer) !== `${event}.data`) continue;
    for (const name of boundNames(declaration.name)) {
      seeds.push({ name, origin: `${name} (${event}.data, the payload posted to this service worker)` });
    }
  }
  return seeds;
}

/**
 * `self.addEventListener("message", handler)` and `self.onmessage = handler`.
 *
 * A background service worker is still a service worker, so it also receives
 * whatever a client posts to it directly. This shape is only claimed inside a
 * file that reaches a real extension API, because the identical two lines in a
 * progressive web app's `sw.js` describe a page talking to its own worker rather
 * than an attacker talking to a privileged one.
 */
function workerMessageEntryPoints(file: ParsedFile): EntryPoint[] {
  const entries: EntryPoint[] = [];

  for (const call of collect(file.source, ts.isCallExpression)) {
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    if (call.expression.name.text !== "addEventListener") continue;
    if (!isWorkerGlobal(call.expression.expression)) continue;
    if (stringArgument(call, 0) !== "message") continue;
    const handler = handlerOf(file, call.arguments[1]);
    if (!handler) continue;
    entries.push(entryPoint(file, call, WORKER_CHANNEL, handler, workerMessageSeeds(handler), []));
  }

  for (const statement of file.source.statements) {
    if (!ts.isExpressionStatement(statement)) continue;
    const assignment = statement.expression;
    if (!ts.isBinaryExpression(assignment) || assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
    if (!ts.isPropertyAccessExpression(assignment.left)) continue;
    if (assignment.left.name.text !== "onmessage" || !isWorkerGlobal(assignment.left.expression)) continue;
    const handler = handlerOf(file, assignment.right);
    if (!handler) continue;
    entries.push(entryPoint(file, statement, WORKER_CHANNEL, handler, workerMessageSeeds(handler), []));
  }

  return entries;
}

/* ------------------------------------------------------------------------- *
 * The adapter
 * ------------------------------------------------------------------------- */

/** The events this adapter claims, as they are written before `.addListener`. */
const EVENT_MENTION =
  /\b(?:onMessage|onMessageExternal|onUserScriptMessage|onConnect|onConnectExternal|onUserScriptConnect|onBeforeRequest|onBeforeSendHeaders|onSendHeaders|onHeadersReceived|onAuthRequired|onBeforeRedirect|onResponseStarted|onCompleted|onErrorOccurred)\s*\.\s*addListener\s*\(/;

/** A service worker's own message event, in both spellings. */
const WORKER_MESSAGE_MENTION =
  /\b(?:self|globalThis|window)\s*\.\s*(?:addEventListener\s*\(\s*["'`]message["'`]|onmessage\s*=)/;

/**
 * The extension namespace, in the three ways a worker reaches it: a member read,
 * the cross-browser pick between the two names, and the whole namespace bound to
 * a local. Requiring one of them — rather than the bare word `chrome` — is what
 * keeps a `chrome` user-agent string and a page about browsers out; `detect`
 * then re-establishes the namespace through the AST against a list of members
 * that belong to no other API, which is what keeps a Playwright `browser` handle
 * out.
 */
const EXTENSION_NAMESPACE =
  /\b(?:chrome|browser)\s*\.\s*(?:runtime|webRequest|tabs)\b|\b(?:chrome|browser)\s*(?:\?\?|\|\|)|=\s*(?:(?:globalThis|self|window)\s*\.\s*)?(?:chrome|browser)\s*[;\r\n]/;

/**
 * The pre-check.
 *
 * Both halves are required: something in this file has to register one of the
 * events, and the extension namespace has to be present for that registration to
 * be the extension's rather than some other object's `onMessage`. `detect` then
 * re-establishes both properly through the AST, so a mention inside a comment or
 * a string cannot get a file claimed.
 */
function applies(file: ParsedFile): boolean {
  const text = file.text;
  if (!EVENT_MENTION.test(text) && !WORKER_MESSAGE_MENTION.test(text)) return false;
  return EXTENSION_NAMESPACE.test(text);
}

function detect(file: ParsedFile): EntryPoint[] {
  const aliases = namespaceAliases(file);
  if (!usesExtensionApi(file, aliases)) return [];

  const found = registrations(file, aliases);
  return [
    ...messageEntryPoints(file, found),
    ...connectEntryPoints(file, found),
    ...webRequestEntryPoints(file, found),
    ...workerMessageEntryPoints(file)
  ];
}

export const extensionAdapter: FrameworkAdapter = { id: FRAMEWORK, applies, detect };

/**
 * Deliberately not claimed.
 *
 * `chrome.tabs.onUpdated`, `chrome.webNavigation.*` and `chrome.storage.onChanged`
 * do carry values an outsider influenced, but their listeners take two and three
 * arguments in an order that varies per event, and their first argument is
 * usually a tab id rather than a payload. A seed placed on the wrong argument of
 * those would announce attacker control over a number the browser generated.
 * `chrome.runtime.onInstalled` and `chrome.alarms.onAlarm` are the browser
 * talking to the extension about the extension and carry nothing an outsider
 * chose at all. The deprecated `chrome.extension.onRequest` family was removed
 * with Manifest V2 and no longer runs anywhere.
 */
