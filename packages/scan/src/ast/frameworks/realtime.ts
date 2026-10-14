import ts from "typescript";
import { collect, expressionName, literalTextOf, walk } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";
import { functionOf, type EntryPoint, type FrameworkAdapter, type TaintSeed } from "../entrypoints.js";

/**
 * Message-driven entry points: Socket.IO, the `ws` WebSocket server, the
 * WebSocket surface the modern runtimes expose, and BroadcastChannel.
 *
 * A socket message is caller data exactly as much as a request body is, and it
 * usually reaches the same queries. The application that answers
 * `POST /conversations/search` over HTTP answers `conversation:search` over a
 * socket with the same code, against the same collection, behind the same
 * session — and only one of the two is visible to a scanner that looks for route
 * registrations. Nothing in a gateway file looks like an endpoint: there is no
 * verb, no path, and the payload parameter is called `payload`, `msg` or
 * `message` rather than `req`, so the engine's parameter-name model finds no
 * caller data anywhere and every data-flow rule stays silent over a handler that
 * spreads the client's object straight into a filter.
 *
 * The discipline here is the one the other adapters keep. A seed is a claim
 * about the world, and a wrong claim is not one wrong finding but one per rule,
 * in a file the reader had no reason to doubt. So every shape is gated on
 * evidence that this file really uses the library — the import, or a member that
 * belongs to no other API — and the receiver of every listener registration has
 * to be traceable to a socket rather than merely spelled like one. An emitter is
 * not a socket, a thread is not a client, and a handler whose payload could not
 * be located is emitted as a bare address with no seeds at all.
 *
 * Bun's `Bun.serve({ websocket: { message } })` is a WebSocket surface this file
 * does not touch, because that runtime's own adapter already claims it together
 * with the `fetch` handler it is declared beside: two adapters describing one
 * handler would put the same function in the report twice.
 *
 * Two things are deliberately never claimed. A browser client is one of them:
 * `socket.io-client`, `EventSource` and an outbound `new WebSocket(url)` all
 * receive data from the server the page chose to talk to, which is not the
 * caller-controlled direction this analysis is about, and claiming them would
 * put attacker control on the application's own responses. Server-Sent Events
 * are the other: an SSE endpoint is an ordinary HTTP handler that another
 * adapter already claims, and the stream itself is outbound — the client sends
 * nothing over it — so an adapter here would add no seed and duplicate an
 * address that is already correct.
 */

const FRAMEWORK = "realtime";

/* ------------------------------------------------------------------------- *
 * Shared plumbing
 * ------------------------------------------------------------------------- */

/** Every identifier a binding pattern introduces, rest elements included. */
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
 * A TypeScript `this` parameter occupies the first slot in the AST and no slot
 * at the call site. Counting it would shift every position by one, which in this
 * file means seeding the socket instead of the payload it delivers.
 */
function callerParameters(fn: ts.Node | undefined): readonly ts.ParameterDeclaration[] {
  const parameters = (fn as ts.FunctionLikeDeclaration | undefined)?.parameters ?? [];
  const first = parameters[0];
  if (first && ts.isIdentifier(first.name) && first.name.text === "this") return parameters.slice(1);
  return parameters;
}

/** A function declared or bound anywhere in this file under the given name. */
function localFunction(file: ParsedFile, name: string): ts.Node | undefined {
  for (const declaration of collect(file.source, ts.isFunctionDeclaration)) {
    if (declaration.name?.text === name && declaration.body) return declaration;
  }
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
    const fn = functionOf(declaration.initializer);
    if (fn) return fn;
  }
  return undefined;
}

/**
 * The function a handler argument denotes.
 *
 * `socket.on("contact:search", searchContacts)` is as common as an inline arrow,
 * and the named form is where the interesting code usually lives. Only
 * declarations in this same file are resolved: an imported name could be
 * anything, and a seed bound to the wrong function is worse than no seed at all.
 */
function handlerOf(file: ParsedFile, argument: ts.Node | undefined): ts.Node | undefined {
  const direct = functionOf(argument);
  if (direct) return direct;
  if (!argument || !ts.isIdentifier(argument)) return undefined;
  return localFunction(file, argument.text);
}

/** The method a call invokes, or null when it is not a method call. */
function methodName(call: ts.CallExpression): string | null {
  return ts.isPropertyAccessExpression(call.expression) ? call.expression.name.text : null;
}

/** The expression a method call hangs off, or undefined for a bare call. */
function receiverOf(call: ts.CallExpression): ts.Expression | undefined {
  return ts.isPropertyAccessExpression(call.expression) ? call.expression.expression : undefined;
}

/** An expression seen through the wrappers that do not change what it is. */
function unwrap(node: ts.Expression): ts.Expression {
  let current = node;
  for (let depth = 0; depth < 4; depth += 1) {
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isAwaitExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

/** The declared type of a parameter, with any generic arguments stripped. */
function typeNameOf(parameter: ts.ParameterDeclaration | undefined, file: ParsedFile): string {
  if (!parameter?.type) return "";
  return parameter.type.getText(file.source).replace(/<[\s\S]*$/, "").trim();
}

/** Is this call `require("<module>")`? */
function isRequireOf(node: ts.Expression, pattern: RegExp): boolean {
  if (!ts.isCallExpression(node) || expressionName(node.expression) !== "require") return false;
  const first = node.arguments[0];
  return Boolean(first && ts.isStringLiteralLike(first) && pattern.test(first.text));
}

/**
 * What this file imported from a module, as local name to exported name.
 *
 * The mapping is what makes the type annotations usable as evidence: a parameter
 * typed `Socket` is a Socket.IO socket only when `Socket` is the name this file
 * bound to that module's export, and `import { Socket as Client } from "ws"`
 * says the same thing under a name no heuristic would guess. `default` stands
 * for the module object itself, which is what the CommonJS forms bind.
 */
function importedBindings(file: ParsedFile, pattern: RegExp): Map<string, string> {
  const bindings = new Map<string, string>();

  for (const statement of file.source.statements) {
    if (!ts.isImportDeclaration(statement)) continue;
    if (!ts.isStringLiteralLike(statement.moduleSpecifier) || !pattern.test(statement.moduleSpecifier.text)) continue;
    const clause = statement.importClause;
    if (!clause) continue;
    if (clause.name) bindings.set(clause.name.text, "default");
    const named = clause.namedBindings;
    if (!named) continue;
    if (ts.isNamespaceImport(named)) bindings.set(named.name.text, "default");
    else for (const element of named.elements) bindings.set(element.name.text, (element.propertyName ?? element.name).text);
  }

  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    const initializer = declaration.initializer;
    if (!initializer || !isRequireOf(initializer, pattern)) continue;
    if (ts.isIdentifier(declaration.name)) {
      bindings.set(declaration.name.text, "default");
      continue;
    }
    if (!ts.isObjectBindingPattern(declaration.name)) continue;
    for (const element of declaration.name.elements) {
      if (!ts.isIdentifier(element.name)) continue;
      const exported = element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : element.name.text;
      bindings.set(element.name.text, exported);
    }
  }

  return bindings;
}

/** The local names this file bound to one of a module's exports. */
function localsFor(bindings: Map<string, string>, exported: RegExp): Set<string> {
  const names = new Set<string>();
  for (const [local, original] of bindings) if (exported.test(original)) names.add(local);
  return names;
}

/**
 * Names a trailing parameter carries when it is the acknowledgement callback.
 *
 * Socket.IO passes the acknowledgement last, and it is a function the handler
 * calls to answer — the one parameter of a message handler that holds nothing
 * the client sent. Seeding it would announce attacker control over the
 * application's own reply.
 */
const ACKNOWLEDGEMENT_NAMES = new Set(["ack", "callback", "cb", "respond"]);

/** Is this trailing parameter the acknowledgement rather than part of the payload? */
function isAcknowledgement(parameter: ts.ParameterDeclaration, file: ParsedFile): boolean {
  if (ts.isIdentifier(parameter.name) && ACKNOWLEDGEMENT_NAMES.has(parameter.name.text)) return true;
  // A parameter declared as a function type is a callback whatever it is called,
  // which is the half of this the naming convention does not cover.
  return Boolean(parameter.type && ts.isFunctionTypeNode(parameter.type));
}

/**
 * Every payload parameter of a message handler, seeded under its own name.
 *
 * A destructured payload seeds each bound name: `async ({ filter }) => {}` hands
 * the client's value over under a name of the handler's choosing, and a seed on
 * an object that never exists as a binding would reach nothing.
 */
function payloadSeeds(handler: ts.Node, file: ParsedFile, skip = 0): TaintSeed[] {
  const parameters = callerParameters(handler);
  const seeds: TaintSeed[] = [];

  parameters.forEach((parameter, index) => {
    if (index < skip) return;
    if (index === parameters.length - 1 && isAcknowledgement(parameter, file)) return;
    for (const name of boundNames(parameter.name)) {
      seeds.push({ name, origin: `${name} (payload sent by the connected client)` });
    }
  });

  return seeds;
}

function entryPoint(
  file: ParsedFile,
  at: ts.Node,
  address: { method: string; path: string },
  handler: ts.Node | undefined,
  seeds: TaintSeed[],
  trusted: string[]
): EntryPoint {
  return {
    framework: FRAMEWORK,
    kind: "ipc",
    method: address.method,
    path: address.path,
    line: lineOf(file, at),
    ...(handler ? { node: handler } : {}),
    ...(seeds.length > 0 ? { seeds } : {}),
    ...(trusted.length > 0 ? { trustedParameters: trusted } : {})
  };
}

/** The literal event name at the given argument position, or null when computed. */
function eventArgument(call: ts.CallExpression, index: number): string | null {
  const argument = call.arguments[index];
  return argument ? literalTextOf(argument) : null;
}

/** Listener registrations that take an event name and a handler. */
const NAMED_LISTENERS = new Set(["on", "once", "addListener", "prependListener", "prependOnceListener"]);

/** Socket.IO's catch-all listeners, which are handed the event name as well. */
const CATCH_ALL_LISTENERS = new Set(["onAny", "prependAny"]);

/** The event a connection handler answers, in both spellings the libraries use. */
const CONNECTION_EVENT = /^connect(ion)?$/;

/**
 * Events the libraries raise themselves.
 *
 * `disconnect` carries a reason the server chose from a fixed list, `error`
 * carries an exception, and the listener bookkeeping events carry a listener.
 * None of them is a message the client composed, so none of them is an entry
 * point and none of their parameters is a seed.
 */
const LIFECYCLE_EVENTS = new Set([
  "connect",
  "connection",
  "connect_error",
  "connect_timeout",
  "disconnect",
  "disconnecting",
  "error",
  "close",
  "open",
  "upgrade",
  "newListener",
  "removeListener",
  "reconnect",
  "reconnect_attempt",
  "reconnect_error",
  "reconnect_failed"
]);

/* ------------------------------------------------------------------------- *
 * A. Socket.IO, server side
 * ------------------------------------------------------------------------- */

/** The server package. `socket.io-client` is a different library and a client. */
const SOCKET_IO_MODULE = /^socket\.io$/;
const SOCKET_IO_CLIENT_MODULE = /^socket\.io-client$/;

/**
 * Members that exist on a Socket.IO server socket and on nothing else.
 *
 * These are what make a helper module recognisable. A gateway is routinely split
 * into files that receive the socket as a parameter and import nothing from the
 * library at all, and in a JavaScript project there is not even a type
 * annotation to read. `handshake`, `nsp`, `rooms` and `broadcast` belong to no
 * other API in common use — in particular to neither `net.Socket` nor a cluster
 * worker, both of which also answer `.on("message", …)` and neither of which
 * carries anything an outside caller chose.
 */
const SOCKET_IO_ONLY_MEMBERS = /^(handshake|nsp|rooms|broadcast)$/;

/** Identifiers this file uses as a Socket.IO socket, however it obtained one. */
function socketIoSocketNames(file: ParsedFile, bindings: Map<string, string>, usesLibrary: boolean): Set<string> {
  const names = new Set<string>();

  for (const access of collect(file.source, ts.isPropertyAccessExpression)) {
    if (!SOCKET_IO_ONLY_MEMBERS.test(access.name.text)) continue;
    if (ts.isIdentifier(access.expression)) names.add(access.expression.text);
  }

  if (!usesLibrary) return names;
  const socketTypes = localsFor(bindings, /^Socket$/);
  for (const parameter of collect(file.source, ts.isParameter)) {
    if (!ts.isIdentifier(parameter.name)) continue;
    // In a file that imports the library, a parameter called `socket` is the
    // socket. The convention is universal in this framework's own documentation,
    // and the import is what keeps the assumption inside a Socket.IO file.
    if (parameter.name.text === "socket" || socketTypes.has(typeNameOf(parameter, file))) names.add(parameter.name.text);
  }

  return names;
}

/**
 * Identifiers this file uses as a Socket.IO server or namespace.
 *
 * The distinction from a socket matters because the two hand their handlers
 * completely different arguments: a namespace's `connection` handler receives
 * the socket, which is the server's own object, while a socket's handler
 * receives what the client sent. Getting it backwards would seed the socket —
 * and with it `socket.data`, where a gateway keeps the tenant it resolved from
 * the session — as attacker data, which would make every correctly scoped query
 * in the file look like a defect.
 */
function socketIoNamespaceNames(file: ParsedFile, bindings: Map<string, string>, usesLibrary: boolean): Set<string> {
  const known = new Set<string>();
  if (!usesLibrary) return known;

  // `io` is what this library's documentation, and therefore essentially every
  // application using it, calls the server object.
  known.add("io");

  const namespaceTypes = localsFor(bindings, /^(Server|Namespace)$/);
  for (const parameter of collect(file.source, ts.isParameter)) {
    if (!ts.isIdentifier(parameter.name)) continue;
    if (namespaceTypes.has(typeNameOf(parameter, file))) known.add(parameter.name.text);
  }

  const factories = localsFor(bindings, /^(Server|default)$/);
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
    if (producesNamespace(declaration.initializer, factories, known)) known.add(declaration.name.text);
  }

  return known;
}

/** Does this expression evaluate to a Socket.IO server or one of its namespaces? */
function producesNamespace(node: ts.Expression, factories: Set<string>, known: Set<string>, depth = 0): boolean {
  if (depth > 4) return false;
  const expression = unwrap(node);

  if (ts.isIdentifier(expression)) return known.has(expression.text);

  // `new Server(httpServer)`, in either module system.
  if (ts.isNewExpression(expression)) return factories.has(expressionName(expression.expression));

  // `io.sockets` is the default namespace under the name the older releases used.
  if (ts.isPropertyAccessExpression(expression) && expression.name.text === "sockets") {
    return producesNamespace(expression.expression, factories, known, depth + 1);
  }

  if (!ts.isCallExpression(expression)) return false;
  const callee = expression.expression;
  // `require("socket.io")(httpServer)` is the server constructed without a name
  // for the module, and it is how most of the JavaScript in this ecosystem is
  // still written.
  if (isRequireOf(callee, SOCKET_IO_MODULE)) return true;
  if (ts.isIdentifier(callee) && factories.has(callee.text)) return true;
  // `io.of("/agents")` is a namespace of the server, and a namespace registers
  // its own connection handler.
  if (ts.isPropertyAccessExpression(callee) && callee.name.text === "of") {
    return producesNamespace(callee.expression, factories, known, depth + 1);
  }
  return false;
}

/**
 * The Socket.IO surface of one file.
 *
 * The connection handlers are read first because they are where a socket gets
 * its local name: inside `io.on("connection", (socket) => …)` the parameter *is*
 * the socket, whatever it was called, and every registration in that body hangs
 * off it. Without that pass a gateway written entirely inline — which is the
 * shape the documentation shows — would expose no message handler at all.
 */
function socketIoEntryPoints(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const bindings = importedBindings(file, SOCKET_IO_MODULE);
  // A file that talks to the client library is the browser half of the
  // application. Its socket receives what the server sends, which is not the
  // direction this analysis is about, and claiming it would put attacker control
  // on the application's own replies.
  if (bindings.size === 0 && importedBindings(file, SOCKET_IO_CLIENT_MODULE).size > 0) return [];

  // `require("socket.io")(httpServer)` names neither the module nor its export,
  // so the constructed server is the only evidence the file leaves behind — and
  // it is how a great deal of the JavaScript in this ecosystem is still written.
  const constructsServer = collect(file.source, ts.isCallExpression).some((call) =>
    isRequireOf(call.expression, SOCKET_IO_MODULE)
  );
  const usesLibrary = bindings.size > 0 || constructsServer;

  const namespaces = socketIoNamespaceNames(file, bindings, usesLibrary);
  const sockets = socketIoSocketNames(file, bindings, usesLibrary);
  if (namespaces.size === 0 && sockets.size === 0) return [];

  const entries: EntryPoint[] = [];
  const factories = localsFor(bindings, /^(Server|default)$/);

  for (const call of collect(file.source, ts.isCallExpression)) {
    const method = methodName(call);
    const receiver = receiverOf(call);
    if (!method || !receiver || !NAMED_LISTENERS.has(method)) continue;
    const event = eventArgument(call, 0);
    if (event === null || !CONNECTION_EVENT.test(event)) continue;
    if (!producesNamespace(receiver, factories, namespaces)) continue;

    const handler = handlerOf(file, call.arguments[1]);
    const socket = callerParameters(handler)[0];
    for (const name of socket ? boundNames(socket.name) : []) sockets.add(name);

    if (handler) claimed.add(handler);
    // The socket is the server's own object, not the client's message. Its
    // `handshake` and `request` do carry what the connecting client sent, but a
    // seed names a binding rather than a path through one, so seeding the socket
    // to reach them would also hand the caller `socket.data` — where the
    // authenticated tenant lives — and every scoped query would become a finding.
    entries.push(
      entryPoint(file, call, { method: "CONNECT", path: "connection" }, handler, [], socket ? boundNames(socket.name) : [])
    );
  }

  for (const call of collect(file.source, ts.isCallExpression)) {
    const method = methodName(call);
    const receiver = receiverOf(call);
    if (!method || !receiver) continue;
    if (!ts.isIdentifier(receiver) || !sockets.has(receiver.text)) continue;

    if (CATCH_ALL_LISTENERS.has(method)) {
      const handler = handlerOf(file, call.arguments[0]);
      if (!handler || claimed.has(handler)) continue;
      claimed.add(handler);
      const parameters = callerParameters(handler);
      const first = parameters[0];
      // The catch-all listener is handed the event name before the arguments,
      // and the client chose the name as surely as it chose the arguments.
      const seeds: TaintSeed[] = first
        ? boundNames(first.name).map((name) => ({ name, origin: `${name} (event name chosen by the connected client)` }))
        : [];
      seeds.push(...payloadSeeds(handler, file, 1));
      entries.push(entryPoint(file, call, { method: "MESSAGE", path: "*" }, handler, seeds, []));
      continue;
    }

    if (!NAMED_LISTENERS.has(method)) continue;
    if (call.arguments.length < 1) continue;
    const event = eventArgument(call, 0);
    if (event !== null && LIFECYCLE_EVENTS.has(event)) continue;

    const handler = handlerOf(file, call.arguments[1]);
    if (handler && claimed.has(handler)) continue;
    if (handler) claimed.add(handler);
    // A computed event name is still an event. Reporting `*` says "this is
    // reachable from the client and we could not read the address", which is
    // honest, where inventing a name would not be.
    entries.push(
      entryPoint(file, call, { method: "MESSAGE", path: event ?? "*" }, handler, handler ? payloadSeeds(handler, file) : [], [])
    );
  }

  return entries;
}

/* ------------------------------------------------------------------------- *
 * B. The `ws` server and the runtimes' own WebSocket
 * ------------------------------------------------------------------------- */

const WS_MODULE = /^ws$/;

/** Identifiers this file uses as a `ws` server. */
function webSocketServerNames(file: ParsedFile, bindings: Map<string, string>): Set<string> {
  const known = new Set<string>();
  if (bindings.size === 0) return known;

  // `wss` is what this library's documentation calls the server.
  known.add("wss");

  const serverTypes = localsFor(bindings, /^(WebSocketServer|Server)$/);
  const moduleObjects = localsFor(bindings, /^default$/);
  for (const parameter of collect(file.source, ts.isParameter)) {
    if (!ts.isIdentifier(parameter.name)) continue;
    const type = typeNameOf(parameter, file);
    if (serverTypes.has(type) || [...moduleObjects].some((object) => type === `${object}.Server`)) known.add(parameter.name.text);
  }

  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
    const initializer = unwrap(declaration.initializer);
    if (!ts.isNewExpression(initializer)) continue;
    const constructed = expressionName(initializer.expression);
    // `new WebSocketServer({ port })` and the `new WebSocket.Server({ port })`
    // spelling the same library has carried since before it had named exports.
    if (serverTypes.has(constructed) || [...moduleObjects].some((object) => constructed === `${object}.Server`)) {
      known.add(declaration.name.text);
    }
  }

  return known;
}

/**
 * Identifiers this file uses as an inbound WebSocket connection.
 *
 * An outbound `new WebSocket(url)` is deliberately absent. That object receives
 * what the server the application chose to call sends back, which is a different
 * trust question from the one this engine models, and treating it as caller data
 * would make every client of a well-known API look like an attack surface.
 */
function webSocketNames(file: ParsedFile, bindings: Map<string, string>): Set<string> {
  const known = new Set<string>();

  // `Deno.upgradeWebSocket(request)` answers the upgrade and hands back the
  // client's socket, so what it binds is a connection somebody dialled in on.
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    const initializer = declaration.initializer ? unwrap(declaration.initializer) : undefined;
    if (!initializer || !ts.isCallExpression(initializer)) continue;
    if (!/(^|\.)upgradeWebSocket$/.test(expressionName(initializer.expression))) continue;
    if (!ts.isObjectBindingPattern(declaration.name)) continue;
    for (const element of declaration.name.elements) {
      const property = element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : null;
      const bound = ts.isIdentifier(element.name) ? element.name.text : null;
      if (!bound) continue;
      if ((property ?? bound) === "socket") known.add(bound);
    }
  }

  if (bindings.size === 0) return known;
  const socketTypes = localsFor(bindings, /^(WebSocket|default)$/);
  for (const parameter of collect(file.source, ts.isParameter)) {
    if (!ts.isIdentifier(parameter.name)) continue;
    if (socketTypes.has(typeNameOf(parameter, file))) known.add(parameter.name.text);
  }

  return known;
}

/**
 * The `ws` surface of one file, plus the standard WebSocket event API.
 *
 * As with Socket.IO the connection handlers come first, because the socket only
 * has a name inside one. The upgrade request beside it is the caller's: it is
 * the HTTP request that opened the connection, and its URL, headers and cookies
 * are as attacker-chosen here as they are in any route handler — which is
 * exactly why a gateway routinely reads a token or a room out of it.
 */
function webSocketEntryPoints(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const bindings = importedBindings(file, WS_MODULE);
  const servers = webSocketServerNames(file, bindings);
  const sockets = webSocketNames(file, bindings);
  if (servers.size === 0 && sockets.size === 0) return [];

  const entries: EntryPoint[] = [];

  for (const call of collect(file.source, ts.isCallExpression)) {
    const method = methodName(call);
    const receiver = receiverOf(call);
    if (!method || !receiver || !NAMED_LISTENERS.has(method)) continue;
    if (!ts.isIdentifier(receiver) || !servers.has(receiver.text)) continue;
    const event = eventArgument(call, 0);
    if (event === null || !CONNECTION_EVENT.test(event)) continue;

    const handler = handlerOf(file, call.arguments[1]);
    const parameters = callerParameters(handler);
    const socket = parameters[0];
    for (const name of socket ? boundNames(socket.name) : []) sockets.add(name);

    if (handler) claimed.add(handler);
    const request = parameters[1];
    const seeds: TaintSeed[] = request
      ? boundNames(request.name).map((name) => ({ name, origin: `${name} (HTTP request that opened the connection)` }))
      : [];
    entries.push(
      entryPoint(file, call, { method: "CONNECT", path: "connection" }, handler, seeds, socket ? boundNames(socket.name) : [])
    );
  }

  for (const call of collect(file.source, ts.isCallExpression)) {
    const method = methodName(call);
    const receiver = receiverOf(call);
    if (!method || !receiver) continue;
    if (!ts.isIdentifier(receiver) || !sockets.has(receiver.text)) continue;
    if (!NAMED_LISTENERS.has(method) && method !== "addEventListener") continue;
    if (eventArgument(call, 0) !== "message") continue;

    const handler = handlerOf(file, call.arguments[1]);
    if (!handler || claimed.has(handler)) continue;
    claimed.add(handler);
    entries.push(entryPoint(file, call, { method: "MESSAGE", path: "message" }, handler, messageSeeds(handler, method), []));
  }

  for (const assignment of onMessageAssignments(file)) {
    const receiver = assignment.receiver;
    if (!ts.isIdentifier(receiver) || !sockets.has(receiver.text)) continue;
    const handler = handlerOf(file, assignment.value);
    if (!handler || claimed.has(handler)) continue;
    claimed.add(handler);
    entries.push(entryPoint(file, assignment.node, { method: "MESSAGE", path: "message" }, handler, messageSeeds(handler, "onmessage"), []));
  }

  return entries;
}

/**
 * The one parameter of a WebSocket message handler that holds the payload.
 *
 * The two APIs disagree about what that parameter is. The `ws` library's own
 * event passes the data first and a `isBinary` flag second, and the flag is a
 * property of the frame rather than anything the client composed. The standard
 * `addEventListener` and `onmessage` forms pass a single `MessageEvent`, whose
 * `data` is the payload — seeding the event covers it, because the taint model
 * already walks properties off a root it has been given.
 */
function messageSeeds(handler: ts.Node, method: string): TaintSeed[] {
  const first = callerParameters(handler)[0];
  if (!first) return [];
  const origin =
    method === "addEventListener" || method === "onmessage"
      ? "message sent by the connected client"
      : "payload sent by the connected client";
  return boundNames(first.name).map((name) => ({ name, origin: `${name} (${origin})` }));
}

interface OnMessageAssignment {
  node: ts.Node;
  receiver: ts.Expression;
  value: ts.Expression;
}

/** `socket.onmessage = handler`, wherever in the file it was written. */
function onMessageAssignments(file: ParsedFile): OnMessageAssignment[] {
  const found: OnMessageAssignment[] = [];
  for (const assignment of collect(file.source, ts.isBinaryExpression)) {
    if (assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
    const left = assignment.left;
    if (!ts.isPropertyAccessExpression(left) || left.name.text !== "onmessage") continue;
    found.push({ node: assignment, receiver: left.expression, value: assignment.right });
  }
  return found;
}

/* ------------------------------------------------------------------------- *
 * C. BroadcastChannel
 * ------------------------------------------------------------------------- */

/**
 * `new BroadcastChannel("jobs")` and the listener hung off it.
 *
 * The constructor name belongs to this API alone, in the browser and in Node
 * alike, which is what makes the channel safe to claim without an import to
 * check. What arrives is a message another context of the same application
 * posted — another tab, another worker, another thread — and it is exactly as
 * trustworthy as whatever put the data there, which is routinely a request.
 *
 * `EventSource` is the shape this deliberately does not resemble: it is a client
 * subscribing to a server's stream, so its `onmessage` carries the application's
 * own output and claiming it would invent an attacker where there is none.
 */
function broadcastChannelEntryPoints(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const channels = new Map<string, string>();

  const channelName = (expression: ts.Expression): string | null => {
    const created = unwrap(expression);
    if (!ts.isNewExpression(created) || expressionName(created.expression) !== "BroadcastChannel") return null;
    const first = created.arguments?.[0];
    return (first ? literalTextOf(first) : null) ?? "broadcast";
  };

  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
    const name = channelName(declaration.initializer);
    if (name !== null) channels.set(declaration.name.text, name);
  }
  const entries: EntryPoint[] = [];
  const record = (at: ts.Node, channel: string, handler: ts.Node | undefined): void => {
    if (!handler || claimed.has(handler)) return;
    claimed.add(handler);
    const first = callerParameters(handler)[0];
    const seeds: TaintSeed[] = first
      ? boundNames(first.name).map((name) => ({ name, origin: `${name} (message posted on the broadcast channel)` }))
      : [];
    entries.push(entryPoint(file, at, { method: "MESSAGE", path: channel }, handler, seeds, []));
  };

  for (const assignment of onMessageAssignments(file)) {
    const receiver = unwrap(assignment.receiver);
    const channel = ts.isIdentifier(receiver) ? channels.get(receiver.text) ?? null : channelName(receiver);
    if (channel === null) continue;
    record(assignment.node, channel, handlerOf(file, assignment.value));
  }

  for (const call of collect(file.source, ts.isCallExpression)) {
    if (methodName(call) !== "addEventListener") continue;
    const receiver = receiverOf(call);
    if (!receiver) continue;
    const target = unwrap(receiver);
    const channel = ts.isIdentifier(target) ? channels.get(target.text) ?? null : channelName(target);
    if (channel === null) continue;
    if (eventArgument(call, 0) !== "message") continue;
    record(call, channel, handlerOf(file, call.arguments[1]));
  }

  return entries;
}

/* ------------------------------------------------------------------------- *
 * The adapter
 * ------------------------------------------------------------------------- */

/**
 * The text pre-check.
 *
 * It has to be cheap, because it runs for every adapter over every file, and
 * strict, because a file that merely registers a listener is not a socket
 * gateway. Every shape below either registers a listener or assigns one, so a
 * file with neither cannot be any of them; past that gate each clause names a
 * token that belongs to one of these libraries. `detect` re-checks all of it
 * against the AST before anything is claimed.
 */
function applies(file: ParsedFile): boolean {
  const text = file.text;
  const registersAListener =
    /\.(on|once|addListener|prependListener|prependOnceListener|onAny|prependAny|addEventListener)\s*\(/.test(text) ||
    /\bonmessage\s*=/.test(text);
  if (!registersAListener) return false;

  if (
    /["'`]socket\.io["'`]/.test(text) ||
    /\.(handshake|nsp|rooms|broadcast)\b/.test(text) ||
    /["'`]ws["'`]/.test(text) ||
    /\bWebSocketServer\b|\bWebSocket\s*\.\s*Server\b|\bupgradeWebSocket\s*\(/.test(text) ||
    /\bnew\s+BroadcastChannel\s*\(/.test(text)
  ) {
    return true;
  }

  /*
   * A gateway module that imports none of those tokens.
   *
   * Every clause above names a library, which meant the file had to mention one. Real
   * applications do not: the idiom is one module per event, `export function
   * register(socket) { socket.on("ticket:open", …) }`, importing only its own types
   * and a database helper. The server that constructs the io instance is somewhere
   * else entirely, so a held-out corpus over that layout produced nothing at all in
   * three of its files — the same blindness holdout-2 diagnosed, one layer in.
   *
   * The shape is the evidence instead: a function whose parameter is used *both* to
   * register a listener and to do something only a socket does — join a room, emit,
   * acknowledge, or carry `.data`. One of those alone is too weak; an `EventEmitter`
   * satisfies the first and nothing else.
   */
  return socketShapedParameter(file);
}

/**
 * A parameter used as a socket: `.on(...)` plus at least one socket-only member.
 *
 * Deliberately conservative, because an invented seed is worse than a missed one. A
 * plain emitter — `emitter.on("x", …)` and nothing else — does not qualify, and
 * neither does a parameter that only carries `.data`.
 */
function socketShapedParameter(file: ParsedFile): boolean {
  const SOCKET_ONLY = new Set(["join", "leave", "emit", "to", "in", "disconnect", "data", "rooms", "nsp", "handshake"]);
  let found = false;
  walk(file.source, (node: ts.Node) => {
    if (found) return;
    if (!ts.isFunctionDeclaration(node) && !ts.isArrowFunction(node) && !ts.isFunctionExpression(node)) return;
    const parameters = (node as ts.FunctionLikeDeclaration).parameters ?? [];
    for (const parameter of parameters) {
      if (!ts.isIdentifier(parameter.name)) continue;
      const name = parameter.name.text;
      let registers = false;
      const members = new Set<string>();
      walk(node, (inner: ts.Node) => {
        if (!ts.isPropertyAccessExpression(inner)) return;
        if (!ts.isIdentifier(inner.expression) || inner.expression.text !== name) return;
        const member = inner.name.text;
        if (member === "on" || member === "once") registers = true;
        else members.add(member);
      });
      if (registers && [...members].some((member) => SOCKET_ONLY.has(member))) {
        found = true;
        return;
      }
    }
  });
  return found;
}

/**
 * One handler is one entry point.
 *
 * The families overlap inside a single file — a process can run a Socket.IO
 * server and a raw WebSocket server on the same HTTP listener — and a handler
 * claimed twice would appear in the report twice, the second time possibly with
 * the arguments in the other library's order.
 */
function detect(file: ParsedFile): EntryPoint[] {
  const claimed = new Set<ts.Node>();
  return [
    ...socketIoEntryPoints(file, claimed),
    ...webSocketEntryPoints(file, claimed),
    ...broadcastChannelEntryPoints(file, claimed)
  ];
}

export const realtimeAdapter: FrameworkAdapter = { id: FRAMEWORK, applies, detect };

/**
 * The registry may name the families separately; they are one adapter on
 * purpose, because one `detect` pass with one claimed set is what keeps a
 * handler from being described twice. `registerAdapter` deduplicates on the id,
 * so registering either name registers the pass once.
 */
export const socketIoAdapter = realtimeAdapter;
export const websocketAdapter = realtimeAdapter;
