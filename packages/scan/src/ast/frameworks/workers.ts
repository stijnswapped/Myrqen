import ts from "typescript";
import { calleeTail, collect, expressionName, literalTextOf } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";
import { functionOf, importsFrom, type EntryPoint, type FrameworkAdapter, type TaintSeed } from "../entrypoints.js";

/**
 * Background job consumers and message handlers.
 *
 * A queue is a request that arrived earlier. Whatever an outside caller uploaded,
 * signed up with, or webhooked in was written into the payload by the public
 * endpoint that accepted it, and the processor on the other end reads it back
 * whole. A worker that interpolates `job.data.path` into a filesystem read is
 * exactly as exploitable as a route that interpolates `req.query.path`; the only
 * difference is that nobody reviews the queue's code while thinking about an
 * attacker.
 *
 * Nothing about a consumer looks like a route. There is no path, no verb, and the
 * parameter is called `job`, `msg`, or `event` rather than `req`, so the engine's
 * parameter-name model finds no caller data anywhere in the file and every
 * data-flow rule stays silent on it. This adapter supplies both halves of what is
 * missing: the address the report needs in order to name the thing, and — the part
 * that actually matters — the one binding in each handler that holds data an
 * outsider chose.
 *
 * The discipline throughout is that a seed is a claim about the world, and a wrong
 * claim is not one wrong finding but one per rule, in a file the reader had no
 * reason to doubt. Every shape below is therefore gated on evidence that this file
 * really uses the library — the import, or a name that belongs to no other API —
 * and any handler whose payload could not be located is emitted as a bare address
 * with no seeds at all. A missing seed costs recall on one file; an invented one
 * costs the reader's trust in the whole report.
 */

const FRAMEWORK = "workers";

/* ------------------------------------------------------------------ *
 * Library gates
 *
 * Each shape has its own gate, and `applies` is their disjunction, so the cheap
 * pre-check and the detection can never disagree about whether a file uses a
 * library. `importsFrom` already understands `require()`, which is how most of
 * the worker code in the world is still written.
 * ------------------------------------------------------------------ */

/**
 * BullMQ and Bull v3. The import is required rather than merely preferred,
 * because `new Worker(...)` is also the constructor of `node:worker_threads` and
 * of the DOM's web worker, and those take a script path where BullMQ takes a
 * processor.
 */
function usesJobQueue(file: ParsedFile): boolean {
  return importsFrom(file, /^bullmq$|^bull$/);
}

/**
 * kafkajs. The consumer's `run({ eachMessage })` is often written in a file that
 * imports only the shared client, so the option name — which belongs to no other
 * API — also counts as evidence.
 */
function usesKafka(file: ParsedFile): boolean {
  return importsFrom(file, /^kafkajs$/) || /\beachMessage\b|\beachBatch\b/.test(file.text);
}

/** amqplib, directly or through the connection manager wrapper. */
function usesAmqp(file: ParsedFile): boolean {
  return importsFrom(file, /^amqplib(\/|$)|^amqp-connection-manager$/) || /\bamqplib\b|amqp:\/\//.test(file.text);
}

/**
 * Worker threads. `process.on("message", ...)` alone is deliberately not enough:
 * it appears in ordinary scripts that never fork anything, and claiming those
 * would seed a parameter that holds nothing an outsider ever touched.
 */
function usesThreadMessaging(file: ParsedFile): boolean {
  return importsFrom(file, /^(node:)?worker_threads$/) || /\bparentPort\b/.test(file.text);
}

/**
 * A Lambda consumer of SQS, SNS, DynamoDB Streams, or Kinesis. The batch envelope
 * is the only thing all four share and the only thing worth keying on, so the text
 * check is confirmed in `recordBatchEntryPoints` against the handler's own
 * parameter before anything is claimed.
 */
function mentionsRecordBatch(file: ParsedFile): boolean {
  return /\.Records\b|\bRecords\s*[,}:]/.test(file.text);
}

/* ------------------------------------------------------------------ *
 * Shared plumbing
 * ------------------------------------------------------------------ */

/**
 * The handler a registration was given, whether written inline or declared above
 * it. Half of the worker code in a real repository passes a named processor —
 * `new Worker(QUEUE, processInvoice)` — and a resolver that only understands the
 * inline arrow form finds no handler, which means no seed, which means the file
 * stays as invisible as it was before this adapter existed.
 */
function handlerOf(file: ParsedFile, argument: ts.Expression | undefined): ts.Node | undefined {
  const inline = functionOf(argument);
  if (inline) return inline;
  if (!argument || !ts.isIdentifier(argument)) return undefined;

  const name = argument.text;
  for (const declaration of collect(file.source, ts.isFunctionDeclaration)) {
    if (declaration.name?.text === name) return declaration;
  }
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
    const resolved = functionOf(declaration.initializer);
    if (resolved) return resolved;
  }
  return undefined;
}

/** The handler held by one member of an options object, in any of its three spellings. */
function memberHandler(file: ParsedFile, member: ts.ObjectLiteralElementLike): ts.Node | undefined {
  if (ts.isPropertyAssignment(member)) return handlerOf(file, member.initializer);
  if (ts.isShorthandPropertyAssignment(member)) return handlerOf(file, member.name);
  if (ts.isMethodDeclaration(member)) return member;
  return undefined;
}

function memberName(file: ParsedFile, member: ts.ObjectLiteralElementLike): string {
  return member.name ? member.name.getText(file.source).replace(/["']/g, "") : "";
}

function firstParameter(fn: ts.Node | undefined): ts.ParameterDeclaration | undefined {
  return (fn as ts.FunctionLikeDeclaration | undefined)?.parameters?.[0];
}

function parameterIdentifier(parameter: ts.ParameterDeclaration | undefined): string | null {
  if (!parameter) return null;
  return ts.isIdentifier(parameter.name) ? parameter.name.text : null;
}

/**
 * The local name a destructured parameter binds `property` to, if it binds it at
 * all. `async ({ topic, message }) => {}` is the shape kafkajs's own documentation
 * uses, and there is no identifier parameter in it to seed.
 */
function destructuredName(
  file: ParsedFile,
  parameter: ts.ParameterDeclaration | undefined,
  property: string
): string | null {
  if (!parameter || !ts.isObjectBindingPattern(parameter.name)) return null;
  for (const element of parameter.name.elements) {
    if ((element.propertyName ?? element.name).getText(file.source) !== property) continue;
    if (ts.isIdentifier(element.name)) return element.name.text;
  }
  return null;
}

function consumer(
  file: ParsedFile,
  site: ts.Node,
  path: string,
  handler: ts.Node | undefined,
  seeds: TaintSeed[],
  kind: EntryPoint["kind"] = "queue"
): EntryPoint {
  return {
    framework: FRAMEWORK,
    kind,
    method: "CONSUME",
    path,
    line: lineOf(file, site),
    ...(handler ? { node: handler } : {}),
    ...(seeds.length > 0 ? { seeds } : {})
  };
}

/**
 * The name a queue was declared with somewhere in this file.
 *
 * Both `const QUEUE = "invoices"` passed to a worker and `const queue = new
 * Queue("invoices")` addressed by `queue.process(...)` hide the same literal one
 * hop away, and a report that says `CONSUME QUEUE` instead of `CONSUME invoices`
 * names something the reader cannot look up.
 */
function declaredQueueName(file: ParsedFile, variable: string): string | null {
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== variable) continue;
    const initializer = declaration.initializer;
    if (!initializer) continue;
    const direct = literalTextOf(initializer);
    if (direct) return direct;
    if (ts.isNewExpression(initializer) || ts.isCallExpression(initializer)) {
      const first = initializer.arguments?.[0];
      if (first) {
        const literal = literalTextOf(first);
        if (literal) return literal;
      }
    }
  }
  return null;
}

/** The queue name argument as an address: its literal, the constant behind it, or its own text. */
function queueLabel(file: ParsedFile, argument: ts.Expression | undefined): string {
  if (!argument) return "queue";
  const literal = literalTextOf(argument);
  if (literal) return literal;
  if (ts.isIdentifier(argument)) return declaredQueueName(file, argument.text) ?? argument.text;
  const name = expressionName(argument);
  return name.length > 0 ? name : "queue";
}

/* ------------------------------------------------------------------ *
 * BullMQ and Bull v3
 * ------------------------------------------------------------------ */

/**
 * `job.data` is whatever the producer put there, and the producer is normally the
 * request handler that accepted the work. `job` itself carries framework state
 * too — attempts, timestamps — but taint on the root propagates only where the
 * rules follow a value, and every value they follow out of a job comes from
 * `data`, so seeding the parameter is both the useful and the honest choice.
 */
function jobSeeds(file: ParsedFile, handler: ts.Node): TaintSeed[] {
  const parameter = firstParameter(handler);
  const named = parameterIdentifier(parameter);
  if (named) return [{ name: named, origin: `${named}.data (payload enqueued by an outside caller)` }];
  const destructured = destructuredName(file, parameter, "data");
  if (destructured) return [{ name: destructured, origin: "job.data (payload enqueued by an outside caller)" }];
  return [];
}

function jobQueueEntryPoints(file: ParsedFile): EntryPoint[] {
  const found: EntryPoint[] = [];

  for (const construction of collect(file.source, ts.isNewExpression)) {
    const constructed = expressionName(construction.expression);
    if (constructed !== "Worker" && !constructed.endsWith(".Worker")) continue;
    // `new Worker(path, { workerData })` from node:worker_threads shares this
    // constructor name exactly. What separates them is the second argument: a
    // processor function against an options object or a file path. A file that
    // imports both libraries therefore still gets each of its workers right.
    const handler = handlerOf(file, construction.arguments?.[1]);
    if (!handler) continue;
    found.push(consumer(file, construction, queueLabel(file, construction.arguments?.[0]), handler, jobSeeds(file, handler)));
  }

  // Bull v3 registers the processor on the queue itself, in any of
  // `process(fn)`, `process(concurrency, fn)`, and `process(name, concurrency, fn)`.
  // Taking the first function-shaped argument covers all three without having to
  // know which overload was written.
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (calleeTail(call) !== "process") continue;
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    const receiver = call.expression.expression;
    if (!ts.isIdentifier(receiver)) continue;

    let handler: ts.Node | undefined;
    for (const argument of call.arguments) {
      handler = handlerOf(file, argument);
      if (handler) break;
    }
    if (!handler) continue;
    found.push(consumer(file, call, declaredQueueName(file, receiver.text) ?? receiver.text, handler, jobSeeds(file, handler)));
  }

  return found;
}

/* ------------------------------------------------------------------ *
 * kafkajs
 * ------------------------------------------------------------------ */

/**
 * The topic this file subscribes to, so the entry point carries an address a
 * reader can find in the broker rather than the word "kafka". A consumer that
 * subscribes to several topics is reported under the first: the handler is one
 * piece of code either way, and naming one real topic beats naming none.
 */
function subscribedTopic(file: ParsedFile): string | null {
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (calleeTail(call) !== "subscribe") continue;
    const options = call.arguments[0];
    if (!options || !ts.isObjectLiteralExpression(options)) continue;
    for (const property of options.properties) {
      if (!ts.isPropertyAssignment(property)) continue;
      const key = memberName(file, property);
      if (key === "topic") {
        const literal = literalTextOf(property.initializer);
        if (literal) return literal;
      }
      if (key === "topics" && ts.isArrayLiteralExpression(property.initializer)) {
        for (const element of property.initializer.elements) {
          const literal = literalTextOf(element);
          if (literal) return literal;
        }
      }
    }
  }
  return null;
}

/**
 * Everything in an `eachMessage` payload — key, value, headers — was written by
 * the producer. The batch form is the same envelope with the messages in an
 * array, so it is seeded the same way rather than left as the one shape where a
 * high-throughput consumer silently loses its taint.
 */
function kafkaSeeds(file: ParsedFile, handler: ts.Node, member: string): TaintSeed[] {
  const parameter = firstParameter(handler);
  const property = member === "eachBatch" ? "batch" : "message";
  const suffix = member === "eachBatch" ? "messages" : "value";

  const destructured = destructuredName(file, parameter, property);
  if (destructured) {
    return [{ name: destructured, origin: `${destructured}.${suffix} (payload published by an outside producer)` }];
  }
  const whole = parameterIdentifier(parameter);
  if (whole) {
    return [{ name: whole, origin: `${whole}.${property}.${suffix} (payload published by an outside producer)` }];
  }
  return [];
}

function kafkaEntryPoints(file: ParsedFile): EntryPoint[] {
  const found: EntryPoint[] = [];
  const topic = subscribedTopic(file) ?? "kafka";

  for (const call of collect(file.source, ts.isCallExpression)) {
    if (calleeTail(call) !== "run") continue;
    const options = call.arguments[0];
    if (!options || !ts.isObjectLiteralExpression(options)) continue;
    for (const member of options.properties) {
      const key = memberName(file, member);
      if (key !== "eachMessage" && key !== "eachBatch") continue;
      const handler = memberHandler(file, member);
      if (!handler) continue;
      found.push(consumer(file, member, topic, handler, kafkaSeeds(file, handler, key)));
    }
  }

  return found;
}

/* ------------------------------------------------------------------ *
 * amqplib
 * ------------------------------------------------------------------ */

/**
 * `msg.content` is the raw body the publisher sent, and the publisher is reachable
 * from anywhere that can reach the exchange. The handler is also called with
 * `null` when the consumer is cancelled, which changes nothing here: a rule that
 * follows the payload is asking who wrote it, not whether it arrived.
 */
function amqpSeeds(file: ParsedFile, handler: ts.Node): TaintSeed[] {
  const parameter = firstParameter(handler);
  const named = parameterIdentifier(parameter);
  if (named) return [{ name: named, origin: `${named}.content (payload published by an outside producer)` }];
  const destructured = destructuredName(file, parameter, "content");
  if (destructured) return [{ name: destructured, origin: "msg.content (payload published by an outside producer)" }];
  return [];
}

function amqpEntryPoints(file: ParsedFile): EntryPoint[] {
  const found: EntryPoint[] = [];

  for (const call of collect(file.source, ts.isCallExpression)) {
    if (calleeTail(call) !== "consume") continue;
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    const handler = handlerOf(file, call.arguments[1]);
    if (!handler) continue;
    found.push(consumer(file, call, queueLabel(file, call.arguments[0]), handler, amqpSeeds(file, handler)));
  }

  return found;
}

/* ------------------------------------------------------------------ *
 * node:worker_threads
 * ------------------------------------------------------------------ */

const LISTENER_METHODS = new Set(["on", "once", "addListener"]);

/**
 * A message crossing a thread boundary is only as trustworthy as the thread that
 * sent it, and the reason work is on another thread is almost always that a
 * request handed it there. The whole parameter is the payload — unlike a job,
 * there is no envelope around it — so it is seeded directly.
 *
 * A destructured parameter is left unseeded on purpose. Which property of a
 * hand-rolled message carries the caller's data is a per-application convention,
 * and guessing at it is precisely the kind of invention that makes a scanner
 * report defects in code that has none.
 */
function threadMessageEntryPoints(file: ParsedFile): EntryPoint[] {
  const found: EntryPoint[] = [];

  for (const call of collect(file.source, ts.isCallExpression)) {
    if (!LISTENER_METHODS.has(calleeTail(call))) continue;
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    const event = call.arguments[0];
    if (!event || literalTextOf(event) !== "message") continue;
    const handler = handlerOf(file, call.arguments[1]);
    if (!handler) continue;

    const named = parameterIdentifier(firstParameter(handler));
    const seeds: TaintSeed[] = named
      ? [{ name: named, origin: `${named} (payload sent over the thread's message port)` }]
      : [];
    found.push(consumer(file, call, "message", handler, seeds, "ipc"));
  }

  return found;
}

/* ------------------------------------------------------------------ *
 * AWS record-batch Lambda consumers
 * ------------------------------------------------------------------ */

function isExported(statement: ts.FunctionDeclaration | ts.VariableStatement): boolean {
  return statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ?? false;
}

/**
 * Functions this module hands to a runtime, in both module systems. A Lambda
 * handler is only ever reached by being exported, so anything private is
 * somebody's helper and claiming it would put an entry point on code no event
 * ever enters.
 */
function exportedFunctions(file: ParsedFile): ts.Node[] {
  const found: ts.Node[] = [];

  for (const statement of file.source.statements) {
    if (ts.isFunctionDeclaration(statement)) {
      if (isExported(statement)) found.push(statement);
      continue;
    }
    if (ts.isVariableStatement(statement)) {
      if (!isExported(statement)) continue;
      for (const declaration of statement.declarationList.declarations) {
        const fn = functionOf(declaration.initializer);
        if (fn) found.push(fn);
      }
      continue;
    }
    if (ts.isExportAssignment(statement)) {
      const fn = functionOf(statement.expression);
      if (fn) found.push(fn);
      continue;
    }
    if (!ts.isExpressionStatement(statement)) continue;
    const assignment = statement.expression;
    if (!ts.isBinaryExpression(assignment) || assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
    if (!/^(module\.)?exports(\.|$)/.test(expressionName(assignment.left))) continue;
    const fn = functionOf(assignment.right);
    if (fn) {
      found.push(fn);
      continue;
    }
    // `module.exports = { handler }` is the other half of the CommonJS idiom.
    if (!ts.isObjectLiteralExpression(assignment.right)) continue;
    for (const member of assignment.right.properties) {
      const handler = memberHandler(file, member);
      if (handler) found.push(handler);
    }
  }

  return found;
}

/** Does this function actually read `Records` off its own first parameter? */
function readsRecordBatch(file: ParsedFile, fn: ts.Node, parameter: string): boolean {
  for (const access of collect(fn, ts.isPropertyAccessExpression)) {
    if (access.name.text !== "Records") continue;
    if (ts.isIdentifier(access.expression) && access.expression.text === parameter) return true;
  }
  for (const declaration of collect(fn, ts.isVariableDeclaration)) {
    if (!ts.isObjectBindingPattern(declaration.name)) continue;
    if (!declaration.initializer || !ts.isIdentifier(declaration.initializer)) continue;
    if (declaration.initializer.text !== parameter) continue;
    for (const element of declaration.name.elements) {
      if ((element.propertyName ?? element.name).getText(file.source) === "Records") return true;
    }
  }
  return false;
}

/**
 * SQS, SNS, DynamoDB Streams, and Kinesis all deliver to Lambda as a batch of
 * records, and a handler that reads `event.Records` has said so itself. Requiring
 * that read is what keeps this apart from an HTTP Lambda, whose `event` is a
 * different envelope entirely and belongs to whichever adapter owns API Gateway —
 * a duplicate entry point would merely deduplicate away, but a queue entry point
 * on an HTTP handler would mislabel a route in every finding under it.
 */
function recordBatchEntryPoints(file: ParsedFile): EntryPoint[] {
  const found: EntryPoint[] = [];

  for (const fn of exportedFunctions(file)) {
    const parameter = firstParameter(fn);
    if (!parameter) continue;

    const named = parameterIdentifier(parameter);
    if (named) {
      if (!readsRecordBatch(file, fn, named)) continue;
      found.push(
        consumer(file, fn, "sqs", fn, [
          { name: named, origin: `${named}.Records (message payloads delivered by the queue or topic)` }
        ])
      );
      continue;
    }

    const records = destructuredName(file, parameter, "Records");
    if (!records) continue;
    found.push(
      consumer(file, fn, "sqs", fn, [
        { name: records, origin: "event.Records (message payloads delivered by the queue or topic)" }
      ])
    );
  }

  return found;
}

/* ------------------------------------------------------------------ *
 * Adapter
 * ------------------------------------------------------------------ */

function applies(file: ParsedFile): boolean {
  return (
    usesJobQueue(file) ||
    usesKafka(file) ||
    usesAmqp(file) ||
    usesThreadMessaging(file) ||
    mentionsRecordBatch(file)
  );
}

function detect(file: ParsedFile): EntryPoint[] {
  const found: EntryPoint[] = [];
  if (usesJobQueue(file)) found.push(...jobQueueEntryPoints(file));
  if (usesKafka(file)) found.push(...kafkaEntryPoints(file));
  if (usesAmqp(file)) found.push(...amqpEntryPoints(file));
  if (usesThreadMessaging(file)) found.push(...threadMessageEntryPoints(file));
  if (mentionsRecordBatch(file)) found.push(...recordBatchEntryPoints(file));
  return found;
}

/**
 * Scheduled work — node-cron, agenda's recurring jobs, Temporal activities — is
 * deliberately absent. A job the application schedules for itself carries the
 * arguments the application chose, so seeding its callback would announce
 * attacker data in code no attacker can reach. When such a job does read outside
 * input it reads it from the database or an HTTP call, and the rule that cares
 * sees that read for what it is without any help from here.
 */
export const workersAdapter: FrameworkAdapter = { id: "workers", applies, detect };

/**
 * The registry names this one after what it recognises rather than after its
 * file. Both names are the same object, so registering either registers the
 * adapter once — `registerAdapter` deduplicates on the id in any case.
 */
export const queueAdapter = workersAdapter;
