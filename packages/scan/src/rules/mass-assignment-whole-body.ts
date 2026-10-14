import ts from "typescript";
import { calleeTail, collect, expressionName, walk } from "../ast/helpers.js";
import { functionsIn } from "../ast/taint.js";
import { lineOf } from "../ast/parse.js";
import { routeOf } from "./attribution.js";
import { declarationFor } from "./browser-sources.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * The request body handed to an ORM write as it arrived.
 *
 * `mass-assignment-spread` owns the spread — `data: { ...req.body, ownerId }` — and
 * the `Object.assign` copy. The commoner form has neither: `User.create(req.body)`,
 * `data: body`, `repo.save(await request.json())`. Nothing is spread, so nothing
 * named a spread is there to see, and the receiver is a model class the write
 * classifier does not know. The defect is identical — the caller, not the code,
 * decides which columns are written — and so is the fix.
 *
 * The source/sink spec is deliberately thin so the engine's cross-function flow
 * can take it over: a *whole-body source* (`isWholeBody`) and an *ORM write sink*
 * (`writeOf`). A field read (`req.body.name`) is never a whole body, and neither is
 * anything that passed through a call — a schema parse, a `pick`, a mapper — which
 * is why a validated body is silent without this rule naming any validator.
 *
 * Covered: Prisma `data`/`create`/`update`; Mongoose and Sequelize static
 * `create`/`insertMany`/`bulkCreate`/`build`, `new Model(body)`, the
 * `findByIdAndUpdate` family and `{ $set: body }`, instance `set`/`update`/`overwrite`
 * on a record this function fetched; Sequelize `Model.update(body, { where })`;
 * TypeORM `save`/`insert`/`create`/`update`/`merge`; Drizzle and Kysely `.values`
 * and `.set`; Knex `.insert` and `.update`.
 */

/** Packages and paths whose presence says this module talks to a database. */
const ORM_EVIDENCE = /["'`](?:mongoose|sequelize|@prisma\/client|typeorm|drizzle-orm[^"'`]*|knex|kysely|objection|@mikro-orm\/[^"'`]+|[^"'`]*\/(?:models?|entities|entity|db|database|repositories|repository|schema|prisma)(?:\/[^"'`]*)?)["'`]/;

const STATIC_CREATES = new Set(["create", "insertMany", "bulkCreate", "build", "createOne"]);
const UPDATE_SECOND_ARGUMENT = new Set([
  "findByIdAndUpdate",
  "findOneAndUpdate",
  "updateOne",
  "updateMany",
  "replaceOne",
  "findOneAndReplace",
  "findByIdAndReplace"
]);
const INSTANCE_WRITES = new Set(["set", "update", "overwrite", "assign"]);
const FETCHES = /^(?:findById|findByPk|findOne|findOneBy|findOneOrFail|findOneByOrFail|findFirst|findUnique|findFirstOrThrow|findUniqueOrThrow|get|load|fetch)$/;
const PRISMA_METHODS = new Set(["create", "update", "upsert", "createMany", "updateMany", "createManyAndReturn"]);
const REPOSITORY_RECEIVER = /(?:repo|repository|manager|entityManager|em)$/i;
const VALIDATING_MIDDLEWARE = /valid|celebrate|schema|zod|joi|yup|ajv|sanitiz|whitelist|allowlist|checkBody|body\s*\(/i;

/** Field names whose presence on a row makes a whole-body write a privilege question. */
const PRIVILEGED_FIELD = /\b(?:role|roles|isAdmin|is_admin|isStaff|is_staff|isSuperuser|permissions|scopes|ownerId|owner_id|tenantId|tenant_id|organizationId|orgId|plan|planId|tier|credits|balance|emailVerified|email_verified|isVerified|isApproved)\b/;
const IDENTITY_MODEL = /^(?:user|users|account|accounts|member|members|membership|profile|profiles|customer|customers|subscription|subscriptions|team|teams|workspace|workspaces|organi[sz]ation|organi[sz]ations|employee|employees|admin|admins|staff)$/i;

interface Write {
  /** The expression that receives the whole body. */
  payload: ts.Expression;
  /** What performs the write, for the evidence. */
  subject: string;
  /** The model, table or entity named by the call, when it names one. */
  model: string | null;
}

export const massAssignmentWholeBody: Rule = {
  id: "mass-assignment-whole-body",
  category: "mass_assignment",
  describes: "the request body passed whole to an ORM create or update",
  run(context: RuleContext) {
    if (!ORM_EVIDENCE.test(context.file.text) && !/\bprisma\./.test(context.file.text)) return;
    const reported = new Set<number>();

    for (const fn of functionsIn(context.file.source)) {
      if (ts.isSourceFile(fn)) continue;
      if (routeValidatesBody(fn)) continue;
      for (const node of collect(fn, (inner): inner is ts.CallExpression | ts.NewExpression => ts.isCallExpression(inner) || ts.isNewExpression(inner))) {
        if (directFunction(node) !== fn) continue;
        const write = ts.isNewExpression(node) ? constructedModel(context, node) : writeOf(context, node, fn);
        if (!write) continue;
        const whole = isWholeBody(write.payload, fn, 0);
        if (!whole) continue;
        const line = lineOf(context.file, node);
        if (reported.has(line)) continue;
        reported.add(line);

        const privileged = privilegedEvidence(context, write.model);
        context.report({
          ruleId: "mass-assignment-whole-body",
          category: "mass_assignment",
          title: `The request body is written to the database whole by ${write.subject}`,
          severity: privileged ? "high" : "medium",
          verification: privileged ? "strong_evidence" : "needs_review",
          summary: `${whole} is handed to ${write.subject} as it arrived, so every key the caller sends becomes a column this write sets. No list of accepted fields, and no schema that drops unknown keys, stands between the request and the row.${
            privileged ? ` ${privileged}` : ""
          }`,
          impact:
            "A caller adds a field the form never shows — a role, an owner, a plan, a verification flag — and it is stored on their record. On a create that mints a privileged account; on an update it is privilege escalation through the ordinary settings endpoint.",
          remediation:
            "Copy the fields this operation accepts into a new object by name, or parse the body with a schema that strips or rejects unknown keys (for example a Zod object without `.passthrough()`) and write the parsed result. Set ownership and privilege columns from the session, never from the body.",
          verificationPlan: `Send the request this endpoint expects with one extra field${privileged ? " (one of the fields named above)" : " such as `role` or `isAdmin`"}, then read the record back. The extra field must not be stored, and ideally the request is rejected.`,
          taxonomy: ["CWE-915", "OWASP-A01", "OWASP-A04"],
          location: locationOf(context, node),
          ...routeOf(context, node),
          evidence: [
            sourceEvidence(context, node, `${write.subject} receives ${whole} unchanged; no field is named between the request and the write.`),
            { kind: "source", description: `Data flow: ${whole} reaches ${write.subject} with no allowlist, schema parse, or field selection on the path.` }
          ],
          reasoning: `The whole request body (${whole}) is the payload of ${write.subject}${write.model ? ` on ${write.model}` : ""}. Any call between the two — a parse, a pick, a mapper — would have ended the flow, and none is present.`
        });
      }
    }
  }
};

/** Classify a call as an ORM write and say which argument is its payload. */
function writeOf(context: RuleContext, call: ts.CallExpression | ts.NewExpression, fn: ts.Node): Write | null {
  if (!ts.isCallExpression(call) || !ts.isPropertyAccessExpression(call.expression)) return null;
  const tail = call.expression.name.text;
  const receiver = call.expression.expression;
  const receiverText = expressionName(receiver);
  const receiverTail = receiverText.split(".").pop() ?? "";
  const subject = `${receiverText || receiver.getText(context.file.source)}.${tail}()`;
  const first = call.arguments[0];
  const second = call.arguments[1];

  // Prisma: prisma.user.create({ data: body }), upsert's create/update.
  if (PRISMA_METHODS.has(tail) && first && ts.isObjectLiteralExpression(first) && /\.\w+$/.test(receiverText)) {
    for (const key of tail === "upsert" ? ["create", "update"] : ["data"]) {
      const payload = propertyNamed(first, key);
      if (payload) return { payload, subject, model: receiverTail };
    }
    return null;
  }

  // Mongoose / Sequelize statics on a model class.
  if (STATIC_CREATES.has(tail) && first && isModelClass(receiver)) {
    return { payload: first, subject, model: receiverTail };
  }
  if (UPDATE_SECOND_ARGUMENT.has(tail) && second && isModelLike(receiver)) {
    const payload = ts.isObjectLiteralExpression(second) ? propertyNamed(second, "$set") : second;
    return payload ? { payload, subject, model: receiverTail } : null;
  }
  // Sequelize Model.update(values, { where }) — unless `fields` limits the columns.
  if (tail === "update" && first && second && isModelClass(receiver) && ts.isObjectLiteralExpression(second)) {
    if (propertyNamed(second, "fields")) return null;
    if (!propertyNamed(second, "where")) return null;
    return { payload: first, subject, model: receiverTail };
  }

  // TypeORM repositories and entity managers.
  if (REPOSITORY_RECEIVER.test(receiverTail)) {
    if ((tail === "save" || tail === "insert" || tail === "create") && first) {
      // manager.save(User, body) names the entity first.
      const payload = second && ts.isIdentifier(first) && /^[A-Z]/.test(first.text) ? second : first;
      return { payload, subject, model: modelOfRepository(receiverTail) };
    }
    if ((tail === "update" || tail === "merge") && second) return { payload: second, subject, model: modelOfRepository(receiverTail) };
  }

  // Drizzle / Kysely / Knex chains: db.insert(users).values(body), knex("users").update(body).
  if (["values", "set", "insert", "update"].includes(tail) && first && call.arguments.length === 1 && isQueryChain(receiver)) {
    return { payload: first, subject: `${tail}() in a query-builder chain`, model: chainTable(receiver) };
  }

  // A record this function fetched, updated in place: user.set(body); await user.save().
  if (INSTANCE_WRITES.has(tail) && first && call.arguments.length === 1 && ts.isIdentifier(receiver) && fetchedInFunction(receiver, fn)) {
    return { payload: first, subject, model: receiver.text };
  }
  return null;
}

function constructedModel(context: RuleContext, node: ts.NewExpression): Write | null {
  const first = node.arguments?.[0];
  if (!first || !ts.isIdentifier(node.expression) || !/^[A-Z][A-Za-z0-9]*$/.test(node.expression.text)) return null;
  // `new User(body)` is only a write when this module is visibly a document store,
  // because a class constructor is otherwise anybody's.
  if (!/["'`]mongoose["'`]|\.save\(\)/.test(context.file.text)) return null;
  if (/^(?:URL|URLSearchParams|Map|Set|Error|Date|Response|Request|Headers|FormData|Blob|Buffer|Promise|RegExp|Array|Object)$/.test(node.expression.text)) return null;
  return { payload: first, subject: `new ${node.expression.text}()`, model: node.expression.text };
}

/**
 * Is this, after following local bindings, the request body as it arrived?
 *
 * Returns a description of it, or null. The one transformation followed is object
 * rest — `const { id, ...changes } = req.body` — because removing named keys and
 * keeping the rest is the same defect with a denylist in front of it.
 */
export function isWholeBody(node: ts.Expression, fn: ts.Node, depth: number): string | null {
  if (depth > 6) return null;
  let current: ts.Expression = node;
  while (ts.isAwaitExpression(current) || ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isNonNullExpression(current) || ts.isSatisfiesExpression(current)) {
    current = current.expression;
  }

  if (ts.isPropertyAccessExpression(current) && current.name.text === "body") {
    const base = expressionName(current.expression);
    if (/^(?:req|request|ctx\.request|context\.request|ctx\.req)$/.test(base)) return `${base}.body`;
    return null;
  }

  if (ts.isCallExpression(current)) {
    const name = expressionName(current.expression);
    const tail = calleeTail(current);
    if (["json", "formData", "parseBody"].includes(tail) && ts.isPropertyAccessExpression(current.expression)) {
      const base = expressionName(current.expression.expression);
      if (/^(?:req|request|c\.req|ctx\.req|context\.req)$/.test(base)) return `${name}()`;
    }
    if (name === "JSON.parse" && current.arguments[0]) {
      const inner = current.arguments[0];
      if (ts.isPropertyAccessExpression(inner) && inner.name.text === "body" && /^(?:event|req|request)$/.test(expressionName(inner.expression))) {
        return `JSON.parse(${expressionName(inner)})`;
      }
    }
    if (name === "Object.fromEntries" && current.arguments[0]) {
      const inner = isWholeBody(current.arguments[0], fn, depth + 1);
      return inner ? `Object.fromEntries(${inner})` : null;
    }
    if (name === "readBody" && current.arguments[0] && ts.isIdentifier(current.arguments[0])) return `readBody(${current.arguments[0].text})`;
    return null;
  }

  if (ts.isIdentifier(current)) {
    const declaration = declarationFor(current);
    if (!declaration || !isInside(declaration, fn)) return null;
    if (reassignedInFunction(current.text, fn)) return null;
    if (ts.isVariableDeclaration(declaration) && declaration.initializer) return isWholeBody(declaration.initializer, fn, depth + 1);
    if (ts.isBindingElement(declaration) && declaration.dotDotDotToken) {
      let container: ts.Node = declaration.parent;
      while (container && !ts.isVariableDeclaration(container)) container = container.parent;
      if (container && ts.isVariableDeclaration(container) && container.initializer) {
        const inner = isWholeBody(container.initializer, fn, depth + 1);
        return inner ? `the rest of ${inner}` : null;
      }
    }
  }
  return null;
}

/** A binding written again after its declaration is not provably the body any more. */
function reassignedInFunction(name: string, fn: ts.Node): boolean {
  let reassigned = false;
  walk(fn, (node) => {
    if (reassigned) return;
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left) && node.left.text === name) {
      reassigned = true;
    }
  });
  return reassigned;
}

/**
 * Is this handler registered behind a validating middleware, or with a route
 * schema? Either one changes what the body can contain, and this rule cannot read
 * what the validator does, so it stays quiet rather than guess.
 */
function routeValidatesBody(fn: ts.Node): boolean {
  const registration = fn.parent;
  if (!registration || !ts.isCallExpression(registration)) return false;
  for (const argument of registration.arguments) {
    if (argument === fn) continue;
    if (ts.isCallExpression(argument) && VALIDATING_MIDDLEWARE.test(argument.expression.getText())) return true;
    if (ts.isIdentifier(argument) && VALIDATING_MIDDLEWARE.test(argument.text)) return true;
    if (ts.isObjectLiteralExpression(argument) && propertyNamed(argument, "schema")) return true;
    if (ts.isArrayLiteralExpression(argument) && VALIDATING_MIDDLEWARE.test(argument.getText())) return true;
  }
  return false;
}

function propertyNamed(object: ts.ObjectLiteralExpression, key: string): ts.Expression | null {
  for (const property of object.properties) {
    if (ts.isPropertyAssignment(property)) {
      const name = property.name.getText().replace(/["']/g, "");
      if (name === key) return property.initializer;
    }
    if (ts.isShorthandPropertyAssignment(property) && property.name.text === key) return property.name;
  }
  return null;
}

/** `User`, `models.User`, `db.models.User`, `UserModel`. */
function isModelClass(receiver: ts.Expression): boolean {
  const name = expressionName(receiver);
  const last = name.split(".").pop() ?? "";
  return /^[A-Z][A-Za-z0-9]*$/.test(last) && !/^(?:Object|Array|JSON|Math|Promise|Reflect|Date|Number|String|Buffer|URL|Map|Set|Response|NextResponse)$/.test(last);
}

function isModelLike(receiver: ts.Expression): boolean {
  if (isModelClass(receiver)) return true;
  // db.collection("users").updateOne(...) — the native driver.
  return ts.isCallExpression(receiver) && calleeTail(receiver) === "collection";
}

function modelOfRepository(name: string): string | null {
  const match = /^(\w+?)(?:Repo|Repository)$/i.exec(name);
  return match ? match[1]! : null;
}

function isQueryChain(receiver: ts.Expression): boolean {
  let current: ts.Expression = receiver;
  for (let depth = 0; depth < 8 && ts.isCallExpression(current); depth += 1) {
    const callee = current.expression;
    if (ts.isIdentifier(callee)) return /^(?:knex|db|trx|tx|database|qb|sql)$/.test(callee.text);
    if (!ts.isPropertyAccessExpression(callee)) return false;
    const method = callee.name.text;
    if (["insert", "insertInto", "update", "updateTable", "into", "table", "from", "where", "returning"].includes(method)) {
      const base = callee.expression;
      if (ts.isIdentifier(base)) return /^(?:knex|db|trx|tx|database|qb|kysely)$/.test(base.text);
      if (ts.isPropertyAccessExpression(base)) return /(?:db|knex|trx|tx|database|kysely)$/i.test(expressionName(base));
    }
    current = callee.expression;
  }
  return false;
}

function chainTable(receiver: ts.Expression): string | null {
  let current: ts.Expression = receiver;
  for (let depth = 0; depth < 8 && ts.isCallExpression(current); depth += 1) {
    const argument = current.arguments[0];
    if (argument && (ts.isIdentifier(argument) || ts.isStringLiteralLike(argument))) {
      return ts.isIdentifier(argument) ? argument.text : argument.text;
    }
    const callee = current.expression;
    if (!ts.isPropertyAccessExpression(callee)) return null;
    current = callee.expression;
  }
  return null;
}

/** Was this binding filled from a fetch in the same function — `const user = await User.findByPk(id)`? */
function fetchedInFunction(identifier: ts.Identifier, fn: ts.Node): boolean {
  const declaration = declarationFor(identifier);
  if (!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer || !isInside(declaration, fn)) return false;
  let found = false;
  walk(declaration.initializer, (node) => {
    if (ts.isCallExpression(node) && FETCHES.test(calleeTail(node))) found = true;
  });
  return found;
}

/**
 * Say why a whole-body write here can reach a privileged column, or null.
 *
 * A model named for an identity (a user, an account, a membership), or a privileged
 * field name anywhere in the module. Either one turns "the caller picks the columns"
 * from a data-quality problem into an authorization one.
 */
function privilegedEvidence(context: RuleContext, model: string | null): string | null {
  const tokens = (model ?? "").replace(/Model$|Entity$|Schema$/, "").split(/(?=[A-Z])|[_.\s-]/).filter(Boolean);
  const identity = tokens.find((token) => IDENTITY_MODEL.test(token));
  const field = PRIVILEGED_FIELD.exec(context.file.text.replace(/\/\/.*$/gm, ""));
  if (identity && field) return `The target is an identity record (${model}) and this module refers to \`${field[0]}\`, which a caller can now set.`;
  if (identity) return `The target is an identity record (${model}), the kind of row that carries roles and ownership.`;
  if (field) return `This module refers to \`${field[0]}\`, a field a caller can now set by including it in the body.`;
  return null;
}

function isInside(node: ts.Node, container: ts.Node): boolean {
  return node.getStart() >= container.getStart() && node.getEnd() <= container.getEnd();
}

function directFunction(node: ts.Node): ts.Node | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current) || ts.isArrowFunction(current) || ts.isMethodDeclaration(current)) {
      return current;
    }
    current = current.parent;
  }
  return undefined;
}
