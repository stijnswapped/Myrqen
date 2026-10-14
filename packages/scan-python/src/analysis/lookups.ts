import type { Expr, FunctionDef, Span } from "../syntax/ast.js";
import type { PyModule } from "../project/modules.js";
import { calleeTail, dotted, keyword } from "../syntax/ast.js";
import type { Value } from "./values.js";

/**
 * Records fetched by an identifier the caller chose.
 *
 * Observed while a route handler is interpreted, because "the caller chose it"
 * is a data-flow fact: `session.get(Order, order_id)` matters when `order_id`
 * came from the path, and not when it came from the signed-in user's own row.
 * Whether the lookup is then scoped to the caller is decided afterwards, from
 * the whole handler, by the object-level authorization rule.
 */

export interface Lookup {
  span: Span;
  /** The module the lookup is written in: the handler's, or a helper's it calls. */
  module?: PyModule;
  /** The identifier the record was chosen by, as the lookup saw it. */
  key?: Value;
  /** Project functions between the route handler and the lookup, outermost first. */
  path?: FunctionDef[];
  /** For a lookup in a helper, the line of the handler's call that reached it. */
  siteLine?: number;
  /** The model class or table name, when the call names one. */
  model: string | null;
  /** How the lookup was spelled, for the report. */
  via: string;
}

export const OWNER_COLUMN =
  /^(user_id|owner_id|account_id|tenant_id|customer_id|org_id|organization_id|organisation_id|created_by|created_by_id|author_id|member_id|shop_id|merchant_id|company_id|team_id|workspace_id|patient_id|client_id|profile_id|uploaded_by|owner|user|account|tenant)$/;
const OWNER_COLUMN_IN_SQL =
  /\b(user_id|owner_id|account_id|tenant_id|customer_id|org_id|organization_id|created_by|author_id|member_id|shop_id|merchant_id|company_id|team_id|workspace_id|patient_id|client_id|uploaded_by)\b/i;

const ID_NAME = /^(id|pk|uuid|slug|key|\w+_id|\w+_uuid|\w+_pk|\w+_slug)$/i;

/** A value the caller chose through the path or query string (or the body). */
export function callerChosen(value: Value | undefined): boolean {
  return Boolean(
    value?.taint?.origins.some((origin) => origin.kind === "source" && (origin.source === "path" || origin.source === "query" || origin.source === "body" || origin.source === "form"))
  );
}

/**
 * Does the statement pick one row of its own table by an identifier? The identifier
 * has to be a column of the table the statement reads (`documents.id`, `d.id` for
 * `FROM documents d`, or an unqualified `id`), not of a table it joins for filtering
 * (`r.code = :region` on `FROM orders o JOIN regions r`). A statement that aggregates
 * (`GROUP BY`, `SELECT COUNT(...)`) answers with totals, not with a chosen record.
 */
function identifiesRow(text: string, table: string | undefined): boolean {
  if (/\bgroup\s+by\b/i.test(text) || /^\s*select\s+(count|sum|avg|min|max)\s*\(/i.test(text)) return false;
  const from = /\b(?:from|update)\s+["`]?(\w+)["`]?(?:\s+(?:as\s+)?(?!where\b|join\b|inner\b|left\b|right\b|on\b|set\b|order\b|group\b|limit\b)(\w+))?/i.exec(text);
  const owners = new Set([table, from?.[1], from?.[2]].filter((name): name is string => Boolean(name)).map((name) => name.toLowerCase()));
  const predicate = /\bwhere\b([^;]*)$/i.exec(text)?.[1] ?? "";
  for (const match of predicate.matchAll(/(?:(\w+)\.)?\b\w*(?:id|pk|uuid|slug|number|token|code)\b\s*=\s*(?:\?|%s|%\(\w+\)s|:\w+|\$\d)/gi)) {
    if (!match[1] || owners.has(match[1].toLowerCase())) return true;
  }
  return false;
}

/** A helper's parameter: whether the caller chose it is decided at the call site. */
export function fromParameter(value: Value | undefined): boolean {
  return Boolean(value?.taint?.origins.some((origin) => origin.kind === "param"));
}

export function observeLookup(
  call: Extract<Expr, { k: "call" }>,
  receiver: Value | null,
  args: Value[],
  kwargs: Map<string, Value>,
  evaluate: (expr: Expr) => Value,
  chosen: (value: Value | undefined) => boolean = callerChosen
): Lookup | null {
  let key: Value | undefined;
  const callerChosen = (value: Value | undefined): boolean => {
    if (!chosen(value)) return false;
    key = value;
    return true;
  };
  const found = observe(call, receiver, args, kwargs, evaluate, callerChosen);
  return found && key ? { ...found, key } : found;
}

function observe(
  call: Extract<Expr, { k: "call" }>,
  receiver: Value | null,
  args: Value[],
  kwargs: Map<string, Value>,
  evaluate: (expr: Expr) => Value,
  callerChosen: (value: Value | undefined) => boolean
): Lookup | null {
  const tail = calleeTail(call);
  if (!tail) return null;
  const receiverExpr = call.func.k === "attr" ? call.func.value : null;
  const receiverName = receiverExpr ? dotted(receiverExpr) ?? "" : "";

  // session.get(Order, order_id), db.get_or_404(Order, order_id)
  if (/^(get|get_or_404|get_one|aget)$/.test(tail) && /(^|\.)(session|db|database|sess|async_session|s|conn|tx)$/.test(receiverName) && call.args.length >= 2) {
    if (callerChosen(args[1])) return { span: call.span, model: dotted(call.args[0]!) ?? null, via: `${receiverName}.${tail}()` };
  }

  // Order.query.get(order_id), Order.query.get_or_404(order_id)
  if (/^(get|get_or_404)$/.test(tail) && /\.query$/.test(receiverName) && callerChosen(args[0])) {
    return { span: call.span, model: receiverName.replace(/\.query$/, ""), via: `${receiverName}.${tail}()` };
  }

  // Order.query.filter_by(id=order_id), Order.objects.get(pk=order_id)
  if (/^(filter_by|get|get_or_404|first_or_404|filter)$/.test(tail) && call.kwargs.length > 0) {
    const names = call.kwargs.map((kw) => kw.name ?? "");
    if (names.some((name) => OWNER_COLUMN.test(name))) return null;
    for (const kw of call.kwargs) {
      if (kw.name && ID_NAME.test(kw.name) && callerChosen(kwargs.get(kw.name))) {
        return { span: call.span, model: receiverName.split(".")[0] || null, via: `${receiverName}.${tail}(${kw.name}=…)` };
      }
    }
  }

  // select(Order).where(Order.id == order_id), query.filter(Order.id == order_id)
  if (/^(where|filter)$/.test(tail)) {
    const comparisons = call.args.filter((arg): arg is Extract<Expr, { k: "compare" }> => arg.k === "compare" && arg.op === "==");
    if (comparisons.some((comparison) => comparison.left.k === "attr" && OWNER_COLUMN.test(comparison.left.attr))) return null;
    for (const comparison of comparisons) {
      if (comparison.left.k !== "attr" || !ID_NAME.test(comparison.left.attr)) continue;
      if (callerChosen(evaluate(comparison.right))) {
        return { span: call.span, model: dotted(comparison.left.value) ?? null, via: `.${tail}(${dotted(comparison.left) ?? "id"} == …)` };
      }
    }
  }

  // cursor.execute("SELECT … FROM documents WHERE id = ?", (doc_id,))
  if (/^(execute|fetchrow|fetchval|fetch|fetch_one|fetch_all|query)$/.test(tail) && args.length >= 2) {
    const statement = args[0]!;
    const table = /\bfrom\s+["`]?(\w+)/i.exec(statement.text)?.[1] ?? /\bupdate\s+["`]?(\w+)/i.exec(statement.text)?.[1] ?? /\bdelete\s+from\s+["`]?(\w+)/i.exec(statement.text)?.[1];
    // Only an equality on an identifier column is a record lookup; a LIKE search
    // or a date filter returns whatever matches, not one chosen record.
    const byIdentifier = identifiesRow(statement.text, table);
    // An owner column only scopes the lookup when it is in the predicate; selecting
    // `user_id` in the column list constrains nothing.
    const predicate = /\bwhere\b([\s\S]*)$/i.exec(statement.text)?.[1] ?? "";
    if (table && byIdentifier && !OWNER_COLUMN_IN_SQL.test(predicate) && args.slice(1).some(callerChosen) && !statement.taint) {
      return { span: call.span, model: table, via: `${receiverName ? `${receiverName}.` : ""}${tail}()` };
    }
  }

  // orders.get(order_id) on a repository or service object
  if (
    /^(get|get_by_id|find|find_by_id|fetch|load|retrieve|read|get_one|find_one|by_id)$/.test(tail) &&
    (/(repo|repository|store|service|crud|dao|manager)s?$/i.test(receiverName) || /(Repo|Repository|Store|Service|Crud|Dao|Manager)$/.test(receiver?.instance?.cls ?? "")) &&
    callerChosen(args[0])
  ) {
    return { span: call.span, model: receiverName || receiver?.instance?.cls || null, via: `${receiverName}.${tail}()` };
  }
  void keyword;
  return null;
}
