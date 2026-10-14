import { joinTaint, joinValues, withClean, type Taint, type Value } from "./values.js";
import type { Expr } from "../syntax/ast.js";
import { dotted } from "../syntax/ast.js";

/** Environments map a local name, or a dotted attribute path, to what it holds. */
export type Env = Map<string, Value>;

/** Replace parameter origins with what the caller actually passed. */
export function substitute(taint: Taint | null, actual: Map<number, Value>): Taint | null {
  if (!taint) return null;
  let out: Taint | null = null;
  let hasSource = false;
  for (const origin of taint.origins) {
    if (origin.kind === "source") {
      hasSource = true;
      out = joinTaint(out, { origins: [origin], clean: taint.clean });
      continue;
    }
    const passed = actual.get(origin.index)?.taint;
    if (!passed) continue;
    out = joinTaint(out, { origins: passed.origins, clean: new Set([...passed.clean, ...taint.clean]) });
  }
  if (out && hasSource) out = { origins: out.origins, clean: new Set([...out.clean].filter((sink) => taint.clean.has(sink))) };
  return out;
}

/**
 * A composition whose fixed text already decides the destination.
 *
 * `f"https://api.partner.test/v2/items/{item_id}"` sends the request to one host
 * whatever `item_id` holds, and `f"/orders/{order_id}"` redirects within the
 * application. The caller still controls part of the value, so it stays tainted
 * — for SQL it still matters — but not for the sinks whose danger is the
 * destination.
 */
export function withPrefixCleaning(value: Value): Value {
  if (!value.taint) return value;
  const prefix = value.prefix;
  if (/^[a-z][a-z0-9+.-]*:\/\/[^/?#{}\s@]+[/?#]/i.test(prefix)) return withClean(value, ["ssrf", "redirect"]);
  if (/^\/[^/\\]/.test(prefix)) return withClean(value, ["redirect"]);
  return value;
}

/** Calls that end the request: `abort(403)`, `sys.exit()`. */
export function isTerminatingCall(expr: Expr): boolean {
  if (expr.k !== "call") return false;
  const name = dotted(expr.func) ?? "";
  return /(^|\.)(abort|exit|_exit|fail|deny|forbid|raise_for_status_code|unauthorized|forbidden)$/.test(name);
}

/**
 * Merge alternative environments into `target`.
 *
 * An attribute assigned on one path only (`if posted: user.signature = form_value`)
 * still holds what it held before on the other paths. `before` reads that value, so
 * the merge keeps both; without it the merged attribute would be only the assignment.
 */
export function mergeInto(target: Env, alternatives: Env[], before?: (key: string, env: Env) => Value | null): void {
  if (alternatives.length === 0) return;
  const keys = new Set<string>();
  for (const alternative of alternatives) for (const key of alternative.keys()) keys.add(key);
  target.clear();
  for (const key of keys) {
    let merged: Value | null = null;
    for (const alternative of alternatives) {
      let value = alternative.get(key);
      if (!value && before && key.includes(".")) {
        const previous = before(key, alternative);
        if (previous?.taint) value = previous;
      }
      if (!value) continue;
      merged = merged ? joinValues(merged, value) : value;
    }
    if (merged) target.set(key, merged);
  }
}
