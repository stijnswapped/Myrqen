/**
 * When a reported finding is about a ground-truth case.
 *
 * Extracted from `score-corpus.mjs` so the static scorer and the agent harness apply the
 * *same* rule. Two figures produced by two different matchers cannot be compared, and
 * comparing them is the entire point of measuring an agent against inputs the engine has
 * already been measured on.
 */

/**
 * How far from the stated line a finding may sit and still plainly be about it.
 *
 * A composition and the sink it feeds are usually a handful of lines apart; a finding half a
 * handler away is about a different statement. Fixed before any corpus was authored (ruling
 * U2) so it cannot be tuned to a result.
 */
export const NEAR_LINES = 8;

/**
 * Do two CWE references name the same weakness?
 *
 * Compared on the number alone, so `CWE-639`, `cwe-639` and `639` agree. Nothing cleverer:
 * CWE has a class/base/variant hierarchy, and a report naming the parent of the author's
 * class is arguably right, but crediting that automatically would let the scorer grant itself
 * partial marks. A parent-child disagreement is argued case by case after the score is
 * recorded, per ruling S4.
 */
export function sameCwe(reported, expected) {
  const digits = (value) => String(value ?? "").match(/\d+/)?.[0] ?? null;
  const left = digits(reported);
  return left !== null && left === digits(expected);
}

/**
 * Does the reported route name the case's route?
 *
 * The ground truth's path may *end with* the discovered one on a segment boundary. A router
 * module declares `/search` and the application mounts it at `/invoices`, so a single file
 * genuinely cannot know the full path — the mount lives elsewhere. The method still has to be
 * right, so this is not a free pass.
 */
export function routeMatches(reported, expected) {
  if (!expected) return true;
  if (!reported) return false;
  if (reported === expected) return true;

  const [reportedMethod, ...reportedRest] = reported.split(" ");
  const [expectedMethod, ...expectedRest] = expected.split(" ");
  const reportedPath = reportedRest.join(" ");
  const expectedPath = expectedRest.join(" ");
  if (reportedPath.length === 0 || expectedPath.length === 0) return false;
  if (reportedMethod !== expectedMethod && reportedMethod !== "ANY") return false;

  // A router-root declaration carries no path of its own: every segment of the expected path
  // is the mount prefix, which the file cannot see.
  if (reportedPath === "/") return true;
  return expectedPath === reportedPath || expectedPath.endsWith(`/${reportedPath.replace(/^\/+/, "")}`);
}

/** The strict reading: same class name, same route, inside the author's line range. */
export function satisfies(candidate, entry) {
  if (candidate.category !== entry.category) return false;
  if (!routeMatches(candidate.route, entry.route)) return false;
  const [from, to] = entry.lineRange ?? [entry.line, entry.line];
  return candidate.location.line >= from && candidate.location.line <= to;
}

/**
 * The class name, normalised the way the CLI normalises it.
 *
 * Mirrors `normalizeCategory` in `packages/policy/src/intake.ts` — trim, lower-case, collapse
 * whitespace and dashes to underscores, drop everything else. Needed here because an agent
 * answers `"Path Traversal"` where the corpus says `path_traversal`, and scoring that as a
 * class-name disagreement would measure formatting rather than detection.
 *
 * It does not make the class names *agree* — thirty blind authors invent thirty names the
 * engine does not use, which is why CWE is the join (ruling S2). It only stops the comparison
 * being defeated by capitalisation.
 */
export function normalizeCategory(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, "_")
    .replace(/[^a-z0-9_]/g, "")
    .slice(0, 120);
}

/**
 * Is this finding about this case, ignoring what either side calls the class?
 *
 * The reading the corpus programme actually publishes. `classBlind` asks only whether
 * something landed inside the author's line range; `cwe` additionally requires the CWE to
 * agree, which is the standard both sides were given independently.
 */
export function creditFor(candidate, entry) {
  const [from, to] = entry.lineRange ?? [entry.line, entry.line];
  const line = candidate.location?.line ?? candidate.line;
  if (typeof line !== "number") return null;
  if (line < from || line > to) return null;
  return {
    classBlind: true,
    cwe: sameCwe(candidate.cwe ?? candidate.taxonomy?.find((t) => /cwe/i.test(t)), entry.cwe),
    near: Math.abs(line - entry.line) <= NEAR_LINES,
    exactCategory: normalizeCategory(candidate.category) === normalizeCategory(entry.category),
    line
  };
}
