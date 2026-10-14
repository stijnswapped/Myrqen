import type { AdvisoryRange } from "./advisory-types.js";

/**
 * The part of semantic versioning the advisory check needs, and no more.
 *
 * Written here rather than imported because the scanner ships with no runtime
 * dependency beyond TypeScript, and the comparison it needs is twenty lines. It
 * follows semver.org's precedence: numeric core, then a release outranks any of its
 * pre-releases, then pre-release identifiers compared numerically or lexically.
 */
export interface Version {
  core: [number, number, number];
  pre: string[];
}

export function parseVersion(text: string): Version | null {
  const match = /^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$/.exec(text);
  if (!match) return null;
  return {
    core: [Number(match[1]), Number(match[2] ?? 0), Number(match[3] ?? 0)],
    pre: match[4] ? match[4].split(".") : []
  };
}

export function compare(a: Version, b: Version): number {
  for (let index = 0; index < 3; index += 1) {
    const difference = a.core[index]! - b.core[index]!;
    if (difference !== 0) return difference;
  }
  if (a.pre.length === 0 && b.pre.length === 0) return 0;
  if (a.pre.length === 0) return 1;
  if (b.pre.length === 0) return -1;
  for (let index = 0; index < Math.max(a.pre.length, b.pre.length); index += 1) {
    const left = a.pre[index];
    const right = b.pre[index];
    if (left === undefined) return -1;
    if (right === undefined) return 1;
    const leftNumeric = /^\d+$/.test(left);
    const rightNumeric = /^\d+$/.test(right);
    if (leftNumeric && rightNumeric) {
      const difference = Number(left) - Number(right);
      if (difference !== 0) return difference;
    } else if (leftNumeric !== rightNumeric) {
      return leftNumeric ? -1 : 1;
    } else if (left !== right) {
      return left < right ? -1 : 1;
    }
  }
  return 0;
}

/** Is this exact version inside the advisory range? */
export function inRange(version: Version, range: AdvisoryRange): boolean {
  const introduced = range.introduced === "0" ? null : parseVersion(range.introduced);
  if (introduced && compare(version, introduced) < 0) return false;
  if (range.fixed) {
    const fixed = parseVersion(range.fixed);
    return fixed ? compare(version, fixed) < 0 : false;
  }
  if (range.lastAffected) {
    const last = parseVersion(range.lastAffected);
    return last ? compare(version, last) <= 0 : false;
  }
  return true;
}

/**
 * What a declared range in `package.json` lets the installer choose, as a half-open
 * interval `[lowest, upper)`. `upper` is null for an open-ended range. Exact pins are
 * an interval of one. Anything this does not understand — a tag, a URL, a workspace
 * protocol, a union — returns null, and is treated as unknown rather than guessed at.
 */
export function declaredInterval(spec: string): { lowest: Version; upper: Version | null; exact: boolean } | null {
  const text = spec.trim();
  if (/^(?:npm:|workspace:|file:|link:|git|https?:|github:)|\|\||\s-\s/.test(text)) return null;
  const caret = /^\^(.+)$/.exec(text);
  const tilde = /^~>?(.+)$/.exec(text);
  const atLeast = /^>=\s*([^\s<]+)(?:\s+<\s*(\S+))?$/.exec(text);
  if (caret) {
    const lowest = parseVersion(caret[1]!);
    if (!lowest) return null;
    const [major, minor, patch] = lowest.core;
    const upper: Version = major > 0
      ? { core: [major + 1, 0, 0], pre: [] }
      : minor > 0
        ? { core: [0, minor + 1, 0], pre: [] }
        : { core: [0, 0, patch + 1], pre: [] };
    return { lowest, upper, exact: false };
  }
  if (tilde) {
    const lowest = parseVersion(tilde[1]!);
    if (!lowest) return null;
    return { lowest, upper: { core: [lowest.core[0], lowest.core[1] + 1, 0], pre: [] }, exact: false };
  }
  if (atLeast) {
    const lowest = parseVersion(atLeast[1]!);
    if (!lowest) return null;
    const upper = atLeast[2] ? parseVersion(atLeast[2]) : null;
    return { lowest, upper, exact: false };
  }
  const xRange = /^v?(\d+)(?:\.(\d+|x|\*))?(?:\.(x|\*))?$/i.exec(text);
  if (xRange && (xRange[2] === undefined || /x|\*/i.test(xRange[2] ?? "") || xRange[3] !== undefined)) {
    const major = Number(xRange[1]);
    const minor = xRange[2] && /^\d+$/.test(xRange[2]) ? Number(xRange[2]) : null;
    if (minor === null) return { lowest: { core: [major, 0, 0], pre: [] }, upper: { core: [major + 1, 0, 0], pre: [] }, exact: false };
    return { lowest: { core: [major, minor, 0], pre: [] }, upper: { core: [major, minor + 1, 0], pre: [] }, exact: false };
  }
  const exact = parseVersion(text.replace(/^=/, ""));
  if (exact && /^\s*=?v?\d+\.\d+\.\d+/.test(text)) {
    return { lowest: exact, upper: null, exact: true };
  }
  return null;
}

/**
 * For a declared range with no lockfile: is every version it admits affected?
 *
 * The installer picks the newest version the range allows, which is at least the
 * range's lowest. So the range is certainly affected only when its lowest version is
 * inside the advisory range and the advisory's fix lies *outside* what the range may
 * choose. A `^4.17.11` lodash range admits 4.17.21, so it is not certain; a pinned
 * `4.17.11` is.
 */
export function declaredRangeCertainlyAffected(spec: string, ranges: readonly AdvisoryRange[]): "affected" | "possibly" | "no" {
  const interval = declaredInterval(spec);
  if (!interval) return "no";
  const hit = ranges.find((range) => inRange(interval.lowest, range));
  if (!hit) return "no";
  if (interval.exact) return "affected";
  if (!hit.fixed) return "affected";
  const fixed = parseVersion(hit.fixed);
  if (!fixed) return "possibly";
  const fixWithinRange = compare(fixed, interval.lowest) >= 0 && (interval.upper === null || compare(fixed, interval.upper) < 0);
  return fixWithinRange ? "possibly" : "affected";
}
