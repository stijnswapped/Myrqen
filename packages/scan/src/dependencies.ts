import fs from "node:fs/promises";
import path from "node:path";
import type { Candidate } from "./types.js";

/**
 * A small, offline advisory table.
 *
 * This is deliberately not a vulnerability database: it carries only entries
 * that are unambiguous, widely known, and cheap to state honestly. Anything it
 * reports is `needs_review`, because whether an advisory is reachable from this
 * application's own code paths is a question the table cannot answer.
 */
interface Advisory {
  name: string;
  /** Highest affected version, inclusive. */
  affectedThrough: string;
  summary: string;
  severity: "critical" | "high" | "medium" | "low";
  reference: string;
}

const ADVISORIES: readonly Advisory[] = Object.freeze([
  {
    name: "lodash",
    affectedThrough: "4.17.20",
    summary: "prototype pollution in zipObjectDeep and related deep-merge helpers",
    severity: "high",
    reference: "CVE-2020-8203"
  },
  {
    name: "minimist",
    affectedThrough: "1.2.5",
    summary: "prototype pollution through crafted argument names",
    severity: "medium",
    reference: "CVE-2021-44906"
  },
  {
    name: "axios",
    affectedThrough: "0.21.1",
    summary: "server-side request forgery through unvalidated redirects",
    severity: "high",
    reference: "CVE-2020-28168"
  },
  {
    name: "node-fetch",
    affectedThrough: "2.6.6",
    summary: "the Authorization header is forwarded across a cross-origin redirect",
    severity: "high",
    reference: "CVE-2022-0235"
  },
  {
    name: "jsonwebtoken",
    affectedThrough: "8.5.1",
    summary: "insecure default key handling allows signature bypass in some configurations",
    severity: "high",
    reference: "CVE-2022-23529"
  },
  {
    name: "semver",
    affectedThrough: "7.5.1",
    summary: "regular-expression denial of service in range parsing",
    severity: "medium",
    reference: "CVE-2022-25883"
  },
  {
    name: "tar",
    affectedThrough: "6.1.8",
    summary: "path traversal when extracting a crafted archive",
    severity: "high",
    reference: "CVE-2021-37713"
  },
  {
    name: "express",
    affectedThrough: "4.17.3",
    summary: "open redirect in res.location and res.redirect with a crafted path",
    severity: "medium",
    reference: "CVE-2022-24999"
  },
  {
    name: "ws",
    affectedThrough: "7.5.9",
    summary: "denial of service through a request with many headers",
    severity: "medium",
    reference: "CVE-2024-37890"
  }
]);

function compareVersions(a: string, b: string): number {
  const left = a.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const right = b.split(".").map((part) => Number.parseInt(part, 10) || 0);
  for (let index = 0; index < 3; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

/** Strip a range operator to the version it pins at its lowest. */
function baseVersion(range: string): string | null {
  const match = /(\d+\.\d+\.\d+)/.exec(range);
  return match ? match[1]! : null;
}

export async function analyzeDependencies(repoRoot: string): Promise<Candidate[]> {
  let manifest: { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; name?: string };
  try {
    manifest = JSON.parse(await fs.readFile(path.join(repoRoot, "package.json"), "utf8"));
  } catch {
    return [];
  }

  // Development dependencies are reported separately and never as high, because
  // they do not run in production.
  const runtime = Object.entries(manifest.dependencies ?? {});
  const development = Object.entries(manifest.devDependencies ?? {});

  const affected: Array<{ advisory: Advisory; version: string; scope: "runtime" | "development" }> = [];

  for (const [scope, entries] of [
    ["runtime", runtime],
    ["development", development]
  ] as const) {
    for (const [name, range] of entries) {
      const advisory = ADVISORIES.find((entry) => entry.name === name);
      if (!advisory) continue;
      const version = baseVersion(String(range));
      if (!version) continue;
      if (compareVersions(version, advisory.affectedThrough) > 0) continue;
      affected.push({ advisory, version, scope });
    }
  }

  if (affected.length === 0) return [];

  const runtimeAffected = affected.filter((entry) => entry.scope === "runtime");
  const worst = affected.reduce((highest, entry) => {
    const rank = { critical: 4, high: 3, medium: 2, low: 1 };
    return rank[entry.advisory.severity] > rank[highest.advisory.severity] ? entry : highest;
  });

  // The advisory's own rating assumes the vulnerable code path is reached. A
  // manifest read cannot establish that, so a declared version alone is capped
  // at medium: ranking it beside a proven exploitable path would train a reader
  // to distrust the severities that were earned.
  const severity = runtimeAffected.length === 0 ? "low" : worst.advisory.severity === "low" ? "low" : "medium";

  return [
    {
      ruleId: "dependency-advisory",
      category: "dependency_with_known_advisory",
      title: `${affected.length} dependenc${affected.length === 1 ? "y is" : "ies are"} pinned inside a published advisory range`,
      severity,
      // Reachability is exactly what a manifest read cannot establish.
      verification: "needs_review",
      summary: `${affected
        .map((entry) => `${entry.advisory.name}@${entry.version} (${entry.scope}) is at or below ${entry.advisory.affectedThrough}: ${entry.advisory.summary}`)
        .join("; ")}. Whether the affected code path is reachable from this application was not determined.`,
      impact:
        runtimeAffected.length === 0
          ? "These are development dependencies, so the exposure is to the build and test environment rather than to production traffic."
          : "If the affected code path is reachable from a request, the advisory applies directly. Until reachability is established this is a supply-chain exposure rather than a proven exploit.",
      remediation:
        "Upgrade each dependency past its advisory range and run the test suite. Where an upgrade is blocked, record the reachability analysis that justifies accepting the risk, rather than leaving the pin unexplained.",
      verificationPlan:
        "Re-read the manifest and the lockfile and confirm the resolved versions are above the advisory range.",
      taxonomy: ["CWE-1104", "OWASP-A06"],
      location: { file: "package.json", line: 1 },
      evidence: [
        {
          kind: "dependency",
          description: affected
            .map((entry) => `${entry.advisory.name}@${entry.version} ≤ ${entry.advisory.affectedThrough} — ${entry.advisory.reference}`)
            .join("; "),
          location: "package.json"
        }
      ],
      reasoning:
        "Declared versions were compared against an offline advisory table. No lockfile resolution or reachability analysis was performed, which is why this is reported as needing review."
    }
  ];
}

export const ADVISORY_COUNT = ADVISORIES.length;
