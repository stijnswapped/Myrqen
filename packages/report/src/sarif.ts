import { BRAND, CLI_VERSION } from "@myrqen/brand";
import type { Finding } from "@myrqen/contracts";
import { baselineFingerprint } from "./baseline.js";
import { complianceFor, cweUrl, type ComplianceReference } from "./compliance.js";
import { reportFacts } from "./facts.js";
import type { ViewableReport } from "./html.js";
import { buildVerdict } from "./verdict.js";

type SarifLevel = "error" | "warning" | "note";

interface SarifRelationship {
  target: { id: string; toolComponent: { name: "CWE" } };
  kinds: ["superset"];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  helpUri?: string;
  properties: { category: string; tags: string[]; "security-severity"?: string };
  defaultConfiguration: { level: SarifLevel };
  relationships?: SarifRelationship[];
}

/** Conservative mapping: no invented rule ids, no invented line locations. */
const LEVEL_BY_SEVERITY: Record<Finding["severity"], SarifLevel> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note"
};

const SECURITY_SEVERITY: Record<Finding["severity"], string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "1.0"
};

function ruleId(finding: Finding): string {
  // Derived from the normalized category the CLI assigned, never guessed.
  return `${BRAND.cliName}/${finding.category}`;
}

/**
 * Tags in the shapes code-scanning tools already understand: GitHub reads
 * `external/cwe/cwe-89` as a CWE link, and the OWASP tags name their edition so a
 * 2021 dashboard and a 2025 dashboard never mix.
 */
function complianceTags(reference: ComplianceReference): string[] {
  return [
    ...reference.cwe.map((cwe) => `external/cwe/${cwe.toLowerCase()}`),
    ...reference.owasp2025.map((id) => `owasp-top10-2025/${id.slice(0, 3)}`),
    ...reference.owasp2021.map((id) => `owasp-top10-2021/${id.slice(0, 3)}`),
    ...reference.asvs.map((id) => `owasp-asvs/${id}`)
  ];
}

function cweNumber(cwe: string): string {
  return cwe.replace(/^CWE-/i, "");
}

export function renderSarif(report: ViewableReport): string {
  const findings = report.findings ?? [];
  const rules = new Map<string, SarifRule>();
  const taxa = new Set<string>();

  for (const finding of findings) {
    const id = ruleId(finding);
    if (rules.has(id)) continue;
    const reference = complianceFor(finding);
    reference.cwe.forEach((cwe) => taxa.add(cweNumber(cwe)));
    const primary = reference.cwe[0];
    const rule: SarifRule = {
      id,
      name: finding.category,
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.summary },
      help: { text: finding.remediation },
      properties: {
        category: finding.category,
        tags: [...new Set(["security", ...(finding.taxonomy ?? []), ...complianceTags(reference)])],
        "security-severity": SECURITY_SEVERITY[finding.severity]
      },
      defaultConfiguration: { level: LEVEL_BY_SEVERITY[finding.severity] }
    };
    const helpUri = primary ? cweUrl(primary) : null;
    if (helpUri) rule.helpUri = helpUri;
    if (reference.cwe.length > 0) {
      rule.relationships = reference.cwe.map((cwe) => ({
        target: { id: cweNumber(cwe), toolComponent: { name: "CWE" } },
        kinds: ["superset"]
      }));
    }
    rules.set(id, rule);
  }

  const results = findings.map((finding) => {
    const locations = [];
    if (finding.affected.file) {
      const region: Record<string, number> = {};
      if (typeof finding.affected.lineStart === "number") region.startLine = finding.affected.lineStart;
      if (typeof finding.affected.lineEnd === "number") region.endLine = finding.affected.lineEnd;
      locations.push({
        physicalLocation: {
          artifactLocation: { uri: finding.affected.file.replace(/\\/g, "/"), uriBaseId: "%SRCROOT%" },
          ...(Object.keys(region).length > 0 ? { region } : {})
        }
      });
    }

    const messageParts = [finding.title, finding.summary];
    if (finding.affected.route) messageParts.push(`Route: ${finding.affected.route}`);
    const partialFingerprints: Record<string, string> = { "myrqenBaseline/v1": baselineFingerprint(finding) };
    if (finding.fingerprint) partialFingerprints.myrqenFingerprint = finding.fingerprint;

    return {
      ruleId: ruleId(finding),
      level: LEVEL_BY_SEVERITY[finding.severity],
      message: { text: messageParts.join(" — ") },
      locations,
      partialFingerprints,
      // Only stated when a baseline was compared: "new" without one would be a guess.
      ...(finding.baselineState ? { baselineState: finding.baselineState } : {}),
      properties: {
        findingId: finding.id,
        severity: finding.severity,
        verification: finding.verification,
        component: finding.affected.component,
        tags: complianceTags(complianceFor(finding)),
        ...(finding.affected.route ? { route: finding.affected.route } : {}),
        ...(finding.status ? { status: finding.status } : {})
      }
    };
  });

  const facts = reportFacts(report);
  const verdict = buildVerdict(report);
  const counts = facts.counts;

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: BRAND.displayName,
            informationUri: "https://myrqen.invalid",
            semanticVersion: CLI_VERSION,
            rules: [...rules.values()],
            ...(taxa.size > 0 ? { supportedTaxonomies: [{ name: "CWE", index: 0 }] } : {})
          }
        },
        ...(taxa.size > 0
          ? {
              taxonomies: [
                {
                  name: "CWE",
                  organization: "MITRE",
                  shortDescription: { text: "The MITRE Common Weakness Enumeration" },
                  informationUri: "https://cwe.mitre.org/",
                  taxa: [...taxa]
                    .sort((a, b) => Number(a) - Number(b))
                    .map((id) => ({ id, helpUri: `https://cwe.mitre.org/data/definitions/${id}.html` }))
                }
              ]
            }
          : {}),
        automationDetails: { id: `${BRAND.cliName}/${report.id}` },
        invocations: [
          {
            executionSuccessful: true,
            ...(report.scan?.startedAt ? { startTimeUtc: report.scan.startedAt } : {}),
            ...(report.scan?.completedAt ? { endTimeUtc: report.scan.completedAt } : {})
          }
        ],
        results,
        properties: {
          myrqen: {
            verdict: verdict.headline,
            runMode: facts.run.mode,
            ...(counts
              ? {
                  findingCount: counts.total,
                  severityCounts: counts.severity,
                  verificationCounts: counts.verification,
                  fixedCount: counts.fixed
                }
              : {}),
            ...(report.baseline ? { baseline: { createdAt: report.baseline.createdAt, ...report.baseline.counts } } : {})
          }
        }
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}
