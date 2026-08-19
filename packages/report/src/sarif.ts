import { BRAND, CLI_VERSION } from "@myrqen/brand";
import type { Finding } from "@myrqen/contracts";
import type { ViewableReport } from "./html.js";

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  properties: { category: string; tags: string[]; "security-severity"?: string };
  defaultConfiguration: { level: SarifLevel };
}

type SarifLevel = "error" | "warning" | "note";

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

export function renderSarif(report: ViewableReport): string {
  const findings = report.findings ?? [];
  const rules = new Map<string, SarifRule>();

  for (const finding of findings) {
    const id = ruleId(finding);
    if (rules.has(id)) continue;
    const rule: SarifRule = {
      id,
      name: finding.category,
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.summary },
      help: { text: finding.remediation },
      properties: {
        category: finding.category,
        tags: ["security", ...(finding.taxonomy ?? [])],
        "security-severity": SECURITY_SEVERITY[finding.severity]
      },
      defaultConfiguration: { level: LEVEL_BY_SEVERITY[finding.severity] }
    };
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

    return {
      ruleId: ruleId(finding),
      level: LEVEL_BY_SEVERITY[finding.severity],
      message: { text: messageParts.join(" — ") },
      ...(locations.length > 0 ? { locations } : { locations: [] }),
      partialFingerprints: finding.fingerprint ? { myrqenFingerprint: finding.fingerprint } : undefined,
      properties: {
        severity: finding.severity,
        verification: finding.verification,
        component: finding.affected.component,
        ...(finding.affected.route ? { route: finding.affected.route } : {}),
        ...(finding.status ? { status: finding.status } : {})
      }
    };
  });

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
            rules: [...rules.values()]
          }
        },
        automationDetails: { id: `${BRAND.cliName}/${report.id}` },
        invocations: [
          {
            executionSuccessful: true,
            ...(report.scan?.startedAt ? { startTimeUtc: report.scan.startedAt } : {}),
            ...(report.scan?.completedAt ? { endTimeUtc: report.scan.completedAt } : {})
          }
        ],
        results
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}
