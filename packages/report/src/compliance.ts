import type { Finding, FindingCompliance } from "@myrqen/contracts";

/**
 * Compliance references for every category the scanner, or an agent following the
 * methodology, can emit.
 *
 * One table, keyed by category, so a reviewer can audit the whole mapping on one
 * screen and a test can prove nothing the scanner emits is missing from it.
 *
 * Sources, checked against the published standards rather than recalled:
 * - OWASP Top 10:2021 and Top 10:2025. 2025 is the released edition
 *   (https://top10.owasp.org/2025/); a category is placed where OWASP's own CWE list
 *   for that edition puts the finding's primary CWE. Where neither edition lists the
 *   CWE, the category is placed by the risk it describes, and that is noted inline.
 * - OWASP ASVS 4.0.3 (the CSV published with the v4.0.3 tag) and ASVS 5.0.0 (the
 *   5.0/en chapters). Requirement ids use ASVS's own versioned notation,
 *   `v<version>-<chapter>.<section>.<requirement>`, because the same number names a
 *   different requirement in the two editions. A category only carries an ASVS
 *   reference where a requirement states the control that would prevent it; where
 *   none does, the list is empty rather than stretched.
 */

/** CWE ids, OWASP Top 10 2021/2025 ids, and versioned ASVS requirement ids. */
export type ComplianceReference = FindingCompliance;

export const OWASP_TOP10_2021: Readonly<Record<string, string>> = Object.freeze({
  "A01:2021": "Broken Access Control",
  "A02:2021": "Cryptographic Failures",
  "A03:2021": "Injection",
  "A04:2021": "Insecure Design",
  "A05:2021": "Security Misconfiguration",
  "A06:2021": "Vulnerable and Outdated Components",
  "A07:2021": "Identification and Authentication Failures",
  "A08:2021": "Software and Data Integrity Failures",
  "A09:2021": "Security Logging and Monitoring Failures",
  "A10:2021": "Server-Side Request Forgery"
});

export const OWASP_TOP10_2025: Readonly<Record<string, string>> = Object.freeze({
  "A01:2025": "Broken Access Control",
  "A02:2025": "Security Misconfiguration",
  "A03:2025": "Software Supply Chain Failures",
  "A04:2025": "Cryptographic Failures",
  "A05:2025": "Injection",
  "A06:2025": "Insecure Design",
  "A07:2025": "Authentication Failures",
  "A08:2025": "Software or Data Integrity Failures",
  "A09:2025": "Security Logging and Alerting Failures",
  "A10:2025": "Mishandling of Exceptional Conditions"
});

type Row = readonly [cwe: string[], owasp2021: string[], owasp2025: string[], asvs: string[]];

// prettier-ignore
const TABLE: Readonly<Record<string, Row>> = Object.freeze({
  // Injection and interpretation
  sql_injection:                 [["CWE-89"], ["A03:2021"], ["A05:2025"], ["v4.0.3-5.3.4", "v5.0.0-1.2.4"]],
  unsafe_query_composition:      [["CWE-943", "CWE-89"], ["A03:2021"], ["A05:2025"], ["v4.0.3-5.3.4", "v5.0.0-1.2.4"]],
  nosql_injection:               [["CWE-943"], ["A03:2021"], ["A05:2025"], ["v4.0.3-5.3.4", "v5.0.0-1.2.4"]],
  command_injection:             [["CWE-78"], ["A03:2021"], ["A05:2025"], ["v4.0.3-5.3.8", "v5.0.0-1.2.5"]],
  argument_injection:            [["CWE-88"], ["A03:2021"], ["A05:2025"], ["v4.0.3-5.3.8", "v5.0.0-1.2.5"]],
  code_injection:                [["CWE-94", "CWE-95"], ["A03:2021"], ["A05:2025"], ["v4.0.3-5.2.4", "v5.0.0-1.3.2"]],
  template_injection:            [["CWE-1336", "CWE-94"], ["A03:2021"], ["A05:2025"], ["v4.0.3-5.2.5", "v5.0.0-1.3.7"]],
  reflected_cross_site_scripting:[["CWE-79"], ["A03:2021"], ["A05:2025"], ["v4.0.3-5.3.3", "v5.0.0-1.2.1"]],
  stored_cross_site_scripting:   [["CWE-79"], ["A03:2021"], ["A05:2025"], ["v4.0.3-5.3.3", "v5.0.0-1.2.1"]],
  dom_html_injection:            [["CWE-79"], ["A03:2021"], ["A05:2025"], ["v4.0.3-5.3.3", "v5.0.0-3.2.2"]],
  xml_external_entity:           [["CWE-611"], ["A05:2021"], ["A02:2025"], ["v4.0.3-5.5.2", "v5.0.0-1.5.1"]],
  unsafe_deserialization:        [["CWE-502"], ["A08:2021"], ["A08:2025"], ["v4.0.3-5.5.3", "v5.0.0-1.5.2"]],
  // CWE-1321 is in neither edition's list; its parent class CWE-915 is in A08 of both.
  prototype_pollution:           [["CWE-1321", "CWE-915"], ["A08:2021"], ["A08:2025"], ["v5.0.0-15.3.6"]],

  // What the application reads, writes, fetches, and redirects to
  path_traversal:                [["CWE-22", "CWE-23"], ["A01:2021"], ["A01:2025"], ["v4.0.3-12.3.1", "v5.0.0-5.3.2"]],
  zip_slip:                      [["CWE-22"], ["A01:2021"], ["A01:2025"], ["v4.0.3-12.3.1", "v5.0.0-5.3.3"]],
  unrestricted_file_upload:      [["CWE-434"], ["A04:2021"], ["A06:2025"], ["v4.0.3-12.5.2", "v5.0.0-5.2.2", "v5.0.0-5.3.1"]],
  server_side_request_forgery:   [["CWE-918"], ["A10:2021"], ["A01:2025"], ["v4.0.3-5.2.6", "v4.0.3-12.6.1", "v5.0.0-1.3.6"]],
  open_redirect:                 [["CWE-601"], ["A01:2021"], ["A01:2025"], ["v4.0.3-5.1.5", "v5.0.0-3.7.2"]],

  // Who is allowed to ask
  broken_object_level_authorization:   [["CWE-639", "CWE-284"], ["A01:2021"], ["A01:2025"], ["v4.0.3-4.2.1", "v5.0.0-8.2.2"]],
  broken_function_level_authorization: [["CWE-285", "CWE-862"], ["A01:2021"], ["A01:2025"], ["v4.0.3-4.1.3", "v5.0.0-8.2.1"]],
  missing_authentication:        [["CWE-306"], ["A07:2021"], ["A07:2025"], ["v4.0.3-4.1.3", "v5.0.0-8.2.1"]],
  mass_assignment:               [["CWE-915"], ["A08:2021"], ["A08:2025"], ["v4.0.3-5.1.2", "v5.0.0-15.3.3"]],
  missing_csrf_protection:       [["CWE-352"], ["A01:2021"], ["A01:2025"], ["v4.0.3-4.2.2", "v5.0.0-3.5.1"]],
  insecure_cors_configuration:   [["CWE-942"], ["A05:2021"], ["A02:2025"], ["v4.0.3-14.5.3", "v5.0.0-3.4.2"]],

  // Secrets, credentials, sessions, and comparisons
  hardcoded_secret:              [["CWE-798", "CWE-259"], ["A07:2021"], ["A07:2025"], ["v4.0.3-2.10.4", "v4.0.3-6.4.1", "v5.0.0-13.3.1"]],
  secret_exposed_to_client_bundle:[["CWE-540", "CWE-798"], ["A01:2021", "A07:2021"], ["A01:2025", "A07:2025"], ["v4.0.3-2.10.4", "v5.0.0-13.3.1"]],
  weak_password_hashing:         [["CWE-916"], ["A02:2021"], ["A04:2025"], ["v4.0.3-2.4.1", "v5.0.0-11.4.2"]],
  weak_hash_algorithm:           [["CWE-328", "CWE-327"], ["A02:2021"], ["A04:2025"], ["v4.0.3-6.2.5", "v5.0.0-11.4.1"]],
  // CWE-208 is in neither list; a timing leak of a secret is a cryptographic failure.
  timing_unsafe_comparison:      [["CWE-208"], ["A02:2021"], ["A04:2025"], ["v4.0.3-6.2.8", "v5.0.0-11.2.4"]],
  insecure_randomness:           [["CWE-330", "CWE-338"], ["A02:2021"], ["A04:2025"], ["v4.0.3-6.3.1", "v5.0.0-11.5.1"]],
  weak_session_identifier:       [["CWE-330", "CWE-384"], ["A02:2021", "A07:2021"], ["A04:2025", "A07:2025"], ["v4.0.3-3.2.2", "v4.0.3-3.2.4", "v5.0.0-7.2.3"]],
  jwt_verification_bypass:       [["CWE-347", "CWE-287"], ["A02:2021", "A07:2021"], ["A04:2025", "A07:2025"], ["v4.0.3-3.5.3", "v5.0.0-9.1.1", "v5.0.0-9.1.2"]],
  // A guessable or committed HMAC key. CWE-321 sits in A02:2021 and A04:2025 and CWE-798 in
  // A07 of both, so both editions carry two categories, as jwt_verification_bypass does.
  // ASVS: secrets kept out of source (2.10.4, 6.4.1, 13.3.1), tokens protected against
  // tampering (3.5.3), and a non-guessable value carrying at least 128 bits (11.5.1).
  jwt_weak_secret:               [["CWE-1391", "CWE-798", "CWE-321"], ["A02:2021", "A07:2021"], ["A04:2025", "A07:2025"], ["v4.0.3-2.10.4", "v4.0.3-3.5.3", "v4.0.3-6.4.1", "v5.0.0-11.5.1", "v5.0.0-13.3.1"]],
  insecure_cookie_configuration: [["CWE-1004", "CWE-614", "CWE-1275"], ["A05:2021"], ["A02:2025"], ["v4.0.3-3.4.1", "v4.0.3-3.4.2", "v4.0.3-3.4.3", "v5.0.0-3.3.1", "v5.0.0-3.3.2", "v5.0.0-3.3.4"]],
  missing_rate_limit_on_credentials:[["CWE-307"], ["A07:2021"], ["A07:2025"], ["v4.0.3-2.2.1", "v5.0.0-6.3.1"]],

  // Disclosure, limits, and business logic
  // CWE-215 and CWE-489 sit in no 2021 list; a reachable debug surface is misconfiguration.
  debug_endpoint_exposure:       [["CWE-215", "CWE-489"], ["A05:2021"], ["A02:2025"], ["v4.0.3-14.3.2", "v5.0.0-13.4.2"]],
  verbose_error_response:        [["CWE-209"], ["A04:2021"], ["A10:2025"], ["v4.0.3-7.4.1", "v5.0.0-16.5.1"]],
  sensitive_data_in_logs:        [["CWE-532"], ["A09:2021"], ["A09:2025"], ["v4.0.3-7.1.1", "v5.0.0-16.2.5"]],
  business_logic_price_manipulation:[["CWE-840", "CWE-20"], ["A04:2021"], ["A06:2025"], ["v4.0.3-11.1.5", "v5.0.0-2.2.3", "v5.0.0-2.3.2"]],
  race_condition_double_spend:   [["CWE-362", "CWE-367"], ["A04:2021"], ["A06:2025"], ["v4.0.3-11.1.6", "v5.0.0-15.4.2"]],
  unbounded_resource_consumption:[["CWE-770", "CWE-400"], ["A04:2021"], ["A06:2025"], ["v4.0.3-11.1.4", "v5.0.0-2.4.1", "v5.0.0-15.2.2"]],
  dependency_with_known_advisory:[["CWE-1104", "CWE-1395"], ["A06:2021"], ["A03:2025"], ["v4.0.3-14.2.1", "v5.0.0-15.2.1"]]
});

/**
 * Spellings an agent is likely to use for a category in the table. The methodology
 * asks for snake case and suggests the canonical names, but an agent that writes
 * `idor` or `xss` has still named a mapped risk.
 */
const ALIASES: Readonly<Record<string, string>> = Object.freeze({
  idor: "broken_object_level_authorization",
  bola: "broken_object_level_authorization",
  insecure_direct_object_reference: "broken_object_level_authorization",
  bfla: "broken_function_level_authorization",
  privilege_escalation: "broken_function_level_authorization",
  missing_authorization: "broken_function_level_authorization",
  sqli: "sql_injection",
  xss: "reflected_cross_site_scripting",
  cross_site_scripting: "reflected_cross_site_scripting",
  dom_xss: "reflected_cross_site_scripting",
  ssrf: "server_side_request_forgery",
  csrf: "missing_csrf_protection",
  xxe: "xml_external_entity",
  rce: "code_injection",
  remote_code_execution: "code_injection",
  os_command_injection: "command_injection",
  ssti: "template_injection",
  server_side_template_injection: "template_injection",
  directory_traversal: "path_traversal",
  hardcoded_credentials: "hardcoded_secret",
  secret_in_source: "hardcoded_secret",
  vulnerable_dependency: "dependency_with_known_advisory",
  insecure_deserialization: "unsafe_deserialization",
  information_disclosure: "verbose_error_response",
  missing_rate_limit: "missing_rate_limit_on_credentials",
  brute_force: "missing_rate_limit_on_credentials"
});

/** Every category with a curated row, sorted. */
export function mappedCategories(): string[] {
  return Object.keys(TABLE).sort();
}

export function canonicalCategory(category: string): string {
  const key = category.trim().toLowerCase().replace(/[\s-]+/g, "_");
  return TABLE[key] ? key : (ALIASES[key] ?? key);
}

const CWE_TOKEN = /^CWE-(\d+)$/i;
/** The scanner writes `OWASP-A03` without an edition; those ids are 2021's. */
const OWASP_TOKEN = /^OWASP-(A(?:0[1-9]|10))(?::(2021|2025))?$/i;

/**
 * The references for one finding. A curated row wins for the OWASP and ASVS columns,
 * because a bare `OWASP-A05` token carries no edition and can be wrong for one. CWE
 * ids the finding itself names are kept alongside the row's, since an agent may have
 * pinned the weakness more precisely than its category does.
 */
export function complianceFor(finding: Pick<Finding, "category" | "taxonomy">): ComplianceReference {
  const row = TABLE[canonicalCategory(finding.category)];
  const taxonomy = finding.taxonomy ?? [];
  const ownCwe = taxonomy.filter((token) => CWE_TOKEN.test(token)).map((token) => token.toUpperCase());
  const cwe = [...new Set([...(row?.[0] ?? []), ...ownCwe])];

  if (row) return { cwe, owasp2021: [...row[1]], owasp2025: [...row[2]], asvs: [...row[3]] };

  const owasp2021: string[] = [];
  const owasp2025: string[] = [];
  for (const token of taxonomy) {
    const match = OWASP_TOKEN.exec(token);
    if (!match) continue;
    const id = match[1]!.toUpperCase();
    if (match[2] === "2025") owasp2025.push(`${id}:2025`);
    else owasp2021.push(`${id}:2021`);
  }
  return { cwe, owasp2021: [...new Set(owasp2021)], owasp2025: [...new Set(owasp2025)], asvs: [] };
}

export function isMapped(category: string): boolean {
  return TABLE[canonicalCategory(category)] !== undefined;
}

export function owaspTitle(id: string): string {
  return OWASP_TOP10_2025[id] ?? OWASP_TOP10_2021[id] ?? id;
}

const CWE_BASE = "https://cwe.mitre.org/data/definitions/";

export function cweUrl(cwe: string): string | null {
  const match = CWE_TOKEN.exec(cwe);
  return match ? `${CWE_BASE}${match[1]}.html` : null;
}

/** "ASVS 5.0.0 · 1.2.4" — readable in prose without losing the edition. */
export function asvsLabel(id: string): string {
  const match = /^v(\d+\.\d+\.\d+)-(.+)$/.exec(id);
  return match ? `ASVS ${match[1]} ${match[2]}` : id;
}

/** One line per finding, for Markdown and plain-text surfaces. */
export function complianceLine(reference: ComplianceReference): string {
  const parts = [
    reference.cwe.join(", "),
    reference.owasp2025.length > 0 ? `OWASP ${reference.owasp2025.join(", ")}` : null,
    reference.owasp2021.length > 0 ? `OWASP ${reference.owasp2021.join(", ")}` : null,
    reference.asvs.length > 0 ? reference.asvs.map(asvsLabel).join(", ") : null
  ].filter((part): part is string => Boolean(part));
  return parts.length > 0 ? parts.join(" · ") : "No standard reference is mapped for this category.";
}

export interface ComplianceRow {
  /** OWASP Top 10 id, `A01:2025`, or `unmapped`. */
  id: string;
  title: string;
  findingIds: string[];
  cwe: string[];
  asvs: string[];
}

/**
 * Findings grouped by OWASP Top 10:2025 category, in the standard's own order, with
 * the CWE and ASVS references under each. A finding that maps to two categories is
 * listed under both, so the rows can add up to more than the finding count; the
 * renderers say so.
 */
export function aggregateCompliance(findings: readonly Finding[]): ComplianceRow[] {
  const rows = new Map<string, ComplianceRow>();
  const add = (id: string, finding: Finding, reference: ComplianceReference): void => {
    const row = rows.get(id) ?? { id, title: id === "unmapped" ? "No OWASP Top 10 mapping" : owaspTitle(id), findingIds: [], cwe: [], asvs: [] };
    if (!row.findingIds.includes(finding.id)) row.findingIds.push(finding.id);
    row.cwe = [...new Set([...row.cwe, ...reference.cwe])];
    row.asvs = [...new Set([...row.asvs, ...reference.asvs])];
    rows.set(id, row);
  };
  for (const finding of findings) {
    const reference = complianceFor(finding);
    if (reference.owasp2025.length === 0) add("unmapped", finding, reference);
    for (const id of reference.owasp2025) add(id, finding, reference);
  }
  const order = Object.keys(OWASP_TOP10_2025);
  return [...rows.values()].sort((a, b) => {
    const ai = a.id === "unmapped" ? order.length : order.indexOf(a.id);
    const bi = b.id === "unmapped" ? order.length : order.indexOf(b.id);
    return ai - bi;
  });
}
