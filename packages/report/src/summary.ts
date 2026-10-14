import { BRAND } from "@myrqen/brand";
import type { Finding, FindingEvidence, ReportProjection, ScanReport } from "@myrqen/contracts";
import { sortFindings } from "./facts.js";

/**
 * Every renderer in this package also has to serve a server-side projection, which
 * may withhold findings, scope, or metadata from the viewer that asked for it. A
 * summary written from a projection must describe only what that projection carries,
 * so every field here is read as if it could be absent. Nothing is inferred from a
 * missing field: absent means the sentence is not written, never that it is guessed.
 */
export type SummarizableReport = ScanReport | ReportProjection;

/** One step in a source-to-sink story. `detail` is always verbatim report text. */
export interface AttackStep {
  label: string;
  detail?: string;
}

/** A grouping several findings share, counted rather than asserted. */
export interface RiskConcentration {
  kind: "category" | "route_prefix" | "component";
  /** Name of the shared group, spelled as the findings spell it. */
  label: string;
  /** How many findings fall in the group. */
  count: number;
  /** How many findings were considered, so the share is checkable. */
  total: number;
  /** The findings in the group, so a reader can jump straight to them. */
  findingIds: string[];
}

// Prose reads better with words for the counts a report actually reaches. Past
// twenty the word is harder to scan than the digits, so the digits win.
const NUMBER_WORDS = [
  "no",
  "one",
  "two",
  "three",
  "four",
  "five",
  "six",
  "seven",
  "eight",
  "nine",
  "ten",
  "eleven",
  "twelve",
  "thirteen",
  "fourteen",
  "fifteen",
  "sixteen",
  "seventeen",
  "eighteen",
  "nineteen",
  "twenty"
];

function count(value: number): string {
  if (!Number.isInteger(value) || value < 0) return String(value);
  return NUMBER_WORDS[value] ?? String(value);
}

function upperFirst(value: string): string {
  return value.length === 0 ? value : value[0]!.toUpperCase() + value.slice(1);
}

function plural(value: number, singular: string, pluralForm = `${singular}s`): string {
  return value === 1 ? singular : pluralForm;
}

/** Joins a short list without the ambiguity of a bare comma run. */
function joinList(parts: string[], conjunction = "and"): string {
  if (parts.length === 0) return "";
  if (parts.length === 1) return parts[0]!;
  if (parts.length === 2) return `${parts[0]!}, ${conjunction} ${parts[1]!}`;
  return `${parts.slice(0, -1).join(", ")}, ${conjunction} ${parts[parts.length - 1]!}`;
}

function sentences(parts: Array<string | null>): string {
  return parts.filter((part): part is string => Boolean(part && part.trim())).join(" ");
}

function humanize(value: string): string {
  return value.replaceAll("_", " ").trim();
}

/** The evidence a finding stands on, in the order every other renderer reads it. */
function allEvidence(finding: Finding): FindingEvidence[] {
  return [...finding.evidence, ...(finding.corroboration ?? [])];
}

/* ------------------------------------------------------------------ *
 * Risk concentration
 * ------------------------------------------------------------------ */

const HTTP_METHOD = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+/i;
const PARAMETER_SEGMENT = /^[:{*]/;
const MAX_PREFIX_DEPTH = 3;

/**
 * Route prefixes are generated from the left, and generation stops at the first
 * parameter segment: `/api/orders` is a place in the application a developer can go
 * and look at, `/api/orders/:id` is a single route wearing a prefix's clothes.
 */
function routePrefixes(route: string): string[] {
  const path = route.replace(HTTP_METHOD, "").trim();
  const segments = path.split("/").filter((segment) => segment.length > 0);
  const prefixes: string[] = [];
  for (const segment of segments.slice(0, MAX_PREFIX_DEPTH)) {
    if (PARAMETER_SEGMENT.test(segment)) break;
    prefixes.push(`${prefixes.length > 0 ? prefixes[prefixes.length - 1]! : ""}/${segment}`);
  }
  return prefixes;
}

interface Group {
  kind: RiskConcentration["kind"];
  label: string;
  findingIds: string[];
}

function collectGroups(findings: Finding[]): Group[] {
  const groups = new Map<string, Group>();
  const add = (kind: Group["kind"], label: string, id: string): void => {
    if (!label) return;
    const key = `${kind} ${label}`;
    const existing = groups.get(key);
    if (existing) {
      if (!existing.findingIds.includes(id)) existing.findingIds.push(id);
      return;
    }
    groups.set(key, { kind, label, findingIds: [id] });
  };

  for (const finding of findings) {
    add("category", humanize(finding.category), finding.id);
    add("component", finding.affected.component, finding.id);
    if (finding.affected.route) {
      for (const prefix of routePrefixes(finding.affected.route)) add("route_prefix", prefix, finding.id);
    }
  }
  return [...groups.values()];
}

// A shared class of problem tells a developer something a shared file does not: in a
// single-file application every finding trivially shares the file. So when two
// groupings cover the same number of findings, the more informative kind is reported.
const KIND_RANK: Record<RiskConcentration["kind"], number> = { category: 0, route_prefix: 1, component: 2 };

/**
 * Ties are broken towards the grouping that sends a developer somewhere. `/api` and
 * `/api/admin` can cover the same three findings; only the second is a place to go
 * and look, so the deeper prefix wins.
 */
function preferable(candidate: Group, incumbent: Group): boolean {
  if (candidate.findingIds.length !== incumbent.findingIds.length) {
    return candidate.findingIds.length > incumbent.findingIds.length;
  }
  if (KIND_RANK[candidate.kind] !== KIND_RANK[incumbent.kind]) {
    return KIND_RANK[candidate.kind] < KIND_RANK[incumbent.kind];
  }
  return candidate.kind === "route_prefix" && candidate.label.length > incumbent.label.length;
}

/**
 * The largest grouping several findings genuinely share, or null. Two findings only
 * count as a cluster when they are at least a third of the report; three or more is a
 * cluster whatever the report size. Below that the "concentration" is just the shape
 * of a small sample, and saying otherwise would be a claim the data cannot carry.
 */
export function riskConcentration(findings: Finding[]): RiskConcentration | null {
  const total = findings.length;
  if (total < 2) return null;

  let best: Group | null = null;
  for (const group of collectGroups(findings)) {
    const size = group.findingIds.length;
    if (size < 2) continue;
    if (size < 3 && size * 3 < total) continue;
    if (best === null || preferable(group, best)) best = group;
  }
  if (best === null) return null;

  return {
    kind: best.kind,
    label: best.label,
    count: best.findingIds.length,
    total,
    findingIds: [...best.findingIds]
  };
}

function concentrationSentence(concentration: RiskConcentration): string {
  const share =
    concentration.count === concentration.total
      ? `All ${count(concentration.total)} findings`
      : `${upperFirst(count(concentration.count))} of the ${count(concentration.total)} findings`;
  if (concentration.kind === "category") return `${share} are the same class of problem, ${concentration.label}.`;
  if (concentration.kind === "route_prefix") return `${share} are on routes under ${concentration.label}.`;
  return `${share} are in one component, ${concentration.label}.`;
}

/* ------------------------------------------------------------------ *
 * Attack path
 * ------------------------------------------------------------------ */

const REACHES = /\s+reaches\s+/i;
const DATA_FLOW_MARKER = /data flow:\s*/i;
const TAINT_MARKER = /taint from\s+/i;
const TRAILING_GUARD = /\bwith\s+(no\s[^.]+?)\s*\.?\s*$/i;
const IN_SAME_FUNCTION = /\s+in the same function\b.*$/i;
const PARAMETER_FLOW = /parameter\s+(`?[A-Za-z_$][\w$]*`?)\s+of this function appears inside\s+(.+?)\.?\s*$/i;

// A source or a sink is a short phrase. Anything longer is prose that happened to
// contain the word "reaches", and reading prose as a data flow would invent one.
const PHRASE_MAX = 140;

interface ParsedFlow {
  /** Lower is a better source and sink: an explicit data-flow line beats prose. */
  rank: number;
  source: string;
  sourceLabel: string;
  sink: string;
  /** Present only when the evidence names what is absent. */
  guard?: string;
  /** Ranked separately: the taint line names the specific guards that were sought. */
  guardRank: number;
  location?: string;
}

function trimTerminal(value: string): string {
  return value.replace(/[\s;.]+$/, "").trim();
}

function isPhrase(value: string): boolean {
  return value.length > 0 && value.length <= PHRASE_MAX;
}

/**
 * "Data flow: X reaches Y in the same function with no validating guard between
 * them." The analysis emits this shape only for a flow it followed from an
 * attacker-controlled source, which is what lets the first step be labelled as one.
 */
function parseDataFlow(text: string, location?: string): ParsedFlow | null {
  const marker = DATA_FLOW_MARKER.exec(text);
  if (!marker) return null;
  const body = text.slice(marker.index + marker[0].length);
  const split = REACHES.exec(body);
  if (!split || split.index === 0) return null;

  const source = trimTerminal(body.slice(0, split.index));
  let tail = body.slice(split.index + split[0].length).trim();
  let guard: string | undefined;
  const guardMatch = TRAILING_GUARD.exec(tail);
  if (guardMatch) {
    guard = trimTerminal(guardMatch[1]!);
    tail = tail.slice(0, guardMatch.index);
  }
  const sink = trimTerminal(tail.replace(IN_SAME_FUNCTION, ""));
  if (!isPhrase(source) || !isPhrase(sink)) return null;

  return {
    rank: 0,
    source,
    sourceLabel: "Caller-controlled input",
    sink,
    ...(guard ? { guard } : {}),
    guardRank: 1,
    ...(location ? { location } : {})
  };
}

/**
 * "Taint from X reaches Y; <the guards that were looked for and not found>." The
 * clause after the semicolon is the most specific statement of what is missing that a
 * finding carries, so it outranks the generic phrase a data-flow line ends with.
 */
function parseTaint(text: string, location?: string): ParsedFlow | null {
  const marker = TAINT_MARKER.exec(text);
  if (!marker) return null;
  const body = text.slice(marker.index + marker[0].length);
  const split = REACHES.exec(body);
  if (!split || split.index === 0) return null;

  const source = trimTerminal(body.slice(0, split.index));
  const tail = body.slice(split.index + split[0].length).trim();
  const semicolon = tail.indexOf(";");
  const sink = trimTerminal(semicolon === -1 ? tail : tail.slice(0, semicolon));
  const guard = semicolon === -1 ? "" : trimTerminal(tail.slice(semicolon + 1));
  if (!isPhrase(source) || !isPhrase(sink)) return null;

  return {
    rank: 1,
    source,
    sourceLabel: "Caller-controlled input",
    sink,
    ...(guard ? { guard } : {}),
    guardRank: 0,
    ...(location ? { location } : {})
  };
}

/**
 * "Parameter `x` of this function appears inside <sink>." No request is involved here:
 * the caller is another call site rather than a browser, so the step says so.
 */
function parseParameterFlow(text: string, location?: string): ParsedFlow | null {
  const match = PARAMETER_FLOW.exec(text);
  if (!match) return null;
  const source = trimTerminal(match[1]!);
  const sink = trimTerminal(match[2]!);
  if (!isPhrase(source) || !isPhrase(sink)) return null;
  return {
    rank: 2,
    source,
    sourceLabel: "Caller-supplied parameter",
    sink,
    guardRank: 2,
    ...(location ? { location } : {})
  };
}

function parseEvidence(item: FindingEvidence): ParsedFlow[] {
  const text = item.description ?? "";
  const location = item.location;
  return [parseDataFlow(text, location), parseTaint(text, location), parseParameterFlow(text, location)].filter(
    (parsed): parsed is ParsedFlow => parsed !== null
  );
}

function findingLocation(finding: Finding): string | undefined {
  const file = finding.affected.file;
  if (!file) return undefined;
  return finding.affected.lineStart ? `${file}:${finding.affected.lineStart}` : file;
}

/**
 * The sink a finding's evidence names, as the evidence spells it, or null when the
 * evidence describes no data flow. This is the part of a finding that stays the same
 * when the lines above it move, which is what a baseline needs to match on.
 */
export function flowSink(finding: Finding): string | null {
  const parses = allEvidence(finding).flatMap(parseEvidence);
  if (parses.length === 0) return null;
  return [...parses].sort((a, b) => a.rank - b.rank)[0]!.sink;
}

/**
 * The source-to-sink story a finding's own evidence supports, as ordered steps.
 *
 * Only findings whose evidence names both an attacker-controlled source and what it
 * reaches get a path. That is deliberate and it is not a gap: a hard-coded credential,
 * a missing ownership check, and a pinned vulnerable dependency are all real findings
 * with no data flow to draw, and a diagram invented for them would state something the
 * evidence never did. Those return null.
 */
export function attackPath(finding: Finding): AttackStep[] | null {
  const parses = allEvidence(finding).flatMap(parseEvidence);
  if (parses.length === 0) return null;

  const flow = [...parses].sort((a, b) => a.rank - b.rank)[0]!;
  const guardSource = [...parses].filter((parsed) => parsed.guard).sort((a, b) => a.guardRank - b.guardRank)[0];

  const location = flow.location ?? findingLocation(finding);
  const sinkDetail = location && !flow.sink.includes(location) ? `${flow.sink} (${location})` : flow.sink;

  const steps: AttackStep[] = [{ label: flow.sourceLabel, detail: flow.source }];
  if (finding.affected.route) steps.push({ label: "Entry point", detail: finding.affected.route });
  steps.push({ label: "Reaches", detail: sinkDetail });
  if (guardSource?.guard) steps.push({ label: "Missing check", detail: guardSource.guard });
  steps.push({ label: "Outcome", detail: finding.impact });

  // Six is the point where a path stops being read as one thought. Nothing above can
  // produce more, but the cap is enforced rather than assumed.
  return steps.slice(0, 6);
}

/* ------------------------------------------------------------------ *
 * Executive summary
 * ------------------------------------------------------------------ */

const VERIFICATION_LEAD: Record<Finding["verification"], (clause: string) => string> = {
  verified: (clause) => `${BRAND.displayName} verified ${clause}.`,
  strong_evidence: (clause) => `${BRAND.displayName} found strong evidence for ${clause}.`,
  needs_review: (clause) => `${BRAND.displayName} recorded ${clause}, and it still needs review.`
};

const VERIFICATION_ALSO: Record<Finding["verification"], (list: string) => string> = {
  verified: (list) => `${BRAND.displayName} also verified ${list}.`,
  strong_evidence: (list) => `Also on strong evidence: ${list}.`,
  needs_review: (list) => `Also awaiting review: ${list}.`
};

/**
 * Names a finding the way a developer would go looking for it: the id they can search,
 * the route they can open, and the title as written. The route is dropped when the
 * title already contains it, because repeating it reads as two different places.
 */
function nameFinding(finding: Finding): string {
  const route = finding.affected.route;
  if (route && !finding.title.includes(route)) return `${finding.id} on ${route} — ${finding.title}`;
  const file = finding.affected.file;
  if (!route && file && !finding.title.includes(file)) return `${finding.id} in ${file} — ${finding.title}`;
  return `${finding.id} — ${finding.title}`;
}

function stackSentence(report: SummarizableReport): string | null {
  const stack = report.scan?.stack;
  if (!stack) return null;
  const languages = stack.languages.filter(Boolean);
  const frameworks = stack.frameworks.filter(Boolean);
  if (languages.length === 0 && frameworks.length === 0) return null;
  if (languages.length === 0) return `The recorded stack is ${joinList(frameworks)}.`;
  if (frameworks.length === 0) return `The recorded stack is ${joinList(languages)}.`;
  return `The recorded stack is ${joinList(languages)} with ${joinList(frameworks)}.`;
}

function scopeSentence(report: SummarizableReport): string | null {
  const scope = report.scan?.scope;
  if (!scope) return null;
  const local = scope.localTargets.filter(Boolean);
  const external = scope.externalTargets.map((target) => target.target).filter(Boolean);
  if (local.length === 0 && external.length === 0) return null;
  if (local.length === 0) {
    return `It ran against ${count(external.length)} authorized external ${plural(external.length, "origin")}: ${joinList(external)}.`;
  }
  const externalClause =
    external.length === 0
      ? "no external origin was authorized"
      : `${count(external.length)} external ${plural(external.length, "origin")} ${plural(external.length, "was", "were")} authorized as well: ${joinList(external)}`;
  return `It ran against ${joinList(local)} on this machine, and ${externalClause}.`;
}

/**
 * Coverage notes are free prose written by the host agent, so no number is parsed out
 * of them; a percentage read out of a sentence would be a percentage this code made
 * up. The route and component counts below are counted from the findings themselves,
 * and the sentence says so rather than presenting them as coverage.
 */
function scaleSentence(findings: Finding[]): string {
  const present = (value: string | undefined): value is string => Boolean(value);
  const routes = new Set(findings.map((finding) => finding.affected.route).filter(present));
  const components = new Set(findings.map((finding) => finding.affected.component).filter(present));
  const total = `${upperFirst(count(findings.length))} ${plural(findings.length, "finding")} ${plural(findings.length, "is", "are")} recorded`;
  const routeClause = routes.size > 0 ? `naming ${count(routes.size)} distinct ${plural(routes.size, "route")}` : null;
  const componentClause =
    components.size > 0 ? `across ${count(components.size)} ${plural(components.size, "component")}` : null;
  const detail = [routeClause, componentClause].filter(Boolean).join(" ");
  return detail ? `${total}, ${detail}.` : `${total}.`;
}

function coverageAreaSentence(report: SummarizableReport): string | null {
  const areas = report.coverageAreas;
  if (!areas || areas.length === 0) return null;
  const assessed = areas.filter((area) => area.assessed).length;
  if (areas.length === 1) {
    return `The one recorded coverage area was ${assessed === 1 ? "assessed" : "not assessed"}.`;
  }
  const areaWord = plural(areas.length, "area");
  if (assessed === areas.length) return `All ${count(areas.length)} recorded coverage ${areaWord} were assessed.`;
  if (assessed === 0) return `None of the ${count(areas.length)} recorded coverage ${areaWord} were assessed.`;
  return `${upperFirst(count(assessed))} of the ${count(areas.length)} recorded coverage ${areaWord} ${plural(assessed, "was", "were")} assessed.`;
}

function whatWasTested(report: SummarizableReport, findings: Finding[] | undefined): string {
  /*
   * A share can withhold the project name, and a report identifier is not a
   * substitute for it: "Myrqen assessed rpt_6d7b9706-ca9c-4676-895d-ec400079c71c"
   * is the first sentence a recipient reads, and it tells them nothing they can
   * act on. Where the name is withheld the subject becomes the application
   * itself, which is true whether or not the reader is allowed to know its name.
   */
  const name = report.project?.name ?? "this application";
  const scan = report.scan;
  const effortClause = scan
    ? scan.effortRequested === scan.effortResolved
      ? ` at ${scan.effortResolved} effort`
      : ` at ${scan.effortResolved} effort, resolved from ${scan.effortRequested === "auto" ? "an auto" : `a ${scan.effortRequested}`} request`
    : "";
  return sentences([
    `${BRAND.displayName} assessed ${name}${effortClause}.`,
    stackSentence(report),
    scopeSentence(report),
    // An empty findings list gets its own paragraph, which says the same thing with
    // the honesty the count on its own would not carry.
    findings && findings.length > 0 ? scaleSentence(findings) : null,
    coverageAreaSentence(report)
  ]);
}

function highestRisk(findings: Finding[]): string | null {
  const ranked = sortFindings(findings);
  const lead = ranked[0];
  if (!lead) return null;

  // Only findings that match the lead on both severity and verification join the
  // headline. Naming a verified critical and an unreviewed low in one sentence lends
  // the credibility of the first to the second.
  const peers = ranked
    .slice(1)
    .filter((finding) => finding.severity === lead.severity && finding.verification === lead.verification)
    .slice(0, 2);

  return sentences([
    VERIFICATION_LEAD[lead.verification](nameFinding(lead)),
    lead.impact,
    peers.length > 0 ? VERIFICATION_ALSO[lead.verification](joinList(peers.map(nameFinding))) : null
  ]);
}

function confidenceSentence(findings: Finding[], hasAntecedent: boolean): string {
  const verified = findings.filter((finding) => finding.verification === "verified").length;
  const strong = findings.filter((finding) => finding.verification === "strong_evidence").length;
  const review = findings.filter((finding) => finding.verification === "needs_review").length;
  const clauses = [
    verified > 0 ? `${count(verified)} ${plural(verified, "is", "are")} verified` : null,
    strong > 0 ? `${count(strong)} ${plural(strong, "rests", "rest")} on strong evidence` : null,
    review > 0 ? `${count(review)} still ${plural(review, "needs", "need")} review` : null
  ].filter((clause): clause is string => clause !== null);

  const opening = hasAntecedent
    ? `Of those ${count(findings.length)} findings`
    : `Of the ${count(findings.length)} ${plural(findings.length, "finding")}`;
  return `${opening}, ${joinList(clauses)}.`;
}

// Long enough to carry two real limitations, short enough that the paragraph is still
// read rather than skipped.
const LIMITATION_BUDGET = 420;
const MAX_LIMITATIONS = 3;

/**
 * Limitations are quoted verbatim and in the order the report records them. That order
 * is the only ranking the data carries: sorting them by an invented notion of severity
 * would be this code asserting which caveat matters most, which is not something the
 * report says. Whatever does not fit is counted, never dropped silently.
 */
function limitationsParagraph(limitations: string[]): string | null {
  const lines = limitations.map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0) return null;

  const shown: string[] = [];
  let used = 0;
  for (const line of lines) {
    if (shown.length >= MAX_LIMITATIONS) break;
    if (shown.length > 0 && used + line.length > LIMITATION_BUDGET) break;
    shown.push(line);
    used += line.length;
  }

  const remaining = lines.length - shown.length;
  return sentences([
    ...shown,
    remaining > 0
      ? `${upperFirst(count(remaining))} further ${plural(remaining, "limitation")} ${plural(remaining, "is", "are")} recorded with this report.`
      : null
  ]);
}

const NOT_EVIDENCE =
  "No findings were recorded. That is not evidence that the application is secure: it is evidence that these checks, over this scope, did not produce one. Read the coverage notes and the limitations before treating the result as a clean bill of health.";

const FINDINGS_WITHHELD = "This view does not include the report's findings, so it cannot summarise them.";

function assemble(paragraphs: Array<string | null>): string[] {
  return paragraphs.filter((paragraph): paragraph is string => Boolean(paragraph && paragraph.trim())).slice(0, 4);
}

/**
 * Two to four short paragraphs stating what was tested, what the worst findings are,
 * where the risk clusters, how confident the scan is, and what it could not reach.
 *
 * Every sentence is derived from a field the report already carries. Where a field is
 * absent the sentence is not written, so a thin report yields a short summary rather
 * than a padded one.
 */
export function executiveSummary(report: SummarizableReport): string[] {
  const findings = report.findings;
  const opening = whatWasTested(report, findings);

  // A projection may withhold the findings from this viewer. Saying nothing about them
  // is the only honest option; reporting none would be the projection lying about
  // itself.
  if (!findings) {
    return assemble([opening, FINDINGS_WITHHELD, limitationsParagraph(report.limitations ?? [])]);
  }

  if (findings.length === 0) {
    // buildReport appends this same caveat to limitations, and the test it uses to
    // avoid duplicating it is the one repeated here. Stating it twice on one page
    // reads as emphasis the data does not warrant.
    const rest = (report.limitations ?? []).filter((line) => !line.includes("not evidence"));
    return assemble([opening, NOT_EVIDENCE, limitationsParagraph(rest)]);
  }

  const concentration = riskConcentration(findings);
  return assemble([
    opening,
    highestRisk(findings),
    sentences([
      concentration ? concentrationSentence(concentration) : null,
      confidenceSentence(findings, concentration !== null)
    ]),
    limitationsParagraph(report.limitations ?? [])
  ]);
}
