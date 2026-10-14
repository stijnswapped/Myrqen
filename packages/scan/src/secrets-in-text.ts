import { assessCredentialValue } from "./rules/credentials.js";

/**
 * The `credential-literal` rule, applied to plain text.
 *
 * The rule proper walks a parsed syntax tree, which only exists for source the
 * engine can parse. A diff about to be committed can be anything — an `.env`
 * file, YAML, JSON, a shell script — so this reads it line by line, pulls out the
 * values a line could carry, and asks the same question the rule asks of each
 * one. It reports where, and what kind; never the value.
 */

export interface TextCredentialHit {
  /** 1-based line number within the text given. */
  line: number;
  label: string;
  live: boolean;
}

const QUOTED = /(["'`])((?:\\.|(?!\1)[^\\])*)\1/g;
/** `name = `, `name: `, `"name": `, `name ||` immediately before a quoted value. */
const BINDING_BEFORE = /([A-Za-z_][\w.-]*)["']?\s*(?::|=|\|\||\?\?)\s*$/;
/** `NAME=value`, `export NAME=value`, `name: value` — an unquoted value bound to a name. */
const UNQUOTED_ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][\w.-]*)\s*[:=]\s*([^\s"'`#,;]+)/;
const TOKEN_SEPARATOR = /[\s"'`,;()[\]{}<>=]+/;
const PEM_HEADER = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const MAX_LINE_LENGTH = 8192;

function candidatesIn(line: string): Array<{ value: string; boundTo: string[] }> {
  const candidates: Array<{ value: string; boundTo: string[] }> = [];
  for (const match of line.matchAll(QUOTED)) {
    const before = line.slice(0, match.index);
    const binding = BINDING_BEFORE.exec(before);
    candidates.push({ value: match[2] ?? "", boundTo: binding ? [binding[1]!] : [] });
  }
  const assignment = UNQUOTED_ASSIGNMENT.exec(line);
  if (assignment) candidates.push({ value: assignment[2]!, boundTo: [assignment[1]!] });
  // A bare token is judged by its shape alone, as the rule's last pass does.
  for (const token of line.split(TOKEN_SEPARATOR)) {
    if (token.length >= 8) candidates.push({ value: token, boundTo: [] });
  }
  if (PEM_HEADER.test(line)) candidates.push({ value: line, boundTo: [] });
  return candidates;
}

/** Credential-shaped values in `text`, one hit per line and kind. */
export function findCredentialsInText(text: string): TextCredentialHit[] {
  const hits: TextCredentialHit[] = [];
  text.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.length > MAX_LINE_LENGTH ? raw.slice(0, MAX_LINE_LENGTH) : raw;
    const seen = new Set<string>();
    for (const candidate of candidatesIn(line)) {
      const verdict = assessCredentialValue(candidate.value, candidate.boundTo);
      if (!verdict || seen.has(verdict.label)) continue;
      seen.add(verdict.label);
      hits.push({ line: index + 1, label: verdict.label, live: verdict.live });
    }
  });
  return hits;
}
