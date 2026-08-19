import crypto from "node:crypto";

const REDACTED_SECRET = "[REDACTED_SECRET]";
const REDACTED_TOKEN = "[REDACTED_TOKEN]";

/**
 * Heuristic detectors. These are one layer among several: typed schemas,
 * agent-marked sensitive spans, the known-secret matcher, this scrubber, and
 * canary tests. No single layer is treated as a complete boundary.
 */
const TOKEN_PATTERNS: ReadonlyArray<{ label: string; pattern: RegExp }> = Object.freeze([
  { label: "stripe_like", pattern: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b/g },
  { label: "generic_sk", pattern: /\b(?:sk|pk)_[A-Za-z0-9_-]{16,}\b/g },
  { label: "bearer", pattern: /\bBearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}/gi },
  { label: "basic_auth", pattern: /\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}/g },
  { label: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { label: "aws_access_key", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { label: "google_api_key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { label: "github_token", pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { label: "slack_token", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { label: "openai_like", pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { label: "anthropic_like", pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  {
    label: "private_key_block",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g
  },
  { label: "hex_secret", pattern: /\b[A-Fa-f0-9]{40,}\b/g },
  { label: "connection_string_password", pattern: /\b([a-z0-9+.-]{2,20}:\/\/[^\s:@/]{1,64}):([^\s@/]{6,})@/gi },
  {
    label: "env_assignment",
    // The value must not already be a placeholder. Without that guard the
    // pattern matches its own output, redaction never reaches a fixed point,
    // and the intake's residual check rejects every finding that quotes a line
    // of this shape — including the debug endpoint that dumps the environment,
    // which is precisely the finding a reader needs.
    pattern:
      /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET|SESSION_KEY)[A-Z0-9_]*)(\s*[=:]\s*)(?!\[REDACTED)["']?([^\s"']{6,})["']?/g
  }
]);

const CONTROL_CHARACTERS = new RegExp("[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]");

export interface RedactionResult {
  value: string;
  replacements: number;
  labels: string[];
}

/** Replace known local secret values and secret-shaped tokens. */
export function redactText(value: string, knownSecrets: readonly string[] = []): RedactionResult {
  let output = value;
  let replacements = 0;
  const labels = new Set<string>();

  const candidates = [...new Set(knownSecrets)]
    .filter((secret) => typeof secret === "string" && secret.trim().length >= 6)
    .sort((a, b) => b.length - a.length);

  for (const secret of candidates) {
    if (!output.includes(secret)) continue;
    const occurrences = output.split(secret).length - 1;
    output = output.split(secret).join(REDACTED_SECRET);
    replacements += occurrences;
    labels.add("known_local_secret");
  }

  for (const { label, pattern } of TOKEN_PATTERNS) {
    output = output.replace(new RegExp(pattern.source, pattern.flags), (match, ...groups) => {
      replacements += 1;
      labels.add(label);
      if (label === "connection_string_password" && typeof groups[0] === "string") {
        return `${groups[0]}:${REDACTED_SECRET}@`;
      }
      if (label === "env_assignment" && typeof groups[0] === "string") {
        // Keep the original separator: rewriting `SECRET: value` as `SECRET=`
        // silently changes the quoted source and misleads whoever reads it.
        const separator = typeof groups[1] === "string" ? groups[1] : "=";
        return `${groups[0]}${separator}${REDACTED_SECRET}`;
      }
      return REDACTED_TOKEN;
    });
  }

  return { value: output, replacements, labels: [...labels] };
}

export function containsSecretLikeMaterial(value: string, knownSecrets: readonly string[] = []): boolean {
  return redactText(value, knownSecrets).replacements > 0;
}

/** Deep-redact any string in a structure destined for a report or the cloud. */
export function redactDeep<T>(value: T, knownSecrets: readonly string[] = []): { value: T; replacements: number } {
  let replacements = 0;
  const walk = (node: unknown): unknown => {
    if (typeof node === "string") {
      const result = redactText(node, knownSecrets);
      replacements += result.replacements;
      return result.value;
    }
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === "object") {
      const out: Record<string, unknown> = {};
      for (const [key, child] of Object.entries(node as Record<string, unknown>)) out[key] = walk(child);
      return out;
    }
    return node;
  };
  return { value: walk(value) as T, replacements };
}

/**
 * Progress messages are the highest-risk small payload: they leave the machine
 * for every synced scan. Reject rather than silently rewrite.
 */
export function assertSafeProgressMessage(message?: string, knownSecrets: readonly string[] = []): void {
  if (!message) return;
  if (message.length > 300) throw new Error("Progress message exceeds safe length.");
  if (containsSecretLikeMaterial(message, knownSecrets)) {
    throw new Error("Progress message appears to contain secret-like material.");
  }
  if (CONTROL_CHARACTERS.test(message)) {
    throw new Error("Progress message contains control characters.");
  }
}

export interface SecretFingerprint {
  label: string;
  kind: string;
  fingerprint: string;
  location?: string;
}

/**
 * A secret is represented by a keyed fingerprint, never by its value or a bare
 * hash. The key stays on the local device so fingerprints cannot be brute
 * forced from a synced report.
 */
export function fingerprintSecret(
  value: string,
  localKey: string,
  meta: { label: string; kind: string; location?: string }
): SecretFingerprint {
  const mac = crypto.createHmac("sha256", localKey).update(value).digest("base64url").slice(0, 24);
  const fingerprint: SecretFingerprint = {
    label: meta.label,
    kind: meta.kind,
    fingerprint: `fp_${mac}`
  };
  if (meta.location !== undefined) fingerprint.location = meta.location;
  return fingerprint;
}

/** Parse a dotenv-style file into candidate secret values for the matcher. */
export function extractEnvSecretValues(fileContents: string): string[] {
  const values: string[] = [];
  for (const rawLine of fileContents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    let value = (match[2] ?? "").trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length > 1) ||
      (value.startsWith("'") && value.endsWith("'") && value.length > 1)
    ) {
      value = value.slice(1, -1);
    }
    if (value.length >= 6 && !/^(true|false|null|\d+)$/i.test(value)) values.push(value);
  }
  return [...new Set(values)];
}

/** Shannon entropy per character, used to flag high-entropy literals. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function looksHighEntropySecret(value: string): boolean {
  if (value.length < 20 || value.length > 200) return false;
  if (/\s/.test(value)) return false;
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) return false;
  return shannonEntropy(value) >= 3.6;
}
