import { BRAND } from "@myrqen/brand";

/** Default-prohibited action classes. Higher effort never relaxes these. */
export const DEFAULT_PROHIBITED_ACTIONS = Object.freeze([
  "denial_of_service",
  "resource_exhaustion",
  "mass_delete",
  "mass_mutation",
  "destructive_database_change",
  "destructive_filesystem_change",
  "persistence",
  "uncontrolled_account_creation",
  "spam_or_mass_messaging",
  "financial_or_billing_side_effect",
  "credential_theft_or_reuse",
  "malware_deployment",
  "scope_expansion",
  "unrelated_infrastructure_recon",
  "authorization_prompt_bypass",
  "policy_or_logging_tampering",
  "secret_exfiltration"
] as const);

export type ProhibitedActionClass = (typeof DEFAULT_PROHIBITED_ACTIONS)[number];

export interface PlannedAction {
  /** Short machine-readable intent, e.g. "delete_all_orders". */
  intent: string;
  description?: string;
  method?: string;
  target?: string;
  /** True when the target is a machine-local disposable fixture. */
  localDisposableFixture?: boolean;
  /** Requested count of operations, used for mass-mutation detection. */
  repeatCount?: number;
}

export interface ActionDecision {
  allowed: boolean;
  violations: ProhibitedActionClass[];
  reason?: string;
  guidance?: string;
}

interface Rule {
  klass: ProhibitedActionClass;
  pattern: RegExp;
}

const RULES: readonly Rule[] = Object.freeze([
  { klass: "denial_of_service", pattern: /\b(dos|ddos|flood|stress[_ -]?test|slowloris|zip[_ -]?bomb|fork[_ -]?bomb|exhaust)\b/i },
  { klass: "resource_exhaustion", pattern: /\b(memory[_ -]?exhaust|cpu[_ -]?burn|fill[_ -]?disk|infinite[_ -]?loop[_ -]?request)\b/i },
  { klass: "mass_delete", pattern: /\b(delete[_ -]?all|drop[_ -]?(table|database|schema)|truncate|purge[_ -]?all|wipe|rm[_ -]?-rf)\b/i },
  { klass: "mass_mutation", pattern: /\b(update[_ -]?all|overwrite[_ -]?all|bulk[_ -]?(update|overwrite)|reset[_ -]?all[_ -]?passwords)\b/i },
  { klass: "destructive_database_change", pattern: /\b(alter[_ -]?table[_ -]?drop|delete[_ -]?from[_ -]?\w+[_ -]?where[_ -]?1|drop[_ -]?column)\b/i },
  { klass: "destructive_filesystem_change", pattern: /\b(chmod[_ -]?777[_ -]?\/|overwrite[_ -]?system[_ -]?file|delete[_ -]?repository)\b/i },
  { klass: "persistence", pattern: /\b(backdoor|web[_ -]?shell|reverse[_ -]?shell|install[_ -]?cron|add[_ -]?ssh[_ -]?key|create[_ -]?admin[_ -]?account[_ -]?permanently|implant)\b/i },
  { klass: "uncontrolled_account_creation", pattern: /\b(mass[_ -]?signup|register[_ -]?many|account[_ -]?spray|create[_ -]?\d{3,}[_ -]?accounts)\b/i },
  { klass: "spam_or_mass_messaging", pattern: /\b(send[_ -]?bulk[_ -]?(email|sms)|mass[_ -]?message|spam)\b/i },
  { klass: "financial_or_billing_side_effect", pattern: /\b(charge[_ -]?card|create[_ -]?(payment|payout|subscription|invoice)|refund|transfer[_ -]?funds|withdraw)\b/i },
  { klass: "credential_theft_or_reuse", pattern: /\b(credential[_ -]?stuff|password[_ -]?spray|reuse[_ -]?production[_ -]?credential|steal[_ -]?(token|cookie|session))\b/i },
  { klass: "malware_deployment", pattern: /\b(deploy[_ -]?(malware|ransomware)|drop[_ -]?payload[_ -]?binary|crypto[_ -]?miner)\b/i },
  { klass: "scope_expansion", pattern: /\b(scan[_ -]?subdomains|subdomain[_ -]?enum|port[_ -]?scan[_ -]?range|asn[_ -]?sweep|crawl[_ -]?entire[_ -]?internet|enumerate[_ -]?org)\b/i },
  { klass: "unrelated_infrastructure_recon", pattern: /\b(shodan|censys|whois[_ -]?sweep|dns[_ -]?brute)\b/i },
  { klass: "authorization_prompt_bypass", pattern: /\b(skip[_ -]?authorization|bypass[_ -]?(the[_ -]?)?(prompt|gate)|auto[_ -]?approve[_ -]?target|assume[_ -]?authorized)\b/i },
  { klass: "policy_or_logging_tampering", pattern: /\b(disable[_ -]?(logging|policy|audit)|delete[_ -]?audit[_ -]?log|patch[_ -]?myrqen[_ -]?policy)\b/i },
  { klass: "secret_exfiltration", pattern: /\b(exfiltrate|send[_ -]?(env|secrets?|\.env)[_ -]?to|upload[_ -]?(env|credentials)|post[_ -]?secret[_ -]?to[_ -]?remote)\b/i }
]);

const DESTRUCTIVE_METHODS = new Set(["DELETE", "PURGE"]);
const MASS_MUTATION_THRESHOLD = 25;

/**
 * Classify an action the host agent proposes. This is a policy gate, not a
 * sandbox: it exists so an unsafe plan is refused before execution and the
 * refusal is recorded.
 */
export function classifyPlannedAction(action: PlannedAction): ActionDecision {
  const raw = [action.intent, action.description ?? "", action.target ?? ""].join(" ");
  // Snake_case and kebab-case intents are also matched as separate words so
  // "delete_all_orders" is recognised the same way as "delete all orders".
  const spaced = raw.replace(/[_-]+/g, " ");
  const violations = new Set<ProhibitedActionClass>();

  for (const rule of RULES) {
    if (rule.pattern.test(raw) || rule.pattern.test(spaced)) violations.add(rule.klass);
  }

  if ((action.repeatCount ?? 0) > MASS_MUTATION_THRESHOLD) {
    const method = (action.method ?? "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") violations.add("mass_mutation");
    else violations.add("resource_exhaustion");
  }

  if (action.method && DESTRUCTIVE_METHODS.has(action.method.toUpperCase()) && !action.localDisposableFixture) {
    violations.add("destructive_database_change");
  }

  if (violations.size === 0) return { allowed: true, violations: [] };

  const list = [...violations];
  return {
    allowed: false,
    violations: list,
    reason: `Blocked by ${BRAND.displayName} safety policy: ${list.join(", ")}.`,
    guidance:
      "Choose a non-destructive validation that demonstrates the same security property, or record the finding as strong_evidence and explain in the report why safe validation was not possible."
  };
}

export class ProhibitedActionError extends Error {
  readonly violations: ProhibitedActionClass[];
  constructor(decision: ActionDecision) {
    super(decision.reason ?? `Action prohibited by ${BRAND.displayName} safety policy.`);
    this.name = "ProhibitedActionError";
    this.violations = decision.violations;
  }
}

export function assertActionAllowed(action: PlannedAction): void {
  const decision = classifyPlannedAction(action);
  if (!decision.allowed) throw new ProhibitedActionError(decision);
}
