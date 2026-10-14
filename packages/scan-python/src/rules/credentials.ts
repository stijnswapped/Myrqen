/**
 * Credential shapes, mirrored from `packages/scan/src/rules/credentials.ts`.
 *
 * Mirrored rather than imported because `@myrqen/scan` depends on this package
 * and the dependency must run one way. The list is a set of documented token
 * formats published by their issuers, so it changes rarely; when it changes in
 * the JavaScript engine it should change here too, and the shared test in
 * `test/credentials.test.mjs` compares the two lists so drift fails a build.
 */

export interface CredentialShape {
  id: string;
  label: string;
  pattern: RegExp;
  live: boolean;
}

export const CREDENTIAL_SHAPES: readonly CredentialShape[] = [
  { id: "stripe_live", label: "Stripe live secret key", pattern: /^(sk|rk)_live_[A-Za-z0-9]{10,}$/, live: true },
  { id: "stripe_test", label: "Stripe test secret key", pattern: /^(sk|rk)_test_[A-Za-z0-9]{10,}$/, live: false },
  { id: "stripe_webhook", label: "Stripe webhook signing secret", pattern: /^whsec_[A-Za-z0-9]{20,}$/, live: true },
  { id: "openai", label: "OpenAI-style API key", pattern: /^sk-(proj-)?[A-Za-z0-9_-]{20,}$/, live: true },
  { id: "anthropic", label: "Anthropic API key", pattern: /^sk-ant-[A-Za-z0-9_-]{20,}$/, live: true },
  { id: "aws_access_key", label: "AWS access key id", pattern: /^(AKIA|ASIA)[0-9A-Z]{16}$/, live: true },
  { id: "google_api", label: "Google API key", pattern: /^AIza[0-9A-Za-z_-]{35}$/, live: false },
  { id: "github_token", label: "GitHub token", pattern: /^gh[pousr]_[A-Za-z0-9]{20,}$/, live: true },
  { id: "slack_token", label: "Slack token", pattern: /^xox[abprs]-[A-Za-z0-9-]{10,}$/, live: true },
  { id: "jwt", label: "signed JSON Web Token", pattern: /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/, live: false },
  { id: "sendgrid", label: "SendGrid API key", pattern: /^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/, live: true },
  { id: "npm_token", label: "npm access token", pattern: /^npm_[A-Za-z0-9]{36}$/, live: true },
  { id: "gitlab_pat", label: "GitLab personal access token", pattern: /^glpat-[A-Za-z0-9_-]{20,}$/, live: true },
  { id: "google_oauth_secret", label: "Google OAuth client secret", pattern: /^GOCSPX-[A-Za-z0-9_-]{20,}$/, live: true },
  { id: "shopify", label: "Shopify access token", pattern: /^shp(at|ss|ca|pa)_[a-fA-F0-9]{32}$/, live: true },
  { id: "square", label: "Square access token", pattern: /^sq0(atp|csp)-[A-Za-z0-9_-]{20,}$/, live: true },
  { id: "mailgun", label: "Mailgun API key", pattern: /^key-[a-f0-9]{32}$/, live: true },
  { id: "twilio_api_key", label: "Twilio API key", pattern: /^SK[a-f0-9]{32}$/, live: true },
  { id: "supabase_service", label: "Supabase service key", pattern: /^sbp_[a-f0-9]{40}$/, live: true },
  { id: "doppler", label: "Doppler service token", pattern: /^dp\.(pt|st|sa)\.[A-Za-z0-9_-]{20,}$/, live: true },
  { id: "linear", label: "Linear API key", pattern: /^lin_api_[A-Za-z0-9]{20,}$/, live: true },
  { id: "huggingface", label: "Hugging Face access token", pattern: /^hf_[A-Za-z0-9]{30,}$/, live: true },
  { id: "resend", label: "Resend API key", pattern: /^re_[A-Za-z0-9_]{20,}$/, live: true },
  { id: "groq", label: "Groq API key", pattern: /^gsk_[A-Za-z0-9]{40,}$/, live: true },
  { id: "discord_bot", label: "Discord bot token", pattern: /^[MNO][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}$/, live: true },
  { id: "telegram_bot", label: "Telegram bot token", pattern: /^\d{8,12}:[A-Za-z0-9_-]{35}$/, live: true },
  { id: "sentry_dsn", label: "Sentry DSN with an inline key", pattern: /^https:\/\/[a-f0-9]{16,}@[\w.-]*ingest[\w.-]*\.sentry\.io\/\d+$/, live: true },
  { id: "azure_storage", label: "Azure storage connection string", pattern: /AccountKey=[A-Za-z0-9+/=]{40,}/, live: true },
  { id: "private_key", label: "PEM private key", pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/, live: true },
  {
    id: "connection_string",
    label: "connection string with an inline password",
    pattern: /^[a-z0-9+.-]{2,20}:\/\/[^\s:@/]{1,64}:[^\s@/]{6,}@/i,
    live: true
  }
];

const PUBLIC_VALUE_PREFIX = /^(pk_|pub_|price_|prod_|cus_|acct_|sub_|in_|pi_|seti_|whsec_test_|npm_public_|ghs_public_)/;

export function classifyCredential(value: string): { label: string; live: boolean } | null {
  if (PUBLIC_VALUE_PREFIX.test(value)) return null;
  for (const shape of CREDENTIAL_SHAPES) if (shape.pattern.test(value)) return { label: shape.label, live: shape.live };
  return null;
}

export function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}
