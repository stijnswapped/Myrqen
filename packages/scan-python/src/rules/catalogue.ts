import type { Severity } from "@myrqen/contracts";
import type { SinkClass } from "../analysis/values.js";

/**
 * Report text for each data-flow rule.
 *
 * Category names are the ones the JavaScript engine already uses wherever the
 * semantics match, so the report, the SARIF export and the compliance mapping
 * treat a Python SQL injection exactly as they treat a JavaScript one. Rule ids
 * are prefixed `py-` so a reader (and a disabled-rules list) can tell the
 * engines apart.
 */

export interface FlowRule {
  id: string;
  category: string;
  severity: Severity;
  title: (sink: string) => string;
  summary: (origin: string, sink: string) => string;
  impact: string;
  remediation: string;
  verificationPlan: string;
  taxonomy: string[];
}

export const FLOW_RULES: Record<SinkClass, FlowRule> = {
  sql: {
    id: "py-sql-injection",
    category: "sql_injection",
    severity: "critical",
    title: (sink) => `Caller-controlled data is formatted into SQL passed to ${sink}`,
    summary: (origin, sink) =>
      `A value derived from ${origin} is interpolated into the statement text given to ${sink}, rather than bound as a parameter. The caller therefore controls the structure of the query, not only its values.`,
    impact:
      "An attacker can read or change any data the database user can reach — including other tenants' rows through a UNION — and on some databases run commands on the database host.",
    remediation:
      "Bind the value as a parameter (`?`, `%s` or `:name` with a params tuple or dict, or a SQLAlchemy `bindparam`). For identifiers such as a sort column, map the caller's choice through a fixed dictionary of allowed column names instead of formatting it in.",
    verificationPlan:
      "Request the route with a value containing a single quote and with a boolean tautology; confirm the response neither errors nor widens, and that the statement text in the database log contains only placeholders.",
    taxonomy: ["CWE-89", "OWASP-A03"]
  },
  command: {
    id: "py-command-injection",
    category: "command_injection",
    severity: "critical",
    title: (sink) => `Caller-controlled data reaches a shell through ${sink}`,
    summary: (origin, sink) =>
      `A value derived from ${origin} is part of a command string that ${sink} hands to a shell. Shell metacharacters in the value — \`;\`, \`|\`, \`$(…)\` — start commands of the caller's choosing.`,
    impact: "Arbitrary command execution with the privileges of the application process.",
    remediation:
      "Pass an argument list with `shell=False` (the default) so no shell parses the input, and validate any value that selects an option against a fixed set. `shlex.quote` is a fallback for the rare case that genuinely needs a shell.",
    verificationPlan:
      "Send a value containing a harmless separator such as `; echo myrqen-probe` and confirm the probe never appears in output or logs; prefer a non-executing probe if the command has side effects.",
    taxonomy: ["CWE-78", "OWASP-A03"]
  },
  path: {
    id: "py-path-traversal",
    category: "path_traversal",
    severity: "high",
    title: (sink) => `A caller-controlled path reaches ${sink}`,
    summary: (origin, sink) =>
      `A value derived from ${origin} becomes part of a filesystem path that ${sink} opens, with no containment check on the resolved result. \`../\` segments or an absolute path move the operation outside the intended directory.`,
    impact: "Reading (or writing, or deleting) files outside the intended directory: configuration, credentials, source, other users' files.",
    remediation:
      "Resolve the joined path (`os.path.realpath` or `Path.resolve()`) and refuse it unless it is still inside the resolved base directory (`is_relative_to` / `commonpath`). For downloads, prefer `send_from_directory`, or reduce the input to `os.path.basename` / `secure_filename` first.",
    verificationPlan:
      "Request the route with `../` sequences and an absolute path; confirm both are refused with a 4xx and that no file outside the base directory is served.",
    taxonomy: ["CWE-22", "OWASP-A01"]
  },
  ssrf: {
    id: "py-server-side-request-forgery",
    category: "server_side_request_forgery",
    severity: "high",
    title: (sink) => `The destination of an outbound request through ${sink} is caller-controlled`,
    summary: (origin, sink) =>
      `A value derived from ${origin} decides the URL that ${sink} requests from the server, and no allow-list of hosts is consulted first.`,
    impact:
      "The server can be made to call internal services, cloud metadata endpoints and administrative interfaces that are unreachable from outside, and to return or act on what they answer.",
    remediation:
      "Parse the URL and require its scheme and host to be in an explicit allow-list before requesting it; resolve the host and refuse private, loopback and link-local addresses; disable redirects or re-check every hop.",
    verificationPlan:
      "Point the route at a local origin you control and confirm the request is refused; then confirm an allow-listed host still works.",
    taxonomy: ["CWE-918", "OWASP-A10"]
  },
  template: {
    id: "py-template-injection",
    category: "template_injection",
    severity: "critical",
    title: (sink) => `Caller-controlled text is compiled as a template by ${sink}`,
    summary: (origin, sink) =>
      `A value derived from ${origin} becomes the template source compiled by ${sink}. Template syntax in the value is evaluated on the server, and Jinja2 expressions can reach Python objects.`,
    impact: "Server-side template injection: disclosure of configuration and secrets, and in Jinja2 typically remote code execution.",
    remediation:
      "Keep the template fixed and pass the caller's value as a context variable (`render_template_string(TEMPLATE, name=value)`), or render from a template file. If users must author templates, use `jinja2.sandbox.SandboxedEnvironment` with a minimal context.",
    verificationPlan: "Submit `{{7*7}}` and confirm the response contains it literally rather than `49`.",
    taxonomy: ["CWE-1336", "CWE-94", "OWASP-A03"]
  },
  deserialization: {
    id: "py-unsafe-deserialization",
    category: "unsafe_deserialization",
    severity: "critical",
    title: (sink) => `Caller-supplied bytes are deserialised by ${sink}`,
    summary: (origin, sink) =>
      `Data derived from ${origin} is passed to ${sink}, which can construct arbitrary Python objects — and call arbitrary functions while doing so — from its input.`,
    impact: "Remote code execution: a crafted payload runs code during deserialisation, before any validation of the result.",
    remediation:
      "Exchange data as JSON and validate it with a schema. Where YAML is needed use `yaml.safe_load`. If server-issued state must round-trip through the client, sign it (`itsdangerous`) and verify the signature before decoding anything.",
    verificationPlan:
      "Confirm the route rejects a pickle or YAML object payload without decoding it; never send an executing gadget to a shared environment.",
    taxonomy: ["CWE-502", "OWASP-A08"]
  },
  redirect: {
    id: "py-open-redirect",
    category: "open_redirect",
    severity: "medium",
    title: (sink) => `The target of ${sink} is caller-controlled`,
    summary: (origin, sink) =>
      `A value derived from ${origin} is used as the destination of ${sink} without checking that it stays on this site.`,
    impact: "Links on the application's own domain can send users to a look-alike site, which makes phishing and token theft through redirect chains credible.",
    remediation:
      "Accept only relative paths (`urlparse(target).netloc == ''` and no leading `//` or backslash), or map the caller's choice to a fixed set of destinations; fall back to a default page otherwise.",
    verificationPlan: "Request the route with `next=https://example.invalid/` and with `//example.invalid`; confirm both land on the default page.",
    taxonomy: ["CWE-601", "OWASP-A01"]
  },
  xss: {
    id: "py-reflected-xss",
    category: "reflected_cross_site_scripting",
    severity: "medium",
    title: (sink) => `Caller-controlled text reaches HTML without escaping through ${sink}`,
    summary: (origin, sink) =>
      `A value derived from ${origin} is placed into an HTML response through ${sink}, which marks it as safe markup or bypasses the template engine's escaping.`,
    impact: "Script runs in the victim's browser on this origin, with access to their session and to every action they can take.",
    remediation:
      "Let the template engine escape the value (`{{ value }}` without `|safe`), or escape it explicitly with `markupsafe.escape` before composing markup. Never wrap caller text in `Markup()`.",
    verificationPlan: "Send `<myrqen-probe>` through the parameter and confirm the response contains `&lt;myrqen-probe&gt;`.",
    taxonomy: ["CWE-79", "OWASP-A03"]
  }
};

export const RULE_IDS = [
  ...Object.values(FLOW_RULES).map((rule) => rule.id),
  "py-hardcoded-secret",
  "py-debug-mode",
  "py-insecure-cookie",
  "py-missing-authentication",
  "py-object-level-authorization"
];
