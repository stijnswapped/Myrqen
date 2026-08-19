# Secrets and data handling

## Local secrets

Myrqen may need test credentials/API keys to exercise a project's own API. Values stay local and are not included raw in reports, logs, analytics, progress, crash reports, or support bundles.

Represent a secret in report context as:
- type/label if known;
- source location if safe;
- stable local fingerprint (one-way HMAC using local-only key preferred over bare hash for low-entropy values);
- last characters only when product security review explicitly approves.

## Redaction

Run redaction before serialization to any cloud-bound contract, not only in UI rendering. Layer defenses:
1. typed schemas exclude secret fields;
2. scanner findings mark sensitive spans;
3. deterministic secret-set matcher from known local credentials;
4. heuristic token detectors;
5. final outbound scrubber;
6. canary-secret tests.

## Reports

Cloud may store the complete report including relevant code snippets/evidence necessary to explain a finding. It must not store the full repository. A report must not include raw secret values even if those values were central to a finding.

## Operational logs

Structured logs use request IDs, account/workspace/project/report IDs, error codes, versions, timing, and safe dimensions. Never log authorization headers, passwords, device tokens, share passwords, raw report bodies, code, or raw HTTP traffic.

## Crash reporting

POC should prefer local/first-party sanitized errors. If third-party crash telemetry is added later, treat it as a new data processor and perform privacy/security review before enabling.

## Retention

Free synced report data expires after 21 days. Analytics and operational/audit retention are separate and must have documented periods/purposes. Report deletion must delete object data and derived content rather than only hiding the row.
