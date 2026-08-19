# Finding contract

Submit one finding per root cause as JSON on stdin:

```bash
echo '{ ... }' | myrqen --json finding submit
```

The canonical schema is `schemas/finding-submission.schema.json`. The CLI assigns the
finding id, computes the deduplication fingerprint, redacts secret-shaped material,
normalizes the category, and records verification state. Do not send an `id`.

## Required fields

| field | rule |
| --- | --- |
| `title` | Specific and readable. Name the defect, not the category. |
| `category` | Snake case, for example `broken_object_level_authorization`. |
| `severity` | `critical`, `high`, `medium`, `low`, or `info` — realistic impact here. |
| `verification` | `verified`, `strong_evidence`, or `needs_review` — how well you proved it. |
| `summary` | The root cause in plain language, at least 20 characters. |
| `impact` | What an attacker gains, in this application's terms. |
| `affected` | `component`, plus any of `file`, `lineStart`, `lineEnd`, `route`, `origin`. |
| `evidence` | At least one entry; `kind` is `source`, `runtime`, `identity_differential`, `configuration`, `dependency`, or `other`. |
| `remediation` | The smallest durable fix, and the framework safeguard to prefer. |
| `verificationPlan` | The check that fails before the fix and passes after it. |

Optional: `taxonomy` (CWE or OWASP identifiers you can justify), `reproduction`,
`references`, `tags`.

## Rules that get submissions rejected

- Any extra top-level field, including `id`.
- A secret value anywhere in the payload that survives redaction.
- Missing evidence, or evidence that only restates the category.
- Severity `critical` with verification `needs_review` is downgraded to `high`, with a
  warning, because an unvalidated finding is a lead.
- Categories that are commonly over-rated (missing headers, verbose errors, an
  advisory with no reachability analysis) are capped at `medium` without runtime or
  differential evidence.

## Worked example

```json
{
  "title": "Order records are readable across accounts",
  "category": "broken_object_level_authorization",
  "severity": "high",
  "verification": "verified",
  "summary": "The order route resolves the record by identifier and returns it without checking that the record belongs to the authenticated subject.",
  "impact": "Any signed-in customer can read another customer's order, including delivery address and partial card data, by changing the identifier in the path.",
  "affected": {
    "component": "orders API",
    "route": "GET /api/orders/:id",
    "file": "src/routes/orders.ts",
    "lineStart": 42
  },
  "evidence": [
    {
      "kind": "identity_differential",
      "description": "Test identity user_a requested order 102, which belongs to user_b, and received HTTP 200 with the other account's record.",
      "location": "GET /api/orders/102"
    },
    {
      "kind": "source",
      "description": "The handler looks the order up by identifier alone; no ownership predicate is applied before the response.",
      "snippet": "const order = await db.orders.find(id);\nreturn Response.json(order);"
    }
  ],
  "remediation": "Scope the lookup to the authenticated subject, or verify ownership before serialising the record. Prefer making ownership part of the query rather than a separate check that can be forgotten.",
  "verificationPlan": "Repeat the cross-account request as user_a for an order owned by user_b and assert a 403 or 404 with no record body.",
  "reproduction": "curl -s -H 'Cookie: session=<user_a>' http://127.0.0.1:4010/api/orders/102",
  "taxonomy": ["CWE-639", "OWASP-API1"]
}
```
