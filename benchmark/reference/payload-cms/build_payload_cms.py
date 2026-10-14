#!/usr/bin/env python3
"""Generate cases.json for the payload-cms reference family.

extraFiles are read from the files on disk so the shipped copies of the shared
modules can never drift from the application source.
"""

import json
import os

FAMILY = "payload-cms"
ROOT = os.path.dirname(os.path.abspath(__file__))

ARCHITECTURE = (
    "Payload CMS 3 application in TypeScript: collection configs with their own `endpoints` "
    "arrays plus root endpoints, all assembled in src/payload.config.ts; Payload's Local API "
    "over MongoDB (@payloadcms/db-mongodb) is the only data layer; the caller's identity is "
    "`req.user`, populated by the `users` auth collection and carrying a role and a tenant "
    "relationship."
)

PACKAGE_JSON = {
    "name": "orderbook-portal",
    "version": "1.4.2",
    "private": True,
    "type": "module",
    "scripts": {
        "dev": "next dev",
        "build": "next build",
        "generate:types": "payload generate:types",
    },
    "dependencies": {
        "@payloadcms/db-mongodb": "3.33.0",
        "@payloadcms/next": "3.33.0",
        "@payloadcms/richtext-lexical": "3.33.0",
        "@payloadcms/ui": "3.33.0",
        "graphql": "^16.9.0",
        "next": "15.2.4",
        "payload": "3.33.0",
        "react": "19.0.0",
        "react-dom": "19.0.0",
    },
    "devDependencies": {
        "@types/node": "^22.13.0",
        "@types/react": "19.0.0",
        "typescript": "5.7.3",
    },
}

TENANT_SCOPE = "src/lib/tenant-scope.ts"
ATTACHMENT_STORAGE = "src/lib/attachment-storage.ts"
CONFIG = "src/payload.config.ts"


def read(rel_path):
    with open(os.path.join(ROOT, rel_path), "r", encoding="utf-8") as handle:
        return handle.read()


CASES = [
    # --- pair 1: cross-tenant object read by id -----------------------------
    {
        "id": "ref-payload-cms-purchase-order-approval-trail",
        "scanAs": "src/collections/PurchaseOrders.ts",
        "kind": "vulnerable",
        "category": "cross_tenant_object_read_via_unscoped_id_lookup",
        "cwe": "CWE-639",
        "severityBand": ["high", "critical"],
        "line": 185,
        "lineRange": [172, 203],
        "extras": [TENANT_SCOPE],
        "why": (
            "The `:id` route parameter is handed to `payload.findByID` with `overrideAccess: true`, "
            "which switches off the very `access.read` filter the comment above it relies on, so any "
            "authenticated caller — a buyer in another organisation, or an external supplier user — can "
            "read any purchase order's reference, status, supplier and approval trail by guessing or "
            "replaying an id."
        ),
    },
    {
        "id": "ref-payload-cms-invoice-payment-timeline",
        "scanAs": "src/collections/Invoices.ts",
        "kind": "safe",
        "pairedWith": "ref-payload-cms-purchase-order-approval-trail",
        "extras": [TENANT_SCOPE],
        "why": (
            "Same untrusted `:id` and the same `overrideAccess: true` read, but the id is only one clause "
            "of a `where` whose other clause is `ownershipClause(user)`, pinning the query to the caller's "
            "`tenant` (or `supplierCode` for supplier users), so another organisation's invoice id matches "
            "nothing and the handler answers 404. `ownershipClause` throws rather than returning an empty "
            "clause when ownership cannot be established."
        ),
    },
    # --- pair 2: collection-level read access -------------------------------
    {
        "id": "ref-payload-cms-payout-account-collection-read",
        "scanAs": "src/collections/PayoutAccounts.ts",
        "kind": "vulnerable",
        "category": "unauthenticated_read_access_on_sensitive_collection",
        "cwe": "CWE-862",
        "severityBand": ["high", "critical"],
        "line": 25,
        "lineRange": [20, 29],
        "extras": [TENANT_SCOPE],
        "why": (
            "`access.read` on the payout-accounts collection returns `true` unconditionally, so the "
            "collection's own REST and GraphQL surface hands the IBAN, BIC, mandate reference and SEPA "
            "creditor id of every organisation to any caller, including an unauthenticated one. The comment "
            "assumes the admin panel's login is the gate, but the collection API is reachable without it."
        ),
    },
    {
        "id": "ref-payload-cms-tenant-scope-access-helpers",
        "scanAs": "src/lib/tenant-scope.ts",
        "kind": "safe",
        "pairedWith": "ref-payload-cms-payout-account-collection-read",
        "extras": [],
        "why": (
            "The shared access helpers deny anonymous callers outright and otherwise return a `Where` that "
            "pins every read and write to the caller's own tenant; the only `return true` in them is reached "
            "solely on the `platform-admin` role, so the truthy return is a role decision rather than an open "
            "collection."
        ),
    },
    # --- pair 3: mass assignment through a self-service update ---------------
    {
        "id": "ref-payload-cms-account-profile-patch",
        "scanAs": "src/collections/Users.ts",
        "kind": "vulnerable",
        "category": "privilege_escalation_via_unfiltered_profile_update",
        "cwe": "CWE-915",
        "severityBand": ["high", "critical"],
        "line": 196,
        "lineRange": [171, 201],
        "extras": [TENANT_SCOPE],
        "why": (
            "The PATCH /me/profile handler spreads the entire request body into `payload.update` with "
            "`overrideAccess: true`, and `overrideAccess` skips field-level access control as well as "
            "collection access, so a caller can include `role: 'platform-admin'`, another `tenant` id or a "
            "`supplierCode` in the body and rewrite their own privileges — the field-level `access.update` "
            "guards the comment relies on never run."
        ),
    },
    {
        "id": "ref-payload-cms-tenant-billing-profile-patch",
        "scanAs": "src/collections/Tenants.ts",
        "kind": "safe",
        "pairedWith": "ref-payload-cms-account-profile-patch",
        "extras": [TENANT_SCOPE],
        "why": (
            "The same `payload.update` with `overrideAccess: true` on a body-derived object, but the data is "
            "assembled by copying only the four names in `EDITABLE_BILLING_FIELDS` and validating each one, so "
            "`apiCredentials`, `payoutAccount`, `slug` and `suspendedAt` in the body are never read; the target "
            "id is also compared against the caller's own tenant before the write."
        ),
    },
    # --- pair 4: operator injection into a Payload where clause -------------
    {
        "id": "ref-payload-cms-dispatch-order-tracking",
        "scanAs": "src/endpoints/order-tracking.ts",
        "kind": "vulnerable",
        "category": "query_operator_injection_via_untrusted_filter_value",
        "cwe": "CWE-943",
        "severityBand": ["medium", "high"],
        "line": 40,
        "lineRange": [29, 44],
        "route": "POST /api/order-tracking",
        "extras": [TENANT_SCOPE, CONFIG],
        "why": (
            "`body.reference` is dropped into the `where` clause as the whole field condition instead of as the "
            "value of an operator, so posting `{\"reference\": {\"not_equals\": \"__none__\"}}` turns the "
            "`overrideAccess: true` find into a dump of up to twenty arbitrary purchase orders — references, "
            "statuses, supplier names and delivery dates from every organisation — on an endpoint that has no "
            "session at all."
        ),
    },
    {
        "id": "ref-payload-cms-invoice-reference-lookup",
        "scanAs": "src/endpoints/invoice-reference-lookup.ts",
        "kind": "safe",
        "pairedWith": "ref-payload-cms-dispatch-order-tracking",
        "route": "POST /api/invoice-lookup",
        "extras": [TENANT_SCOPE, CONFIG],
        "why": (
            "The same unauthenticated `overrideAccess: true` lookup by reference, but the submitted value is "
            "rejected unless `typeof` it is a string matching `/^INV-[0-9A-Z]{10}$/`, and it is then placed as "
            "the value of an explicit `equals` operator, so a caller can never substitute a Payload operator "
            "object for the value."
        ),
    },
    # --- pair 5: relation depth and response shaping ------------------------
    {
        "id": "ref-payload-cms-invoice-statement-header",
        "scanAs": "src/endpoints/invoice-statements.ts",
        "kind": "vulnerable",
        "category": "sensitive_related_fields_exposed_by_verbatim_document_response",
        "cwe": "CWE-201",
        "severityBand": ["medium", "high"],
        "line": 77,
        "lineRange": [70, 89],
        "route": "GET /api/statements/:invoiceId",
        "extras": [TENANT_SCOPE, CONFIG],
        "why": (
            "The invoice is read with `depth: 2`, which populates the invoice's `tenant` and then that tenant's "
            "`payoutAccount`, and the document is then serialised into the response verbatim — so a supplier "
            "user opening their own statement also receives the buying organisation's IBAN, BIC and mandate "
            "reference along with `apiCredentials.webhookSigningSecret`. `overrideAccess: true` bypasses the "
            "field-level read access the comment counts on to hold the secret back."
        ),
    },
    {
        "id": "ref-payload-cms-supplier-order-feed",
        "scanAs": "src/endpoints/order-feed.ts",
        "kind": "safe",
        "pairedWith": "ref-payload-cms-invoice-statement-header",
        "route": "GET /api/order-feed",
        "extras": [TENANT_SCOPE, CONFIG],
        "why": (
            "The same `overrideAccess: true` list read on a tenant-owned collection, but `depth: 0` plus the "
            "`select` allow-list means no relation is followed at all, and each document is mapped into an "
            "explicit feed item before it is returned, so nothing hanging off the organisation can reach the "
            "caller even if a field is added to it later."
        ),
    },
    # --- pair 6: filesystem path handling -----------------------------------
    {
        "id": "ref-payload-cms-attachment-download",
        "scanAs": "src/endpoints/attachment-download.ts",
        "kind": "vulnerable",
        "category": "path_traversal_in_attachment_download",
        "cwe": "CWE-22",
        "severityBand": ["high", "critical"],
        "line": 32,
        "lineRange": [24, 48],
        "route": "GET /api/attachments/:filename/download",
        "extras": [TENANT_SCOPE, ATTACHMENT_STORAGE, CONFIG],
        "why": (
            "The `:filename` route parameter goes straight into `path.join(ATTACHMENT_ROOT, tenantId, filename)` "
            "with no containment check, so a value like `../<other-tenant-id>/statement.pdf` or "
            "`../../../etc/passwd` escapes both the organisation's folder and the attachment root, and whatever "
            "the join resolves to is streamed back to the caller."
        ),
    },
    {
        "id": "ref-payload-cms-report-export-download",
        "scanAs": "src/endpoints/report-export.ts",
        "kind": "safe",
        "pairedWith": "ref-payload-cms-attachment-download",
        "route": "GET /api/exports/:filename/download",
        "extras": [TENANT_SCOPE, ATTACHMENT_STORAGE, CONFIG],
        "why": (
            "The same route parameter reaches the same stat-and-stream, but the name must first match "
            "`/^[a-z0-9][a-z0-9._-]{0,119}$/i` — a character class that excludes both path separators — `..` is "
            "rejected explicitly, and `resolveWithinTenantStore` re-resolves the name against the organisation's "
            "own folder and throws when the result lands outside it."
        ),
    },
]


def build():
    out = {"family": FAMILY, "cases": []}

    for spec in CASES:
        scan_as = spec["scanAs"]
        case = {
            "id": spec["id"],
            "family": FAMILY,
            "architecture": ARCHITECTURE,
            "language": "typescript",
            "file": "%s/%s" % (FAMILY, scan_as),
            "scanAs": scan_as,
            "kind": spec["kind"],
        }

        if spec["kind"] == "vulnerable":
            case["category"] = spec["category"]
            case["cwe"] = spec["cwe"]
            case["severityBand"] = spec["severityBand"]
            case["line"] = spec["line"]
            case["lineRange"] = spec["lineRange"]
        else:
            case["pairedWith"] = spec["pairedWith"]

        if "route" in spec:
            case["route"] = spec["route"]

        case["runtimeVerifiable"] = True
        case["why"] = spec["why"]
        case["packageJson"] = PACKAGE_JSON

        extras = {path: read(path) for path in spec["extras"] if path != scan_as}
        if extras:
            case["extraFiles"] = extras

        out["cases"].append(case)

    with open(os.path.join(ROOT, "cases.json"), "w", encoding="utf-8") as handle:
        json.dump(out, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    return out


if __name__ == "__main__":
    result = build()
    vulnerable = [c for c in result["cases"] if c["kind"] == "vulnerable"]
    safe = [c for c in result["cases"] if c["kind"] == "safe"]
    print("cases: %d (%d vulnerable, %d safe)" % (len(result["cases"]), len(vulnerable), len(safe)))
    for c in vulnerable:
        print("  %-30s %s  line %d in %s" % (c["cwe"], c["category"], c["line"], c["scanAs"]))
    for c in safe:
        print("  safe %-52s -> %s" % (c["scanAs"], c["pairedWith"]))
