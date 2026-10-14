#!/usr/bin/env python3
"""Generate cases.json for the feathers-crm reference family.

extraFiles are read from the files on disk so the shipped copies of the shared
modules can never drift from the application source.
"""

import json
import os

FAMILY = "loopback-inventory"
ROOT = os.path.dirname(os.path.abspath(__file__))

ARCHITECTURE = (
    "LoopBack 4 application in TypeScript: one controller class per screen, routes declared "
    "with @get/@post/@patch decorators and parameters bound by @param.path, @param.query, "
    "@param.filter and @requestBody; data access through DefaultCrudRepository over a "
    "PostgreSQL juggler datasource, with a raw `execute` escape hatch for the two aggregate "
    "reports; authentication is @authenticate('jwt') applied either on a class or on "
    "individual methods, and the caller is injected as @inject(SecurityBindings.USER), "
    "carrying roles and the operating company every stored row belongs to."
)

PACKAGE_JSON = {
    "name": "northgate-warehouse",
    "version": "3.2.0",
    "private": True,
    "scripts": {
        "build": "lb-tsc",
        "start": "node -r source-map-support/register .",
        "migrate": "node ./dist/migrate",
    },
    "dependencies": {
        "@loopback/authentication": "^11.0.9",
        "@loopback/authentication-jwt": "^0.15.9",
        "@loopback/boot": "^7.0.9",
        "@loopback/core": "^6.1.6",
        "@loopback/repository": "^7.0.9",
        "@loopback/rest": "^14.0.9",
        "@loopback/rest-explorer": "^7.0.9",
        "@loopback/security": "^0.11.9",
        "@loopback/service-proxy": "^7.0.9",
        "loopback-connector-postgresql": "^7.1.6",
        "tslib": "^2.8.1",
    },
    "devDependencies": {
        "@loopback/build": "^11.0.8",
        "@types/node": "^22.13.0",
        "source-map-support": "^0.5.21",
        "typescript": "~5.7.3",
    },
}

TENANCY = "src/lib/tenancy.ts"
STOCK_REPO = "src/repositories/stock.repository.ts"


def read(rel_path):
    with open(os.path.join(ROOT, rel_path), "r", encoding="utf-8") as handle:
        return handle.read()


CASES = [
    # --- pair 1: a client-supplied filter reaching the repository unscoped ---
    {
        "id": "ref-loopback-inventory-stock-search-filter",
        "scanAs": "src/controllers/stock-search.controller.ts",
        "kind": "vulnerable",
        "category": "cross_company_read_via_unscoped_client_filter",
        "cwe": "CWE-639",
        "severityBand": ["high", "critical"],
        "line": 31,
        "lineRange": [24, 33],
        "extras": [TENANCY, STOCK_REPO],
        "why": (
            "`@param.filter` hands the caller's whole LoopBack filter to `repository.find` unchanged. "
            "Authentication proves the caller is a user of the product and nothing narrows the query to "
            "their company, so any token reads every company's SKUs, costs and supplier references — and "
            "the filter's own `where` can search them."
        ),
    },
    {
        "id": "ref-loopback-inventory-catalogue-search-filter",
        "scanAs": "src/controllers/catalogue-search.controller.ts",
        "kind": "safe",
        "pairedWith": "ref-loopback-inventory-stock-search-filter",
        "extras": [TENANCY, STOCK_REPO],
        "why": (
            "The same client-supplied filter for the same kind of search, passed through `scopeFilter`, "
            "which `and`-s a company clause on top of the caller's `where` so the two must both hold and "
            "a caller-sent `companyId` cannot displace it. `include` is dropped because a relation "
            "traversal is a second query the helper cannot bound, and `companyOf` throws when the caller "
            "has no company rather than returning an unnarrowed filter."
        ),
    },
    # --- pair 2: mass assignment through an administrative patch -------------
    {
        "id": "ref-loopback-inventory-account-admin-patch",
        "scanAs": "src/controllers/account-admin.controller.ts",
        "kind": "vulnerable",
        "category": "privilege_escalation_via_unfiltered_admin_patch",
        "cwe": "CWE-915",
        "severityBand": ["high", "critical"],
        "line": 40,
        "lineRange": [33, 43],
        "extras": [TENANCY, STOCK_REPO],
        "why": (
            "`@requestBody()` binds the whole account shape and the object is merged into the stored row, "
            "so a company administrator can send `{\"roles\": [\"platform-admin\"]}` and leave their own "
            "company's scope entirely, or move an account into another company by sending `companyId`. The "
            "role check gates who reaches the route, not what they may write, and the update matches on id "
            "alone so the id need not belong to the administrator's company."
        ),
    },
    {
        "id": "ref-loopback-inventory-profile-admin-patch",
        "scanAs": "src/controllers/profile-admin.controller.ts",
        "kind": "safe",
        "pairedWith": "ref-loopback-inventory-account-admin-patch",
        "extras": [TENANCY, STOCK_REPO],
        "why": (
            "Same administrative patch behind the same role check, but the payload is reduced to the two "
            "administrable fields before it reaches the database, so neither `roles` nor `companyId` can "
            "be written, and the row is additionally matched on the administrator's own company so the id "
            "has to belong to it."
        ),
    },
    # --- pair 3: caller text interpolated into a hand-written aggregate ------
    {
        "id": "ref-loopback-inventory-valuation-grouping",
        "scanAs": "src/controllers/valuation-report.controller.ts",
        "kind": "vulnerable",
        "category": "sql_injection_via_interpolated_grouping_column",
        "cwe": "CWE-89",
        "severityBand": ["critical"],
        "line": 39,
        "lineRange": [34, 43],
        "extras": [TENANCY, STOCK_REPO],
        "why": (
            "`groupBy` and `direction` arrive as query parameters and are interpolated into the statement "
            "text, while only the company id is bound. A caller controls part of the SQL, so the grouping "
            "column can carry a subquery or a `UNION` that reads any table the datasource user can see — "
            "the `WHERE company_id = $1` clause bounds the rows this statement scans, not the statement."
        ),
    },
    {
        "id": "ref-loopback-inventory-turnover-grouping",
        "scanAs": "src/controllers/turnover-report.controller.ts",
        "kind": "safe",
        "pairedWith": "ref-loopback-inventory-valuation-grouping",
        "extras": [TENANCY, STOCK_REPO],
        "why": (
            "The same two toolbar parameters for the same hand-written aggregate, but each one selects an "
            "entry from a table declared in this file, so the SQL that reaches the query is the file's and "
            "never the caller's. A value that is not a key is refused rather than defaulted, so an "
            "unexpected string cannot silently select a different column."
        ),
    },
    # --- pair 4: a write route left off the authentication decorator ---------
    {
        "id": "ref-loopback-inventory-goods-receipt-book",
        "scanAs": "src/controllers/goods-receipt.controller.ts",
        "kind": "vulnerable",
        "category": "unauthenticated_stock_write_on_undecorated_route",
        "cwe": "CWE-306",
        "severityBand": ["critical"],
        "line": 50,
        "lineRange": [45, 64],
        "extras": [TENANCY, STOCK_REPO],
        "why": (
            "The class carries no `@authenticate` because the health probe has to answer the load "
            "balancer, so each route is decorated individually — and the booking route was not. An "
            "unauthenticated POST increments on-hand quantities for any SKU in any company, and the "
            "statement matches on `sku` alone with no company clause and no caller to derive one from."
        ),
    },
    {
        "id": "ref-loopback-inventory-goods-issue-book",
        "scanAs": "src/controllers/goods-issue.controller.ts",
        "kind": "safe",
        "pairedWith": "ref-loopback-inventory-goods-receipt-book",
        "extras": [TENANCY, STOCK_REPO],
        "why": (
            "The same per-method decoration around the same deliberately open health probe, with "
            "`@authenticate('jwt')` present on the write route, and the decrement matched on the caller's "
            "company as well as the sku so a valid token still cannot reach another company's row."
        ),
    },
    # --- pair 5: a caller-named file joined onto a per-company root ----------
    {
        "id": "ref-loopback-inventory-label-download",
        "scanAs": "src/controllers/label-download.controller.ts",
        "kind": "vulnerable",
        "category": "path_traversal_in_label_download",
        "cwe": "CWE-22",
        "severityBand": ["high", "critical"],
        "line": 32,
        "lineRange": [27, 40],
        "extras": [TENANCY],
        "why": (
            "The path parameter is joined onto the company's label directory with no check, so a name "
            "containing `..` resolves outside it and is streamed to the caller. The company segment gives "
            "the appearance of isolation while the caller controls the segment after it."
        ),
    },
    {
        "id": "ref-loopback-inventory-manifest-download",
        "scanAs": "src/controllers/manifest-download.controller.ts",
        "kind": "safe",
        "pairedWith": "ref-loopback-inventory-label-download",
        "extras": [TENANCY],
        "why": (
            "The same join onto the same kind of per-company root, but the name must first match a "
            "pattern admitting a single path segment ending in `.pdf`, and `..` is refused explicitly "
            "because the character class allows a dot. Both checks run before the join."
        ),
    },
    # --- pair 6: driver error text returned to the caller -------------------
    {
        "id": "ref-loopback-inventory-stock-import-errors",
        "scanAs": "src/controllers/stock-import.controller.ts",
        "kind": "vulnerable",
        "category": "schema_disclosure_via_driver_error_message",
        "cwe": "CWE-209",
        "severityBand": ["medium", "high"],
        "line": 41,
        "lineRange": [35, 45],
        "extras": [TENANCY, STOCK_REPO],
        "why": (
            "The PostgreSQL driver's own message is interpolated into the 422 body. That message carries "
            "the failing statement, the table and column names, the constraint name and the conflicting "
            "value, so anyone able to post a malformed row can read the schema back one error at a time."
        ),
    },
    {
        "id": "ref-loopback-inventory-stock-upload-errors",
        "scanAs": "src/controllers/stock-upload.controller.ts",
        "kind": "safe",
        "pairedWith": "ref-loopback-inventory-stock-import-errors",
        "extras": [TENANCY, STOCK_REPO],
        "why": (
            "The same per-row failure reporting for the same import feature, but the response is chosen "
            "from advice keyed by the driver's SQLSTATE code, and the driver's message is logged "
            "server-side instead. The operator still learns what to fix; the caller learns nothing about "
            "the schema."
        ),
    },
]


def build():
    out = {"family": FAMILY, "cases": []}
    for case in CASES:
        entry = {
            "id": case["id"],
            "family": FAMILY,
            "architecture": ARCHITECTURE,
            "language": "typescript",
            "file": os.path.join(FAMILY, case["scanAs"]).replace(os.sep, "/"),
            "scanAs": case["scanAs"],
            "kind": case["kind"],
            "runtimeVerifiable": True,
            "why": case["why"],
            "packageJson": PACKAGE_JSON,
            "extraFiles": {extra: read(extra) for extra in case["extras"]},
        }
        if case["kind"] == "vulnerable":
            entry.update(
                {
                    "category": case["category"],
                    "cwe": case["cwe"],
                    "severityBand": case["severityBand"],
                    "line": case["line"],
                    "lineRange": case["lineRange"],
                }
            )
        else:
            entry["pairedWith"] = case["pairedWith"]
        out["cases"].append(entry)
    return out


if __name__ == "__main__":
    target = os.path.join(ROOT, "cases.json")
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(build(), handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print(f"wrote {target}: {len(CASES)} case(s)")
