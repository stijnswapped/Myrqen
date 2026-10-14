#!/usr/bin/env python3
"""Emits cases.json for the azure-functions holdout-7 family.

Reads the source files that were written by hand and embeds the shared modules each
case needs so that every case can be analysed alone in an empty directory.
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
FAMILY = "azure-functions"
ARCH = (
    "Azure Functions for Node.js v4 programming model in TypeScript, with Azure Cosmos DB "
    "(@azure/cosmos SQL API) as the only data layer, and caller identity taken from a "
    "validated Entra ID bearer token, except on the handlers that read the "
    "platform-injected x-ms-client-principal header."
)


def text(rel: str) -> str:
    return (ROOT / rel).read_text()


PACKAGE_JSON = json.loads(text("package.json"))
SHARED = {
    "host.json": text("host.json"),
    "src/shared/auth.ts": text("src/shared/auth.ts"),
    "src/shared/cosmos.ts": text("src/shared/cosmos.ts"),
}


def case(cid, path, kind, why, route=None, **kw):
    entry = {
        "id": f"h7-{FAMILY}-{cid}",
        "family": FAMILY,
        "architecture": ARCH,
        "language": "typescript",
        "file": f"{FAMILY}/{path}",
        "scanAs": path,
        "kind": kind,
    }
    if kind == "vulnerable":
        entry["category"] = kw["category"]
        entry["cwe"] = kw["cwe"]
        entry["severityBand"] = kw["severity"]
        entry["line"] = kw["line"]
        entry["lineRange"] = kw["line_range"]
    else:
        entry["pairedWith"] = f"h7-{FAMILY}-{kw['paired_with']}"
    if route:
        entry["route"] = route
    entry["runtimeVerifiable"] = True
    entry["why"] = why
    entry["packageJson"] = PACKAGE_JSON
    entry["extraFiles"] = dict(SHARED)
    return entry


cases = [
    case(
        "permit-detail-read",
        "src/functions/permitDetail.ts",
        "vulnerable",
        "siteId comes from the query string and is used as the Cosmos partition key for the "
        "point read, and nothing afterwards compares the permit's tenantId with the caller's "
        "tid or checks a site membership, so any authenticated caller who knows a permit id "
        "and its site id reads another customer's permit.",
        route="GET /api/permits/{permitId}",
        category="partition_key_trusted_as_tenant_boundary",
        cwe="CWE-639",
        severity=["high", "critical"],
        line=74,
        line_range=[61, 90],
    ),
    case(
        "inspection-detail-read",
        "src/functions/inspectionDetail.ts",
        "safe",
        "The same item(id, partitionKey).read() shape, but resolveSiteMembership on the "
        "caller's own tid gates the read and the document's tenantId is compared with the "
        "token's tid afterwards, so the partition key is only used for addressing.",
        route="GET /api/inspections/{inspectionId}",
        paired_with="permit-detail-read",
    ),
    case(
        "permit-board-filter",
        "src/functions/permitSearch.ts",
        "vulnerable",
        "The status query parameter is concatenated into the Cosmos SQL text as a quoted "
        "literal (and sortBy into the ORDER BY clause) while the tenant filter is a bound "
        "parameter, so a caller can close the quote and neutralise the c.tenantId predicate "
        "in a cross-partition query and read other tenants' permits.",
        route="GET /api/permits",
        category="cosmos_sql_query_assembled_by_string_interpolation",
        cwe="CWE-943",
        severity=["high", "critical"],
        line=60,
        line_range=[51, 75],
    ),
    case(
        "asset-register-filter",
        "src/functions/assetSearch.ts",
        "safe",
        "Same query shape over the same containers, but status is bound as @status, the sort "
        "column is looked up in the SORTABLE_COLUMNS allowlist, and the page size is a "
        "clamped integer, so no request text reaches the query string.",
        route="GET /api/assets",
        paired_with="permit-board-filter",
    ),
    case(
        "manual-site-export",
        "src/functions/siteExportTrigger.ts",
        "vulnerable",
        "runSiteExportNow is registered with authLevel \"anonymous\" and never validates a "
        "token or checks a role, yet it takes tenantId and siteId from the request body and "
        "creates an export job (signatures included) whose download path it returns, so any "
        "caller who can reach the function app exports any tenant's permit records.",
        route="POST /api/internal/site-exports",
        category="state_changing_endpoint_with_no_caller_authentication",
        cwe="CWE-306",
        severity=["high", "critical"],
        line=115,
        line_range=[73, 118],
    ),
    case(
        "manual-compliance-report",
        "src/functions/complianceReportTrigger.ts",
        "safe",
        "Also registered authLevel \"anonymous\", but the handler calls verifyAccessToken and "
        "requireRole before writing anything and takes the tenant from the validated token "
        "rather than the body, so the missing function key grants nothing.",
        route="POST /api/internal/compliance-reports",
        paired_with="manual-site-export",
    ),
    case(
        "member-role-assignment",
        "src/functions/siteMemberRoles.ts",
        "vulnerable",
        "The admin decision and the tenant partition key both come from the base64 "
        "x-ms-client-principal header, which this app no longer has Easy Auth in front of to "
        "inject or strip it, so a caller can present their own principal claiming TenantAdmin "
        "in any tenant and rewrite that tenant's site membership roles.",
        route="POST /api/sites/{siteId}/members/{memberId}/role",
        category="platform_principal_header_trusted_for_role_decision",
        cwe="CWE-290",
        severity=["high", "critical"],
        line=47,
        line_range=[42, 68],
    ),
    case(
        "member-directory-listing",
        "src/functions/siteMemberDirectory.ts",
        "safe",
        "Decodes the same x-ms-client-principal header, but only to label the audit event; "
        "the tenant, the membership check and the role check all come from verifyAccessToken, "
        "so the unsigned header decides nothing.",
        route="GET /api/sites/{siteId}/members",
        paired_with="member-role-assignment",
    ),
    case(
        "inspection-form-sync",
        "src/functions/inspectionUpdate.ts",
        "vulnerable",
        "The client's patch object is spread wholesale over the stored inspection and written "
        "back with replace(), so a supervisor can set status to signed_off, forge signedOffBy "
        "and signedOffAt, downgrade defectSeverity, or rewrite tenantId - fields the sign-off "
        "workflow is supposed to own.",
        route="PATCH /api/inspections/{inspectionId}",
        category="client_supplied_patch_merged_into_stored_document",
        cwe="CWE-915",
        severity=["medium", "high"],
        line=57,
        line_range=[30, 64],
    ),
    case(
        "permit-form-sync",
        "src/functions/permitFieldUpdate.ts",
        "safe",
        "Same read-merge-replace shape, but the merge iterates the FIELD_PARSERS allowlist "
        "instead of the payload keys and rejects anything else with a 400, so status, "
        "approvals, tenantId and siteId cannot be reached from the request.",
        route="PATCH /api/permits/{permitId}",
        paired_with="inspection-form-sync",
    ),
    case(
        "webhook-registration",
        "src/functions/webhookRegistration.ts",
        "vulnerable",
        "callbackUrl from the request body becomes the target of a server-side fetch with no "
        "scheme, address or host-ownership check, and the response body is echoed back in the "
        "201, so a site admin can make the function app read internal endpoints - the IMDS "
        "address, private-endpoint services, the Cosmos account host - and see the answer.",
        route="POST /api/sites/{siteId}/webhooks",
        category="webhook_target_fetched_without_destination_allowlist",
        cwe="CWE-918",
        severity=["medium", "high"],
        line=75,
        line_range=[63, 82],
    ),
    case(
        "webhook-test-delivery",
        "src/functions/webhookDelivery.ts",
        "safe",
        "Fetches a callbackUrl that can also come from the request body, but only after "
        "assertDeliverableTarget requires https, rejects address literals and requires the "
        "host to sit on a domain the tenant verified by DNS, fetches with redirect \"manual\", "
        "and returns only the status code.",
        route="POST /api/sites/{siteId}/webhooks/{webhookId}/deliveries",
        paired_with="webhook-registration",
    ),
]

payload = {"family": FAMILY, "cases": cases}
(ROOT / "cases.json").write_text(json.dumps(payload, indent=2) + "\n")
print(f"cases: {len(cases)}")
print("vulnerable:", sum(1 for c in cases if c["kind"] == "vulnerable"))
print("safe:", sum(1 for c in cases if c["kind"] == "safe"))
