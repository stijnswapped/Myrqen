#!/usr/bin/env python3
"""Assemble cases.json for the strapi-cms holdout-7 family."""

import json
import os

FAMILY = "strapi-cms"
FAMILY_DIR = os.path.dirname(os.path.abspath(__file__))
EXTRA_ROOT = (
    "/private/tmp/claude-501/-Users-stijn-thuis-myrqen/"
    "6843b007-36d3-4403-9148-cf4c0af1e2c8/scratchpad/strapi-cms-extra"
)

ARCHITECTURE = (
    "Strapi 5 content-API application in TypeScript: content-type controllers, services "
    "and routers under src/api/, the Document Service API over Postgres as the data layer "
    "(with strapi.db.query and a strapi.db.connection.raw escape hatch), and the caller's "
    "identity coming from the Users & Permissions plugin's JWT on ctx.state.user (API "
    "tokens on ctx.state.auth), with the newsroom tenant resolved from the user's "
    "organisation relation."
)

PACKAGE_JSON = {
    "name": "northbeam-newsroom",
    "version": "1.7.2",
    "private": True,
    "description": "Northbeam newsroom CMS and reader portal",
    "scripts": {
        "build": "strapi build",
        "console": "strapi console",
        "deploy": "strapi deploy",
        "develop": "strapi develop",
        "start": "strapi start",
        "strapi": "strapi",
    },
    "dependencies": {
        "@strapi/plugin-cloud": "5.6.0",
        "@strapi/plugin-users-permissions": "5.6.0",
        "@strapi/strapi": "5.6.0",
        "pg": "8.12.0",
        "react": "^18.3.1",
        "react-dom": "^18.3.1",
        "react-router-dom": "^6.26.2",
        "styled-components": "^6.1.13",
    },
    "devDependencies": {
        "@types/node": "^20.14.10",
        "typescript": "^5.5.4",
    },
    "engines": {"node": ">=18.0.0 <=22.x.x", "npm": ">=6.0.0"},
}


def extra(*paths):
    out = {}
    for rel in paths:
        with open(os.path.join(EXTRA_ROOT, rel), "r", encoding="utf-8") as handle:
            out[rel] = handle.read()
    return out


ACCESS = "src/utils/access.ts"
AUTH_POLICY = "src/policies/is-authenticated.ts"
DESK_POLICY = "src/policies/is-editorial-staff.ts"
DB_CONFIG = "config/database.ts"

CASES = [
    # ------------------------------------------------------------------ pair 1
    {
        "id": "h7-strapi-cms-invoice-portal-view",
        "file": "src/api/invoice/controllers/invoice.ts",
        "kind": "vulnerable",
        "category": "cross_tenant_record_access_by_document_id",
        "cwe": "CWE-639",
        "severityBand": ["medium", "high"],
        "line": 70,
        "lineRange": [63, 88],
        "route": "GET /invoices/:documentId/portal",
        "why": (
            "portalView takes documentId straight from ctx.params and loads the invoice with "
            "strapi.documents(...).findOne without ever comparing the invoice's subscriber "
            "organisation to the caller's membership.organisationId, so any signed-in reader "
            "can read another newsroom's invoice - amounts, billing reference and the "
            "subscriber's email - by swapping the documentId in the URL. The find() handler "
            "above shows the scoping this handler is missing, and the route's "
            "global::is-authenticated policy only proves there is a session."
        ),
        "extraFiles": extra(ACCESS, "src/api/invoice/routes/invoice.ts", AUTH_POLICY),
    },
    {
        "id": "h7-strapi-cms-statement-portal-view",
        "file": "src/api/statement/controllers/statement.ts",
        "kind": "safe",
        "route": "GET /statements/:documentId",
        "pairedWith": "h7-strapi-cms-invoice-portal-view",
        "why": (
            "Same operation - fetch a billing document addressed by the documentId in the URL - "
            "but the lookup is a findMany whose filters carry both the documentId and "
            "organisation: { documentId: membership.organisationId }, so the ownership check is "
            "the query. A statement from another newsroom returns an empty array and the "
            "handler answers 404."
        ),
        "extraFiles": extra(ACCESS, "src/api/statement/routes/statement.ts", AUTH_POLICY),
    },
    # ------------------------------------------------------------------ pair 2
    {
        "id": "h7-strapi-cms-subscriber-self-update",
        "file": "src/api/subscriber/controllers/subscriber.ts",
        "kind": "vulnerable",
        "category": "mass_assignment_from_request_body",
        "cwe": "CWE-915",
        "severityBand": ["high", "critical"],
        "line": 70,
        "lineRange": [61, 78],
        "route": "PUT /subscribers/me",
        "why": (
            "updateMe spreads the whole ctx.request.body.data into the Document Service update "
            "call, so a reader can send plan, entitlements, internalNotes or organisation along "
            "with their display name and have them persisted. The comment is wrong about why "
            "that is safe: `private: true` in subscriber/schema.json only strips those "
            "attributes from responses, it does not filter them out of an inbound payload, and "
            "this handler never calls sanitizeInput."
        ),
        "extraFiles": extra(
            ACCESS,
            "src/api/subscriber/routes/subscriber.ts",
            "src/api/subscriber/content-types/subscriber/schema.json",
            AUTH_POLICY,
        ),
    },
    {
        "id": "h7-strapi-cms-reader-preference-self-update",
        "file": "src/api/reader-preference/controllers/reader-preference.ts",
        "kind": "safe",
        "route": "PUT /reader-preferences/me",
        "pairedWith": "h7-strapi-cms-subscriber-self-update",
        "why": (
            "The same self-service PUT against the same data layer, but the body is never handed "
            "to the document service: the handler copies exactly the three fields the form owns "
            "into a fresh patch object, type-checking each and rejecting values outside the "
            "enumerations, so no extra attribute in the payload can reach update()."
        ),
        "extraFiles": extra(ACCESS, "src/api/reader-preference/routes/reader-preference.ts", AUTH_POLICY),
    },
    # ------------------------------------------------------------------ pair 3
    {
        "id": "h7-strapi-cms-archive-relevance-search",
        "file": "src/api/article/services/article.ts",
        "kind": "vulnerable",
        "category": "sql_injection_via_interpolated_raw_query",
        "cwe": "CWE-89",
        "severityBand": ["high", "critical"],
        "line": 47,
        "lineRange": [31, 52],
        "route": "GET /articles/archive-search",
        "why": (
            "searchArchive builds the statement by template interpolation and hands it to "
            "strapi.db.connection.raw with no bindings: the search term reaches the ILIKE "
            "literals and query.sortBy is pasted in as an ORDER BY identifier, both of them "
            "arriving unmodified from ctx.query.q and ctx.query.sort in the archive-search "
            "controller. Quoting a value in the template is not a binding, so a term containing "
            "a quote breaks out of the literal and the whole database is reachable."
        ),
        "extraFiles": extra(
            ACCESS,
            "src/api/article/controllers/archive-search.ts",
            "src/api/article/routes/archive-search.ts",
            DB_CONFIG,
        ),
    },
    {
        "id": "h7-strapi-cms-tag-suggest",
        "file": "src/api/tag/services/tag.ts",
        "kind": "safe",
        "route": "GET /tags/suggest",
        "pairedWith": "h7-strapi-cms-archive-relevance-search",
        "why": (
            "The same knex escape hatch on the same connection with a caller-supplied term and "
            "sort, but every value travels as a positional binding and the only interpolated "
            "fragments are a column looked up in the SORTABLE_COLUMNS allowlist and a direction "
            "narrowed to asc/desc by a ternary, so nothing from the request becomes SQL text."
        ),
        "extraFiles": extra(
            ACCESS,
            "src/api/tag/controllers/tag-suggest.ts",
            "src/api/tag/routes/tag.ts",
            DB_CONFIG,
        ),
    },
    # ------------------------------------------------------------------ pair 4
    {
        "id": "h7-strapi-cms-article-retraction",
        "file": "src/api/article/controllers/moderation.ts",
        "kind": "vulnerable",
        "category": "missing_authorization_on_content_state_change",
        "cwe": "CWE-862",
        "severityBand": ["high", "critical"],
        "line": 51,
        "lineRange": [23, 62],
        "route": "POST /articles/:documentId/retract",
        "why": (
            "retract establishes only that some caller exists - any users-permissions JWT, or "
            "any full-access API token - and then unpublishes and rewrites any article by the "
            "documentId in the URL. The comment says the desk routes sit in the editorial policy "
            "group, but src/api/article/routes/moderation.ts ships with policies: [] and the "
            "editorial policy commented out, so neither the route nor the handler checks the "
            "caller's role or newsroom: a reader can take any newsroom's story off the site."
        ),
        "extraFiles": extra(ACCESS, "src/api/article/routes/moderation.ts", DESK_POLICY),
    },
    {
        "id": "h7-strapi-cms-article-embargo-hold",
        "file": "src/api/article/controllers/embargo.ts",
        "kind": "safe",
        "route": "POST /articles/:documentId/embargo",
        "pairedWith": "h7-strapi-cms-article-retraction",
        "why": (
            "The same kind of privileged state change - unpublish plus update by documentId - "
            "behind the same route group with policies: [], but here the handler does the work "
            "the policy would have done: it resolves the membership, refuses anyone who is not "
            "editorial staff, and compares the loaded article's organisation.documentId with the "
            "caller's organisationId before mutating."
        ),
        "extraFiles": extra(ACCESS, "src/api/article/routes/embargo.ts", DESK_POLICY),
    },
    # ------------------------------------------------------------------ pair 5
    {
        "id": "h7-strapi-cms-contributor-byline",
        "file": "src/api/contributor/controllers/contributor.ts",
        "kind": "vulnerable",
        "category": "over_populated_relation_exposes_account_secrets",
        "cwe": "CWE-200",
        "severityBand": ["high", "critical"],
        "line": 31,
        "lineRange": [26, 50],
        "route": "GET /contributors/:documentId/profile",
        "why": (
            "publicProfile populates the `account` relation - a plugin::users-permissions.user - "
            "without a `fields` list and returns the document straight on ctx.body, so every "
            "scalar on the user row leaves the server: email, provider, resetPasswordToken and "
            "confirmationToken among them. The comment is wrong that private attributes are "
            "stripped: that only happens in the core controller's sanitizeOutput, which this "
            "handler never calls, and the route is auth: false with a five-minute public "
            "Cache-Control, so the tokens land in the CDN."
        ),
        "extraFiles": extra(
            "src/api/contributor/routes/contributor.ts",
            "src/api/contributor/content-types/contributor/schema.json",
        ),
    },
    {
        "id": "h7-strapi-cms-contributor-directory",
        "file": "src/api/contributor/controllers/contributor-directory.ts",
        "kind": "safe",
        "route": "GET /contributors/directory",
        "pairedWith": "h7-strapi-cms-contributor-byline",
        "why": (
            "The same unauthenticated, CDN-cached endpoint populating the same "
            "users-permissions relation, but the populate names fields: [\"username\"] on the "
            "account so nothing else on the user row is selected, and the result still goes "
            "through this.sanitizeOutput before it is written to ctx.body."
        ),
        "extraFiles": extra(
            "src/api/contributor/routes/contributor-directory.ts",
            "src/api/contributor/content-types/contributor/schema.json",
        ),
    },
    # ------------------------------------------------------------------ pair 6
    {
        "id": "h7-strapi-cms-press-kit-download",
        "file": "src/api/press-kit/controllers/press-kit.ts",
        "kind": "vulnerable",
        "category": "path_traversal_in_download_handler",
        "cwe": "CWE-22",
        "severityBand": ["high", "critical"],
        "line": 53,
        "lineRange": [32, 71],
        "route": "GET /press-kits/:documentId/download",
        "why": (
            "The `file` query parameter is joined onto PRESS_KIT_ROOT and the result is opened "
            "with fs.createReadStream, with no normalisation and no check that the resolved path "
            "is still inside the root. The comment reasons about `folder`, which is generated, "
            "and never about `requested`, which is not: ?file=../../../.env on this "
            "unauthenticated route streams any file the Node process can read."
        ),
        "extraFiles": extra("src/api/press-kit/routes/press-kit.ts"),
    },
    {
        "id": "h7-strapi-cms-brand-asset-download",
        "file": "src/api/press-kit/controllers/brand-asset.ts",
        "kind": "safe",
        "route": "GET /press-kits/:documentId/assets/:assetId",
        "pairedWith": "h7-strapi-cms-press-kit-download",
        "why": (
            "The same unauthenticated fs.createReadStream download, but the file name never "
            "comes off the request: the asset is looked up by documentId under its press kit and "
            "the stored storageKey is used, then resolveInsideRoot path.resolves it and refuses "
            "anything that does not start with the asset root, so a crafted parameter cannot "
            "select a file outside it."
        ),
        "extraFiles": extra("src/api/press-kit/routes/brand-asset.ts"),
    },
    # ------------------------------------------------------------------ pair 7
    {
        "id": "h7-strapi-cms-feed-preview",
        "file": "src/api/syndication-feed/controllers/syndication-feed.ts",
        "kind": "vulnerable",
        "category": "server_side_request_forgery_in_feed_preview",
        "cwe": "CWE-918",
        "severityBand": ["medium", "high"],
        "line": 47,
        "lineRange": [34, 70],
        "route": "POST /syndication-feeds/preview",
        "why": (
            "preview fetches whatever URL the request body carries - only checking that it "
            "parses - and reflects the status, content type and first four kilobytes of the "
            "response back to the caller, with caller-supplied headers merged in. An editor, or "
            "anyone who has taken an editorial session, can point it at "
            "http://169.254.169.254/latest/meta-data/ or an internal admin service and read the "
            "answer; being behind an editorial role check limits who can do it, not what the "
            "server will connect to."
        ),
        "extraFiles": extra(ACCESS, "src/api/syndication-feed/routes/syndication-feed.ts", AUTH_POLICY),
    },
    {
        "id": "h7-strapi-cms-partner-mirror-preview",
        "file": "src/api/syndication-feed/controllers/partner-mirror.ts",
        "kind": "safe",
        "route": "POST /syndication-feeds/mirror",
        "pairedWith": "h7-strapi-cms-feed-preview",
        "why": (
            "The same server-side fetch of a body-supplied URL with the response reflected back, "
            "but the URL must parse as https and its hostname must be present in the "
            "PARTNER_HOSTS set by exact match before anything is opened, redirects are not "
            "followed (redirect: \"manual\") and no caller-supplied headers are forwarded, so "
            "the reachable set is three partner hosts."
        ),
        "extraFiles": extra(ACCESS, "src/api/syndication-feed/routes/partner-mirror.ts", AUTH_POLICY),
    },
]


def build():
    cases = []
    for raw in CASES:
        scan_as = raw["file"]
        case = {
            "id": raw["id"],
            "family": FAMILY,
            "architecture": ARCHITECTURE,
            "language": "typescript",
            "file": f"{FAMILY}/{scan_as}",
            "scanAs": scan_as,
            "kind": raw["kind"],
        }
        if raw["kind"] == "vulnerable":
            case["category"] = raw["category"]
            case["cwe"] = raw["cwe"]
            case["severityBand"] = raw["severityBand"]
            case["line"] = raw["line"]
            case["lineRange"] = raw["lineRange"]
        else:
            case["pairedWith"] = raw["pairedWith"]
        if "route" in raw:
            case["route"] = raw["route"]
        case["runtimeVerifiable"] = True
        case["why"] = raw["why"]
        case["packageJson"] = PACKAGE_JSON
        if "extraFiles" in raw:
            case["extraFiles"] = raw["extraFiles"]
        cases.append(case)

    # sanity: every referenced source file exists, ids and scanAs unique,
    # line sits inside lineRange, pairs point at vulnerable ids in this family.
    seen_ids = set()
    seen_scan = set()
    vulnerable_ids = {c["id"] for c in cases if c["kind"] == "vulnerable"}
    for case in cases:
        assert case["id"] not in seen_ids, case["id"]
        seen_ids.add(case["id"])
        assert case["scanAs"] not in seen_scan, case["scanAs"]
        seen_scan.add(case["scanAs"])
        on_disk = os.path.join(FAMILY_DIR, case["scanAs"])
        assert os.path.isfile(on_disk), on_disk
        if case["kind"] == "vulnerable":
            low, high = case["lineRange"]
            total = sum(1 for _ in open(on_disk, encoding="utf-8"))
            assert low <= case["line"] <= high, case["id"]
            assert 1 <= low and high <= total, (case["id"], high, total)
        else:
            assert case["pairedWith"] in vulnerable_ids, case["id"]
        if "route" in case:
            path = case["route"].split(" ", 1)[1]
            haystack = open(on_disk, encoding="utf-8").read()
            haystack += "".join(case.get("extraFiles", {}).values())
            assert path in haystack, (case["id"], path)

    payload = {"family": FAMILY, "cases": cases}
    out = os.path.join(FAMILY_DIR, "cases.json")
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print(
        f"wrote {out}: {len(cases)} cases "
        f"({len(vulnerable_ids)} vulnerable, {len(cases) - len(vulnerable_ids)} safe)"
    )


if __name__ == "__main__":
    build()
