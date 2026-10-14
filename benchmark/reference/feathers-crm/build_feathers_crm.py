#!/usr/bin/env python3
"""Generate cases.json for the feathers-crm reference family.

extraFiles are read from the files on disk so the shipped copies of the shared
modules can never drift from the application source.
"""

import json
import os

FAMILY = "feathers-crm"
ROOT = os.path.dirname(os.path.abspath(__file__))

ARCHITECTURE = (
    "Feathers 5 application in TypeScript: one service per resource, each a MongoDBService "
    "over @feathersjs/mongodb, with authentication and authorization expressed as `around` "
    "and `before` hooks rather than as middleware; the caller's identity is `params.user`, "
    "resolved by @feathersjs/authentication from a JWT, and `params.provider` is set by the "
    "transport ('rest' or 'socketio') and absent for in-process calls, which is what the "
    "internal-versus-external guards are written against. Two services are additionally "
    "reachable through plain Express routes mounted on the same app."
)

PACKAGE_JSON = {
    "name": "northwind-crm",
    "version": "2.6.1",
    "private": True,
    "type": "module",
    "scripts": {
        "dev": "ts-node-dev --respawn src/index.ts",
        "compile": "shx rm -rf lib/ && tsc",
        "start": "node lib/index.js",
    },
    "dependencies": {
        "@feathersjs/authentication": "^5.0.30",
        "@feathersjs/authentication-local": "^5.0.30",
        "@feathersjs/configuration": "^5.0.30",
        "@feathersjs/errors": "^5.0.30",
        "@feathersjs/express": "^5.0.30",
        "@feathersjs/feathers": "^5.0.30",
        "@feathersjs/mongodb": "^5.0.30",
        "@feathersjs/schema": "^5.0.30",
        "@feathersjs/socketio": "^5.0.30",
        "express": "^4.21.2",
        "mongodb": "^6.13.0",
        "winston": "^3.17.0",
    },
    "devDependencies": {
        "@types/express": "^4.17.21",
        "@types/node": "^22.13.0",
        "ts-node-dev": "^2.0.0",
        "typescript": "^5.7.3",
    },
}

IDENTITY = "src/hooks/identity.ts"
QUERY_SAFETY = "src/hooks/query-safety.ts"


def read(rel_path):
    with open(os.path.join(ROOT, rel_path), "r", encoding="utf-8") as handle:
        return handle.read()


CASES = [
    # --- pair 1: cross-workspace read through the adapter's own get ----------
    {
        "id": "ref-feathers-crm-contact-detail-drawer",
        "scanAs": "src/services/contacts.service.ts",
        "kind": "vulnerable",
        "category": "cross_workspace_record_read_via_unscoped_get",
        "cwe": "CWE-639",
        "severityBand": ["high", "critical"],
        "line": 58,
        "lineRange": [50, 62],
        "extras": [IDENTITY],
        "why": (
            "`contactForDrawer` hands the route's id straight to the adapter's `get`, which resolves a "
            "document by `_id` alone. The `before.find` hook narrows the *list* to the caller's territory "
            "and nothing narrows this read, so any authenticated user of the product can read any "
            "workspace's contact — name, email, phone, deal value and notes — by supplying its id."
        ),
    },
    {
        "id": "ref-feathers-crm-deal-detail-drawer",
        "scanAs": "src/services/deals.service.ts",
        "kind": "safe",
        "pairedWith": "ref-feathers-crm-contact-detail-drawer",
        "extras": [IDENTITY],
        "why": (
            "Same untrusted id for the same kind of drawer, but read through `find` with "
            "`scopeToCaller` applied, so the id is one clause of a query already pinned to the caller's "
            "workspace and territory; another workspace's id matches nothing and the handler answers 404. "
            "`scopeToCaller` throws rather than returning an unnarrowed query when the workspace or "
            "territory is missing."
        ),
    },
    # --- pair 2: mass assignment through a self-service patch ----------------
    {
        "id": "ref-feathers-crm-member-self-service-patch",
        "scanAs": "src/services/members.service.ts",
        "kind": "vulnerable",
        "category": "privilege_escalation_via_unfiltered_self_patch",
        "cwe": "CWE-915",
        "severityBand": ["high", "critical"],
        "line": 36,
        "lineRange": [30, 41],
        "extras": [IDENTITY],
        "why": (
            "The patch hook pins `context.id` to the caller, which stops one member editing another, and "
            "then passes `context.data` through untouched. A rep can therefore patch their own document "
            "with `{\"role\": \"owner\"}` — or move themselves into another workspace by sending "
            "`workspaceId` — because the adapter writes whatever fields it is given."
        ),
    },
    {
        "id": "ref-feathers-crm-profile-self-service-patch",
        "scanAs": "src/services/profile.service.ts",
        "kind": "safe",
        "pairedWith": "ref-feathers-crm-member-self-service-patch",
        "extras": [IDENTITY, QUERY_SAFETY],
        "why": (
            "Same pinned id and the same self-service patch, but the payload is reduced by `pickFields` to "
            "the three fields a member administers for themselves, so `role`, `territory` and "
            "`workspaceId` are dropped before the adapter sees them rather than being trusted not to "
            "arrive."
        ),
    },
    # --- pair 3: query operators reaching the Mongo adapter ------------------
    {
        "id": "ref-feathers-crm-saved-report-runner",
        "scanAs": "src/services/reports.service.ts",
        "kind": "vulnerable",
        "category": "query_operator_injection_via_saved_criteria",
        "cwe": "CWE-943",
        "severityBand": ["high", "critical"],
        "line": 36,
        "lineRange": [28, 39],
        "extras": [IDENTITY],
        "why": (
            "A saved report's criteria are spread into the query and handed to the Mongo adapter, which "
            "passes `$` operators through verbatim. The workspace clause bounds which documents match but "
            "not what the caller may ask: `$where` and `$function` run server-side JavaScript, and a "
            "`$regex` on an unindexed field is a denial of service."
        ),
    },
    {
        "id": "ref-feathers-crm-saved-segment-runner",
        "scanAs": "src/services/segments.service.ts",
        "kind": "safe",
        "pairedWith": "ref-feathers-crm-saved-report-runner",
        "extras": [IDENTITY, QUERY_SAFETY],
        "why": (
            "The same caller-authored criteria for the same kind of stored query, checked by "
            "`refuseUnknownOperators` against the operators this application uses before they reach the "
            "adapter. It walks nested objects and arrays and refuses rather than strips, so a segment "
            "carrying `$where` is rejected instead of quietly answering a different question."
        ),
    },
    # --- pair 4: an Express route that calls a service internally ------------
    {
        "id": "ref-feathers-crm-import-run-route",
        "scanAs": "src/services/imports.service.ts",
        "kind": "vulnerable",
        "category": "authentication_bypass_via_internal_service_call",
        "cwe": "CWE-306",
        "severityBand": ["critical"],
        "line": 45,
        "lineRange": [40, 52],
        "extras": [IDENTITY],
        "why": (
            "The `around` hook authenticates only calls that have a `provider`, which is correct on its "
            "own. The Express route then calls `create` with no params at all, so `provider` is undefined "
            "and the hook concludes the caller is the in-process scheduler: an unauthenticated POST to "
            "/imports/run creates an import job for whatever `workspaceId` the body names."
        ),
    },
    {
        "id": "ref-feathers-crm-export-run-route",
        "scanAs": "src/services/exports.service.ts",
        "kind": "safe",
        "pairedWith": "ref-feathers-crm-import-run-route",
        "extras": [IDENTITY],
        "why": (
            "The same provider-gated hook behind the same kind of Express route, but the route forwards "
            "`provider: 'rest'` and the request's bearer token, so the call is treated as what it is — one "
            "from outside — and authenticated. The workspace is then taken from the resolved user rather "
            "than from the body."
        ),
    },
    # --- pair 5: a caller-named file joined onto a storage root --------------
    {
        "id": "ref-feathers-crm-attachment-stream",
        "scanAs": "src/services/attachments.service.ts",
        "kind": "vulnerable",
        "category": "path_traversal_in_attachment_stream",
        "cwe": "CWE-22",
        "severityBand": ["high", "critical"],
        "line": 44,
        "lineRange": [38, 48],
        "extras": [IDENTITY],
        "why": (
            "The file name is joined onto the workspace's attachment directory with no check, so "
            "`../../etc/passwd` — or a name climbing into another workspace's directory — resolves outside "
            "the intended root and is streamed back. The workspace segment gives the appearance of "
            "isolation while the caller controls the segment after it."
        ),
    },
    {
        "id": "ref-feathers-crm-document-stream",
        "scanAs": "src/services/documents.service.ts",
        "kind": "safe",
        "pairedWith": "ref-feathers-crm-attachment-stream",
        "extras": [IDENTITY],
        "why": (
            "Same join onto the same kind of per-workspace root, but the name must first match a pattern "
            "admitting a single path segment, and `..` is refused explicitly because that character class "
            "allows a dot. Both checks run before the join, so no name reaching `path.join` can climb out "
            "of the workspace directory."
        ),
    },
    # --- pair 6: credential columns loaded into a joined view ----------------
    {
        "id": "ref-feathers-crm-audit-timeline-actor-join",
        "scanAs": "src/services/audit.service.ts",
        "kind": "vulnerable",
        "category": "credential_material_in_joined_response",
        "cwe": "CWE-200",
        "severityBand": ["high"],
        "line": 52,
        "lineRange": [46, 56],
        "extras": [IDENTITY],
        "why": (
            "Each audit entry is joined to its actor with a bare `members.get`, which loads the whole "
            "document, and the result is spread into the response. The members document holds the bcrypt "
            "hash and the live password-reset token, so both are serialised to every member who can open "
            "the workspace's audit screen. `protect('password')` on the members service does not apply: "
            "this is an internal call, and it is the audit service that serialises the result."
        ),
    },
    {
        "id": "ref-feathers-crm-activity-timeline-actor-join",
        "scanAs": "src/services/activity.service.ts",
        "kind": "safe",
        "pairedWith": "ref-feathers-crm-audit-timeline-actor-join",
        "extras": [IDENTITY],
        "why": (
            "The same per-entry join for the same kind of timeline, but the adapter is asked for the three "
            "fields the view renders through `$select`, so the credential columns are never loaded. A "
            "later change to the response shape cannot leak what was not read."
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
