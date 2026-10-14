#!/usr/bin/env python3
"""Assemble cases.json for the grpc-service reference family.

Line numbers and extraFiles are derived from the files on disk so the ground
truth cannot drift away from the sources.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
FAMILY = "grpc-service"

ARCHITECTURE = (
    "A gRPC service on @grpc/grpc-js 1.12 (depot.v1.DepotService, defined in "
    "proto/depot/v1/depot.proto and loaded with @grpc/proto-loader), PostgreSQL "
    "reached only through the porsager `postgres` client, with the caller's identity "
    "taken from the bearer token in the gRPC `authorization` metadata header."
)

PACKAGE_JSON = {
    "name": "depot-service",
    "version": "4.2.1",
    "private": True,
    "type": "module",
    "dependencies": {
        "@grpc/grpc-js": "^1.12.5",
        "@grpc/proto-loader": "^0.7.13",
        "jsonwebtoken": "^9.0.2",
        "postgres": "^3.4.5",
    },
    "devDependencies": {
        "@types/jsonwebtoken": "^9.0.7",
        "@types/node": "^22.10.2",
        "typescript": "^5.7.2",
    },
}

PROTO = "proto/depot/v1/depot.proto"
DB = "src/lib/db.ts"
AUTH = "src/lib/auth.ts"

HANDLER_SUPPORT = [DB, AUTH, PROTO]
STREAM_SUPPORT = [DB, PROTO]


def read(rel):
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as fh:
        return fh.read()


def line_of(rel, needle, occurrence=1):
    hits = 0
    for index, text in enumerate(read(rel).splitlines(), start=1):
        if needle in text:
            hits += 1
            if hits == occurrence:
                return index
    raise SystemExit("anchor not found in %s: %r" % (rel, needle))


SPEC = [
    {
        "id": "ref-grpc-service-inventory-audit-stream",
        "scan_as": "src/handlers/inventory-audit-stream.ts",
        "kind": "vulnerable",
        "category": "jwt_claims_trusted_without_signature_verification",
        "cwe": "CWE-347",
        "severity": ["high", "critical"],
        "line_anchor": "const payload = JSON.parse(Buffer.from(segments[1]",
        "range": ("const [header] = metadata.get('authorization')", "const withCosts = request.includeCostLines"),
        "extra": STREAM_SUPPORT,
        "why": (
            "callerFromMetadata base64-decodes the second segment of the bearer token from "
            "call.metadata.get('authorization') and never verifies its signature, and the decoded "
            "`role` is what decides both whether the audit log may be read at all and whether unit "
            "costs and supplier contract references are written to the stream. Any caller that can "
            "reach the port can hand-craft a token with role \"finance\" and drain the whole audit "
            "log with cost data attached."
        ),
    },
    {
        "id": "ref-grpc-service-caller-claims",
        "scan_as": "src/lib/auth.ts",
        "kind": "safe",
        "paired_with": "ref-grpc-service-inventory-audit-stream",
        "extra": [],
        "why": (
            "Same operation — bearer token out of the gRPC `authorization` metadata turned into a "
            "claims object with a subject and a role — but claimsFrom runs jwt.verify with the "
            "algorithm list pinned to HS256 and the issuer and audience checked, and fails closed "
            "when the signing secret is absent, so the role it returns is one the auth service "
            "actually asserted."
        ),
    },
    {
        "id": "ref-grpc-service-cost-report",
        "scan_as": "src/handlers/cost-reports.ts",
        "kind": "vulnerable",
        "category": "sql_injection_via_unsafe_query_interpolation",
        "cwe": "CWE-89",
        "severity": ["high", "critical"],
        "line_anchor": "const rows = await sql.unsafe(statement",
        "range": ("const groupBy = request.groupBy.length > 0", "const rows = await sql.unsafe(statement"),
        "extra": HANDLER_SUPPORT,
        "why": (
            "BuildCostReportRequest.group_by, sort_direction and filter_expression are string fields "
            "off the wire that are concatenated straight into the statement text handed to "
            "sql.unsafe; only depot_id and the two dates are bound as $1..$3. filter_expression is "
            "appended as a raw `and ...` predicate, so a caller controls the WHERE clause, the GROUP "
            "BY and the ORDER BY of a query the postgres client will execute verbatim."
        ),
    },
    {
        "id": "ref-grpc-service-depot-throughput",
        "scan_as": "src/handlers/depot-throughput.ts",
        "kind": "safe",
        "paired_with": "ref-grpc-service-cost-report",
        "extra": HANDLER_SUPPORT,
        "why": (
            "Same dynamic-SQL shape and the same sql.unsafe call, but the only strings that reach it "
            "are literals: the group-by expression is looked up in the GROUPING_EXPRESSIONS table by "
            "the request's enum value and falls back to a literal when it misses, and the direction "
            "is one of two hard-coded words chosen by a boolean. depot_id and the window come in "
            "through the tagged template, which parameterises them."
        ),
    },
    {
        "id": "ref-grpc-service-stock-adjustment",
        "scan_as": "src/handlers/stock-adjustments.ts",
        "kind": "vulnerable",
        "category": "missing_authorization_check_on_internal_write_method",
        "cwe": "CWE-862",
        "severity": ["high", "critical"],
        "line_anchor": "const claims = claimsFrom(call.metadata)",
        "range": ("const claims = claimsFrom(call.metadata)", "and sku = ${request.sku}"),
        "range_occurrences": (1, 2),
        "extra": HANDLER_SUPPORT,
        "why": (
            "AdjustStock authenticates the caller and then writes an inventory correction for any "
            "depot_id and sku in the request without ever checking claims.role or that the caller is "
            "scoped to that depot — the comment treats not being in the gateway's route table as the "
            "authorization. Any valid platform token, including a storefront one, can write off stock "
            "in any depot."
        ),
    },
    {
        "id": "ref-grpc-service-stock-transfer",
        "scan_as": "src/handlers/stock-transfers.ts",
        "kind": "safe",
        "paired_with": "ref-grpc-service-stock-adjustment",
        "extra": HANDLER_SUPPORT,
        "why": (
            "The other internal-only write, with the same comment about the gateway and the platform "
            "CIDRs and the same insert-plus-update shape, but requireRole restricts it to "
            "warehouse_ops, inventory_manager and internal and assertDepotAccess is applied to both "
            "the source and the destination depot before the transaction opens. The role and depot "
            "assertions do the work, not the network placement."
        ),
    },
    {
        "id": "ref-grpc-service-purchase-order",
        "scan_as": "src/handlers/purchase-orders.ts",
        "kind": "vulnerable",
        "category": "missing_depot_scope_on_record_lookup",
        "cwe": "CWE-639",
        "severity": ["medium", "high"],
        "line_anchor": "const [order] = await sql`",
        "range": ("requireRole(claims, 'warehouse_ops'", "      lines,"),
        "extra": HANDLER_SUPPORT,
        "why": (
            "GetPurchaseOrder selects the row by request.purchase_order_id alone and returns it, "
            "including supplier unit costs and the supplier contract reference, without comparing "
            "order.depot_id against claims.depotIds. The role check lets every depot-scoped role in, "
            "so any warehouse_ops caller can read any depot's purchase orders and supplier pricing "
            "given an id; the comment's \"uuids are not enumerable\" is not an access control."
        ),
    },
    {
        "id": "ref-grpc-service-goods-receipt",
        "scan_as": "src/handlers/goods-receipts.ts",
        "kind": "safe",
        "paired_with": "ref-grpc-service-purchase-order",
        "extra": HANDLER_SUPPORT,
        "why": (
            "The same fetch-a-row-by-uuid shape with the same role check, but after the row comes "
            "back assertDepotAccess compares receipt.depot_id with the caller's depot scope and the "
            "handler answers NOT_FOUND when it fails, so an id from another depot yields nothing and "
            "does not leak whether it exists. The post-fetch depot assertion is the guard."
        ),
    },
    {
        "id": "ref-grpc-service-cycle-count-submit",
        "scan_as": "src/handlers/cycle-counts.ts",
        "kind": "vulnerable",
        "category": "caller_supplied_actor_identity_used_for_authorization",
        "cwe": "CWE-807",
        "severity": ["medium", "high"],
        "line_anchor": "const actorId = request.actorUserId !== undefined",
        "range": ("// The warehouse terminals submit through the BFF", "returning id"),
        "extra": HANDLER_SUPPORT,
        "why": (
            "actorId is taken from the request's actor_user_id field and then used as the key of the "
            "staff_entitlements lookup that authorises the write and as the counted_by attribution. "
            "The `!== undefined` test can never fail for a proto3 string — an omitted field arrives "
            "as '' — so the fallback to claims.subject is dead code, and any caller with a valid "
            "token can borrow another staff member's counting entitlement and file counts in their "
            "name."
        ),
    },
    {
        "id": "ref-grpc-service-cycle-count-approval",
        "scan_as": "src/handlers/stock-count-approvals.ts",
        "kind": "safe",
        "paired_with": "ref-grpc-service-cycle-count-submit",
        "extra": HANDLER_SUPPORT,
        "why": (
            "The same actor-override feature on the sibling method: the approver defaults to "
            "claims.subject, and an actor_user_id is only honoured when the field is non-empty "
            "(tested by length, because proto3 gives '' rather than undefined), when the caller's own "
            "verified role is `internal`, and when the named person holds the approval entitlement in "
            "that depot. The role gate on the override is what makes it safe."
        ),
    },
    {
        "id": "ref-grpc-service-invoice-document",
        "scan_as": "src/handlers/invoice-documents.ts",
        "kind": "vulnerable",
        "category": "path_traversal_in_document_fetch",
        "cwe": "CWE-22",
        "severity": ["high", "critical"],
        "line_anchor": "contents = await readFile(target)",
        "range": ("// The procurement UI already holds the object name", "      contents,"),
        "extra": HANDLER_SUPPORT,
        "why": (
            "request.document_name is joined onto DOCUMENT_ROOT and read with no containment check, "
            "even though the invoice row already carries its own document_path. A document_name of "
            "\"../../../var/run/secrets/kubernetes.io/serviceaccount/token\" escapes the documents "
            "volume and the bytes are returned to the caller in the response."
        ),
    },
    {
        "id": "ref-grpc-service-supplier-statement",
        "scan_as": "src/handlers/supplier-statements.ts",
        "kind": "safe",
        "paired_with": "ref-grpc-service-invoice-document",
        "extra": HANDLER_SUPPORT,
        "why": (
            "The same caller-supplied object name reaching fs.readFile, but path.resolve is applied "
            "against an already-resolved STATEMENT_ROOT and the result is rejected unless it is the "
            "root itself or sits under root + path.sep, with a .csv extension check after that. The "
            "resolved-prefix boundary check is what keeps \"../invoices/...\" out."
        ),
    },
]


def build():
    cases = []
    for spec in SPEC:
        scan_as = spec["scan_as"]
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
            occurrences = spec.get("range_occurrences", (1, 1))
            start = line_of(scan_as, spec["range"][0], occurrences[0])
            end = line_of(scan_as, spec["range"][1], occurrences[1])
            line = line_of(scan_as, spec["line_anchor"])
            if not (start <= line <= end):
                raise SystemExit("line %d outside range [%d, %d] for %s" % (line, start, end, spec["id"]))
            case["category"] = spec["category"]
            case["cwe"] = spec["cwe"]
            case["severityBand"] = spec["severity"]
            case["line"] = line
            case["lineRange"] = [start, end]
        else:
            case["pairedWith"] = spec["paired_with"]
        case["runtimeVerifiable"] = True
        case["why"] = spec["why"]
        case["packageJson"] = PACKAGE_JSON
        if spec["extra"]:
            case["extraFiles"] = {rel: read(rel) for rel in spec["extra"]}
        cases.append(case)

    vulnerable = [c for c in cases if c["kind"] == "vulnerable"]
    safe = [c for c in cases if c["kind"] == "safe"]
    ids = {c["id"] for c in cases}
    for case in safe:
        if case["pairedWith"] not in ids:
            raise SystemExit("dangling pairedWith on %s" % case["id"])
    scan_paths = [c["scanAs"] for c in cases]
    if len(set(scan_paths)) != len(scan_paths):
        raise SystemExit("duplicate scanAs")

    payload = {"family": FAMILY, "cases": cases}
    out = os.path.join(ROOT, "cases.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("cases: %d vulnerable, %d safe" % (len(vulnerable), len(safe)))
    for case in vulnerable:
        print("  V %-46s line %d range %s" % (case["id"], case["line"], case["lineRange"]))
    for case in safe:
        print("  S %-46s -> %s" % (case["id"], case["pairedWith"]))
    return 0


if __name__ == "__main__":
    sys.exit(build())
