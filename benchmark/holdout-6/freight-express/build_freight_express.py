#!/usr/bin/env python3
"""Assembles benchmark/holdout-6/freight-express/cases.json.

Reads the shared modules straight off disk so the text shipped in `extraFiles`
can never drift from the application, and synthesises the per-case Express entry
point that makes each route address reachable inside a single-case directory.
"""
from __future__ import annotations

import json
from pathlib import Path

FAMILY = "freight-express"
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

ARCHITECTURE = (
    "Express 5 REST service with Drizzle ORM over Postgres (node-postgres pool), "
    "session identity resolved by middleware from the signed fw_session cookie."
)

PACKAGE_JSON = {
    "name": "freight-express",
    "version": "1.4.0",
    "private": True,
    "type": "module",
    "engines": {"node": ">=22"},
    "scripts": {
        "dev": "tsx watch src/server.ts",
        "build": "tsc -p tsconfig.json",
        "db:generate": "drizzle-kit generate",
    },
    "dependencies": {
        "cookie-parser": "^1.4.7",
        "dotenv": "^16.4.7",
        "drizzle-orm": "^0.44.2",
        "express": "^5.1.0",
        "pg": "^8.13.1",
        "zod": "^3.24.1",
    },
    "devDependencies": {
        "@types/cookie-parser": "^1.4.8",
        "@types/express": "^5.0.1",
        "@types/node": "^22.13.1",
        "@types/pg": "^8.11.11",
        "drizzle-kit": "^0.31.1",
        "tsx": "^4.19.3",
        "typescript": "^5.8.2",
    },
}


def read(rel: str) -> str:
    return (SRC / rel).read_text(encoding="utf-8")


SHARED = {
    "src/db/schema.ts": read("db/schema.ts"),
    "src/db/client.ts": read("db/client.ts"),
}
SESSION = {"src/lib/session.ts": read("lib/session.ts")}


def app_entry(module: str, router: str, mount: str | None, raw_body: bool) -> str:
    """The real src/app.ts trimmed to the router a single case needs.

    Routers that declare their own absolute paths are mounted flat, so the whole
    address of a handler is written in the router module itself.
    """
    use_router = f"app.use({router});" if mount is None else f"app.use('{mount}', {router});"
    body_first = use_router if raw_body else "app.use(express.json({ limit: '256kb' }));"
    body_second = "app.use(express.json({ limit: '256kb' }));" if raw_body else use_router
    note = (
        "// The carrier callbacks verify an HMAC over the exact bytes they signed,\n"
        "// so they are mounted before the JSON body parser.\n"
        if raw_body
        else ""
    )
    return f"""import express from 'express';
import cookieParser from 'cookie-parser';

import {{ {router} }} from './{module}.js';

const cookieSecret = process.env.COOKIE_SECRET;
if (!cookieSecret) {{
  throw new Error('COOKIE_SECRET is not set');
}}

export const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(cookieParser(cookieSecret));
{note}{body_first}
{body_second}

app.get('/healthz', (_req, res) => {{
  res.json({{ ok: true }});
}});

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {{
  console.error('unhandled request failure', err);
  res.status(500).json({{ error: 'internal_error' }});
}});
"""


def entry(module: str, router: str, mount: str | None = None, raw_body: bool = False) -> dict:
    return {"src/app.ts": app_entry(module, router, mount, raw_body)}


cases: list[dict] = [
    # -- tariff search -------------------------------------------------------
    {
        "id": f"h6-{FAMILY}-tariff-search",
        "file": f"{FAMILY}/src/routes/rate-cards.ts",
        "scanAs": "src/routes/rate-cards.ts",
        "kind": "vulnerable",
        "category": "tariff_search_sql_built_by_string_concatenation",
        "cwe": "CWE-89",
        "severityBand": ["high", "critical"],
        "line": 48,
        "lineRange": [34, 53],
        "route": "GET /api/rate-cards/search",
        "why": (
            "req.query.lane and req.query.sort are pasted into a sql.raw statement, so a lane term "
            "such as RO' OR 1=1 -- or an arbitrary ORDER BY expression is executed as SQL text "
            "against rate_cards for every logged in desk user."
        ),
        "extraFiles": {**SHARED, **SESSION, **entry("routes/rate-cards", "rateCardsRouter")},
    },
    {
        "id": f"h6-{FAMILY}-lane-rate-lookup",
        "file": f"{FAMILY}/src/db/lane-rate-queries.ts",
        "scanAs": "src/db/lane-rate-queries.ts",
        "kind": "safe",
        "pairedWith": f"h6-{FAMILY}-tariff-search",
        "runtimeVerifiable": False,
        "why": (
            "Same hand written statement and the same dynamic ORDER BY, but the lane term is bound as a "
            "parameter inside a sql template (with its ILIKE metacharacters escaped) and the sort column "
            "can only be one of the three keys in SORT_COLUMNS, so no request text reaches the SQL string."
        ),
        "extraFiles": dict(SHARED),
    },
    # -- consignment drawer --------------------------------------------------
    {
        "id": f"h6-{FAMILY}-consignment-drawer",
        "file": f"{FAMILY}/src/routes/consignments.ts",
        "scanAs": "src/routes/consignments.ts",
        "kind": "vulnerable",
        "category": "consignment_read_missing_forwarder_scope",
        "cwe": "CWE-639",
        "severityBand": ["high"],
        "line": 89,
        "lineRange": [62, 127],
        "route": "GET /api/consignments/:reference",
        "why": (
            "The detail handler filters on eq(consignments.reference, ...) alone; session.forwarderId is "
            "read but never enters the predicate, so any authenticated desk user can read another "
            "branch's consignment together with its carrier rates and customs document list."
        ),
        "extraFiles": {**SHARED, **SESSION, **entry("routes/consignments", "consignmentsRouter")},
    },
    {
        "id": f"h6-{FAMILY}-tracking-timeline",
        "file": f"{FAMILY}/src/routes/tracking-events.ts",
        "scanAs": "src/routes/tracking-events.ts",
        "kind": "safe",
        "pairedWith": f"h6-{FAMILY}-consignment-drawer",
        "route": "GET /api/consignments/:reference/events",
        "why": (
            "findOwnConsignment resolves the reference with and(eq(reference), eq(forwarderId, "
            "session.forwarderId)) before any event is read and answers 404 for a foreign reference, so "
            "the events query only ever receives an id from the caller's own branch."
        ),
        "extraFiles": {
            **SHARED,
            **SESSION,
            **entry("routes/tracking-events", "trackingEventsRouter"),
        },
    },
    # -- customs paperwork ---------------------------------------------------
    {
        "id": f"h6-{FAMILY}-customs-file-download",
        "file": f"{FAMILY}/src/routes/customs-documents.ts",
        "scanAs": "src/routes/customs-documents.ts",
        "kind": "vulnerable",
        "category": "customs_document_path_joined_from_url_segment",
        "cwe": "CWE-22",
        "severityBand": ["high", "critical"],
        "line": 104,
        "lineRange": [95, 120],
        "route": "GET /api/customs/consignments/:reference/files/:fileName",
        "why": (
            "req.params.fileName reaches path.join(CUSTOMS_ROOT, consignment.customsFolder, ...) behind "
            "nothing but an extension test, so ../../<other-forwarder>/CNS-2026-000001/declaration.pdf "
            "leaves the consignment folder and the stream serves another branch's customs paperwork."
        ),
        "extraFiles": {
            **SHARED,
            **SESSION,
            **entry("routes/customs-documents", "customsDocumentsRouter"),
        },
    },
    {
        "id": f"h6-{FAMILY}-delivery-capture-download",
        "file": f"{FAMILY}/src/routes/delivery-proof.ts",
        "scanAs": "src/routes/delivery-proof.ts",
        "kind": "safe",
        "pairedWith": f"h6-{FAMILY}-customs-file-download",
        "route": "GET /api/delivery-proof/:proofId/files/:fileName",
        "why": (
            "The requested name is reduced with path.basename and matched against a strict capture-name "
            "pattern, and the resolved path must start with PROOF_ROOT + path.sep before the stream is "
            "opened; the folder comes from a row already scoped to the caller's forwarder."
        ),
        "extraFiles": {
            **SHARED,
            **SESSION,
            **entry("routes/delivery-proof", "deliveryProofRouter"),
        },
    },
    # -- carrier callbacks ---------------------------------------------------
    {
        "id": f"h6-{FAMILY}-carrier-status-callback",
        "file": f"{FAMILY}/src/webhooks/carrier-status.ts",
        "scanAs": "src/webhooks/carrier-status.ts",
        "kind": "vulnerable",
        "category": "carrier_webhook_state_change_without_required_signature",
        "cwe": "CWE-347",
        "severityBand": ["high", "critical"],
        "line": 53,
        "lineRange": [48, 102],
        "route": "POST /api/webhooks/carrier-status",
        "why": (
            "HMAC verification only runs inside if (signature && secret), so a callback with no "
            "x-carrier-signature header - or one naming a carrier that has no configured secret - skips "
            "verification and still inserts tracking events and updates consignments.status for any reference."
        ),
        "extraFiles": {
            **SHARED,
            **entry("webhooks/carrier-status", "carrierStatusRouter", raw_body=True),
        },
    },
    {
        "id": f"h6-{FAMILY}-carrier-milestone-callback",
        "file": f"{FAMILY}/src/webhooks/carrier-milestones.ts",
        "scanAs": "src/webhooks/carrier-milestones.ts",
        "kind": "safe",
        "pairedWith": f"h6-{FAMILY}-carrier-status-callback",
        "route": "POST /api/webhooks/carrier-milestones",
        "why": (
            "A missing secret, signature or timestamp is a 401 before the body is even parsed, the "
            "timestamp must fall inside a five minute window, and the HMAC over timestamp.body is "
            "compared with crypto.timingSafeEqual after a length check, so no unsigned callback reaches "
            "the tracking insert or the status update."
        ),
        "extraFiles": {
            **SHARED,
            **entry("webhooks/carrier-milestones", "carrierMilestonesRouter", raw_body=True),
        },
    },
    # -- booking edits -------------------------------------------------------
    {
        "id": f"h6-{FAMILY}-booking-drawer-patch",
        "file": f"{FAMILY}/src/routes/carrier-bookings.ts",
        "scanAs": "src/routes/carrier-bookings.ts",
        "kind": "vulnerable",
        "category": "booking_update_writes_unfiltered_request_body",
        "cwe": "CWE-915",
        "severityBand": ["medium", "high"],
        "line": 95,
        "lineRange": [81, 104],
        "route": "PATCH /api/carrier-bookings/:bookingId",
        "why": (
            "req.body is spread straight into .set(), so beyond pickup time and service level a caller "
            "can write status, agreedRateCents, approvedBy and consignmentId - self-confirming a booking, "
            "rewriting the agreed rate, or re-pointing the booking at another branch's consignment."
        ),
        "extraFiles": {
            **SHARED,
            **SESSION,
            **entry("routes/carrier-bookings", "carrierBookingsRouter"),
        },
    },
    {
        "id": f"h6-{FAMILY}-amendment-patch",
        "file": f"{FAMILY}/src/routes/booking-amendments.ts",
        "scanAs": "src/routes/booking-amendments.ts",
        "kind": "safe",
        "pairedWith": f"h6-{FAMILY}-booking-drawer-patch",
        "route": "PATCH /api/carrier-bookings/:bookingId/amendments/:amendmentId",
        "why": (
            "The patch is parsed by a .strict() zod schema holding only the three editable fields and the "
            "update names those columns explicitly, so status and approvedBy can only be moved by the "
            "separate decision endpoint behind requireRole('admin')."
        ),
        "extraFiles": {
            **SHARED,
            **SESSION,
            **entry("routes/booking-amendments", "bookingAmendmentsRouter"),
        },
    },
    # -- identity ------------------------------------------------------------
    {
        "id": f"h6-{FAMILY}-partner-portal-identity",
        "file": f"{FAMILY}/src/middleware/partner-portal-session.ts",
        "scanAs": "src/middleware/partner-portal-session.ts",
        "kind": "vulnerable",
        "category": "partner_identity_trusted_from_unsigned_cookie",
        "cwe": "CWE-565",
        "severityBand": ["high", "critical"],
        "line": 98,
        "lineRange": [89, 114],
        "why": (
            "When the signed cookie is absent the middleware base64url-decodes the plain fw_partner "
            "cookie from req.cookies and takes partnerId, carrierCode, forwarderId and scopes from it, so "
            "any client that sets that cookie itself chooses which carrier and which forwarder it acts as."
        ),
        "extraFiles": dict(SHARED),
    },
    {
        "id": f"h6-{FAMILY}-desk-session",
        "file": f"{FAMILY}/src/lib/session.ts",
        "scanAs": "src/lib/session.ts",
        "kind": "safe",
        "pairedWith": f"h6-{FAMILY}-partner-portal-identity",
        "why": (
            "Identity is taken only from req.signedCookies.fw_session - the typeof token !== 'string' "
            "check rejects the false that cookie-parser stores for a bad signature - and the token is "
            "re-resolved against a non-expired, non-revoked session joined to a live user, so the "
            "forwarder id is server derived and req.cookies is never consulted."
        ),
        "extraFiles": dict(SHARED),
    },
]


def finalize(case: dict) -> dict:
    out = {
        "id": case["id"],
        "family": FAMILY,
        "architecture": ARCHITECTURE,
        "language": "typescript",
        "file": case["file"],
        "scanAs": case["scanAs"],
        "kind": case["kind"],
    }
    for key in ("category", "cwe", "severityBand", "line", "lineRange", "route", "pairedWith"):
        if key in case:
            out[key] = case[key]
    out["runtimeVerifiable"] = case.get("runtimeVerifiable", True)
    out["why"] = case["why"]
    out["packageJson"] = PACKAGE_JSON
    out["extraFiles"] = case["extraFiles"]
    return out


def main() -> None:
    payload = {"family": FAMILY, "cases": [finalize(case) for case in cases]}

    ids = [case["id"] for case in payload["cases"]]
    assert len(ids) == len(set(ids)), "duplicate case id"
    scan_as = [case["scanAs"] for case in payload["cases"]]
    assert len(scan_as) == len(set(scan_as)), "duplicate scanAs"
    for case in payload["cases"]:
        assert (SRC.parent / Path(case["file"]).relative_to(FAMILY)).is_file(), case["file"]
        assert case["file"] == f"{FAMILY}/{case['scanAs']}", case["id"]
        if case["kind"] == "vulnerable":
            assert case["cwe"].startswith("CWE-") and case["cwe"][4:].isdigit()
            low, high = case["lineRange"]
            assert low <= case["line"] <= high, case["id"]
            total = len((SRC.parent / Path(case["file"]).relative_to(FAMILY)).read_text().splitlines())
            assert high <= total, (case["id"], high, total)
        else:
            assert "category" not in case and case["pairedWith"] in ids

    (ROOT / "cases.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    vulnerable = [c for c in payload["cases"] if c["kind"] == "vulnerable"]
    safe = [c for c in payload["cases"] if c["kind"] == "safe"]
    print(f"vulnerable={len(vulnerable)} safe={len(safe)}")
    for case in vulnerable:
        print(f"  {case['category']}  {case['cwe']}  {case['scanAs']}:{case['line']}")


if __name__ == "__main__":
    main()
