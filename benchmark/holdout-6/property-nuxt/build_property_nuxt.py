#!/usr/bin/env python3
"""Emit cases.json for the property-nuxt holdout-6 family.

Source files live on disk next to this script; extraFiles content is read from
those same files so the shipped text can never drift from the case text.
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
FAMILY = "property-nuxt"

ARCHITECTURE = (
    "Nuxt 4 application whose API is Nitro server routes under server/api "
    "(defineEventHandler), with Drizzle ORM over Postgres as the data layer, "
    "ioredis for short-lived share tokens, and the portal session resolved into "
    "event.context.session by server middleware."
)

PACKAGE_JSON = {
    "name": "harbourlet-portal",
    "version": "3.4.0",
    "private": True,
    "type": "module",
    "scripts": {
        "dev": "nuxt dev",
        "build": "nuxt build",
        "db:generate": "drizzle-kit generate",
    },
    "dependencies": {
        "nuxt": "^4.1.2",
        "vue": "^3.5.13",
        "drizzle-orm": "^0.44.4",
        "pg": "^8.13.1",
        "ioredis": "^5.4.2",
        "jose": "^5.9.6",
        "zod": "^3.24.1",
    },
    "devDependencies": {
        "@types/pg": "^8.11.10",
        "drizzle-kit": "^0.31.4",
        "typescript": "^5.7.2",
    },
}

CONFIG = "nuxt.config.ts"
SCHEMA = "server/db/schema.ts"
CLIENT = "server/db/client.ts"
SESSION = "server/utils/session.ts"
REDIS = "server/utils/redis.ts"

BASE = [CONFIG, SCHEMA, CLIENT]
WITH_SESSION = BASE + [SESSION]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def case(scan_as, kind, slug, why, extras, **rest):
    entry = {
        "id": f"h6-{FAMILY}-{slug}",
        "family": FAMILY,
        "architecture": ARCHITECTURE,
        "language": "typescript",
        "file": f"{FAMILY}/{scan_as}",
        "scanAs": scan_as,
        "kind": kind,
    }
    entry.update(rest)
    entry["why"] = why
    entry["packageJson"] = PACKAGE_JSON
    if extras:
        entry["extraFiles"] = {path: read(path) for path in extras if path != scan_as}
    return entry


cases = [
    case(
        "server/middleware/01.identity.ts",
        "vulnerable",
        "portal-identity-middleware",
        "The portal token is taken from the Authorization header or the "
        "harbourlet_portal cookie and passed to jose's decodeJwt, which parses "
        "the payload without checking the signature; the resulting sub is used "
        "to load the account and the unverified role and landlord_id claims are "
        "written straight into event.context.session, so anyone can mint a token "
        "for any user id and any role.",
        BASE,
        category="portal_token_signature_unverified",
        cwe="CWE-347",
        severityBand=["high", "critical"],
        line=38,
        lineRange=[31, 72],
        runtimeVerifiable=True,
    ),
    case(
        SESSION,
        "safe",
        "portal-token-exchange",
        "Same jose-based token handling, but verifyPortalToken calls jwtVerify "
        "with the configured secret and pins the algorithm to HS256 plus the "
        "expected issuer and audience, so a forged or re-signed token is "
        "rejected before any claim is trusted.",
        BASE,
        route=None,
        pairedWith=f"h6-{FAMILY}-portal-identity-middleware",
        runtimeVerifiable=False,
    ),
    case(
        "server/api/tenancies/[id]/statements.get.ts",
        "vulnerable",
        "tenancy-statements",
        "The tenancy id comes from the route parameter and is looked up with "
        "eq(tenancies.id, tenancyId) alone; nothing ties the row to "
        "session.userId or session.landlordId, so any signed-in tenant can read "
        "the rent statements, arrears and lease deposit of any other tenancy by "
        "changing the id in the URL.",
        WITH_SESSION,
        category="tenancy_statement_owner_scope_missing",
        cwe="CWE-639",
        severityBand=["high"],
        line=37,
        lineRange=[21, 65],
        route="GET /api/tenancies/[id]/statements",
        runtimeVerifiable=True,
    ),
    case(
        "server/api/tenancies/[id]/ledger.get.ts",
        "safe",
        "tenancy-ledger",
        "The same route-parameter lookup over the same tables, but the where "
        "clause is built from the session: a tenant is matched on "
        "tenancies.tenantId and a landlord or agent on tenancies.landlordId, so "
        "an id belonging to somebody else returns 404 before any statement is "
        "read.",
        WITH_SESSION,
        pairedWith=f"h6-{FAMILY}-tenancy-statements",
        route="GET /api/tenancies/[id]/ledger",
        runtimeVerifiable=True,
    ),
    case(
        "server/api/payouts/report.get.ts",
        "vulnerable",
        "payout-report",
        "query.state and query.sort come from the request query string and are "
        "pasted into the statement with sql.raw — once inside a quoted literal "
        "for the state predicate and once as the ORDER BY column — so the "
        "attacker controls SQL text in the query drizzle hands to db.execute; "
        "the landlord_id predicate next to them is correctly parameterised.",
        WITH_SESSION,
        category="payout_report_predicate_string_interpolation",
        cwe="CWE-89",
        severityBand=["high", "critical"],
        line=30,
        lineRange=[16, 54],
        route="GET /api/payouts/report",
        runtimeVerifiable=True,
    ),
    case(
        "server/api/payouts/summary.get.ts",
        "safe",
        "payout-summary",
        "The same drizzle sql template with a caller-chosen filter and ordering, "
        "but the state is only used after passing the PAYOUT_STATES set and is "
        "bound as a placeholder, and the sort key selects a pre-written fragment "
        "from the SORTABLE map, so no request text ever becomes SQL.",
        WITH_SESSION,
        pairedWith=f"h6-{FAMILY}-payout-report",
        route="GET /api/payouts/summary",
        runtimeVerifiable=True,
    ),
    case(
        "server/api/maintenance/[id]/photos.post.ts",
        "vulnerable",
        "maintenance-photos",
        "part.filename is the name supplied by the uploading client and is "
        "joined onto config.uploadRoot without being reduced to a base name, so "
        "a filename containing ../ segments makes writeFile place attacker "
        "content anywhere the Nitro process can write; the MIME and size checks "
        "above it do nothing about the path.",
        WITH_SESSION,
        category="upload_filename_path_escape",
        cwe="CWE-22",
        severityBand=["high", "critical"],
        line=68,
        lineRange=[45, 73],
        route="POST /api/maintenance/[id]/photos",
        runtimeVerifiable=True,
    ),
    case(
        "server/api/documents/[id]/download.get.ts",
        "safe",
        "document-download",
        "The same pattern of building a filesystem path from request data and "
        "streaming it, but the variant segment must be one of the VARIANTS set, "
        "the stored key is reduced with basename, and the resolved target is "
        "rejected unless it sits under the resolved document root — plus "
        "assertTenancyAccess confirms the caller is a party to the tenancy.",
        WITH_SESSION,
        pairedWith=f"h6-{FAMILY}-maintenance-photos",
        route="GET /api/documents/[id]/download",
        runtimeVerifiable=True,
    ),
    case(
        "server/api/inspections/index.post.ts",
        "vulnerable",
        "inspection-booking",
        "body.notifyUrl is an arbitrary caller-supplied URL that only has to "
        "parse and use https before the server issues a POST to it with $fetch, "
        "so a landlord can point the request at internal-only hosts and use the "
        "portal as an outbound request proxy; zod's .url() and the scheme check "
        "say nothing about the destination.",
        WITH_SESSION,
        category="inspection_callback_destination_unrestricted",
        cwe="CWE-918",
        severityBand=["medium", "high"],
        line=65,
        lineRange=[57, 78],
        route="POST /api/inspections",
        runtimeVerifiable=True,
    ),
    case(
        "server/api/inspections/reminders.post.ts",
        "safe",
        "inspection-reminder",
        "The same server-side $fetch to a partner webhook, but the URL is read "
        "from the inspection_partners row joined on the caller's own "
        "landlord_id, and it is only called when its scheme is https and its "
        "hostname appears in the configured inspectionPartnerHosts allowlist, "
        "with redirects refused.",
        WITH_SESSION,
        pairedWith=f"h6-{FAMILY}-inspection-booking",
        route="POST /api/inspections/reminders",
        runtimeVerifiable=True,
    ),
    case(
        "server/api/documents/share.post.ts",
        "vulnerable",
        "document-share-link",
        "The share reference that authorises access to a lease or statement is "
        "built from Date.now() in base36 plus Math.random(), neither of which is "
        "a cryptographic source, so the value is guessable from a known issue "
        "time and a weak PRNG; that reference is the only secret protecting the "
        "Redis-backed link that is handed out.",
        WITH_SESSION + [REDIS],
        category="share_reference_predictable_generation",
        cwe="CWE-338",
        severityBand=["medium", "high"],
        line=44,
        lineRange=[44, 61],
        route="POST /api/documents/share",
        runtimeVerifiable=True,
    ),
    case(
        REDIS,
        "safe",
        "share-token-store",
        "The same short-lived Redis share token, but mintShareToken draws 32 "
        "bytes from node:crypto randomBytes and stores the payload under a "
        "SHA-256 digest of the token with a TTL, and consumeShareToken redeems "
        "it once via getdel, so the token cannot be predicted from a timestamp.",
        [CONFIG],
        pairedWith=f"h6-{FAMILY}-document-share-link",
        runtimeVerifiable=False,
    ),
]

for entry in cases:
    if entry.get("route") is None:
        entry.pop("route", None)

payload = {"family": FAMILY, "cases": cases}
(ROOT / "cases.json").write_text(
    json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
)

vulnerable = [c for c in cases if c["kind"] == "vulnerable"]
safe = [c for c in cases if c["kind"] == "safe"]
print(f"vulnerable={len(vulnerable)} safe={len(safe)}")
for c in vulnerable:
    print(f"  {c['category']:50s} {c['cwe']}  {c['scanAs']}:{c['line']} {c['lineRange']}")
for c in safe:
    print(f"  safe -> {c['pairedWith']:44s} {c['scanAs']}")
