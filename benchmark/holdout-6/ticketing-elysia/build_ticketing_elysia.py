#!/usr/bin/env python3
"""Emit cases.json for the ticketing-elysia holdout-6 family.

Line numbers are resolved from the source files themselves so the ground truth
cannot drift away from the code it describes.
"""

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
FAMILY = "ticketing-elysia"
ARCHITECTURE = (
    "Elysia 1.3 on Bun with Prisma 6 for data access; caller identity comes from a bearer "
    "session token whose HMAC is verified in a scoped Elysia derive plugin (src/lib/identity.ts)."
)

PACKAGE_JSON = json.loads((ROOT / "package.json").read_text())


def lines(rel):
    return (ROOT / rel).read_text().splitlines()


def find(rel, needle, after=0, offset=0):
    """1-based line number of the first line containing needle at/after `after`."""
    src = lines(rel)
    for index in range(max(after - 1, 0), len(src)):
        if needle in src[index]:
            return index + 1 + offset
    raise SystemExit(f"anchor not found in {rel}: {needle!r}")


def find_exact(rel, stripped, after=0, offset=0):
    src = lines(rel)
    for index in range(max(after - 1, 0), len(src)):
        if src[index].strip() == stripped:
            return index + 1 + offset
    raise SystemExit(f"exact anchor not found in {rel}: {stripped!r}")


def read(rel):
    return (ROOT / rel).read_text()


ENV = "src/config/env.ts"
DB = "src/lib/prisma.ts"
IDENTITY = "src/lib/identity.ts"
STATEMENTS = "src/domain/payout-statements.ts"
REFUND_DESK = "src/domain/refund-desk.ts"


def case(case_id, scan_as, kind, why, extra, **rest):
    entry = {
        "id": f"h6-{FAMILY}-{case_id}",
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
    entry["extraFiles"] = {path: read(path) for path in extra}
    return entry


# ---------------------------------------------------------------- events search
EVENTS = "src/routes/events.ts"
events_line = find(EVENTS, "prisma.$queryRawUnsafe<EventSearchRow[]>")
events_start = find(EVENTS, "const term = query.q.trim()")
events_end = find_exact(EVENTS, "`)", after=events_line)

# ------------------------------------------------------------- ticket handover
TICKETS = "src/routes/tickets.ts"
tickets_line = find(TICKETS, "const ticket = await prisma.ticket.findUnique({")
tickets_start = find(TICKETS, "'/:ticketId/transfer',")
tickets_end = find_exact(TICKETS, "])", after=tickets_line)

# --------------------------------------------------------------- gate check-in
GATE = "src/routes/gate.ts"
gate_line = find(GATE, "JSON.parse(Buffer.from(claimSegment, 'base64url')")
gate_start = find(GATE, "function readScannedPass(")
gate_update = find(GATE, "const admitted = await prisma.ticket.update({")
gate_end = find_exact(GATE, "})", after=gate_update)

# ------------------------------------------------------------- payout exports
PAYOUTS = "src/routes/payouts.ts"
payouts_line = find(PAYOUTS, "Bun.file(join(env.statementDir, requestedPath))")
payouts_start = find(PAYOUTS, "'/exports/*',")
payouts_end = find(PAYOUTS, "return artefact")

# ---------------------------------------------------------------- promo codes
PROMOTIONS = "src/routes/promotions.ts"
promo_line = find(PROMOTIONS, "const code = await prisma.discountCode.create({")
promo_start = find(PROMOTIONS, ".onBeforeHandle(requireAccount)")
promo_end = find(PROMOTIONS, "select: { id: true, code: true, percentOff: true", offset=1)

# ------------------------------------------------------------ refund requests
REFUNDS = "src/routes/refunds.ts"
refunds_line = find(REFUNDS, "amountCents: body.amountCents,", after=find(REFUNDS, "prisma.creditNote.create({"))
refunds_start = find(REFUNDS, "requestedAmountCents: body.amountCents,")
refunds_end = find_exact(REFUNDS, "])", after=find(REFUNDS, "walletBalanceCents: { increment: body.amountCents }"))

cases = [
    case(
        "event-relevance-search",
        EVENTS,
        "vulnerable",
        "The search term, sort column, direction and limit taken off the query string are concatenated "
        "straight into the SQL text handed to prisma.$queryRawUnsafe; escaping the LIKE wildcards does "
        "nothing for the surrounding quotes and the ORDER BY clause is unquoted, so a public search "
        "request can append arbitrary SQL that runs with the API's database role.",
        [ENV, DB],
        category="raw_sql_string_interpolation",
        cwe="CWE-89",
        severityBand=["high", "critical"],
        line=events_line,
        lineRange=[events_start, events_end],
        route="GET /api/events/search",
        runtimeVerifiable=True,
    ),
    case(
        "organiser-attendance-report",
        "src/routes/organiser-events.ts",
        "safe",
        "The same hand-written aggregate, but the search term is bound as a Prisma.sql parameter and the "
        "ORDER BY fragment is picked out of the SORT_FRAGMENTS allowlist, so no request value ever reaches "
        "the query text; the rows are additionally scoped to the caller's organiserId.",
        [ENV, DB, IDENTITY],
        route="GET /api/organiser/events/attendance",
        runtimeVerifiable=True,
        pairedWith=f"h6-{FAMILY}-event-relevance-search",
    ),
    case(
        "ticket-handover",
        TICKETS,
        "vulnerable",
        "The transfer resolves the ticket from the path id alone and never compares ticket.ownerId with "
        "identity.accountId, so any authenticated attendee can hand somebody else's ticket to an address "
        "they control; the only checks made are on event and ticket state.",
        [ENV, DB, IDENTITY],
        category="missing_ticket_ownership_check",
        cwe="CWE-639",
        severityBand=["high", "critical"],
        line=tickets_line,
        lineRange=[tickets_start, tickets_end],
        route="POST /api/tickets/:ticketId/transfer",
        runtimeVerifiable=True,
    ),
    case(
        "wallet-holder-change",
        "src/routes/wallet.ts",
        "safe",
        "The same path-id-addressed ticket mutation, but it runs as an updateMany whose where clause "
        "carries ownerId: actor.accountId, so a ticket belonging to another account matches nothing and "
        "the zero count is returned as a 404 — the ownership predicate is the guard.",
        [ENV, DB, IDENTITY],
        route="PATCH /api/wallet/tickets/:ticketId/holder",
        runtimeVerifiable=True,
        pairedWith=f"h6-{FAMILY}-ticket-handover",
    ),
    case(
        "door-admission",
        GATE,
        "vulnerable",
        "readScannedPass splits the compact pass token and JSON.parses its claim segment without ever "
        "recomputing the HMAC that readPassToken in src/lib/identity.ts exists to check, so ticketId, "
        "eventId and exp all come from an unauthenticated string and a hand-crafted QR code is admitted "
        "and written to the gate scan log as a valid pass.",
        [ENV, DB, IDENTITY],
        category="unverified_gate_pass_signature",
        cwe="CWE-347",
        severityBand=["high", "critical"],
        line=gate_line,
        lineRange=[gate_start, gate_end],
        route="POST /api/gate/check-in",
        runtimeVerifiable=True,
    ),
    case(
        "session-token-check",
        IDENTITY,
        "safe",
        "The same `<claims>.<signature>` compact token shape, but readSignedToken recomputes the HMAC over "
        "the claim segment and compares it with timingSafeEqual on equal-length buffers before a single "
        "claim is decoded, and only then applies the expiry check, so a forged or edited token is rejected.",
        [ENV, DB],
        runtimeVerifiable=True,
        pairedWith=f"h6-{FAMILY}-door-admission",
    ),
    case(
        "payout-export-download",
        PAYOUTS,
        "vulnerable",
        "The wildcard segment params['*'] is joined onto env.statementDir and opened with Bun.file with no "
        "containment or allowlist check, so a request like GET /api/organiser/payouts/exports/../../../"
        "../etc/passwd streams a file from outside the statement tree back to any organiser account.",
        [ENV, DB, IDENTITY, STATEMENTS],
        category="caller_controlled_export_file_path",
        cwe="CWE-22",
        severityBand=["high", "critical"],
        line=payouts_line,
        lineRange=[payouts_start, payouts_end],
        route="GET /api/organiser/payouts/exports/*",
        runtimeVerifiable=True,
    ),
    case(
        "payout-statement-file",
        STATEMENTS,
        "safe",
        "The same join + Bun.file download, but the relative key is read off the Payout row that was "
        "selected by organiserId, it has to match the generator's own naming pattern, and the resolved "
        "absolute path has to still sit under STATEMENT_ROOT before the file is opened.",
        [ENV, DB],
        runtimeVerifiable=True,
        pairedWith=f"h6-{FAMILY}-payout-export-download",
    ),
    case(
        "promoter-code-issuance",
        PROMOTIONS,
        "vulnerable",
        "The only guard on the group is requireAccount, and the create handler checks neither the caller's "
        "promoter role nor that body.eventId belongs to their organiser, so any signed-in attendee can mint "
        "a 100%-off code against any published event — the sibling read and revoke handlers in the same file "
        "do apply requirePromoter and an organiserId scope.",
        [ENV, DB, IDENTITY],
        category="unscoped_discount_code_issuance",
        cwe="CWE-862",
        severityBand=["medium", "high"],
        line=promo_line,
        lineRange=[promo_start, promo_end],
        route="POST /api/promotions/codes",
        runtimeVerifiable=True,
    ),
    case(
        "refund-request-credit",
        REFUNDS,
        "vulnerable",
        "body.amountCents is what decides whether the request auto-approves and is also the figure written "
        "to the credit note and incremented onto the account's wallet balance; it is never compared with "
        "ticket.pricePaidCents, so an attendee holding a cheap ticket can request the auto-approve ceiling "
        "and be credited far more than was ever captured.",
        [ENV, DB, IDENTITY, REFUND_DESK],
        category="client_supplied_refund_amount",
        cwe="CWE-472",
        severityBand=["high", "critical"],
        line=refunds_line,
        lineRange=[refunds_start, refunds_end],
        route="POST /api/refunds/requests",
        runtimeVerifiable=True,
    ),
    case(
        "refund-settlement",
        REFUND_DESK,
        "safe",
        "The same credit-note and wallet write, but the amount is recomputed from ticket.pricePaidCents and "
        "the event's fee policy and requestedAmountCents is ignored for the ledger, and the request is only "
        "found when the reviewer is FINANCE staff at the organiser that owns the event.",
        [ENV, DB],
        runtimeVerifiable=True,
        pairedWith=f"h6-{FAMILY}-refund-request-credit",
    ),
]

payload = {"family": FAMILY, "cases": cases}
(ROOT / "cases.json").write_text(json.dumps(payload, indent=2) + "\n")

vulnerable = [entry for entry in cases if entry["kind"] == "vulnerable"]
safe = [entry for entry in cases if entry["kind"] == "safe"]

print(f"vulnerable: {len(vulnerable)}  safe: {len(safe)}")
for entry in vulnerable:
    print(
        f"  {entry['id']:<48} {entry['category']:<38} {entry['cwe']:<9} "
        f"line {entry['line']} in {entry['lineRange']}"
    )
for entry in safe:
    print(f"  {entry['id']:<48} paired -> {entry['pairedWith']}")
