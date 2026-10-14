#!/usr/bin/env python3
"""Emit cases.json for the firebase-functions holdout-7 family.

Reads the shared helper off disk so extraFiles never drifts from the real module.
"""
import json
import os

FAMILY = "firebase-functions"
ROOT = os.path.dirname(os.path.abspath(__file__))
ARCH = (
    "Firebase Cloud Functions 2nd generation (firebase-functions v6, TypeScript) with "
    "Firestore through the firebase-admin SDK as the only data layer, and caller identity "
    "from Firebase Auth: request.auth custom claims inside onCall handlers and a verified "
    "bearer ID token inside onRequest handlers."
)
PKG = {
    "name": "nestlings-functions",
    "version": "3.8.2",
    "private": True,
    "main": "lib/index.js",
    "engines": {"node": "20"},
    "dependencies": {
        "firebase-admin": "^12.6.0",
        "firebase-functions": "^6.1.0",
    },
    "devDependencies": {
        "typescript": "^5.5.4",
    },
}

AUTHZ_PATH = "functions/src/lib/authorization.ts"
with open(os.path.join(ROOT, AUTHZ_PATH), encoding="utf-8") as fh:
    AUTHZ = fh.read()

VULN = [
    {
        "slug": "child-profile-read",
        "path": "functions/src/enrollment/childProfiles.ts",
        "category": "missing_ownership_check_on_document_read",
        "cwe": "CWE-639",
        "severityBand": ["high", "critical"],
        "line": 51,
        "lineRange": [45, 78],
        "why": (
            "getChildProfile takes childId straight from request.data and reads "
            "children/{childId} with the Admin SDK after checking only that the caller is "
            "signed in, so any authenticated guardian can pass another family's child id and "
            "get back that child's medical notes, emergency contacts and subsidy rate. The "
            "firestore.rules clause quoted in the comment is never applied to Admin SDK reads."
        ),
        "authz": True,
    },
    {
        "slug": "staff-role-assignment",
        "path": "functions/src/staff/roleAssignments.ts",
        "category": "privilege_escalation_via_unrestricted_custom_claim_write",
        "cwe": "CWE-269",
        "severityBand": ["critical"],
        "line": 41,
        "lineRange": [22, 54],
        "why": (
            "assignStaffRole requires only that the caller is authenticated and then writes "
            "request.data.role and request.data.centreId into the target account's custom "
            "claims, so any signed-in guardian can call it with their own uid and role "
            "'centre_admin' for any centre id and become an administrator of that centre. The "
            "only thing standing in the way is the admin console hiding the screen."
        ),
        "authz": True,
    },
    {
        "slug": "child-record-patch",
        "path": "functions/src/enrollment/childRecordUpdates.ts",
        "category": "mass_assignment_of_privileged_document_fields",
        "cwe": "CWE-915",
        "severityBand": ["medium", "high"],
        "line": 57,
        "lineRange": [34, 62],
        "why": (
            "updateChildRecord authorises the caller against the child and then merges "
            "request.data.patch into the children document wholesale, so a linked guardian can "
            "write fields the profile form never renders: centreId, which moves the child into "
            "another centre's tenant, subsidyRate, which is billing input, and guardianUids, "
            "which hands a third party access to the record."
        ),
        "authz": True,
    },
    {
        "slug": "invoice-document",
        "path": "functions/src/billing/invoiceDelivery.ts",
        "category": "missing_authentication_on_http_endpoint",
        "cwe": "CWE-306",
        "severityBand": ["high", "critical"],
        "line": 42,
        "lineRange": [21, 77],
        "why": (
            "invoiceDocument is a publicly invokable onRequest handler that reads "
            "invoices/{req.query.invoiceId} through the Admin SDK and returns the guardian's "
            "name, email, billing address and direct debit mandate without verifying any ID "
            "token; the firestore.rules clause cited in the comment does not constrain the "
            "Admin SDK."
        ),
        "authz": False,
    },
    {
        "slug": "payment-callbacks",
        "path": "functions/src/billing/paymentWebhooks.ts",
        "category": "webhook_signature_verification_skipped_when_header_absent",
        "cwe": "CWE-347",
        "severityBand": ["high", "critical"],
        "line": 45,
        "lineRange": [44, 92],
        "why": (
            "The HMAC over req.rawBody is computed only when the x-nestlings-signature header "
            "happens to be present, so anyone who can POST to this public endpoint omits the "
            "header and has an unverified body mark any invoice paid and write a matching "
            "ledger entry."
        ),
        "authz": False,
    },
    {
        "slug": "centre-webhook-registration",
        "path": "functions/src/integrations/parentPortalHooks.ts",
        "category": "server_side_request_forgery_via_stored_webhook_endpoint",
        "cwe": "CWE-918",
        "severityBand": ["high"],
        "line": 68,
        "lineRange": [41, 98],
        "why": (
            "registerCentreWebhook hands request.data.endpointUrl to fetch() with no scheme or "
            "host validation and returns the response status and first 512 bytes to the caller, "
            "so a centre admin can read internal-only addresses through the function, including "
            "the GCE metadata server, and can point the OUTBOUND_WEBHOOK_KEY header at any host "
            "they name."
        ),
        "authz": True,
    },
]

SAFE = [
    {
        "slug": "guardian-child-summary",
        "path": "functions/src/enrollment/guardianAccess.ts",
        "pairedWith": "child-profile-read",
        "why": (
            "The same request.data.childId document read, but assertChildVisibleTo rejects the "
            "call unless the caller's uid appears in the child's guardianUids or the caller is "
            "centre staff whose token centreId equals the child's centreId, so holding an id "
            "grants nothing on its own."
        ),
        "authz": True,
    },
    {
        "slug": "staff-invitation",
        "path": "functions/src/staff/staffOnboarding.ts",
        "pairedWith": "staff-role-assignment",
        "why": (
            "The same setCustomUserClaims write, but requireRole(request, 'centre_admin') gates "
            "the call, normaliseRole rejects any role outside the INVITABLE_ROLES allowlist, and "
            "the centreId written into the claims comes from the caller's own token rather than "
            "from request.data."
        ),
        "authz": True,
    },
    {
        "slug": "daily-report-entry",
        "path": "functions/src/daily/dailyReportEntries.ts",
        "pairedWith": "child-record-patch",
        "why": (
            "The same merge of a caller-supplied object into a Firestore document, but only the "
            "keys listed in EDITABLE_REPORT_FIELDS are copied across and the server-owned fields "
            "(childId, date, centreId, roomId, submittedBy) are stamped after the copy, so "
            "nothing the tablet sends can reach a privileged field."
        ),
        "authz": True,
    },
    {
        "slug": "monthly-statement",
        "path": "functions/src/billing/statementDelivery.ts",
        "pairedWith": "invoice-document",
        "why": (
            "The same public onRequest plus Admin SDK read, but requireBearerCaller verifies the "
            "Firebase ID token before anything is fetched and mayReadStatement then requires the "
            "caller to be the owning guardian or staff at the statement's own centre."
        ),
        "authz": True,
    },
    {
        "slug": "refund-callbacks",
        "path": "functions/src/billing/refundNotifications.ts",
        "pairedWith": "payment-callbacks",
        "why": (
            "The same provider callback, but a missing header and a wrong digest fall into the "
            "same 401 branch, and hasValidSignature compares equal-length buffers over "
            "req.rawBody with timingSafeEqual before any invoice or ledger entry is touched."
        ),
        "authz": False,
    },
    {
        "slug": "messaging-provider-config",
        "path": "functions/src/integrations/messagingProviders.ts",
        "pairedWith": "centre-webhook-registration",
        "why": (
            "The same probe-then-store flow, but parseApprovedEndpoint requires https, the "
            "default port and an exact hostname match against APPROVED_PROVIDER_HOSTS before "
            "fetch() is reached, so the caller cannot steer the outbound request at an internal "
            "address."
        ),
        "authz": True,
    },
]


def case_id(slug):
    return "h7-{}-{}".format(FAMILY, slug)


def base(entry):
    case = {
        "id": case_id(entry["slug"]),
        "family": FAMILY,
        "architecture": ARCH,
        "language": "typescript",
        "file": "{}/{}".format(FAMILY, entry["path"]),
        "scanAs": entry["path"],
    }
    return case


def build():
    cases = []
    for entry in VULN:
        case = base(entry)
        case.update(
            {
                "kind": "vulnerable",
                "category": entry["category"],
                "cwe": entry["cwe"],
                "severityBand": entry["severityBand"],
                "line": entry["line"],
                "lineRange": entry["lineRange"],
                "runtimeVerifiable": True,
                "why": entry["why"],
                "packageJson": PKG,
            }
        )
        if entry["authz"]:
            case["extraFiles"] = {AUTHZ_PATH: AUTHZ}
        cases.append(case)

    for entry in SAFE:
        case = base(entry)
        case.update(
            {
                "kind": "safe",
                "runtimeVerifiable": True,
                "pairedWith": case_id(entry["pairedWith"]),
                "why": entry["why"],
                "packageJson": PKG,
            }
        )
        if entry["authz"]:
            case["extraFiles"] = {AUTHZ_PATH: AUTHZ}
        cases.append(case)

    return {"family": FAMILY, "cases": cases}


def main():
    doc = build()

    seen = set()
    for case in doc["cases"]:
        assert case["id"] not in seen, case["id"]
        seen.add(case["id"])
        on_disk = os.path.join(ROOT, case["scanAs"])
        assert os.path.isfile(on_disk), on_disk
        assert case["file"] == "{}/{}".format(FAMILY, case["scanAs"])
        total = sum(1 for _ in open(on_disk, encoding="utf-8"))
        if case["kind"] == "vulnerable":
            low, high = case["lineRange"]
            assert low <= case["line"] <= high, case["id"]
            assert high <= total, (case["id"], high, total)
        else:
            assert case["pairedWith"] in seen, case["pairedWith"]
            assert "category" not in case

    out = os.path.join(ROOT, "cases.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    print("wrote {} cases to {}".format(len(doc["cases"]), out))


if __name__ == "__main__":
    main()
