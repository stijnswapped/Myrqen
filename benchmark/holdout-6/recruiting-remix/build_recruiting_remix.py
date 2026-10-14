#!/usr/bin/env python3
"""Builds cases.json for the recruiting-remix holdout family.

Line numbers are resolved from anchor substrings in the real source files so the
ground truth cannot drift out of sync with the code.
"""
import json
import pathlib

FAMILY = "recruiting-remix"
ROOT = pathlib.Path(__file__).resolve().parent
APP = ROOT / "app"

ARCHITECTURE = (
    "React Router 7 in framework mode (route modules exporting loader/action), Kysely over "
    "Postgres for all data access, and the acting user resolved from a signed cookie session "
    "read in each loader through app/sessions.server.ts."
)

PACKAGE_JSON = {
    "name": "ats-web",
    "version": "1.6.0",
    "private": True,
    "type": "module",
    "scripts": {
        "build": "react-router build",
        "dev": "react-router dev",
        "start": "react-router-serve ./build/server/index.js",
        "typecheck": "react-router typegen && tsc",
    },
    "dependencies": {
        "@react-router/node": "^7.5.1",
        "@react-router/serve": "^7.5.1",
        "isbot": "^5.1.17",
        "kysely": "^0.27.5",
        "pg": "^8.13.1",
        "react": "^19.0.0",
        "react-dom": "^19.0.0",
        "react-router": "^7.5.1",
        "sanitize-html": "^2.14.0",
        "zod": "^3.24.1",
    },
    "devDependencies": {
        "@react-router/dev": "^7.5.1",
        "@types/pg": "^8.11.11",
        "@types/react": "^19.0.8",
        "@types/react-dom": "^19.0.3",
        "@types/sanitize-html": "^2.13.0",
        "typescript": "^5.7.3",
        "vite": "^6.1.0",
    },
}

DB = "app/db/client.ts"
SESSIONS = "app/sessions.server.ts"
TEAM = "app/lib/hiring-team.server.ts"
ROUTES = "app/routes.ts"


VIRTUAL_FILES = {
    "app/routes.ts": """import { type RouteConfig, route } from "@react-router/dev/routes";

/**
 * Route table. The three careers-site routes at the top are reachable without a
 * session; every route below them calls requireUser()/requireRole() in its own
 * loader, because a shared layout loader does not run for resource requests
 * such as the attachment downloads.
 */
export default [
  route("jobs", "routes/job-board.tsx"),
  route("jobs/:reference", "routes/requisition-description.tsx"),
  route("apply/status", "routes/application-status.tsx"),

  route("candidates", "routes/candidate-search.tsx"),
  route("candidates/:candidateId", "routes/candidate-profile.tsx"),
  route("candidates/:candidateId/attachments", "routes/attachment-download.tsx"),
  route("requisitions/:requisitionId/pipeline", "routes/requisition-pipeline.tsx"),
  route("requisitions/:requisitionId/edit", "routes/requisition-edit.tsx"),
  route("applications/:applicationId/review", "routes/application-review.tsx"),
  route("scorecards/:scorecardId", "routes/scorecard-detail.tsx"),
  route("offers/:offerId/letter", "routes/offer-letter-download.tsx"),
] satisfies RouteConfig;
""",
}


def read(app_relative_path):
    if app_relative_path in VIRTUAL_FILES:
        return VIRTUAL_FILES[app_relative_path]
    return (APP.parent / app_relative_path).read_text()


def line_of(app_relative_path, needle):
    text = read(app_relative_path)
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    raise SystemExit(f"anchor not found in {app_relative_path}: {needle!r}")


def extra(*paths):
    return {path: read(path) for path in paths}


CASES = []


def add(case):
    case["family"] = FAMILY
    case["architecture"] = ARCHITECTURE
    case["language"] = "typescript"
    case["packageJson"] = PACKAGE_JSON
    scan_as = case["scanAs"]
    case["file"] = f"{FAMILY}/{scan_as}"
    CASES.append(case)


# --- 1. search predicate built by hand ---------------------------------------
SEARCH = "app/routes/candidate-search.tsx"
add({
    "id": "h6-recruiting-remix-candidate-search-filter",
    "scanAs": SEARCH,
    "kind": "vulnerable",
    "category": "raw_sql_predicate_string_interpolation",
    "cwe": "CWE-89",
    "severityBand": ["high", "critical"],
    "line": line_of(SEARCH, "const matchPredicate = sql.raw("),
    "lineRange": [
        line_of(SEARCH, 'const term = (url.searchParams.get("q")'),
        line_of(SEARCH, "`.execute(db);"),
    ],
    "route": "GET /candidates",
    "runtimeVerifiable": True,
    "why": (
        "The `q` search parameter is concatenated into a SQL predicate through Kysely's "
        "sql.raw(), which emits its argument as literal statement text rather than a bound "
        "parameter, and that fragment is then executed against the candidates table. A term "
        "containing a single quote closes the literal and appends attacker-chosen SQL to the "
        "recruiter's query."
    ),
    "extraFiles": extra(DB, SESSIONS, ROUTES),
})

PIPELINE = "app/routes/requisition-pipeline.tsx"
add({
    "id": "h6-recruiting-remix-pipeline-filter",
    "scanAs": PIPELINE,
    "kind": "safe",
    "route": "GET /requisitions/:requisitionId/pipeline",
    "runtimeVerifiable": True,
    "pairedWith": "h6-recruiting-remix-candidate-search-filter",
    "why": (
        "Same raw `sql` template shape and the same free-text filter, but the ilike pattern is "
        "interpolated as `${pattern}` into a Kysely sql template, which binds it as a query "
        "parameter; the only sql.raw() call takes its value from the fixed SORT_CLAUSES map, so "
        "no request-controlled text reaches the statement text."
    ),
    "extraFiles": extra(DB, SESSIONS, TEAM, ROUTES),
})

# --- 2. scorecard read without the hiring-team predicate ---------------------
SCORECARD = "app/routes/scorecard-detail.tsx"
add({
    "id": "h6-recruiting-remix-scorecard-open",
    "scanAs": SCORECARD,
    "kind": "vulnerable",
    "category": "scorecard_lookup_missing_hiring_team_scope",
    "cwe": "CWE-639",
    "severityBand": ["medium", "high"],
    "line": line_of(SCORECARD, '.where("s.id", "=", scorecardId)'),
    "lineRange": [
        line_of(SCORECARD, "const user = await requireUser(request);"),
        line_of(SCORECARD, "if (!scorecard) {"),
    ],
    "route": "GET /scorecards/:scorecardId",
    "runtimeVerifiable": True,
    "why": (
        "The loader selects the scorecard purely by the `scorecardId` URL parameter after "
        "requireUser(), with no hiring_team_members predicate and no comparison against the "
        "session user, so any signed-in ATS account can enumerate scorecard ids and read "
        "interview notes, candidate names and salary expectations for requisitions it is not "
        "staffed on. The action on the same route does scope its write to the assigned "
        "interviewer."
    ),
    "extraFiles": extra(DB, SESSIONS, ROUTES),
})

add({
    "id": "h6-recruiting-remix-scorecard-reviewer-lookup",
    "scanAs": TEAM,
    "kind": "safe",
    "runtimeVerifiable": True,
    "pairedWith": "h6-recruiting-remix-scorecard-open",
    "why": (
        "Same by-id scorecard lookup driven by a caller-supplied id, but the statement inner "
        "joins hiring_team_members on the requisition with `htm.user_id = user.id`, so an id "
        "outside the reader's staffed requisitions returns no row at all; assertRequisitionAccess "
        "applies the same membership rule for callers that only hold a requisition id."
    ),
    "extraFiles": extra(DB, SESSIONS),
})

# --- 3. whole form body written onto the candidate row ----------------------
PROFILE = "app/routes/candidate-profile.tsx"
add({
    "id": "h6-recruiting-remix-candidate-profile-save",
    "scanAs": PROFILE,
    "kind": "vulnerable",
    "category": "form_body_to_column_passthrough",
    "cwe": "CWE-915",
    "severityBand": ["medium", "high"],
    "line": line_of(PROFILE, 'await db.updateTable("candidates").set(patch)'),
    "lineRange": [
        line_of(PROFILE, "const form = await request.formData();"),
        line_of(PROFILE, 'console.info("candidate.updated"'),
    ],
    "route": "POST /candidates/:candidateId",
    "runtimeVerifiable": True,
    "why": (
        "The action turns the entire multipart body into an object with Object.fromEntries(form) "
        "and hands it to Kysely's .set() with only `intent` removed, so a crafted POST can write "
        "any candidates column the form never renders — stage, internal_rating, owner_user_id, "
        "recruiter_notes or national_id_last4 — while still passing the recruiter role check."
    ),
    "extraFiles": extra(DB, SESSIONS, ROUTES),
})

EDIT = "app/routes/requisition-edit.tsx"
add({
    "id": "h6-recruiting-remix-requisition-save",
    "scanAs": EDIT,
    "kind": "safe",
    "route": "POST /requisitions/:requisitionId/edit",
    "runtimeVerifiable": True,
    "pairedWith": "h6-recruiting-remix-candidate-profile-save",
    "why": (
        "Same formData-to-update flow on a table that also carries privileged columns "
        "(headcount, owner_user_id, salary bands), but the action reads five named keys with "
        "form.get(), validates them through the zod schema and writes an explicitly spelled-out "
        ".set() object, so extra fields in the body are never read and never reach the statement."
    ),
    "extraFiles": extra(DB, SESSIONS, TEAM, ROUTES),
})

# --- 4. attachment key joined onto the storage root -------------------------
ATTACHMENT = "app/routes/attachment-download.tsx"
add({
    "id": "h6-recruiting-remix-cv-attachment-fetch",
    "scanAs": ATTACHMENT,
    "kind": "vulnerable",
    "category": "storage_key_escapes_attachment_root",
    "cwe": "CWE-22",
    "severityBand": ["high", "critical"],
    "line": line_of(ATTACHMENT, "const filePath = path.join(ATTACHMENT_ROOT, key);"),
    "lineRange": [
        line_of(ATTACHMENT, 'const key = url.searchParams.get("key");'),
        line_of(ATTACHMENT, "const body = await readFile(filePath);"),
    ],
    "route": "GET /candidates/:candidateId/attachments",
    "runtimeVerifiable": True,
    "why": (
        "The `key` query parameter is joined onto ATTACHMENT_ROOT with path.join() and read with "
        "readFile() without ever being checked against the attachments table or re-resolved "
        "against the root, so a staffed reviewer can pass ../../ segments and stream any file "
        "the Node process can open back to themselves."
    ),
    "extraFiles": extra(DB, SESSIONS, ROUTES),
})

OFFER = "app/routes/offer-letter-download.tsx"
add({
    "id": "h6-recruiting-remix-offer-letter-fetch",
    "scanAs": OFFER,
    "kind": "safe",
    "route": "GET /offers/:offerId/letter",
    "runtimeVerifiable": True,
    "pairedWith": "h6-recruiting-remix-cv-attachment-fetch",
    "why": (
        "Same pattern of joining a stored key onto a storage root and reading the file, but the "
        "key is taken from the attachments row reached through the requested offer and the joined "
        "path is re-resolved and required to sit under the resolved OFFER_ROOT before readFile() "
        "is called, so a key with ../ segments is rejected with a 403."
    ),
    "extraFiles": extra(DB, SESSIONS, TEAM, ROUTES),
})

# --- 5. applicant markup rendered into the reviewer page -------------------
REVIEW = "app/routes/application-review.tsx"
add({
    "id": "h6-recruiting-remix-cover-letter-render",
    "scanAs": REVIEW,
    "kind": "vulnerable",
    "category": "applicant_authored_markup_rendered_as_html",
    "cwe": "CWE-79",
    "severityBand": ["medium", "high"],
    "line": line_of(REVIEW, "dangerouslySetInnerHTML={{ __html: application.cover_letter_html"),
    "lineRange": [
        line_of(REVIEW, '"a.cover_letter_html",'),
        line_of(REVIEW, "dangerouslySetInnerHTML={{ __html: application.cover_letter_html") + 1,
    ],
    "route": "GET /applications/:applicationId/review",
    "runtimeVerifiable": True,
    "why": (
        "applications.cover_letter_html is written by the unauthenticated public application "
        "form, is selected unchanged by the loader and is injected into the reviewer's page with "
        "dangerouslySetInnerHTML, so an applicant chooses script that runs in the session of "
        "every recruiter who opens the application."
    ),
    "extraFiles": extra(DB, SESSIONS, ROUTES),
})

DESCRIPTION = "app/routes/requisition-description.tsx"
add({
    "id": "h6-recruiting-remix-job-description-render",
    "scanAs": DESCRIPTION,
    "kind": "safe",
    "route": "GET /jobs/:reference",
    "runtimeVerifiable": True,
    "pairedWith": "h6-recruiting-remix-cover-letter-render",
    "why": (
        "Also renders stored rich-text markup through dangerouslySetInnerHTML, but the loader "
        "passes description_html through sanitize-html with an explicit allowedTags/"
        "allowedAttributes/allowedSchemes policy before it leaves the server, so the value the "
        "component receives can no longer carry script, event handlers or javascript: URLs."
    ),
    "extraFiles": extra(DB, ROUTES),
})

# --- 6. public loader returning the whole joined row -----------------------
STATUS = "app/routes/application-status.tsx"
add({
    "id": "h6-recruiting-remix-applicant-status-lookup",
    "scanAs": STATUS,
    "kind": "vulnerable",
    "category": "public_loader_returns_internal_columns",
    "cwe": "CWE-200",
    "severityBand": ["medium", "high"],
    "line": line_of(STATUS, '.selectAll(["a", "c", "r"])'),
    "lineRange": [
        line_of(STATUS, 'const token = url.searchParams.get("token");'),
        line_of(STATUS, "return { application: row };"),
    ],
    "route": "GET /apply/status",
    "runtimeVerifiable": True,
    "why": (
        "This unauthenticated route selectAll()s the joined applications, candidates and "
        "requisitions row and returns it from the loader; React Router serializes loader data "
        "into the document it sends the applicant, so internal_rating, recruiter_notes, "
        "expected_salary, national_id_last4, the salary band and the requisition owner all reach "
        "the applicant even though the component only renders the status timeline."
    ),
    "extraFiles": extra(DB, ROUTES),
})

BOARD = "app/routes/job-board.tsx"
add({
    "id": "h6-recruiting-remix-job-board-listing",
    "scanAs": BOARD,
    "kind": "safe",
    "route": "GET /jobs",
    "runtimeVerifiable": True,
    "pairedWith": "h6-recruiting-remix-applicant-status-lookup",
    "why": (
        "Another unauthenticated loader returning requisition rows straight to the browser, but "
        "the projection is an explicit column list covering only what the careers page renders, "
        "so the privileged columns on the same table — salary_band_min/max, headcount, "
        "owner_user_id — are never loaded and never serialized into the public document."
    ),
    "extraFiles": extra(DB, ROUTES),
})

for case in CASES:
    if case["kind"] == "vulnerable":
        low, high = case["lineRange"]
        assert low <= case["line"] <= high, case["id"]
        assert case["cwe"].startswith("CWE-"), case["id"]
    else:
        assert "category" not in case, case["id"]
        assert case["pairedWith"] in {c["id"] for c in CASES if c["kind"] == "vulnerable"}, case["id"]

ids = [case["id"] for case in CASES]
assert len(ids) == len(set(ids))
scan_paths = [case["scanAs"] for case in CASES]
assert len(scan_paths) == len(set(scan_paths))
for case in CASES:
    assert case["scanAs"] not in case.get("extraFiles", {}), case["id"]

document = {"family": FAMILY, "cases": CASES}
(ROOT / "cases.json").write_text(json.dumps(document, indent=2) + "\n")

vulnerable = [c for c in CASES if c["kind"] == "vulnerable"]
safe = [c for c in CASES if c["kind"] == "safe"]
print(f"vulnerable={len(vulnerable)} safe={len(safe)}")
for case in vulnerable:
    print(f"  {case['category']}  {case['cwe']}  line={case['line']} range={case['lineRange']}")
