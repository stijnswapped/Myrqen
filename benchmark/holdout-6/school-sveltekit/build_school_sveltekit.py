#!/usr/bin/env python3
"""Emit cases.json for the school-sveltekit holdout-6 family.

Line numbers are derived from anchor substrings in the real source files so the
ground truth cannot drift away from the code.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FAMILY = "school-sveltekit"

ARCHITECTURE = (
    "SvelteKit 2 server routes (+page.server.ts form actions and +server.ts handlers) over a "
    "synchronous better-sqlite3 connection, with the staff session resolved from a signed cookie "
    "in hooks.server.ts and exposed as event.locals.user."
)

PACKAGE_JSON = {
    "name": "school-portal",
    "version": "2.4.0",
    "private": True,
    "type": "module",
    "scripts": {
        "dev": "vite dev",
        "build": "vite build",
        "preview": "vite preview",
        "check": "svelte-kit sync && svelte-check --tsconfig ./tsconfig.json",
    },
    "dependencies": {"better-sqlite3": "^11.5.0", "csv-parse": "^5.5.6"},
    "devDependencies": {
        "@sveltejs/adapter-node": "^5.2.9",
        "@sveltejs/kit": "^2.8.3",
        "@sveltejs/vite-plugin-svelte": "^4.0.1",
        "@types/better-sqlite3": "^7.6.11",
        "svelte": "^5.2.7",
        "svelte-check": "^4.0.9",
        "typescript": "^5.6.3",
        "vite": "^5.4.11",
    },
}

SHARED_MODULE_PATHS = (
    "src/hooks.server.ts",
    "src/lib/server/db.ts",
    "src/lib/server/staffSession.ts",
)


def read(scan_as: str) -> str:
    return (ROOT / scan_as).read_text(encoding="utf-8")


def line_of(scan_as: str, anchor: str) -> int:
    lines = read(scan_as).splitlines()
    hits = [i + 1 for i, text in enumerate(lines) if anchor in text]
    if len(hits) != 1:
        raise SystemExit(f"anchor {anchor!r} matched {len(hits)} lines in {scan_as}")
    return hits[0]


SHARED_FILES = {path: read(path) for path in SHARED_MODULE_PATHS}


def vulnerable(
    slug: str,
    scan_as: str,
    category: str,
    cwe: str,
    bands: list[str],
    anchor_line: str,
    anchor_start: str,
    anchor_end: str,
    why: str,
    route: str | None = None,
) -> dict:
    line = line_of(scan_as, anchor_line)
    start = line_of(scan_as, anchor_start)
    end = line_of(scan_as, anchor_end)
    if not start <= line <= end:
        raise SystemExit(f"{slug}: line {line} outside range [{start}, {end}]")
    case = {
        "id": f"h6-{FAMILY}-{slug}",
        "family": FAMILY,
        "architecture": ARCHITECTURE,
        "language": "typescript",
        "file": f"{FAMILY}/{scan_as}",
        "scanAs": scan_as,
        "kind": "vulnerable",
        "category": category,
        "cwe": cwe,
        "severityBand": bands,
        "line": line,
        "lineRange": [start, end],
        "runtimeVerifiable": True,
        "why": why,
        "packageJson": PACKAGE_JSON,
        "extraFiles": dict(SHARED_FILES),
    }
    if route:
        case["route"] = route
    return case


def safe(slug: str, scan_as: str, paired_with: str, why: str, route: str | None = None) -> dict:
    case = {
        "id": f"h6-{FAMILY}-{slug}",
        "family": FAMILY,
        "architecture": ARCHITECTURE,
        "language": "typescript",
        "file": f"{FAMILY}/{scan_as}",
        "scanAs": scan_as,
        "kind": "safe",
        "runtimeVerifiable": True,
        "pairedWith": f"h6-{FAMILY}-{paired_with}",
        "why": why,
        "packageJson": PACKAGE_JSON,
        "extraFiles": dict(SHARED_FILES),
    }
    if route:
        case["route"] = route
    return case


cases = [
    vulnerable(
        slug="pupil-roll-search",
        scan_as="src/routes/pupils/+page.server.ts",
        category="pupil_roll_search_predicate_string_interpolation",
        cwe="CWE-89",
        bands=["high", "critical"],
        anchor_line="`(p.surname like '%${query}%'",
        anchor_start="const query = (url.searchParams.get('q')",
        anchor_end=".all() as RollRow[];",
        why=(
            "The roll loader interpolates the untrusted q, year and sort query-string values straight "
            "into the WHERE predicates and the ORDER BY clause of a better-sqlite3 statement built at "
            "request time, so a crafted q can close the string literal and append its own SQL against "
            "the pupil, guardian and staff tables."
        ),
        route="GET /pupils",
    ),
    safe(
        slug="attendance-register-search",
        scan_as="src/routes/attendance/registers/+page.server.ts",
        paired_with="pupil-roll-search",
        why=(
            "Structurally the same free-text-plus-filter register search, but every registrar-supplied "
            "value (including the LIKE wildcards) is pushed onto the bound-parameter array and the sort "
            "column is resolved through the fixed SORT_COLUMNS map, so the SQL text is constant."
        ),
        route="GET /attendance/registers",
    ),
    vulnerable(
        slug="pupil-record-view",
        scan_as="src/routes/pupils/[id]/+page.server.ts",
        category="cross_class_pupil_record_exposure",
        cwe="CWE-639",
        bands=["high"],
        anchor_line="const pupil = pupilRecord.get(pupilId) as PupilRecord",
        anchor_start="export const load: PageServerLoad = async ({ params, locals }) => {",
        anchor_end="canEdit: pupil.formTeacherId === user.id",
        why=(
            "params.id is used as the only key into the pupil record: the loader proves the caller is "
            "some signed-in member of staff and then returns medical notes, safeguarding notes and "
            "guardian phone numbers for any id, so a form teacher can enumerate ids and read pupils "
            "outside their own group. The code knows the relation exists — it uses it for canEdit."
        ),
        route="GET /pupils/[id]",
    ),
    safe(
        slug="guardian-contact-view",
        scan_as="src/routes/guardians/[id]/+page.server.ts",
        paired_with="pupil-record-view",
        why=(
            "The same id-in-the-path contact lookup, but a teacher's query joins guardian to pupil to "
            "form_class and requires c.form_teacher_id = the caller, so a contact outside their group "
            "never loads and returns the same 404 as a missing id; only whole-school roles skip the join."
        ),
        route="GET /guardians/[id]",
    ),
    vulnerable(
        slug="report-card-download",
        scan_as="src/routes/api/reports/[document]/+server.ts",
        category="report_card_store_path_escape",
        cwe="CWE-22",
        bands=["high"],
        anchor_line="const target = path.join(REPORT_CARD_ROOT, requested);",
        anchor_start="const requested = decodeURIComponent(params.document);",
        anchor_end="const body = readFileSync(target);",
        why=(
            "The [document] segment is percent-decoded and joined onto REPORT_CARD_ROOT with no "
            "containment check, so ..%2f sequences walk out of the report-card store and readFileSync "
            "returns any .pdf on the host to any signed-in member of staff."
        ),
        route="GET /api/reports/[document]",
    ),
    safe(
        slug="transcript-download",
        scan_as="src/routes/api/transcripts/[id]/+server.ts",
        paired_with="report-card-download",
        why=(
            "Same read-a-pdf-off-disk handler, but the path never comes from the URL: the numeric id is "
            "looked up in the transcript table, only path.basename of the stored filename is used, and "
            "the resolved path must sit under the resolved TRANSCRIPT_ROOT before the read happens."
        ),
        route="GET /api/transcripts/[id]",
    ),
    vulnerable(
        slug="report-card-render",
        scan_as="src/routes/admin/report-cards/+page.server.ts",
        category="pdf_renderer_shell_argument_injection",
        cwe="CWE-78",
        bands=["high", "critical"],
        anchor_line="execSync(command, { cwd: REPORT_CARD_ROOT, timeout: 120_000 });",
        anchor_start="const closingRemark = String(form.get('closingRemark')",
        anchor_end="execSync(command, { cwd: REPORT_CARD_ROOT, timeout: 120_000 });",
        why=(
            "closingRemark comes off the form action's FormData and is concatenated, inside double "
            "quotes, into the wkhtmltopdf command string handed to execSync, which runs it through a "
            "shell; a remark containing \" ; or $( executes attacker-chosen commands as the portal user."
        ),
        route="POST /admin/report-cards",
    ),
    safe(
        slug="leaving-certificate-render",
        scan_as="src/routes/admin/leaving-certificates/+page.server.ts",
        paired_with="report-card-render",
        why=(
            "The same wkhtmltopdf render driven by the same staff-typed remark, but invoked with "
            "execFileSync, an argv array and shell: false, and both file paths are built from the row id "
            "and a regex-validated term code, so shell metacharacters stay a literal footer string."
        ),
        route="POST /admin/leaving-certificates",
    ),
    vulnerable(
        slug="staff-role-assignment",
        scan_as="src/routes/admin/staff/+page.server.ts",
        category="staff_role_assignment_missing_privilege_check",
        cwe="CWE-269",
        bands=["high", "critical"],
        anchor_line="const user = requireStaff(locals);",
        anchor_start="* Move a member of staff between roles at the start of term.",
        anchor_end=".run(role, user.id, staffId);",
        why=(
            "The assignRole action only calls requireStaff, trusting the /admin layout load to have "
            "checked the headteacher role — but SvelteKit runs form actions before any load, so any "
            "signed-in teacher can POST staffId=self&role=headteacher and elevate their own account. "
            "The sibling assignFormClass action in the same file does call requireRole."
        ),
        route="POST /admin/staff",
    ),
    safe(
        slug="staff-permission-update",
        scan_as="src/routes/admin/staff/[id]/+page.server.ts",
        paired_with="staff-role-assignment",
        why=(
            "The same kind of privilege-granting form action, but it calls requireRole(locals, "
            "'headteacher') inside the action rather than relying on the layout, refuses when the target "
            "id is the caller's own, and only accepts flags present in GRANTABLE_FLAGS."
        ),
        route="POST /admin/staff/[id]",
    ),
    vulnerable(
        slug="pupil-roll-import",
        scan_as="src/routes/imports/pupils/+server.ts",
        category="bulk_import_reflective_column_assignment",
        cwe="CWE-915",
        bands=["medium", "high"],
        anchor_line="const writable = headers.filter((header) => header !== 'reference' && pupilColumns.has(header));",
        anchor_start="const headers = Object.keys(rows[0]);",
        anchor_end="const result = statement.run(...columns.map((column) => row[column].trim()), reference);",
        why=(
            "The uploaded CSV's own header row decides which pupil columns get written: any header that "
            "matches the reflected sqlite schema becomes part of the UPDATE, so an office-role clerk can "
            "add a safeguarding_restricted, fee_waiver_approved_by or left_on column to the spreadsheet "
            "and overwrite fields that belong to other workflows."
        ),
        route="POST /imports/pupils",
    ),
    safe(
        slug="guardian-contact-import",
        scan_as="src/routes/imports/guardians/+server.ts",
        paired_with="pupil-roll-import",
        why=(
            "The same csv-parse bulk UPDATE, but the writable set is the intersection of the header row "
            "with the fixed IMPORTABLE_COLUMNS allow list, and any other column aborts the import with a "
            "422, so safeguarding-owned fields cannot be reached from a spreadsheet."
        ),
        route="POST /imports/guardians",
    ),
]

seen_ids: set[str] = set()
seen_paths: set[str] = set()
for case in cases:
    assert case["id"] not in seen_ids, case["id"]
    assert case["scanAs"] not in seen_paths, case["scanAs"]
    seen_ids.add(case["id"])
    seen_paths.add(case["scanAs"])
    assert (ROOT / case["scanAs"]).is_file(), case["scanAs"]

paired = {c["pairedWith"] for c in cases if c["kind"] == "safe"}
assert paired <= seen_ids, paired - seen_ids

payload = {"family": FAMILY, "cases": cases}
(ROOT / "cases.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

vulnerable_cases = [c for c in cases if c["kind"] == "vulnerable"]
safe_cases = [c for c in cases if c["kind"] == "safe"]
print(f"vulnerable: {len(vulnerable_cases)}  safe: {len(safe_cases)}")
for case in vulnerable_cases:
    print(
        f"  {case['category']:<52} {case['cwe']:<9} line {case['line']:>3} "
        f"range {case['lineRange']}  {case['scanAs']}"
    )
