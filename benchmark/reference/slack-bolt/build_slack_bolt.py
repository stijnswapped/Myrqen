#!/usr/bin/env python3
"""Emit cases.json for the slack-bolt reference family.

extraFiles text is read from the real files on disk so the shipped copies can never
drift from the application in this directory.
"""
import json
import pathlib

FAMILY = "slack-bolt"
ROOT = pathlib.Path(__file__).resolve().parent

ARCH = (
    "Slack Bolt for JavaScript 3.x (@slack/bolt) internal purchasing app in TypeScript, "
    "with Sequelize 6 over Postgres as the only data layer, and the caller's identity taken "
    "from the Slack interaction payload (command.user_id / body.user.id / event.user plus "
    "team_id) and resolved against the members table."
)

PACKAGE_JSON = {
    "name": "requisition-slack",
    "version": "1.4.2",
    "private": True,
    "dependencies": {
        "@slack/bolt": "^3.19.0",
        "pg": "^8.11.5",
        "pg-hstore": "^2.3.4",
        "sequelize": "^6.37.3",
    },
    "devDependencies": {
        "@types/node": "^20.12.7",
        "typescript": "^5.4.5",
    },
}

SHARED = ["src/db/models.ts", "src/lib/slack.ts"]


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def extra_files():
    return {path: read(path) for path in SHARED}


CASES = [
    {
        "id": "ref-slack-bolt-requisition-search",
        "scanAs": "src/commands/requisition-search.ts",
        "kind": "vulnerable",
        "category": "sql_injection_via_slash_command_text",
        "cwe": "CWE-89",
        "severityBand": ["high", "critical"],
        "line": 68,
        "lineRange": [22, 72],
        "why": (
            "The search term and the sort column are taken straight out of command.text by "
            "parseArgs and pasted into a sequelize.query template literal, so anyone who can "
            "run /req-search controls the text of the statement; the cost-centre filter the "
            "comment relies on sits in the same string and can be commented out or unioned past."
        ),
    },
    {
        "id": "ref-slack-bolt-spend-report",
        "scanAs": "src/commands/spend-report.ts",
        "kind": "safe",
        "pairedWith": "ref-slack-bolt-requisition-search",
        "why": (
            "Same raw sequelize.query shape over the same tables, but every value from "
            "command.text goes in through replacements, and the only interpolated fragment is "
            "a column name looked up in the SORT_COLUMNS allowlist, which falls back to a "
            "known column when the key is unknown."
        ),
    },
    {
        "id": "ref-slack-bolt-approval-button",
        "scanAs": "src/actions/approval-buttons.ts",
        "kind": "vulnerable",
        "category": "authorization_decision_from_block_action_value",
        "cwe": "CWE-807",
        "severityBand": ["high", "critical"],
        "line": 58,
        "lineRange": [24, 79],
        "why": (
            "The handler resolves the clicker's member row for identity and scopes the lookup to "
            "their cost centre, but the role and the spending ceiling it then checks are "
            "approverRole and limitCents out of the button's own value, which is round-tripped "
            "through the client and can be replayed with any contents, so a plain requester can "
            "approve and any approver can approve above their real limit."
        ),
    },
    {
        "id": "ref-slack-bolt-escalation-button",
        "scanAs": "src/actions/escalation-buttons.ts",
        "kind": "safe",
        "pairedWith": "ref-slack-bolt-approval-button",
        "why": (
            "It parses the same kind of JSON out of the same button value, but takes only the "
            "requisition id from it: requireRole re-reads the caller's role from the members "
            "table by body.user.id and team id, and the ceiling it compares against is "
            "member.approvalLimitCents rather than anything the payload carried."
        ),
    },
    {
        "id": "ref-slack-bolt-budget-transfer",
        "scanAs": "src/views/budget-transfer.ts",
        "kind": "vulnerable",
        "category": "object_reference_from_modal_private_metadata",
        "cwe": "CWE-639",
        "severityBand": ["high"],
        "line": 29,
        "lineRange": [25, 61],
        "why": (
            "sourceBudgetId comes from view.private_metadata, which the submitting client sends "
            "back and can change, and the handler loads that budget by primary key and moves "
            "allocation off it without checking that the submitter owns or belongs to either "
            "budget's cost centre — the signature on the payload proves it came from Slack, not "
            "that this user may spend that line."
        ),
    },
    {
        "id": "ref-slack-bolt-requisition-reassign",
        "scanAs": "src/views/requisition-reassign.ts",
        "kind": "safe",
        "pairedWith": "ref-slack-bolt-budget-transfer",
        "why": (
            "The requisition id also arrives in private_metadata, but the write is gated on a "
            "findOne scoped to the submitter's own costCenterId and status 'draft' resolved from "
            "the members table, so a tampered id simply matches no row and the submission is "
            "acked with an error."
        ),
    },
    {
        "id": "ref-slack-bolt-member-profile",
        "scanAs": "src/views/member-profile.ts",
        "kind": "vulnerable",
        "category": "mass_assignment_from_modal_state_values",
        "cwe": "CWE-915",
        "severityBand": ["high", "critical"],
        "line": 40,
        "lineRange": [23, 42],
        "why": (
            "The patch object is keyed by whatever block_ids came back in view.state.values and "
            "handed whole to Member.update, and block ids are part of the payload the client "
            "submits, so a crafted view submission can set role or approvalLimitCents on the "
            "caller's own member row."
        ),
    },
    {
        "id": "ref-slack-bolt-notification-preferences",
        "scanAs": "src/views/notification-preferences.ts",
        "kind": "safe",
        "pairedWith": "ref-slack-bolt-member-profile",
        "why": (
            "The same block-id loop feeds the same Member.update, but every block id is checked "
            "against the EDITABLE_COLUMNS allowlist before it can reach the patch and digestHour "
            "is range-checked, so nothing outside the three preference columns can be written."
        ),
    },
    {
        "id": "ref-slack-bolt-purchase-order-void",
        "scanAs": "src/commands/purchase-order-void.ts",
        "kind": "vulnerable",
        "category": "workspace_admin_flag_used_as_application_role",
        "cwe": "CWE-863",
        "severityBand": ["medium", "high"],
        "line": 28,
        "lineRange": [24, 46],
        "why": (
            "The finance gate on voiding a purchase order is users.info's is_admin/is_owner, "
            "which describes the caller's standing in the Slack workspace and not the role they "
            "hold in Requisition, so any workspace admin can void any approved order on any cost "
            "centre while a genuine finance_admin who is an ordinary Slack user cannot."
        ),
    },
    {
        "id": "ref-slack-bolt-purchase-order-close",
        "scanAs": "src/commands/purchase-order-close.ts",
        "kind": "safe",
        "pairedWith": "ref-slack-bolt-purchase-order-void",
        "why": (
            "The mirror-image state change is gated on requireRole(command.user_id, "
            "command.team_id, ['finance_admin']), which reads the role from the members table, "
            "and the order is then fetched scoped to that member's cost centre; no Slack "
            "workspace flag takes part in the decision."
        ),
    },
    {
        "id": "ref-slack-bolt-requisition-digest",
        "scanAs": "src/events/requisition-digest.ts",
        "kind": "vulnerable",
        "category": "missing_authorization_on_sensitive_record_read",
        "cwe": "CWE-862",
        "severityBand": ["medium", "high"],
        "line": 32,
        "lineRange": [15, 67],
        "why": (
            "Any reference mentioned by anyone the bot can hear is looked up unscoped and the "
            "reply posts the vendor's tax id, remittance address, bank account tail, negotiated "
            "rate and the contract price into the channel; event.user is never resolved to a "
            "member and the requisition is never checked against that member's cost centre."
        ),
    },
    {
        "id": "ref-slack-bolt-approval-reminder",
        "scanAs": "src/events/approval-reminders.ts",
        "kind": "safe",
        "pairedWith": "ref-slack-bolt-requisition-digest",
        "why": (
            "The same commercial detail is assembled from the same models, but event.user is "
            "resolved through resolveMember, the requisition is fetched with costCenterId scoped "
            "to that member, and the vendor terms go back by chat.postEphemeral to the asker "
            "while the in-channel reply carries only the status."
        ),
    },
]


def build():
    out = {"family": FAMILY, "cases": []}
    for case in CASES:
        scan_as = case["scanAs"]
        record = {
            "id": case["id"],
            "family": FAMILY,
            "architecture": ARCH,
            "language": "typescript",
            "file": f"{FAMILY}/{scan_as}",
            "scanAs": scan_as,
            "kind": case["kind"],
        }
        if case["kind"] == "vulnerable":
            record["category"] = case["category"]
            record["cwe"] = case["cwe"]
            record["severityBand"] = case["severityBand"]
            record["line"] = case["line"]
            record["lineRange"] = case["lineRange"]
        else:
            record["pairedWith"] = case["pairedWith"]
        record["runtimeVerifiable"] = True
        record["why"] = case["why"]
        record["packageJson"] = PACKAGE_JSON
        record["extraFiles"] = extra_files()
        out["cases"].append(record)
    (ROOT / "cases.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"cases: {len(out['cases'])}")
    print("vulnerable:", sum(1 for c in out["cases"] if c["kind"] == "vulnerable"))
    print("safe:", sum(1 for c in out["cases"] if c["kind"] == "safe"))


if __name__ == "__main__":
    build()
