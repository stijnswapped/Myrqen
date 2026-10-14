"""Help-desk ticket queue with column filters from the query string."""
from __future__ import annotations

import sqlite3

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from app.db import get_db

bp = Blueprint("tickets", __name__)

FILTERABLE_COLUMNS = ("status", "priority", "assignee", "channel")


def _where_clause(args) -> str:
    """Translate ?status=open&priority=high into a WHERE clause for the queue."""
    clauses = [f"team_id = {int(current_user.team_id)}"]
    for column in FILTERABLE_COLUMNS:
        value = args.get(column)
        if value:
            clauses.append(f"{column} = '{value}'")
    return " AND ".join(clauses)


@bp.get("/tickets")
@login_required
def ticket_queue():
    """The agent's ticket queue, optionally filtered."""
    db: sqlite3.Connection = get_db()
    page = max(int(request.args.get("page", 1)), 1)
    query = (
        "SELECT id, subject, status, priority, assignee, channel, updated_at FROM tickets WHERE "
        + _where_clause(request.args)
        + " ORDER BY updated_at DESC LIMIT 50 OFFSET ?"
    )
    rows = db.execute(query, ((page - 1) * 50,)).fetchall()
    return jsonify([dict(row) for row in rows])
