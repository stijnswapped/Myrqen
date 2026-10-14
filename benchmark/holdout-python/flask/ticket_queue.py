"""Help-desk ticket queue with column filters from the query string."""
from __future__ import annotations

import sqlite3

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from app.db import get_db

bp = Blueprint("tickets", __name__)

FILTERABLE_COLUMNS = ("status", "priority", "assignee", "channel")
PAGE_SIZE = 50


def _where_clause(args) -> tuple[str, list]:
    """Translate ?status=open&priority=high into a WHERE clause plus bound values."""
    clauses = ["team_id = ?"]
    params: list = [current_user.team_id]
    for column in FILTERABLE_COLUMNS:
        value = args.get(column)
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    return " AND ".join(clauses), params


@bp.get("/tickets")
@login_required
def ticket_queue():
    """The agent's ticket queue, optionally filtered."""
    db: sqlite3.Connection = get_db()
    page = max(request.args.get("page", 1, type=int), 1)
    where, params = _where_clause(request.args)
    query = (
        "SELECT id, subject, status, priority, assignee, channel, updated_at FROM tickets "
        f"WHERE {where} ORDER BY updated_at DESC LIMIT {PAGE_SIZE} OFFSET ?"
    )
    rows = db.execute(query, [*params, (page - 1) * PAGE_SIZE]).fetchall()
    return jsonify([dict(row) for row in rows])
