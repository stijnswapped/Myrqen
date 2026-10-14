"""Invoice lookup endpoints for the billing dashboard."""
from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import CurrentUser, get_current_user
from app.db import get_connection

router = APIRouter(prefix="/invoices", tags=["invoices"])

INVOICE_COLUMNS = "id, number, customer_name, total_cents, issued_at"


def _row_to_dict(row: sqlite3.Row) -> dict:
    return {key: row[key] for key in row.keys()}


@router.get("/search")
def search_invoices(
    customer: Annotated[str, Query(min_length=1, max_length=120)],
    user: CurrentUser = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_connection),
):
    """Find invoices in the caller's organisation by (partial) customer name."""
    pattern = f"%{customer}%"
    sql = (
        f"SELECT {INVOICE_COLUMNS} FROM invoices "
        "WHERE org_id = ? AND customer_name LIKE ? "
        "ORDER BY issued_at DESC LIMIT 50"
    )
    rows = conn.execute(sql, (user.org_id, pattern)).fetchall()
    return [_row_to_dict(row) for row in rows]


@router.get("/{invoice_id}")
def get_invoice(
    invoice_id: int,
    user: CurrentUser = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_connection),
):
    """Return a single invoice belonging to the caller's organisation."""
    row = conn.execute(
        f"SELECT {INVOICE_COLUMNS} FROM invoices WHERE id = ? AND org_id = ?",
        (invoice_id, user.org_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return _row_to_dict(row)
