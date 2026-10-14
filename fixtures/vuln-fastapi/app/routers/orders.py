"""Customer orders."""

import sqlite3

from fastapi import APIRouter, Depends, HTTPException

from app.db import get_db
from app.security import get_current_user

router = APIRouter(prefix="/orders", tags=["orders"])


@router.get("")
def list_orders(db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    rows = db.execute(
        "SELECT id, reference, total_cents FROM orders WHERE user_id = ? ORDER BY id", (current_user["id"],)
    ).fetchall()
    return {"orders": [dict(row) for row in rows]}


@router.get("/{order_id}")
def read_order(order_id: int, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    row = db.execute("SELECT id, user_id, reference, total_cents, address FROM orders WHERE id = ?", (order_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return dict(row)
