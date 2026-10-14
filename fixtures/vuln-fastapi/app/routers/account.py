"""Account pages."""

import sqlite3

from fastapi import APIRouter, Depends

from app.db import get_db
from app.security import get_current_user

router = APIRouter(prefix="/account", tags=["account"])


@router.get("/profile")
def profile(current_user: dict = Depends(get_current_user)):
    return current_user


@router.get("/addresses")
def addresses(db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    rows = db.execute("SELECT DISTINCT address FROM orders WHERE user_id = ?", (current_user["id"],)).fetchall()
    return {"addresses": [row["address"] for row in rows]}


@router.get("/export")
def export_customers(db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute("SELECT u.email, o.reference, o.address FROM orders o JOIN users u ON u.id = o.user_id").fetchall()
    return {"rows": [dict(row) for row in rows]}
