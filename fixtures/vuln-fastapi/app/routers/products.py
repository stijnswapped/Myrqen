"""Public product catalogue."""

import sqlite3

from fastapi import APIRouter, Depends, Query

from app.db import get_db

router = APIRouter(prefix="/products", tags=["products"])


@router.get("")
def list_products(db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute("SELECT id, sku, name, price_cents FROM products WHERE hidden = 0").fetchall()
    return {"products": [dict(row) for row in rows]}


@router.get("/search")
def search_products(q: str = "", db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute(
        f"SELECT id, sku, name, price_cents FROM products WHERE hidden = 0 AND name LIKE '%{q}%'"
    ).fetchall()
    return {"results": [dict(row) for row in rows]}


@router.get("/by-sku")
def product_by_sku(sku: str = Query(..., pattern="^[A-Z]{3,5}-[0-9]{2}$"), db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute(f"SELECT id, sku, name, price_cents FROM products WHERE hidden = 0 AND sku = '{sku}'").fetchall()
    return {"results": [dict(row) for row in rows]}
