"""Invoice search for the back-office console."""

from fastapi import APIRouter, Depends, Query
from psycopg import Connection

from app.db import get_connection
from app.security import get_current_user

router = APIRouter(prefix="/invoices", tags=["invoices"])


@router.get("/search")
def search_invoices(
    customer: str = Query(..., min_length=2),
    limit: int = Query(50, le=200),
    conn: Connection = Depends(get_connection),
    user=Depends(get_current_user),
):
    statement = (
        "SELECT id, number, total_cents FROM invoices "
        "WHERE customer_name ILIKE '%%%s%%' AND account_id = %d ORDER BY issued_at DESC LIMIT %d"
        % (customer, user.account_id, limit)
    )
    with conn.cursor() as cursor:
        cursor.execute(statement)
        rows = cursor.fetchall()
    return [{"id": r[0], "number": r[1], "total_cents": r[2]} for r in rows]
