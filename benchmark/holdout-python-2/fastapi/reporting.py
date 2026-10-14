from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session

router = APIRouter(prefix="/reports", tags=["reports"])


class SalesReportRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def totals_by_region(self, region: str, start: date, end: date) -> list[dict]:
        statement = text(
            "SELECT r.name AS region, SUM(o.total_cents) AS total "
            "FROM orders o JOIN regions r ON r.id = o.region_id "
            f"WHERE r.code = '{region}' "
            "AND o.placed_at BETWEEN :start AND :end "
            "GROUP BY r.name"
        )
        result = await self._session.execute(statement, {"start": start, "end": end})
        return [dict(row._mapping) for row in result]


def get_repository(session: Annotated[AsyncSession, Depends(get_session)]) -> SalesReportRepository:
    return SalesReportRepository(session)


@router.get("/sales")
async def sales_by_region(
    region: Annotated[str, Query(min_length=2, max_length=12)],
    start: date,
    end: date,
    repo: Annotated[SalesReportRepository, Depends(get_repository)],
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> dict:
    rows = await repo.totals_by_region(region, start, end)
    return {"region": region, "from": start, "to": end, "rows": rows}
