"""Support ticket queue."""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_session
from app.security import get_current_user

router = APIRouter(prefix="/support")


def _priority_clause(priority: str | None) -> str:
    if not priority:
        return "1 = 1"
    return "priority = :priority"


@router.get("/tickets")
def ticket_queue(
    priority: str | None = None,
    session: Session = Depends(get_session),
    agent=Depends(get_current_user),
):
    query = "SELECT id, subject, priority FROM tickets WHERE team_id = :team AND " + _priority_clause(priority)
    rows = session.execute(text(query), {"team": agent.team_id, "priority": priority}).mappings().all()
    return {"tickets": [dict(row) for row in rows]}
