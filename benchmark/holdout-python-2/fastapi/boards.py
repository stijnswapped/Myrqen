from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Board, Membership

router = APIRouter(prefix="/boards", tags=["boards"])


class BoardNotFound(Exception):
    pass


class BoardService:
    MANAGER_ROLES = frozenset({"owner", "admin"})

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _membership(self, project_id: int, user_id: int) -> Membership | None:
        stmt = select(Membership).where(
            Membership.project_id == project_id,
            Membership.user_id == user_id,
        )
        return await self.session.scalar(stmt)

    async def archive(self, board_id: int, actor: CurrentUser) -> Board:
        board = await self.session.get(Board, board_id)
        if board is None:
            raise BoardNotFound(board_id)
        membership = await self._membership(board.project_id, actor.id)
        if membership is None or membership.role not in self.MANAGER_ROLES:
            raise BoardNotFound(board_id)
        board.archived_at = datetime.now(timezone.utc)
        board.updated_by = actor.id
        await self.session.commit()
        return board


def get_service(session: Annotated[AsyncSession, Depends(get_session)]) -> BoardService:
    return BoardService(session)


@router.post("/{board_id}/archive", status_code=status.HTTP_200_OK)
async def archive_board(
    board_id: int,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    service: Annotated[BoardService, Depends(get_service)],
) -> dict:
    try:
        board = await service.archive(board_id, user)
    except BoardNotFound:
        raise HTTPException(status_code=404) from None
    return {"id": board.id, "archived_at": board.archived_at}
