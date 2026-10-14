from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Membership, Project

router = APIRouter(prefix="/projects", tags=["projects"])


class ProjectNotFound(Exception):
    pass


class ProjectService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_for(self, actor: CurrentUser) -> list[Project]:
        stmt = (
            select(Project)
            .join(Membership, Membership.project_id == Project.id)
            .where(Membership.user_id == actor.id)
            .order_by(Project.name)
        )
        return list(await self.session.scalars(stmt))

    async def rename(self, project_id: int, name: str, actor: CurrentUser) -> Project:
        project = await self.session.get(Project, project_id)
        if project is None:
            raise ProjectNotFound(project_id)
        project.name = name
        project.updated_by = actor.id
        project.updated_at = datetime.now(timezone.utc)
        await self.session.commit()
        return project


def get_service(session: Annotated[AsyncSession, Depends(get_session)]) -> ProjectService:
    return ProjectService(session)


class Rename(BaseModel):
    name: str = Field(min_length=1, max_length=120)


@router.get("")
async def list_projects(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    service: Annotated[ProjectService, Depends(get_service)],
) -> list[dict]:
    return [{"id": p.id, "name": p.name} for p in await service.list_for(user)]


@router.patch("/{project_id}")
async def rename_project(
    project_id: int,
    body: Rename,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    service: Annotated[ProjectService, Depends(get_service)],
) -> dict:
    try:
        project = await service.rename(project_id, body.name, user)
    except ProjectNotFound:
        raise HTTPException(status_code=404) from None
    return {"id": project.id, "name": project.name}
