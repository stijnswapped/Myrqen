"""Project membership management."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Membership, Project
from app.security import get_current_user

router = APIRouter(prefix="/projects")


@router.get("/{project_id}/members")
def list_members(project_id: int, session: Session = Depends(get_session), user=Depends(get_current_user)):
    project = session.get(Project, project_id)
    if project is None or project.owner_id != user.id:
        raise HTTPException(404)
    return session.execute(select(Membership).where(Membership.project_id == project_id)).scalars().all()


@router.post("/{project_id}/members")
def add_member(project_id: int, email: str, session: Session = Depends(get_session), user=Depends(get_current_user)):
    project = session.get(Project, project_id)
    if project is None or project.owner_id != user.id:
        raise HTTPException(404)
    session.add(Membership(project_id=project_id, email=email))
    session.commit()
    return {"ok": True}


@router.delete("/{project_id}/members/{member_id}", status_code=204)
def remove_member(project_id: int, member_id: int, session: Session = Depends(get_session)):
    session.execute(delete(Membership).where(Membership.id == member_id, Membership.project_id == project_id))
    session.commit()
