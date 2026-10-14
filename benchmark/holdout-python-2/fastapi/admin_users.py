from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, require_admin
from app.db import get_session
from app.models import ApiKey, User

router = APIRouter(prefix="/admin/users", tags=["admin"])

Session = Annotated[AsyncSession, Depends(get_session)]
Admin = Annotated[CurrentUser, Depends(require_admin)]


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    disabled: bool


class RoleChange(BaseModel):
    role: Literal["member", "billing", "admin"]


@router.get("", response_model=list[UserOut])
async def list_users(session: Session, admin: Admin) -> list[User]:
    result = await session.scalars(select(User).where(User.account_id == admin.account_id).order_by(User.email))
    return list(result)


@router.get("/{user_id}", response_model=UserOut)
async def get_user(user_id: int, session: Session, admin: Admin) -> User:
    user = await session.get(User, user_id)
    if user is None or user.account_id != admin.account_id:
        raise HTTPException(status_code=404)
    return user


@router.patch("/{user_id}/role", response_model=UserOut)
async def change_role(user_id: int, change: RoleChange, session: Session, admin: Admin) -> User:
    user = await session.get(User, user_id)
    if user is None or user.account_id != admin.account_id:
        raise HTTPException(status_code=404)
    user.role = change.role
    await session.commit()
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_user(user_id: int, session: Session) -> Response:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404)
    await session.execute(delete(ApiKey).where(ApiKey.user_id == user_id))
    await session.delete(user)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
