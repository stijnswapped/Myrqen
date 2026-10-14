from typing import Annotated

import markdown
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from jinja2 import Environment, select_autoescape
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Note

router = APIRouter(prefix="/notes", tags=["notes"])

_env = Environment(autoescape=select_autoescape(default=True))

NOTE_PAGE = _env.from_string(
    """<article class="note">
  <header><h1>{{ note.title }}</h1><span>by {{ note.author_name }}</span></header>
  <section class="note-body">{{ note.body_html | safe }}</section>
</article>"""
)


def _body_html(text: str) -> str:
    return markdown.markdown(text, extensions=["fenced_code", "tables"])


class NoteIn(BaseModel):
    title: str = Field(max_length=200)
    text: str = Field(max_length=50_000)


@router.post("", status_code=201)
async def create_note(
    body: NoteIn,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    note = Note(
        workspace_id=user.account_id,
        author_name=user.email,
        title=body.title,
        body_html=_body_html(body.text),
    )
    session.add(note)
    await session.commit()
    return {"id": note.id}


@router.get("/{note_id}/view", response_class=HTMLResponse)
async def view_note(
    note_id: int,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> HTMLResponse:
    note = await session.get(Note, note_id)
    if note is None or note.workspace_id != user.account_id:
        raise HTTPException(status_code=404)
    return HTMLResponse(NOTE_PAGE.render(note=note))
