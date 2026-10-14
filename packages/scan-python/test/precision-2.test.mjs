import test from "node:test";
import assert from "node:assert/strict";
import { only, scanFiles } from "./helpers.mjs";

/*
 * The second Python improvement round. Each mechanism has a true positive and at least
 * one near miss: the same code made safe, and where a wrong fix is common, the wrong fix
 * still reported.
 */

const FASTAPI_AUTH = `
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException


@dataclass(frozen=True)
class CurrentUser:
    id: int
    role: str
    account_id: int


async def get_current_user(token: str) -> CurrentUser:
    return CurrentUser(id=1, role="member", account_id=1)


async def require_admin(user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
    if user.role != "admin":
        raise HTTPException(403)
    return user
`;

const FASTAPI_DB = `
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

engine = create_async_engine("postgresql+asyncpg://app@db/app")
SessionLocal = async_sessionmaker(engine)


async def get_session():
    async with SessionLocal() as session:
        yield session
`;

const FASTAPI_MODELS = `
from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[int] = mapped_column(Integer)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    updated_by: Mapped[int | None] = mapped_column(Integer)


class Membership(Base):
    __tablename__ = "memberships"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))


class Note(Base):
    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(200))
    body_html: Mapped[str] = mapped_column(Text)
`;

const fastapiProject = (router, extra = {}) => ({
  "app/__init__.py": "",
  "app/auth.py": FASTAPI_AUTH,
  "app/db.py": FASTAPI_DB,
  "app/models.py": FASTAPI_MODELS,
  "app/main.py": "from fastapi import FastAPI\n\nfrom app import routes\n\napp = FastAPI()\napp.include_router(routes.router)\n",
  "app/routes.py": router,
  ...extra
});

/* ------------------------------------------------- parsed URL components */

const FLASK_FETCH = (check) => `
from urllib.parse import urlsplit

import requests
from flask import Flask, abort, request

app = Flask(__name__)
PARTNER_HOSTS = frozenset({"feeds.partner.example"})


@app.post("/fetch")
def fetch():
    url = request.form["url"]
    parts = urlsplit(url)
${check}
    return requests.get(url, timeout=5).text
`;

test("SSRF: a host derived through `(parts.hostname or \"\").lower()` and allow-listed pins the URL", async () => {
  const result = await scanFiles({
    "app.py": FLASK_FETCH('    host = (parts.hostname or "").lower()\n    if parts.scheme != "https" or host not in PARTNER_HOSTS or parts.port not in (None, 443):\n        abort(400)')
  });
  assert.equal(only(result, "server_side_request_forgery").length, 0);
});

test("SSRF: a scheme checked through a local says nothing about where the URL goes", async () => {
  const result = await scanFiles({
    "app.py": FLASK_FETCH('    scheme = parts.scheme\n    if scheme not in ("http", "https"):\n        abort(400)')
  });
  assert.equal(only(result, "server_side_request_forgery").length, 1);
});

test("SSRF: a port checked through a local says nothing about where the URL goes", async () => {
  const result = await scanFiles({
    "app.py": FLASK_FETCH("    port = parts.port\n    if port not in (None, 443):\n        abort(400)")
  });
  assert.equal(only(result, "server_side_request_forgery").length, 1);
});

/* ---------------------------------------------- functions run by a scheduler */

const MEDIA_ROUTER = (render, schedule) => `
import shlex
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel, Field

router = APIRouter(prefix="/media")
pool = ThreadPoolExecutor(max_workers=2)


class VariantRequest(BaseModel):
    asset_id: int
    caption: str = Field(default="", max_length=80)


def render_variant(target: str, req: VariantRequest) -> None:
${render}


@router.post("/variants")
async def create_variant(req: VariantRequest, tasks: BackgroundTasks) -> dict:
    target = f"/srv/media/{req.asset_id}.png"
    ${schedule}
    return {"status": "queued"}
`;

const SHELL_RENDER = `    command = "convert in.png -annotate +10+10 '{caption}' {dst}".format(caption=req.caption, dst=target)
    subprocess.run(command, shell=True, check=True)`;

test("command: a function handed to BackgroundTasks.add_task runs with the request's data", async () => {
  const result = await scanFiles({ "app/main.py": MEDIA_ROUTER(SHELL_RENDER, "tasks.add_task(render_variant, target, req)") });
  const [finding] = only(result, "command_injection");
  assert.ok(finding, "the background task builds a shell command from the caption");
  assert.equal(finding.route, "POST /media/variants");
  assert.equal(finding.location.line, 20);
});

test("command: the same task with an argument vector is quiet", async () => {
  const render = `    subprocess.run(["convert", "in.png", "-annotate", "+10+10", req.caption, target], check=True)`;
  const result = await scanFiles({ "app/main.py": MEDIA_ROUTER(render, "tasks.add_task(render_variant, target, req)") });
  assert.equal(only(result, "command_injection").length, 0);
});

test("command: the same task with the caption quoted is quiet", async () => {
  const render = `    command = "convert in.png -annotate +10+10 {caption} out.png".format(caption=shlex.quote(req.caption))
    subprocess.run(command, shell=True, check=True)`;
  const result = await scanFiles({ "app/main.py": MEDIA_ROUTER(render, "tasks.add_task(render_variant, target, req)") });
  assert.equal(only(result, "command_injection").length, 0);
});

test("command: executor.submit and threading.Thread(target=, args=) are followed the same way", async () => {
  for (const schedule of ["pool.submit(render_variant, target, req)", "threading.Thread(target=render_variant, args=(target, req)).start()"]) {
    const result = await scanFiles({ "app/main.py": MEDIA_ROUTER(SHELL_RENDER, schedule) });
    assert.equal(only(result, "command_injection").length, 1, schedule);
  }
});

/* -------------------------------------------- missing authentication */

const ADMIN_USERS = (removeSignature, removeBody) => `
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user, require_admin
from app.db import get_session
from app.models import User

router = APIRouter(prefix="/admin/users")

Session = Annotated[AsyncSession, Depends(get_session)]
Admin = Annotated[CurrentUser, Depends(require_admin)]


@router.get("")
async def list_users(session: Session, admin: Admin):
    return list(await session.scalars(select(User).where(User.account_id == admin.account_id)))


@router.get("/{user_id}")
async def get_user(user_id: int, session: Session, admin: Admin):
    user = await session.get(User, user_id)
    if user is None or user.account_id != admin.account_id:
        raise HTTPException(status_code=404)
    return user


@router.delete("/{user_id}", status_code=204)
async def remove_user(${removeSignature}):
${removeBody}
    await session.commit()
`;

test("missing auth: a 404 on a record the handler loaded is not an identity check", async () => {
  const body = `    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404)
    await session.delete(user)`;
  const result = await scanFiles(fastapiProject(ADMIN_USERS("user_id: int, session: Session", body)));
  const [finding] = only(result, "missing_authentication");
  assert.ok(finding, "the DELETE handler has no identity check, unlike its siblings");
  assert.equal(finding.route, "DELETE /admin/users/:user_id");
});

test("missing auth: a handler that resolves the caller itself and refuses without one is authenticated", async () => {
  const body = `    caller = await get_current_user(request.headers.get("authorization", ""))
    if caller is None:
        raise HTTPException(status_code=401)
    user = await session.get(User, user_id)
    await session.delete(user)`;
  const result = await scanFiles(fastapiProject(ADMIN_USERS("user_id: int, request: Request, session: Session", body)));
  assert.equal(only(result, "missing_authentication").length, 0);
});

/* ------------------------------------- object-level authorization in helpers */

const PROJECTS = (renameBody) => `
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Membership, Project

router = APIRouter(prefix="/projects")


class ProjectService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def rename(self, project_id: int, name: str, actor: CurrentUser) -> Project:
${renameBody}
        project.name = name
        project.updated_by = actor.id
        await self.session.commit()
        return project


def get_service(session: Annotated[AsyncSession, Depends(get_session)]) -> ProjectService:
    return ProjectService(session)


class Rename(BaseModel):
    name: str


@router.patch("/{project_id}")
async def rename_project(
    project_id: int,
    body: Rename,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    service: Annotated[ProjectService, Depends(get_service)],
) -> dict:
    project = await service.rename(project_id, body.name, user)
    return {"id": project.id}
`;

test("BOLA: a record a service loads by the caller's id, with the caller used only for the audit column", async () => {
  const body = `        project = await self.session.get(Project, project_id)
        if project is None:
            raise HTTPException(404)`;
  const result = await scanFiles(fastapiProject(PROJECTS(body)));
  const [finding] = only(result, "broken_object_level_authorization");
  assert.ok(finding, "membership is never checked");
  assert.equal(finding.route, "PATCH /projects/:project_id");
  assert.equal(finding.location.line, 20, "reported where the service loads the record");
});

test("BOLA: the same service checking the caller's membership is quiet", async () => {
  const body = `        member = await self.session.scalar(
            select(Membership).where(Membership.project_id == project_id, Membership.user_id == actor.id)
        )
        if member is None:
            raise HTTPException(404)
        project = await self.session.get(Project, project_id)`;
  const result = await scanFiles(fastapiProject(PROJECTS(body)));
  assert.equal(only(result, "broken_object_level_authorization").length, 0);
});

const FLASK_RESULTS = (helper, detail) => `
from flask import Blueprint, abort, jsonify
from flask_login import current_user, login_required

from portal.models import LabResult

bp = Blueprint("lab_results", __name__, url_prefix="/lab-results")

${helper}

@bp.get("/<int:result_id>")
@login_required
def result_detail(result_id):
${detail}
    return jsonify(id=result.id, values=result.values)
`;

const FLASK_MODELS = `
from portal.extensions import db


class LabResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer)
    clinic_id = db.Column(db.Integer)
    values = db.Column(db.Text)
`;

const flaskProject = (view, extra = {}) => ({
  "portal/__init__.py": "",
  "portal/extensions.py": "from flask_sqlalchemy import SQLAlchemy\n\ndb = SQLAlchemy()\n",
  "portal/models.py": FLASK_MODELS,
  "portal/views.py": view,
  ...extra
});

test("BOLA: a query scoped to the caller by a helper is a scoped lookup", async () => {
  const helper = `def _visible_results():
    if current_user.role == "clinician":
        return LabResult.query.filter_by(clinic_id=current_user.clinic_id)
    return LabResult.query.filter_by(patient_id=current_user.patient_id)
`;
  const result = await scanFiles(flaskProject(FLASK_RESULTS(helper, "    result = _visible_results().filter_by(id=result_id).first_or_404()")));
  assert.equal(only(result, "broken_object_level_authorization").length, 0);
});

test("BOLA: the same lookup through a helper that does not scope it is reported", async () => {
  const helper = `def _all_results():
    return LabResult.query.order_by(LabResult.id)
`;
  const result = await scanFiles(flaskProject(FLASK_RESULTS(helper, "    result = _all_results().filter_by(id=result_id).first_or_404()")));
  assert.equal(only(result, "broken_object_level_authorization").length, 1);
});

test("BOLA: checking that the caller is some patient is not checking whose record it is", async () => {
  const detail = `    if current_user.patient_id is None:
        abort(403)
    result = LabResult.query.get_or_404(result_id)`;
  const result = await scanFiles(flaskProject(FLASK_RESULTS("", detail)));
  const [finding] = only(result, "broken_object_level_authorization");
  assert.ok(finding);
  assert.equal(finding.route, "GET /lab-results/:result_id");
});

test("BOLA: comparing the record's patient with the caller's is quiet; so is a privileged-role check", async () => {
  for (const detail of [
    `    if current_user.patient_id is None:
        abort(403)
    result = LabResult.query.get_or_404(result_id)
    if result.patient_id != current_user.patient_id:
        abort(404)`,
    `    if not current_user.is_admin:
        abort(403)
    result = LabResult.query.get_or_404(result_id)`
  ]) {
    const result = await scanFiles(flaskProject(FLASK_RESULTS("", detail)));
    assert.equal(only(result, "broken_object_level_authorization").length, 0, detail);
  }
});

const REVENUE = (sql) => `
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session

router = APIRouter(prefix="/reports")


class ReportRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def run(self, value: str) -> list[dict]:
        result = await self._session.execute(text(${JSON.stringify(sql)}), {"value": value})
        return [dict(row._mapping) for row in result]


def get_repository(session: Annotated[AsyncSession, Depends(get_session)]) -> ReportRepository:
    return ReportRepository(session)


@router.get("/run")
async def run_report(
    value: str,
    repo: Annotated[ReportRepository, Depends(get_repository)],
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> dict:
    return {"rows": await repo.run(value)}
`;

test("BOLA: a totals query filtered on a joined table's code is not a record lookup", async () => {
  const sql = "SELECT r.name, SUM(o.total_cents) FROM orders o JOIN regions r ON r.id = o.region_id WHERE r.code = :value GROUP BY r.name";
  const result = await scanFiles(fastapiProject(REVENUE(sql)));
  assert.equal(only(result, "broken_object_level_authorization").length, 0);
});

test("BOLA: a repository fetching one document by the caller's id is a record lookup", async () => {
  const result = await scanFiles(fastapiProject(REVENUE("SELECT d.title, d.body FROM documents d WHERE d.id = :value")));
  assert.equal(only(result, "broken_object_level_authorization").length, 1);
});

/* --------------------------------------------------------- stored data */

const NOTES = (bodyHtml, marker = "| safe") => `
from typing import Annotated

import bleach
import markdown
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from jinja2 import Environment, select_autoescape
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Note

router = APIRouter(prefix="/notes")

_env = Environment(autoescape=select_autoescape(default=True))

NOTE_PAGE = _env.from_string(
    """<article>
  <h1>{{ note.title }}</h1>
  <section>{{ note.body_html ${marker} }}</section>
</article>"""
)


class NoteIn(BaseModel):
    title: str
    text: str


@router.post("")
async def create_note(
    body: NoteIn,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    note = Note(workspace_id=user.account_id, title=body.title, body_html=${bodyHtml})
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
`;

test("stored XSS: request markdown stored as HTML and marked | safe in an inline template", async () => {
  const result = await scanFiles(fastapiProject(NOTES("markdown.markdown(body.text)")));
  const [finding] = only(result, "reflected_cross_site_scripting");
  assert.ok(finding, "the stored HTML is rendered without escaping");
  assert.equal(finding.location.line, 22, "reported at the template line that marks it safe");
  assert.equal(finding.route, "GET /notes/:note_id/view");
  assert.match(finding.summary, /stored field body_html/);
});

test("stored XSS: the same note sanitised before it is stored is quiet", async () => {
  const result = await scanFiles(fastapiProject(NOTES("bleach.clean(markdown.markdown(body.text))")));
  assert.equal(only(result, "reflected_cross_site_scripting").length, 0);
});

test("stored XSS: the same template escaping the field is quiet", async () => {
  const result = await scanFiles(fastapiProject(NOTES("markdown.markdown(body.text)", "")));
  assert.equal(only(result, "reflected_cross_site_scripting").length, 0);
});

const COMMENTS = (wrap, write = 'request.form.get("body", "")') => `
import re

from flask import Blueprint, redirect, render_template, request
from flask_login import current_user, login_required
from markupsafe import Markup, escape

from portal.extensions import db
from portal.models import Comment, Thread

bp = Blueprint("comments", __name__, url_prefix="/threads")

MENTION = re.compile(r"@([a-z0-9_]{2,30})")


def render_comment(body):
    linked = MENTION.sub(lambda m: f'<a href="/u/{m.group(1)}">@{m.group(1)}</a>', ${wrap})
    return Markup(linked.replace("\\n", "<br>"))


@bp.get("/<int:thread_id>")
@login_required
def show_thread(thread_id):
    thread = Thread.query.filter_by(id=thread_id, team_id=current_user.team_id).first_or_404()
    comments = [render_comment(c.body) for c in thread.comments]
    return render_template("threads/show.html", thread=thread, comments=comments)


@bp.post("/<int:thread_id>/comments")
@login_required
def add_comment(thread_id):
    thread = Thread.query.filter_by(id=thread_id, team_id=current_user.team_id).first_or_404()
    db.session.add(Comment(thread_id=thread.id, author_id=current_user.id, body=${write}))
    db.session.commit()
    return redirect("/threads")
`;

const COMMENT_MODELS = `
from portal.extensions import db


class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    thread_id = db.Column(db.Integer)
    author_id = db.Column(db.Integer)
    body = db.Column(db.Text)
`;

test("stored XSS: a stored comment wrapped in Markup after a regex edit", async () => {
  const result = await scanFiles(flaskProject(COMMENTS("body"), { "portal/models.py": COMMENT_MODELS }));
  const [finding] = only(result, "reflected_cross_site_scripting");
  assert.ok(finding);
  assert.equal(finding.route, "GET /threads/:thread_id");
  assert.equal(finding.location.line, 17);
});

test("stored XSS: the same comment escaped before the links are added is quiet", async () => {
  const result = await scanFiles(flaskProject(COMMENTS("str(escape(body))"), { "portal/models.py": COMMENT_MODELS }));
  assert.equal(only(result, "reflected_cross_site_scripting").length, 0);
});

test("stored XSS: a field no route fills from the request is the application's own data", async () => {
  const result = await scanFiles(flaskProject(COMMENTS("body", '"(deleted)"'), { "portal/models.py": COMMENT_MODELS }));
  assert.equal(only(result, "reflected_cross_site_scripting").length, 0);
});

test("stored XSS: a loop variable over a context list marked | safe in a template file", async () => {
  const view = COMMENTS("body").replace("comments = [render_comment(c.body) for c in thread.comments]", "comments = thread.comments");
  const result = await scanFiles(
    flaskProject(view, {
      "portal/models.py": COMMENT_MODELS,
      "portal/templates/threads/show.html": "{% for c in comments %}<p>{{ c.body|safe }}</p>{% endfor %}\n"
    })
  );
  const findings = only(result, "reflected_cross_site_scripting");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].location.line, 25);
});

test("stored data: a stored field reaching SQL is not reported as attacker data", async () => {
  const view = `
from flask import Blueprint, request
from flask_login import current_user, login_required

from portal.extensions import db

bp = Blueprint("prefs", __name__)


@bp.post("/prefs")
@login_required
def save_prefs():
    current_user.sort_column = request.form["sort"]
    db.session.commit()
    return "ok"


@bp.get("/items")
@login_required
def items():
    return str(db.session.execute(db.text("SELECT * FROM items ORDER BY " + current_user.sort_column)).all())
`;
  const result = await scanFiles(flaskProject(view));
  assert.equal(only(result, "sql_injection").length, 0);
});

const SIGNATURE = (render) => `
from flask import Blueprint, render_template_string, request
from flask_login import current_user, login_required

from portal.extensions import db

bp = Blueprint("signatures", __name__, url_prefix="/settings/signature")


@bp.route("", methods=["GET", "POST"])
@login_required
def edit_signature():
    if request.method == "POST":
        current_user.email_signature = request.form.get("signature", "")[:2000]
        db.session.commit()
    signature = current_user.email_signature or ""
${render}
`;

test("stored SSTI: a stored signature compiled as template source belongs to the GET that renders it", async () => {
  const result = await scanFiles(flaskProject(SIGNATURE('    return render_template_string("<div>" + signature + "</div>")')));
  const [finding] = only(result, "template_injection");
  assert.ok(finding);
  assert.equal(finding.route, "GET /settings/signature");
});

test("stored SSTI: the signature passed as a context value is quiet", async () => {
  const result = await scanFiles(flaskProject(SIGNATURE('    return render_template_string("<div>{{ sig }}</div>", sig=signature)')));
  assert.equal(only(result, "template_injection").length, 0);
});

/* --------------------------------------------------- development config */

test("cookies: SESSION_COOKIE_SECURE = False in a development config class is quiet; in production it is not", async () => {
  const config = (name) => `
class BaseConfig:
    SESSION_COOKIE_SECURE = True


class ${name}(BaseConfig):
    SESSION_COOKIE_SECURE = False
`;
  const development = await scanFiles({ "portal/config.py": config("DevelopmentConfig"), "portal/app.py": "from flask import Flask\n\napp = Flask(__name__)\n" });
  assert.equal(only(development, "insecure_cookie_configuration").length, 0);
  const production = await scanFiles({ "portal/config.py": config("ProductionConfig"), "portal/app.py": "from flask import Flask\n\napp = Flask(__name__)\n" });
  assert.equal(only(production, "insecure_cookie_configuration").length, 1);
});
