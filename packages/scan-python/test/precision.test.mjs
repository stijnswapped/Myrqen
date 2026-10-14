import test from "node:test";
import assert from "node:assert/strict";
import { only, scanFiles } from "./helpers.mjs";

/*
 * Each defect class here has a true positive and at least one near miss: the same code
 * made safe, and where the class has a known wrong fix, the wrong fix still reported.
 */

/* ------------------------------------------------------------------ cookies */

const FASTAPI_LOGIN = (cookieCall, extra = "") => `
from fastapi import APIRouter, Form, Response

from app.sessions import create_session

router = APIRouter(prefix="/auth")

SESSION_COOKIE = "portal_session"
${extra}

@router.post("/login")
def login(response: Response, email: str = Form(...), password: str = Form(...)):
    session_id = create_session(email, password)
    ${cookieCall}
`;

test("cookies: a session cookie named through a module constant is checked", async () => {
  const result = await scanFiles({
    "app/auth.py": FASTAPI_LOGIN('response.set_cookie(key=SESSION_COOKIE, value=session_id, max_age=3600, path="/")')
  });
  const [finding] = only(result, "insecure_cookie_configuration");
  assert.ok(finding, "the cookie named by SESSION_COOKIE is a session cookie");
  assert.equal(finding.route, "POST /auth/login");
  assert.match(finding.title, /HttpOnly, Secure/);
});

test("cookies: flags passed through **mapping are read; a full set is quiet", async () => {
  const result = await scanFiles({
    "app/auth.py": FASTAPI_LOGIN(
      "response.set_cookie(key=SESSION_COOKIE, value=session_id, max_age=3600, **COOKIE_FLAGS)",
      'COOKIE_FLAGS = {"path": "/", "secure": True, "httponly": True, "samesite": "lax"}'
    )
  });
  assert.equal(only(result, "insecure_cookie_configuration").length, 0);
});

test("cookies: a **mapping that leaves Secure out is still reported", async () => {
  const result = await scanFiles({
    "app/auth.py": FASTAPI_LOGIN(
      "response.set_cookie(key=SESSION_COOKIE, value=session_id, **COOKIE_FLAGS)",
      'COOKIE_FLAGS = {"path": "/", "httponly": True}'
    )
  });
  const [finding] = only(result, "insecure_cookie_configuration");
  assert.ok(finding);
  assert.match(finding.title, /without Secure$/);
});

test("cookies: an unreadable **mapping claims nothing", async () => {
  const result = await scanFiles({
    "app/auth.py": FASTAPI_LOGIN("response.set_cookie(key=SESSION_COOKIE, value=session_id, **settings.cookie_flags())", "from app.config import settings")
  });
  assert.equal(only(result, "insecure_cookie_configuration").length, 0);
});

const FLASK_REMEMBER = (flags) => `
from flask import Blueprint, make_response, redirect, render_template, request, url_for
from flask_login import login_user

from app.models import User
from app.security import issue_device_token

bp = Blueprint("auth", __name__)

DEVICE_COOKIE = "device_token"


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("auth/login.html")
    user = User.query.filter_by(email=request.form.get("email", "")).first()
    login_user(user)
    response = make_response(redirect(url_for("dashboard.index")))
    token = issue_device_token(user)
    response.set_cookie(DEVICE_COOKIE, token, max_age=30 * 24 * 3600${flags})
    return response
`;

test("cookies: in a GET/POST view the finding belongs to the POST half", async () => {
  const result = await scanFiles({ "app/auth.py": FLASK_REMEMBER("") });
  const [finding] = only(result, "insecure_cookie_configuration");
  assert.ok(finding);
  assert.equal(finding.route, "POST /login");
  assert.equal(finding.location.line, 20);
});

test("cookies: the same view with secure, httponly and samesite is quiet", async () => {
  const result = await scanFiles({ "app/auth.py": FLASK_REMEMBER(', secure=True, httponly=True, samesite="Strict"') });
  assert.equal(only(result, "insecure_cookie_configuration").length, 0);
});

test("cookies: Flask session flags switched off through config.from_mapping", async () => {
  const result = await scanFiles({
    "app/__init__.py": `
import os
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config.from_mapping(SECRET_KEY=os.environ["SECRET_KEY"], SESSION_COOKIE_SECURE=False)
    return app
`
  });
  assert.equal(only(result, "insecure_cookie_configuration").length, 1);
});

/* ------------------------------------------------------- method attribution */

const FLASK_SIGN_IN = (guard) => `
from urllib.parse import urljoin, urlparse

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import login_user

from app.forms import SignInForm
from app.models import Partner

bp = Blueprint("session", __name__, url_prefix="/session")


def _stays_here(target):
    host = urlparse(request.host_url)
    resolved = urlparse(urljoin(request.host_url, target))
    return resolved.scheme in ("http", "https") and resolved.netloc == host.netloc


def _mentions_host(target):
    return request.host in target


@bp.route("/new", methods=["GET", "POST"])
def sign_in():
    form = SignInForm()
    if not form.validate_on_submit():
        return render_template("session/new.html", form=form)
    login_user(Partner.query.filter_by(email=form.email.data).first())
    next_page = request.args.get("next")
${guard}
    return redirect(next_page)
`;

test("open redirect: after validate_on_submit() the redirect is the POST operation", async () => {
  const result = await scanFiles({ "app/session.py": FLASK_SIGN_IN("") });
  const [finding] = only(result, "open_redirect");
  assert.ok(finding);
  assert.equal(finding.route, "POST /session/new");
  assert.equal(finding.location.line, 30);
});

test("open redirect: a same-host predicate, whatever its name, keeps the redirect home", async () => {
  const result = await scanFiles({
    "app/session.py": FLASK_SIGN_IN(`    if not next_page or not _stays_here(next_page):
        next_page = url_for("portal.home")`)
  });
  assert.equal(only(result, "open_redirect").length, 0);
});

test("open redirect: a substring test for the host is not a same-host check", async () => {
  const result = await scanFiles({
    "app/session.py": FLASK_SIGN_IN(`    if not next_page or not _mentions_host(next_page):
        next_page = url_for("portal.home")`)
  });
  assert.equal(only(result, "open_redirect").length, 1);
});

test("open redirect: an inline netloc comparison with this request's host", async () => {
  const result = await scanFiles({
    "app/session.py": FLASK_SIGN_IN(`    if urlparse(next_page).netloc not in ("", request.host):
        next_page = url_for("portal.home")
    if urlparse(next_page).netloc != request.host:
        next_page = url_for("portal.home")`)
  });
  assert.equal(only(result, "open_redirect").length, 0);
});

/* ------------------------------------------------- redirects through the session */

const SSO = (store, read = 'request.session.pop("return_to", None) or "/dashboard"') => `
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from app.oidc import oidc_client

router = APIRouter(prefix="/auth/sso")


def _local_path(candidate):
    if candidate and candidate.startswith("/") and not candidate.startswith("//"):
        return candidate
    return "/dashboard"


@router.get("/start")
def start_sign_in(request: Request, return_to: str = "/dashboard"):
    state = secrets.token_urlsafe(24)
    request.session["oidc_state"] = state
    request.session["return_to"] = ${store}
    return RedirectResponse(oidc_client.authorization_url(state=state), status_code=302)


@router.get("/callback")
def finish_sign_in(request: Request, code: str):
    oidc_client.exchange_code(code)
    destination = ${read}
    return RedirectResponse(destination, status_code=303)
`;

test("open redirect: a destination stored in the session by one route and followed by another", async () => {
  const result = await scanFiles({ "app/sso.py": SSO("return_to") });
  const findings = only(result, "open_redirect");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].route, "GET /auth/sso/callback");
  assert.equal(findings[0].location.line, 29);
  assert.match(JSON.stringify(findings[0].evidence), /stored from query parameter return_to/);
});

test("open redirect: the stored destination reduced to a local path is quiet", async () => {
  const result = await scanFiles({ "app/sso.py": SSO("_local_path(return_to)") });
  assert.equal(only(result, "open_redirect").length, 0);
});

test("open redirect: a session key no route fills with request data is the application's own", async () => {
  const result = await scanFiles({ "app/sso.py": SSO('"/welcome"') });
  assert.equal(only(result, "open_redirect").length, 0);
});

test("open redirect: Flask's session proxy carries a stored next across views", async () => {
  const vulnerable = await scanFiles({
    "app/views.py": `
from flask import Blueprint, redirect, request, session

bp = Blueprint("auth", __name__)

@bp.get("/login")
def login_form():
    session["next"] = request.args.get("next", "/")
    return "form"

@bp.post("/login")
def login():
    return redirect(session.pop("next", "/"))
`
  });
  const [finding] = only(vulnerable, "open_redirect");
  assert.ok(finding);
  assert.equal(finding.route, "POST /login");

  const own = await scanFiles({
    "app/views.py": `
from flask import Blueprint, redirect, request, session

bp = Blueprint("auth", __name__)

@bp.get("/login")
def login_form():
    session["next"] = "/home"
    return "form"

@bp.post("/login")
def login():
    return redirect(session.pop("next", "/"))
`
  });
  assert.equal(only(own, "open_redirect").length, 0);
});

/* ------------------------------------------------------------ SSRF allow-lists */

const AVATAR = (check, fetch = "requests.get(image_url, timeout=10, allow_redirects=False)") => `
from urllib.parse import urlparse, urlsplit

import requests
from flask import Blueprint, abort, request
from flask_login import login_required

bp = Blueprint("profile", __name__)

IMAGE_HOSTS = {"images.unsplash.com", "secure.gravatar.com"}


def _photo_url(raw):
    parsed = urlparse(raw)
${check}
    return parsed.geturl()


@bp.post("/avatar/import")
@login_required
def import_avatar():
    payload = request.get_json(silent=True) or {}
    image_url = _photo_url(payload.get("image_url"))
    response = ${fetch}
    return {"status": response.status_code}
`;

test("SSRF: a parsed hostname checked against a fixed set pins the destination", async () => {
  const result = await scanFiles({
    "app/profile.py": AVATAR(`    if parsed.scheme != "https" or parsed.hostname not in IMAGE_HOSTS or parsed.port:
        abort(422)`)
  });
  assert.equal(only(result, "server_side_request_forgery").length, 0);
});

test("SSRF: a scheme check alone does not", async () => {
  const result = await scanFiles({
    "app/profile.py": AVATAR(`    if parsed.scheme != "https":
        abort(422)`)
  });
  assert.equal(only(result, "server_side_request_forgery").length, 1);
});

test("SSRF: a substring test of the URL is not an allow-list", async () => {
  const result = await scanFiles({
    "app/profile.py": AVATAR(`    if "images.unsplash.com" not in raw:
        abort(422)`)
  });
  assert.equal(only(result, "server_side_request_forgery").length, 1);
});

test("SSRF: a hostname suffix only counts from a label boundary", async () => {
  const loose = await scanFiles({
    "app/profile.py": AVATAR(`    if not parsed.hostname.endswith("unsplash.com"):
        abort(422)`)
  });
  assert.equal(only(loose, "server_side_request_forgery").length, 1);
  const bounded = await scanFiles({
    "app/profile.py": AVATAR(`    if not parsed.hostname.endswith(".unsplash.com"):
        abort(422)`)
  });
  assert.equal(only(bounded, "server_side_request_forgery").length, 0);
});

test("SSRF: a URL prefix only counts when it closes the authority", async () => {
  const open = await scanFiles({
    "app/profile.py": AVATAR(`    if not raw.startswith("https://images.unsplash.com"):
        abort(422)`)
  });
  assert.equal(only(open, "server_side_request_forgery").length, 1);
  const closed = await scanFiles({
    "app/profile.py": AVATAR(`    if not raw.startswith("https://images.unsplash.com/"):
        abort(422)`)
  });
  assert.equal(only(closed, "server_side_request_forgery").length, 0);
});

test("SSRF: an async client after a urlsplit host check in a helper", async () => {
  const source = (hosts) => `
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl

router = APIRouter(prefix="/webhooks")

PARTNER_HOSTS = frozenset({"hooks.slack.com", "api.pagerduty.com"})


class WebhookIn(BaseModel):
    target_url: HttpUrl


def _partner_url(url):
    parts = urlsplit(str(url))
    if ${hosts}:
        raise HTTPException(status_code=422)
    return parts.geturl()


@router.post("/verify")
async def verify(body: WebhookIn):
    target = _partner_url(body.target_url)
    async with httpx.AsyncClient(follow_redirects=False) as client:
        response = await client.post(target, json={"type": "ping"})
    return {"status": response.status_code}
`;
  const pinned = await scanFiles({ "app/hooks.py": source("parts.scheme != \"https\" or parts.hostname not in PARTNER_HOSTS") });
  assert.equal(only(pinned, "server_side_request_forgery").length, 0);
  const unpinned = await scanFiles({ "app/hooks.py": source("parts.scheme != \"https\"") });
  assert.equal(only(unpinned, "server_side_request_forgery").length, 1);
});

/* --------------------------------------------------------------- bound SQL */

const TICKETS = (clause) => `
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from app.db import get_db

bp = Blueprint("tickets", __name__)

FILTERABLE_COLUMNS = ("status", "priority", "assignee")


def _where_clause(args):
    clauses = ["team_id = ?"]
    params = [current_user.team_id]
    for column in FILTERABLE_COLUMNS:
        value = args.get(column)
        if value:
            clauses.append(${clause})
            params.append(value)
    return " AND ".join(clauses), params


@bp.get("/tickets")
@login_required
def ticket_queue():
    db = get_db()
    where, params = _where_clause(request.args)
    query = f"SELECT id, subject FROM tickets WHERE {where} ORDER BY updated_at DESC"
    rows = db.execute(query, params).fetchall()
    return jsonify([dict(row) for row in rows])
`;

test("SQL: a helper returning (clause, values) keeps the values out of the text", async () => {
  const result = await scanFiles({ "app/tickets.py": TICKETS('f"{column} = ?"') });
  assert.equal(only(result, "sql_injection").length, 0);
});

test("SQL: the same helper quoting each value into the clause is injection", async () => {
  const result = await scanFiles({ "app/tickets.py": TICKETS("f\"{column} = '{value}'\"") });
  const findings = only(result, "sql_injection");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].route, "GET /tickets");
});

test("SQL: iterating a tuple binds each item, not each position", async () => {
  const result = await scanFiles({
    "app/search.py": `
from flask import Blueprint, request

from app.db import get_db

bp = Blueprint("search", __name__)

@bp.get("/search")
def search():
    term = request.args.get("q", "")
    for label, text in (("name", term), ("email", term)):
        get_db().execute(f"SELECT id FROM users WHERE {label} = '{text}'")
    return "ok"
`
  });
  assert.equal(only(result, "sql_injection").length, 1);
});

/* --------------------------------------------------------------------- BOLA */

const VOID = (lookup, helper = "") => `
from flask import Blueprint, jsonify
from flask_login import current_user, login_required

from app.audit import record_event
from app.models import Invoice, db

bp = Blueprint("invoices", __name__, url_prefix="/invoices")
${helper}

@bp.post("/<int:invoice_id>/void")
@login_required
def void_invoice(invoice_id: int):
    invoice = ${lookup}
    invoice.status = "void"
    db.session.commit()
    record_event("invoice.voided", actor_id=current_user.id, invoice_id=invoice.id)
    return jsonify({"ok": True})
`;

test("BOLA: naming the caller in an audit record is not an ownership check", async () => {
  const result = await scanFiles({ "app/invoices.py": VOID("db.get_or_404(Invoice, invoice_id)") });
  const [finding] = only(result, "broken_object_level_authorization");
  assert.ok(finding);
  assert.equal(finding.route, "POST /invoices/:invoice_id/void");
});

test("BOLA: a lookup scoped to the caller's shop in a helper is quiet", async () => {
  const result = await scanFiles({
    "app/invoices.py": VOID(
      "_shop_invoice(invoice_id)",
      `
def _shop_invoice(invoice_id):
    return Invoice.query.filter_by(id=invoice_id, shop_id=current_user.shop_id).first_or_404()
`
    )
  });
  assert.equal(only(result, "broken_object_level_authorization").length, 0);
});

test("BOLA: an ownership comparison after the lookup is quiet", async () => {
  const result = await scanFiles({
    "app/invoices.py": VOID(`db.get_or_404(Invoice, invoice_id)
    if invoice.shop_id != current_user.shop_id:
        abort(404)`).replace("from flask import Blueprint, jsonify", "from flask import Blueprint, abort, jsonify")
  });
  assert.equal(only(result, "broken_object_level_authorization").length, 0);
});

/* -------------------------------------------------- validators that refuse */

const FETCH = (validator) => `
import ipaddress
import socket
from urllib.parse import urlparse

import requests
from flask import Blueprint, abort, request
from flask_login import login_required

bp = Blueprint("previews", __name__)

ALLOWED_HOSTS = {"cdn.partner.test", "img.partner.test"}

${validator}

@bp.post("/previews")
@login_required
def preview():
    url = request.get_json()["url"]
    ensure_fetchable(url)
    return {"status": requests.get(url, timeout=5, allow_redirects=False).status_code}
`;

test("SSRF: a validator that raises unless the host is allowed protects the caller's URL", async () => {
  const result = await scanFiles({
    "app/previews.py": FETCH(`def ensure_fetchable(url):
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        abort(422)`)
  });
  assert.equal(only(result, "server_side_request_forgery").length, 0);
});

test("SSRF: a validator that only checks the scheme protects nothing", async () => {
  const result = await scanFiles({
    "app/previews.py": FETCH(`def ensure_fetchable(url):
    if urlparse(url).scheme != "https":
        abort(422)`)
  });
  assert.equal(only(result, "server_side_request_forgery").length, 1);
});

test("SSRF: refusing private addresses the host resolves to", async () => {
  const result = await scanFiles({
    "app/previews.py": FETCH(`def ensure_fetchable(url):
    host = urlparse(url).hostname
    for info in socket.getaddrinfo(host, None):
        address = ipaddress.ip_address(info[4][0])
        if address.is_private or address.is_loopback or address.is_link_local:
            abort(422)`)
  });
  assert.equal(only(result, "server_side_request_forgery").length, 0);
});

test("SSRF: checking a host that was never resolved is not an address check", async () => {
  const result = await scanFiles({
    "app/previews.py": FETCH(`def ensure_fetchable(url):
    host = urlparse(url).hostname
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if address.is_private:
        abort(422)`)
  });
  assert.equal(only(result, "server_side_request_forgery").length, 1);
});

/* ---------------------------------------------------- guards in expressions */

test("SQL: a conditional expression that falls back unless the column is allowed", async () => {
  const source = (choice) => `
from flask import Blueprint, request

from app.db import get_db

bp = Blueprint("reports", __name__)

SORTABLE = ("created_at", "amount", "status")

@bp.get("/reports")
def reports():
    sort = request.args.get("sort", "created_at")
    column = ${choice}
    return {"rows": get_db().execute(f"SELECT id FROM reports ORDER BY {column}").fetchall()}
`;
  const allowed = await scanFiles({ "app/reports.py": source('sort if sort in SORTABLE else "created_at"') });
  assert.equal(only(allowed, "sql_injection").length, 0);
  const inverted = await scanFiles({ "app/reports.py": source('"created_at" if sort in SORTABLE else sort') });
  assert.equal(only(inverted, "sql_injection").length, 1);
});

test("open redirect: the local-path check written as a refusal", async () => {
  const source = (test) => `
from flask import Blueprint, redirect, request

bp = Blueprint("auth", __name__)

@bp.get("/continue")
def continue_to():
    target = request.args.get("next", "/")
    if ${test}:
        target = "/"
    return redirect(target)
`;
  const refused = await scanFiles({ "app/auth.py": source('not target.startswith("/") or target.startswith("//")') });
  assert.equal(only(refused, "open_redirect").length, 0);
  const halfRefused = await scanFiles({ "app/auth.py": source('not target.startswith("/")') });
  assert.equal(only(halfRefused, "open_redirect").length, 1);
});

/* ------------------------------------------------- session middleware cookie */

test("cookies: Starlette session middleware with https_only=False", async () => {
  const source = (flags) => `
import os
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.environ["SESSION_SECRET"]${flags})
`;
  const off = await scanFiles({ "app/main.py": source(", https_only=False") });
  assert.equal(only(off, "insecure_cookie_configuration").length, 1);
  const on = await scanFiles({ "app/main.py": source(', https_only=True, same_site="lax"') });
  assert.equal(only(on, "insecure_cookie_configuration").length, 0);
});

/* ----------------------------------------- BOLA: recording the caller is not a check */

test("BOLA: stamping the caller on the record is not an ownership check", async () => {
  const result = await scanFiles({
    "app/invoices.py": `
from flask import Blueprint, jsonify
from flask_login import current_user, login_required

from app.models import Invoice, db

bp = Blueprint("invoices", __name__, url_prefix="/invoices")

@bp.post("/<int:invoice_id>/void")
@login_required
def void_invoice(invoice_id: int):
    invoice = db.get_or_404(Invoice, invoice_id)
    invoice.voided_by = current_user.id
    db.session.commit()
    return jsonify({"ok": True})
`
  });
  assert.equal(only(result, "broken_object_level_authorization").length, 1);
});

/* ------------------------------------------------------- reach and response type */

test("XSS: a FastAPI route declared with response_class=HTMLResponse serves its string as HTML", async () => {
  const source = (decorator) => `
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

${decorator}
def greet(name: str):
    return f"<p>Hello {name}</p>"
`;
  const html = await scanFiles({ "app/pages.py": source('@router.get("/greet", response_class=HTMLResponse)') });
  assert.equal(only(html, "reflected_cross_site_scripting").length, 1);
  const json = await scanFiles({ "app/pages.py": source('@router.get("/greet")') });
  assert.equal(only(json, "reflected_cross_site_scripting").length, 0);
});

test("data flow: a method on a module-level instance of a project class is followed", async () => {
  const storage = (join) => `
import os


class Storage:
    def __init__(self, root):
        self.root = root

    def read(self, name):
        with open(${join}, "rb") as handle:
            return handle.read()
`;
  const route = `
from fastapi import APIRouter

from app.storage import Storage

router = APIRouter()
storage = Storage("/srv/data")


@router.get("/download")
def download(name: str):
    return {"data": storage.read(name)}
`;
  const raw = await scanFiles({ "app/api.py": route, "app/storage.py": storage("os.path.join(self.root, name)") });
  const [finding] = only(raw, "path_traversal");
  assert.ok(finding);
  assert.equal(finding.location.file, "app/storage.py");
  assert.equal(finding.route, "GET /download");
  const based = await scanFiles({ "app/api.py": route, "app/storage.py": storage("os.path.join(self.root, os.path.basename(name))") });
  assert.equal(only(based, "path_traversal").length, 0);
});
