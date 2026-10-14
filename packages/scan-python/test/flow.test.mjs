import test from "node:test";
import assert from "node:assert/strict";
import { only, scanFiles } from "./helpers.mjs";

const FLASK_HEAD = `
import os
import sqlite3
import subprocess
from flask import Flask, request, redirect, render_template_string, send_file, abort
from markupsafe import Markup, escape

app = Flask(__name__)
`;

test("flask: f-string SQL from request.args is reported at the execute call", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
@app.route("/customers")
def customers():
    name = request.args.get("name", "")
    db = sqlite3.connect("shop.db")
    rows = db.execute(f"SELECT id, email FROM customers WHERE name = '{name}'").fetchall()
    return {"rows": rows}
`
  });
  const [finding] = only(result, "sql_injection");
  assert.ok(finding, "expected a SQL injection");
  assert.equal(finding.route, "GET /customers");
  assert.equal(finding.location.line, 13);
  // The report names the parameter, as it does for a FastAPI query parameter.
  assert.match(finding.summary, /query parameter name/);
});

test("flask: the parameterised form of the same query is quiet", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
@app.route("/customers")
def customers():
    name = request.args.get("name", "")
    db = sqlite3.connect("shop.db")
    rows = db.execute("SELECT id, email FROM customers WHERE name = ?", (name,)).fetchall()
    return {"rows": rows}
`
  });
  assert.equal(result.candidates.length, 0);
});

test("percent-formatting and list joins carry taint into SQL", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
@app.route("/tickets")
def tickets():
    clauses = ["1 = 1"]
    status = request.args.get("status")
    if status:
        clauses.append("status = '%s'" % status)
    sql = "SELECT * FROM tickets WHERE " + " AND ".join(clauses)
    return {"rows": sqlite3.connect("t.db").execute(sql).fetchall()}
`
  });
  assert.equal(only(result, "sql_injection").length, 1);
});

test("an ORDER BY column chosen through a fixed mapping is not injection", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
SORTS = {"newest": "created_at DESC", "oldest": "created_at ASC"}

@app.route("/orders")
def orders():
    order = SORTS.get(request.args.get("sort"), "created_at DESC")
    sql = f"SELECT * FROM orders ORDER BY {order}"
    return {"rows": sqlite3.connect("o.db").execute(sql).fetchall()}
`
  });
  assert.equal(result.candidates.length, 0);
});

test("fastapi: SQLAlchemy text() with an f-string is reported once, at text()", async () => {
  const result = await scanFiles({
    "app/api/reports.py": `
from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

router = APIRouter(prefix="/reports")

@router.get("/sales")
def sales(region: str = Query(...), session: Session = Depends(lambda: None)):
    statement = text(f"SELECT sum(total) FROM sales WHERE region = '{region}'")
    return session.execute(statement).all()
`
  });
  const findings = only(result, "sql_injection");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].route, "GET /reports/sales");
  assert.equal(findings[0].location.line, 9);
});

test("fastapi: an int or Literal query parameter cannot inject", async () => {
  const result = await scanFiles({
    "app/api/reports.py": `
from typing import Literal
from fastapi import APIRouter
from sqlalchemy import text

router = APIRouter()

@router.get("/sales/{year}")
def sales(year: int, period: Literal["q1", "q2"] = "q1", session=None):
    return session.execute(text(f"SELECT * FROM sales WHERE year = {year} AND period = '{period}'")).all()
`
  });
  assert.equal(result.candidates.length, 0);
});

test("fastapi: a regex-constrained query parameter is clean for SQL", async () => {
  const result = await scanFiles({
    "app/api/reports.py": `
from fastapi import APIRouter, Query
from sqlalchemy import text

router = APIRouter()

@router.get("/sales")
def sales(region: str = Query(..., pattern="^[a-z]{2}-[a-z]+$"), session=None):
    return session.execute(text(f"SELECT * FROM sales WHERE region = '{region}'")).all()
`
  });
  assert.equal(result.candidates.length, 0);
});

test("command injection: shell=True with a body field, argv list is quiet", async () => {
  const vulnerable = await scanFiles({
    "api.py": `
import subprocess
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class Ping(BaseModel):
    host: str
    count: int = 1

@app.post("/diagnostics/ping")
def ping(body: Ping):
    out = subprocess.run(f"ping -c {body.count} {body.host}", shell=True, capture_output=True)
    return {"out": out.stdout.decode()}
`
  });
  const [finding] = only(vulnerable, "command_injection");
  assert.ok(finding);
  assert.equal(finding.route, "POST /diagnostics/ping");

  const safe = await scanFiles({
    "api.py": `
import subprocess
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class Ping(BaseModel):
    host: str

@app.post("/diagnostics/ping")
def ping(body: Ping):
    out = subprocess.run(["ping", "-c", "1", body.host], capture_output=True)
    return {"out": out.stdout.decode()}
`
  });
  assert.equal(safe.candidates.length, 0);
});

test("command injection: shlex.quote on one part does not clean another part", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
import shlex

@app.post("/convert")
def convert():
    data = request.get_json()
    src = shlex.quote(data["src"])
    cmd = f"convert {src} -quality {data['quality']} out.png"
    os.system(cmd)
    return {"ok": True}
`
  });
  assert.equal(only(result, "command_injection").length, 1);
});

test("command injection: a fully constant shell command is quiet", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
@app.get("/ops/disk")
def disk():
    return {"df": subprocess.check_output("df -h / | tail -1", shell=True).decode()}
`
  });
  assert.equal(result.candidates.length, 0);
});

test("path traversal: send_file of a joined path, and the contained near-miss", async () => {
  const vulnerable = await scanFiles({
    "app.py": `${FLASK_HEAD}
BASE = "/srv/exports"

@app.get("/exports/<name>")
def export(name):
    return send_file(os.path.join(BASE, name))
`
  });
  const [finding] = only(vulnerable, "path_traversal");
  assert.ok(finding);
  assert.equal(finding.route, "GET /exports/:name");

  const contained = await scanFiles({
    "app.py": `${FLASK_HEAD}
BASE = "/srv/exports"

@app.get("/exports/<name>")
def export(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(BASE + os.sep):
        abort(400)
    return send_file(target)
`
  });
  assert.equal(contained.candidates.length, 0);
});

test("path traversal: startswith on an unresolved path is not credited", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
BASE = "/srv/exports"

@app.get("/exports/<name>")
def export(name):
    target = os.path.join(BASE, name)
    if not target.startswith(BASE):
        abort(400)
    return send_file(target)
`
  });
  assert.equal(only(result, "path_traversal").length, 1);
});

test("path traversal: basename, secure_filename and send_from_directory are safe", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
from flask import send_from_directory
from werkzeug.utils import secure_filename

@app.get("/a/<name>")
def a(name):
    return send_file(os.path.join("/srv", os.path.basename(name)))

@app.get("/b/<name>")
def b(name):
    return open(os.path.join("/srv", secure_filename(name))).read()

@app.get("/c/<path:name>")
def c(name):
    return send_from_directory("/srv/public", name)
`
  });
  assert.equal(result.candidates.length, 0);
});

test("path traversal: pathlib resolve + is_relative_to containment", async () => {
  const result = await scanFiles({
    "api.py": `
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

app = FastAPI()
ROOT = Path("/srv/reports")

@app.get("/reports/{run_id}/{name:path}")
def report(run_id: int, name: str):
    base = (ROOT / str(run_id)).resolve()
    target = (base / name).resolve()
    if not target.is_relative_to(base):
        raise HTTPException(400)
    return FileResponse(target)

@app.get("/raw/{name:path}")
def raw(name: str):
    return FileResponse(ROOT / name)
`
  });
  const findings = only(result, "path_traversal");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].route, "GET /raw/:name");
});

test("SSRF: a caller URL fetched with requests, and the host allow-list near-miss", async () => {
  const vulnerable = await scanFiles({
    "app.py": `${FLASK_HEAD}
import requests

@app.post("/avatar/import")
def import_avatar():
    url = request.json["url"]
    image = requests.get(url, timeout=5).content
    return {"bytes": len(image)}
`
  });
  assert.equal(only(vulnerable, "server_side_request_forgery").length, 1);

  const safe = await scanFiles({
    "app.py": `${FLASK_HEAD}
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"images.partner.test", "cdn.partner.test"}

@app.post("/avatar/import")
def import_avatar():
    url = request.json["url"]
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        abort(400)
    image = requests.get(url, timeout=5).content
    return {"bytes": len(image)}
`
  });
  assert.equal(safe.candidates.length, 0);
});

test("SSRF: a fixed origin with a caller-chosen path segment is not SSRF", async () => {
  const result = await scanFiles({
    "api.py": `
import httpx
from fastapi import FastAPI

app = FastAPI()
PARTNER = "https://api.partner.test/v2"

@app.get("/rates/{currency}")
async def rates(currency: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{PARTNER}/rates/{currency}")
    return response.json()

@app.get("/proxy")
async def proxy(target: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(target)
    return response.json()
`
  });
  const findings = only(result, "server_side_request_forgery");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].route, "GET /proxy");
});

test("SSTI: render_template_string of request text vs. a fixed template with context", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
@app.post("/preview")
def preview():
    body = request.form["body"]
    return render_template_string("<div>" + body + "</div>")

@app.post("/preview-safe")
def preview_safe():
    body = request.form["body"]
    return render_template_string("<div>{{ body }}</div>", body=body)
`
  });
  const findings = only(result, "template_injection");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].route, "POST /preview");
  assert.equal(only(result, "reflected_cross_site_scripting").length, 0);
});

test("SSTI: user templates compiled in a SandboxedEnvironment are not reported", async () => {
  const result = await scanFiles({
    "api.py": `
from fastapi import FastAPI
from jinja2 import Environment
from jinja2.sandbox import SandboxedEnvironment
from pydantic import BaseModel

app = FastAPI()
sandbox = SandboxedEnvironment(autoescape=True)
env = Environment()

class Draft(BaseModel):
    body: str

@app.post("/preview/sandboxed")
def sandboxed(draft: Draft):
    return sandbox.from_string(draft.body).render()

@app.post("/preview/open")
def open_env(draft: Draft):
    return env.from_string(draft.body).render()
`
  });
  const findings = only(result, "template_injection");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].route, "POST /preview/open");
});

test("deserialization: pickle from a cookie, and the HMAC-verified near-miss", async () => {
  const vulnerable = await scanFiles({
    "app.py": `${FLASK_HEAD}
import base64
import pickle

@app.get("/cart")
def cart():
    raw = request.cookies.get("cart", "")
    items = pickle.loads(base64.b64decode(raw)) if raw else []
    return {"items": items}
`
  });
  assert.equal(only(vulnerable, "unsafe_deserialization").length, 1);

  const safe = await scanFiles({
    "app.py": `${FLASK_HEAD}
import base64
import hashlib
import hmac
import pickle

KEY = os.environ["CART_KEY"].encode()

@app.get("/cart")
def cart():
    raw = request.cookies.get("cart", "")
    payload, _, signature = raw.partition(".")
    expected = hmac.new(KEY, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        abort(400)
    return {"items": pickle.loads(base64.b64decode(payload))}
`
  });
  assert.equal(safe.candidates.length, 0);
});

test("deserialization: yaml.load without a safe loader; SafeLoader is quiet", async () => {
  const result = await scanFiles({
    "api.py": `
import yaml
from fastapi import FastAPI, UploadFile

app = FastAPI()

@app.post("/imports")
async def imports(file: UploadFile):
    return {"spec": yaml.load(await file.read(), Loader=yaml.Loader)}

@app.post("/imports-safe")
async def imports_safe(file: UploadFile):
    return {"spec": yaml.load(await file.read(), Loader=yaml.SafeLoader)}
`
  });
  const findings = only(result, "unsafe_deserialization");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].route, "POST /imports");
});

test("open redirect: next parameter, and the local-path check near-miss", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
from urllib.parse import urlparse

@app.post("/login")
def login():
    return redirect(request.args.get("next", "/"))

@app.post("/login-safe")
def login_safe():
    target = request.args.get("next", "/")
    if urlparse(target).netloc or not target.startswith("/") or target.startswith("//"):
        target = "/"
    return redirect(target)

@app.get("/go/<slug>")
def go(slug):
    return redirect(f"/articles/{slug}")
`
  });
  const findings = only(result, "open_redirect");
  assert.equal(findings.length, 1, JSON.stringify(findings.map((f) => f.route)));
  assert.equal(findings[0].route, "POST /login");
});

test("XSS: Markup over an f-string and a Flask view returning HTML; escape() is safe", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
@app.get("/search")
def search():
    q = request.args.get("q", "")
    return Markup(f"<h1>Results for {q}</h1>")

@app.get("/hello")
def hello():
    name = request.args.get("name", "")
    return f"<p>Hello {name}</p>"

@app.get("/search-safe")
def search_safe():
    q = request.args.get("q", "")
    return Markup(f"<h1>Results for {escape(q)}</h1>")
`
  });
  const routes = only(result, "reflected_cross_site_scripting").map((finding) => finding.route).sort();
  assert.deepEqual(routes, ["GET /hello", "GET /search"]);
});

test("XSS: a template that marks a tainted context variable |safe", async () => {
  const result = await scanFiles({
    "app/views.py": `
from flask import Blueprint, render_template, request

bp = Blueprint("kb", __name__, url_prefix="/kb")

@bp.get("/article")
def article():
    return render_template("article.html", title=request.args.get("title", ""), body="fixed")
`,
    "app/templates/article.html": `<h1>{{ title|safe }}</h1><div>{{ body }}</div>`
  });
  const [finding] = only(result, "reflected_cross_site_scripting");
  assert.ok(finding);
  assert.equal(finding.route, "GET /kb/article");
});

test("cross-module: a route passes a query value to a service that formats SQL", async () => {
  const result = await scanFiles({
    "app/__init__.py": "",
    "app/services/__init__.py": "",
    "app/services/reports.py": `
from sqlalchemy import text

def segment_totals(session, segment):
    clause = f"segment = '{segment}'"
    return session.execute(text("SELECT sum(total) FROM revenue WHERE " + clause)).all()
`,
    "app/api/__init__.py": "",
    "app/api/reports.py": `
from fastapi import APIRouter, Depends
from app.services import reports

router = APIRouter(prefix="/reports")

@router.get("/segments")
def segments(segment: str, session=Depends(lambda: None)):
    return reports.segment_totals(session, segment)
`,
    "app/main.py": `
from fastapi import FastAPI
from app.api import reports

app = FastAPI()
app.include_router(reports.router, prefix="/api")
`
  });
  const [finding] = only(result, "sql_injection");
  assert.ok(finding, "expected the cross-module flow to be followed");
  assert.equal(finding.location.file, "app/services/reports.py");
  assert.equal(finding.route, "GET /api/reports/segments");
  assert.match(finding.reasoning, /across modules/);
});

test("cross-module: a helper that int()s its argument returns a clean value", async () => {
  const result = await scanFiles({
    "app/util.py": `
def page_size(raw):
    return max(1, min(int(raw), 100))
`,
    "app/views.py": `
import sqlite3
from flask import Flask, request
from app.util import page_size

app = Flask(__name__)

@app.get("/rows")
def rows():
    limit = page_size(request.args.get("limit", "20"))
    return {"rows": sqlite3.connect("x.db").execute(f"SELECT * FROM rows LIMIT {limit}").fetchall()}
`
  });
  assert.equal(result.candidates.length, 0);
});

test("allow-list guard written as membership in a module constant cleans the value", async () => {
  const result = await scanFiles({
    "app.py": `${FLASK_HEAD}
COLUMNS = ("name", "created_at", "total")

@app.get("/orders")
def orders():
    column = request.args.get("sort", "created_at")
    if column not in COLUMNS:
        abort(400)
    return {"rows": sqlite3.connect("o.db").execute(f"SELECT * FROM orders ORDER BY {column}").fetchall()}
`
  });
  assert.equal(result.candidates.length, 0);
});

test("a helper that executes whatever statement it is handed is reported where the SQL is built", async () => {
  const result = await scanFiles({
    "app/__init__.py": "",
    "app/db.py": `
import sqlite3
import threading

_lock = threading.Lock()
_connection = sqlite3.connect(":memory:")

def query(statement, params=()):
    with _lock:
        return [dict(row) for row in _connection.execute(statement, params).fetchall()]
`,
    "app/catalogue.py": `
from flask import Blueprint, jsonify, request
from app.db import query

bp = Blueprint("products", __name__, url_prefix="/products")

@bp.get("/search")
def search_products():
    term = request.args.get("q", "")
    statement = "SELECT id FROM products WHERE name LIKE '%" + term + "%'"
    return jsonify({"results": query(statement)})

@bp.get("/by-name")
def by_name():
    term = request.args.get("q", "")
    return jsonify({"results": query("SELECT id FROM products WHERE name = ?", (term,))})

@bp.get("/raw")
def raw():
    return jsonify({"results": query(request.args.get("q", ""))})
`
  });
  const findings = only(result, "sql_injection");
  assert.equal(findings.length, 1, JSON.stringify(findings.map((f) => f.route)));
  assert.equal(findings[0].route, "GET /products/search");
  assert.equal(findings[0].location.file, "app/catalogue.py");
  assert.equal(findings[0].location.line, 10, "the handler's call to query(), where the statement is used");
  assert.match(findings[0].summary, /query parameter q/);
});
