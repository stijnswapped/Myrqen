import test from "node:test";
import assert from "node:assert/strict";
import { only, scanFiles } from "./helpers.mjs";

test("hard-coded secrets: literal signing key reported without its value; env read is quiet", async () => {
  const value = "9f3c1e7a5b2d48c6a0e1f7b3d9c5e2a8";
  const result = await scanFiles({
    "app/config.py": `
import os

JWT_SECRET = "${value}"
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://app:app@localhost:5432/app")
SESSION_SECRET = os.environ["SESSION_SECRET"]
API_TOKEN_HEADER = "X-Api-Token-Value-Header"
`
  });
  const findings = only(result, "hardcoded_secret");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].location.line, 3);
  assert.ok(!JSON.stringify(findings[0]).includes(value), "the secret value must never appear in a finding");
});

test("hard-coded secrets: an environment fallback literal is reported", async () => {
  const result = await scanFiles({
    "app/__init__.py": `
import os
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "c2a9f1e04b7d6e3a8f5c1b9d0e7a4f62")
    return app
`
  });
  assert.equal(only(result, "hardcoded_secret").length, 1);
});

test("hard-coded secrets: self-describing development values are not reported", async () => {
  const result = await scanFiles({
    "settings.py": `SECRET_KEY = "dev-secret-key-change-me-in-production"\nPASSWORD_MIN_LENGTH = 12\n`
  });
  assert.equal(result.candidates.length, 0);
});

test("debug mode: app.run(debug=True) on the Flask app; environment-driven debug is quiet", async () => {
  const vulnerable = await scanFiles({
    "wsgi.py": `
from flask import Flask
app = Flask(__name__)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
`
  });
  const [finding] = only(vulnerable, "debug_endpoint_exposure");
  assert.ok(finding);
  assert.equal(finding.severity, "high");

  const safe = await scanFiles({
    "wsgi.py": `
import os
from flask import Flask
app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
`
  });
  assert.equal(safe.candidates.length, 0);
});

test("debug mode: FastAPI(debug=True)", async () => {
  const result = await scanFiles({ "main.py": `from fastapi import FastAPI\napp = FastAPI(title="Shop", debug=True)\n` });
  assert.equal(only(result, "debug_endpoint_exposure").length, 1);
});

test("cookies: a session cookie without flags; hardened and non-sensitive cookies are quiet", async () => {
  const result = await scanFiles({
    "app.py": `
from flask import Flask, make_response

app = Flask(__name__)

@app.post("/login")
def login():
    response = make_response({"ok": True})
    response.set_cookie("session_token", "x")
    return response

@app.post("/login2")
def login2():
    response = make_response({"ok": True})
    response.set_cookie("session_token", "x", httponly=True, secure=True, samesite="Lax")
    response.set_cookie("theme", "dark")
    return response
`
  });
  const findings = only(result, "insecure_cookie_configuration");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].route, "POST /login");
  assert.equal(findings[0].location.line, 8);
});

test("cookies: FastAPI's SameSite default is respected, HttpOnly/Secure are not defaulted", async () => {
  const result = await scanFiles({
    "api.py": `
from fastapi import FastAPI, Response

app = FastAPI()

@app.post("/session")
def session(response: Response):
    response.set_cookie(key="access_token", value="x", httponly=True)
    return {"ok": True}
`
  });
  const [finding] = only(result, "insecure_cookie_configuration");
  assert.ok(finding);
  assert.match(finding.title, /Secure/);
  assert.doesNotMatch(finding.title, /SameSite/);
});

const DEPS = `
from fastapi import APIRouter, Depends
from app.deps import get_current_user, get_session
from app.models import Address, Order

router = APIRouter(prefix="/account")
`;

test("missing authentication: one data route without the dependency its siblings use", async () => {
  const result = await scanFiles({
    "app/api/account.py": `${DEPS}
@router.get("/profile")
def profile(user=Depends(get_current_user)):
    return user

@router.get("/orders")
def orders(session=Depends(get_session), user=Depends(get_current_user)):
    return session.query(Order).filter(Order.user_id == user.id).all()

@router.get("/addresses/export")
def export_addresses(session=Depends(get_session)):
    return session.query(Address).all()

@router.get("/health")
def health():
    return {"ok": True}
`
  });
  const findings = only(result, "missing_authentication");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].route, "GET /account/addresses/export");
});

test("missing authentication: a router-level dependency covers every route", async () => {
  const result = await scanFiles({
    "app/api/account.py": `
from fastapi import APIRouter, Depends
from app.deps import get_current_user, get_session
from app.models import Address

router = APIRouter(prefix="/account", dependencies=[Depends(get_current_user)])

@router.get("/profile")
def profile(user=Depends(get_current_user)):
    return user

@router.get("/settings")
def settings_view(user=Depends(get_current_user)):
    return user

@router.get("/addresses/export")
def export_addresses(session=Depends(get_session)):
    return session.query(Address).all()
`
  });
  assert.equal(only(result, "missing_authentication").length, 0);
});

test("missing authentication: flask-login siblings and a blueprint before_request hook", async () => {
  const vulnerable = await scanFiles({
    "billing.py": `
from flask import Blueprint
from flask_login import login_required, current_user
from app.db import db
from app.models import Invoice, Statement

bp = Blueprint("billing", __name__, url_prefix="/billing")

@bp.get("/invoices")
@login_required
def invoices():
    return {"items": [i.id for i in Invoice.query.filter_by(user_id=current_user.id)]}

@bp.get("/invoices/<int:invoice_id>/pdf")
@login_required
def invoice_pdf(invoice_id):
    return Invoice.query.filter_by(id=invoice_id, user_id=current_user.id).first_or_404().pdf

@bp.get("/statements")
def statements():
    return {"items": [s.id for s in Statement.query.all()]}
`
  });
  const [finding] = only(vulnerable, "missing_authentication");
  assert.ok(finding);
  assert.equal(finding.route, "GET /billing/statements");

  const safe = await scanFiles({
    "billing.py": `
from flask import Blueprint, abort, g, session
from app.models import Invoice, Statement

bp = Blueprint("billing", __name__, url_prefix="/billing")

@bp.before_request
def require_login():
    if "user_id" not in session:
        abort(401)

@bp.get("/invoices")
def invoices():
    return {"items": [i.id for i in Invoice.query.filter_by(user_id=session["user_id"])]}

@bp.get("/statements")
def statements():
    return {"items": [s.id for s in Statement.query.filter_by(user_id=session["user_id"])]}
`
  });
  assert.equal(safe.candidates.length, 0);
});

test("BOLA: fetched by path id with the subject unused; owner-scoped sibling is quiet", async () => {
  const result = await scanFiles({
    "app/api/orders.py": `
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from app.deps import get_current_user, get_session
from app.models import Order

router = APIRouter(prefix="/orders")

@router.get("")
def list_orders(session=Depends(get_session), current_user=Depends(get_current_user)):
    return session.execute(select(Order).where(Order.account_id == current_user.account_id)).scalars().all()

@router.get("/{order_id}")
def read_order(order_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    order = session.get(Order, order_id)
    if order is None:
        raise HTTPException(404)
    return order

@router.get("/{order_id}/scoped")
def read_scoped(order_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    order = session.get(Order, order_id)
    if order is None or order.account_id != current_user.account_id:
        raise HTTPException(404)
    return order
`
  });
  const findings = only(result, "broken_object_level_authorization");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].route, "GET /orders/:order_id");
  assert.equal(findings[0].location.line, 14);
});

test("BOLA: flask-login view that voids any shop's invoice by id", async () => {
  const result = await scanFiles({
    "views.py": `
from flask import Blueprint
from flask_login import login_required, current_user
from app.db import db
from app.models import Invoice

bp = Blueprint("invoices", __name__)

@bp.post("/invoices/<int:invoice_id>/void")
@login_required
def void_invoice(invoice_id):
    invoice = db.get_or_404(Invoice, invoice_id)
    invoice.status = "void"
    db.session.commit()
    return {"ok": True}
`
  });
  assert.equal(only(result, "broken_object_level_authorization").length, 1);
});

test("BOLA: catalogue records and admin-only routes are not reported", async () => {
  const result = await scanFiles({
    "app/api/catalog.py": `
from fastapi import APIRouter, Depends
from app.deps import get_current_user, require_admin, get_session
from app.models import Product, Order

router = APIRouter()

@router.get("/products/{product_id}")
def product(product_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    return session.get(Product, product_id)

@router.get("/admin/orders/{order_id}")
def admin_order(order_id: int, session=Depends(get_session), admin=Depends(require_admin)):
    return session.get(Order, order_id)
`
  });
  assert.equal(only(result, "broken_object_level_authorization").length, 0);
});
