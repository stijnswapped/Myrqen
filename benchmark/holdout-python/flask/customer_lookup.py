"""Customer lookup for the support desk."""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required
from psycopg2.extras import RealDictCursor

from app.db import get_db

bp = Blueprint("customers", __name__, url_prefix="/customers")

CUSTOMER_FIELDS = "id, email, full_name, plan, created_at"


@bp.route("/lookup")
@login_required
def lookup_by_email():
    """Support agents look a customer up by the e-mail address on the ticket."""
    email = request.args.get("email", "").strip().lower()
    if not email:
        abort(400, description="email is required")
    conn = get_db()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT " + CUSTOMER_FIELDS + " FROM customers "
            "WHERE tenant_id = %d AND email = '%s'" % (current_user.tenant_id, email)
        )
        customer = cur.fetchone()
    if customer is None:
        abort(404)
    return jsonify(customer)


@bp.route("/<int:customer_id>")
@login_required
def customer_detail(customer_id: int):
    """Full customer record for the agent's tenant."""
    conn = get_db()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT " + CUSTOMER_FIELDS + " FROM customers WHERE tenant_id = %s AND id = %s",
            (current_user.tenant_id, customer_id),
        )
        customer = cur.fetchone()
    if customer is None:
        abort(404)
    return jsonify(customer)
