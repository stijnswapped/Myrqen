"""Self-service billing pages for business customers.

Every view on this blueprint requires a signed-in user; the check runs once in a
before_request hook instead of being repeated on each view.
"""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import current_user

from app.billing import payment_provider
from app.models import Customer, Statement, db

bp = Blueprint("billing", __name__, url_prefix="/billing")


@bp.before_request
def require_signed_in_user():
    if not current_user.is_authenticated:
        abort(401)


def _customer_for_current_user() -> Customer:
    customer = Customer.query.filter_by(owner_id=current_user.id).first()
    if customer is None:
        abort(404)
    return customer


@bp.route("/")
def overview():
    """Billing overview: plan, next invoice date and payment method."""
    customer = _customer_for_current_user()
    return render_template("billing/overview.html", customer=customer)


@bp.route("/payment-method", methods=["POST"])
def update_payment_method():
    """Attach a new card using the provider's setup token."""
    customer = _customer_for_current_user()
    token = request.form["setup_token"]
    customer.payment_method_id = payment_provider.attach(customer.provider_id, token)
    db.session.commit()
    return jsonify({"ok": True})


@bp.route("/statements")
def statements():
    """Monthly statements with line totals, newest first."""
    customer = _customer_for_current_user()
    rows = (
        Statement.query.filter_by(customer_id=customer.id)
        .order_by(Statement.period_end.desc())
        .limit(24)
        .all()
    )
    return jsonify(
        [
            {
                "period_end": row.period_end.isoformat(),
                "total_cents": row.total_cents,
                "billing_email": row.billing_email,
                "vat_number": row.vat_number,
            }
            for row in rows
        ]
    )


@bp.route("/cancel", methods=["POST"])
def cancel_subscription():
    """Cancel at the end of the current period."""
    customer = _customer_for_current_user()
    payment_provider.cancel_at_period_end(customer.subscription_id)
    return jsonify({"ok": True})
