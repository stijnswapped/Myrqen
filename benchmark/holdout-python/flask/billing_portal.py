"""Self-service billing pages for business customers."""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import current_user, login_required

from app.billing import payment_provider
from app.models import Customer, Statement, db

bp = Blueprint("billing", __name__, url_prefix="/billing")


def _customer_for_current_user() -> Customer:
    customer = Customer.query.filter_by(owner_id=current_user.id).first()
    if customer is None:
        abort(404)
    return customer


@bp.route("/")
@login_required
def overview():
    """Billing overview: plan, next invoice date and payment method."""
    customer = _customer_for_current_user()
    return render_template("billing/overview.html", customer=customer)


@bp.route("/payment-method", methods=["POST"])
@login_required
def update_payment_method():
    """Attach a new card using the provider's setup token."""
    customer = _customer_for_current_user()
    token = request.form["setup_token"]
    customer.payment_method_id = payment_provider.attach(customer.provider_id, token)
    db.session.commit()
    return jsonify({"ok": True})


@bp.route("/customers/<int:customer_id>/statements")
def statements(customer_id: int):
    """Monthly statements with line totals, newest first."""
    rows = (
        Statement.query.filter_by(customer_id=customer_id)
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
@login_required
def cancel_subscription():
    """Cancel at the end of the current period."""
    customer = _customer_for_current_user()
    payment_provider.cancel_at_period_end(customer.subscription_id)
    return jsonify({"ok": True})
