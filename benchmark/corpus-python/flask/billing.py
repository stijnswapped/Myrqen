"""Billing pages."""

import csv
import io

from flask import Blueprint, Response, render_template
from flask_login import current_user, login_required

from app.models import Payment, Plan

bp = Blueprint("billing", __name__, url_prefix="/billing")


@bp.get("/")
@login_required
def overview():
    return render_template("billing/overview.html", plan=Plan.query.get(current_user.plan_id))


@bp.get("/payments")
@login_required
def payments():
    rows = Payment.query.filter_by(account_id=current_user.account_id).all()
    return render_template("billing/payments.html", payments=rows)


@bp.get("/export")
def export_payments():
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for payment in Payment.query.order_by(Payment.created_at.desc()).all():
        writer.writerow([payment.id, payment.account_id, payment.amount_cents, payment.card_last4])
    return Response(buffer.getvalue(), mimetype="text/csv")
