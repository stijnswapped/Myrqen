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


@bp.get("/export")
@login_required
def export_payments():
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for payment in Payment.query.filter_by(account_id=current_user.account_id).all():
        writer.writerow([payment.id, payment.amount_cents])
    return Response(buffer.getvalue(), mimetype="text/csv")
