import csv
import io

from flask import Blueprint, Response, abort, jsonify, render_template
from flask_login import current_user

from portal.models import PayrollRun

bp = Blueprint("payroll", __name__, url_prefix="/payroll")

PAYROLL_ROLES = {"payroll", "finance_admin"}


@bp.before_request
def require_payroll_access():
    if not current_user.is_authenticated:
        abort(401)
    if current_user.role not in PAYROLL_ROLES:
        abort(403)


@bp.get("/runs")
def list_runs():
    runs = PayrollRun.query.filter_by(company_id=current_user.company_id).order_by(PayrollRun.period.desc()).all()
    return render_template("payroll/runs.html", runs=runs)


@bp.get("/runs/<int:run_id>")
def run_detail(run_id):
    run = PayrollRun.query.filter_by(id=run_id, company_id=current_user.company_id).first_or_404()
    return jsonify(run.summary())


@bp.get("/runs/<int:run_id>/payslips.csv")
def export_payslips(run_id):
    run = PayrollRun.query.filter_by(id=run_id, company_id=current_user.company_id).first_or_404()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["employee", "gross", "tax", "net"])
    for slip in run.payslips:
        writer.writerow([slip.employee_name, slip.gross, slip.tax, slip.net])
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="payroll-{run.period}.csv"'},
    )
