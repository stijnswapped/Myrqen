import csv
import io

from flask import Blueprint, Response, abort, jsonify, render_template
from flask_login import current_user, login_required

from portal.models import Report, ReportRow

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.get("/")
@login_required
def index():
    reports = Report.query.filter_by(team_id=current_user.team_id).order_by(Report.created_at.desc()).all()
    return render_template("reports/index.html", reports=reports)


@bp.get("/<int:report_id>")
@login_required
def show(report_id):
    report = Report.query.filter_by(id=report_id, team_id=current_user.team_id).first_or_404()
    return render_template("reports/show.html", report=report)


@bp.get("/<int:report_id>/rows.json")
@login_required
def rows_json(report_id):
    report = Report.query.filter_by(id=report_id, team_id=current_user.team_id).first_or_404()
    return jsonify([row.as_dict() for row in report.rows])


@bp.get("/<int:report_id>/export.csv")
def export_csv(report_id):
    report = Report.query.get(report_id)
    if report is None:
        abort(404)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(ReportRow.COLUMNS)
    for row in report.rows:
        writer.writerow(row.as_tuple())
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="report-{report.id}.csv"'},
    )
