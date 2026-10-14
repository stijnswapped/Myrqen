from flask import Blueprint, abort, jsonify
from flask_login import current_user, login_required

from portal.models import LabResult

bp = Blueprint("lab_results", __name__, url_prefix="/lab-results")


def _visible_results():
    if current_user.role == "clinician":
        return LabResult.query.filter_by(clinic_id=current_user.clinic_id)
    if current_user.patient_id is not None:
        return LabResult.query.filter_by(patient_id=current_user.patient_id, released=True)
    abort(403)


@bp.get("/<int:result_id>")
@login_required
def result_detail(result_id):
    result = _visible_results().filter_by(id=result_id).first_or_404()
    return jsonify(
        id=result.id,
        panel=result.panel,
        values=result.values,
        reference_ranges=result.reference_ranges,
        collected_at=result.collected_at.isoformat(),
    )
