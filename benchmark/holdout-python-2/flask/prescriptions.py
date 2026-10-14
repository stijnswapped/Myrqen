from flask import Blueprint, abort, jsonify
from flask_login import current_user, login_required

from portal.models import Prescription

bp = Blueprint("prescriptions", __name__, url_prefix="/patient/prescriptions")


@bp.get("")
@login_required
def my_prescriptions():
    if current_user.patient_id is None:
        abort(403)
    items = (
        Prescription.query.filter_by(patient_id=current_user.patient_id)
        .order_by(Prescription.issued_at.desc())
        .all()
    )
    return jsonify([rx.summary() for rx in items])


@bp.get("/<int:rx_id>")
@login_required
def prescription_detail(rx_id):
    if current_user.patient_id is None:
        abort(403)
    rx = Prescription.query.get_or_404(rx_id)
    return jsonify(
        id=rx.id,
        medication=rx.medication,
        dosage=rx.dosage,
        prescriber=rx.prescriber_name,
        pharmacy=rx.pharmacy_name,
        refills_left=rx.refills_left,
        notes=rx.clinical_notes,
    )
