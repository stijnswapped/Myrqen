from flask import Blueprint, jsonify, request
from flask_login import login_required
from sqlalchemy import or_

from portal.models import Member

bp = Blueprint("directory", __name__, url_prefix="/directory")


class DirectoryService:
    def lookup(self, term, limit=25):
        pattern = f"%{term}%"
        return (
            Member.query.filter(or_(Member.display_name.ilike(pattern), Member.email.ilike(pattern)))
            .order_by(Member.display_name)
            .limit(limit)
            .all()
        )


@bp.route("/lookup")
@login_required
def lookup():
    term = request.args.get("q", "").strip()
    if len(term) < 2:
        return jsonify([])
    people = DirectoryService().lookup(term)
    return jsonify([{"id": m.id, "name": m.display_name, "email": m.email} for m in people])
