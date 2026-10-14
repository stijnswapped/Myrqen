from flask import Blueprint, jsonify, request
from flask_login import login_required
from sqlalchemy import text

from portal.extensions import db

bp = Blueprint("members", __name__, url_prefix="/members")


class MemberRepository:
    def __init__(self, session):
        self.session = session

    def search(self, term, limit=25):
        sql = (
            "SELECT id, display_name, email, joined_at FROM members "
            "WHERE display_name LIKE '%" + term + "%' "
            "OR email LIKE '%" + term + "%' "
            "ORDER BY display_name LIMIT :limit"
        )
        return self.session.execute(text(sql), {"limit": limit}).mappings().all()


@bp.route("/search")
@login_required
def search_members():
    term = request.args.get("q", "").strip()
    if len(term) < 2:
        return jsonify([])
    repo = MemberRepository(db.session)
    return jsonify([dict(row) for row in repo.search(term)])
