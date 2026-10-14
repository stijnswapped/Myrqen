import re

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from markupsafe import Markup

from portal.extensions import db
from portal.models import Discussion, Reply

bp = Blueprint("discussions", __name__, url_prefix="/discussions")

MENTION = re.compile(r"@([a-z0-9_]{2,30})")
MENTION_LINK = Markup('<a class="mention" href="/u/{0}">@{0}</a>')


def render_reply(body):
    html = Markup("")
    cursor = 0
    for match in MENTION.finditer(body):
        html += body[cursor:match.start()]
        html += MENTION_LINK.format(match.group(1))
        cursor = match.end()
    html += body[cursor:]
    return Markup("<br>").join(html.split("\n"))


@bp.get("/<int:discussion_id>")
@login_required
def show_discussion(discussion_id):
    discussion = Discussion.query.filter_by(id=discussion_id, team_id=current_user.team_id).first_or_404()
    replies = [(r.author.display_name, render_reply(r.body)) for r in discussion.replies]
    return render_template("discussions/show.html", discussion=discussion, replies=replies)


@bp.post("/<int:discussion_id>/replies")
@login_required
def add_reply(discussion_id):
    discussion = Discussion.query.filter_by(id=discussion_id, team_id=current_user.team_id).first_or_404()
    body = request.form.get("body", "").strip()[:5000]
    if body:
        db.session.add(Reply(discussion_id=discussion.id, author_id=current_user.id, body=body))
        db.session.commit()
    return redirect(url_for("discussions.show_discussion", discussion_id=discussion.id))
