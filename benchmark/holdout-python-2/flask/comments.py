import re

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from markupsafe import Markup

from portal.extensions import db
from portal.models import Comment, Thread

bp = Blueprint("comments", __name__, url_prefix="/threads")

MENTION = re.compile(r"@([a-z0-9_]{2,30})")


def render_comment(body):
    linked = MENTION.sub(lambda m: f'<a class="mention" href="/u/{m.group(1)}">@{m.group(1)}</a>', body)
    return Markup(linked.replace("\n", "<br>"))


@bp.get("/<int:thread_id>")
@login_required
def show_thread(thread_id):
    thread = Thread.query.filter_by(id=thread_id, team_id=current_user.team_id).first_or_404()
    comments = [(c.author.display_name, render_comment(c.body)) for c in thread.comments]
    return render_template("threads/show.html", thread=thread, comments=comments)


@bp.post("/<int:thread_id>/comments")
@login_required
def add_comment(thread_id):
    thread = Thread.query.filter_by(id=thread_id, team_id=current_user.team_id).first_or_404()
    body = request.form.get("body", "").strip()[:5000]
    if body:
        db.session.add(Comment(thread_id=thread.id, author_id=current_user.id, body=body))
        db.session.commit()
    return redirect(url_for("comments.show_thread", thread_id=thread.id))
