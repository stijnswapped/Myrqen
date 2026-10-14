from urllib.parse import urlsplit

import requests
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from portal.extensions import db
from portal.models import CalendarSubscription

bp = Blueprint("ics_import", __name__, url_prefix="/calendar-feeds")

PROVIDER_HOSTS = frozenset({"calendar.google.com", "outlook.office365.com", "p.icloud.com"})


def provider_url(raw):
    parts = urlsplit(raw)
    if parts.scheme != "https" or parts.username or parts.password:
        return None
    if (parts.hostname or "").lower() not in PROVIDER_HOSTS or parts.port not in (None, 443):
        return None
    return parts.geturl()


@bp.post("")
@login_required
def add_feed():
    url = provider_url((request.form.get("ics_url") or "").strip())
    if url is None:
        return jsonify(error="only Google, Outlook and iCloud calendars are supported"), 400

    resp = requests.get(url, timeout=10, allow_redirects=False)
    if resp.status_code != 200 or "BEGIN:VCALENDAR" not in resp.text[:200]:
        return jsonify(error="that link did not return a calendar"), 422

    sub = CalendarSubscription(user_id=current_user.id, url=url, last_payload=resp.text)
    db.session.add(sub)
    db.session.commit()
    return jsonify(id=sub.id, events=resp.text.count("BEGIN:VEVENT")), 201
