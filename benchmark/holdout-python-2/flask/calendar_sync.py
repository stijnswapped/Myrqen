import requests
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from portal.extensions import db
from portal.models import CalendarSubscription

bp = Blueprint("calendar_sync", __name__, url_prefix="/calendars")

SUPPORTED_PROVIDERS = ("calendar.google.com", "outlook.office365.com", "p.icloud.com")


@bp.post("/subscribe")
@login_required
def subscribe():
    ics_url = (request.form.get("ics_url") or "").strip()
    if not any(provider in ics_url for provider in SUPPORTED_PROVIDERS):
        return jsonify(error="only Google, Outlook and iCloud calendars are supported"), 400

    resp = requests.get(ics_url, timeout=10)
    if resp.status_code != 200 or "BEGIN:VCALENDAR" not in resp.text[:200]:
        return jsonify(error="that link did not return a calendar", detail=resp.text[:300]), 422

    sub = CalendarSubscription(user_id=current_user.id, url=ics_url, last_payload=resp.text)
    db.session.add(sub)
    db.session.commit()
    return jsonify(id=sub.id, events=resp.text.count("BEGIN:VEVENT")), 201
