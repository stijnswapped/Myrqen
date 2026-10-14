"""DRF exception handler for the partner API.

Wired in ``config/settings/partner.py``::

    REST_FRAMEWORK = {"EXCEPTION_HANDLER": "config.drf_errors.partner_exception_handler"}

DRF's own handler turns APIException subclasses into responses and returns None
for everything else, which Django then renders as an empty 500. Partners could
not tell those apart from a gateway timeout, so this handler renders them too —
as a stable envelope carrying a correlation id they can quote at support. The
detail stays on this side of the wire.
"""

from __future__ import annotations

import logging
import traceback
import uuid

from rest_framework.response import Response
from rest_framework.views import exception_handler

log = logging.getLogger(__name__)


def partner_exception_handler(exc, context):
    handled = exception_handler(exc, context)
    request = context.get("request")
    correlation_id = getattr(request, "correlation_id", None) or uuid.uuid4().hex

    if handled is not None:
        handled.data = {"error": handled.data, "correlation_id": correlation_id}
        return handled

    # The trace goes to the log aggregator keyed by the same correlation id the
    # partner is handed, which is how support joins the two without the response
    # ever carrying it.
    trace = traceback.format_exc()
    log.error(
        "api.unhandled",
        extra={
            "correlation_id": correlation_id,
            "view": str(context.get("view")),
            "exception": type(exc).__name__,
            "trace": trace,
        },
    )
    return Response(
        {
            "error": {
                "code": "internal_error",
                "detail": "The request could not be completed. Quote the correlation id to support.",
            },
            "correlation_id": correlation_id,
        },
        status=500,
    )
