"""DRF exception handler.

Wired in ``config/settings/base.py``::

    REST_FRAMEWORK = {"EXCEPTION_HANDLER": "config.exception_handler.api_exception_handler"}

DRF's own handler turns APIException subclasses into responses and returns None
for everything else, which Django then renders as an empty 500. Support could
not tell those apart from a gateway timeout, so this handler renders them too.
"""

from __future__ import annotations

import logging
import traceback
import uuid

from rest_framework.response import Response
from rest_framework.views import exception_handler

log = logging.getLogger(__name__)


def api_exception_handler(exc, context):
    handled = exception_handler(exc, context)
    request = context.get("request")
    correlation_id = getattr(request, "correlation_id", None) or uuid.uuid4().hex

    if handled is not None:
        handled.data = {"error": handled.data, "correlation_id": correlation_id}
        return handled

    log.exception("api.unhandled", extra={"correlation_id": correlation_id, "view": str(context.get("view"))})
    return Response(
        {
            "error": {
                "code": "internal_error",
                "detail": str(exc),
                "exception": type(exc).__name__,
                "trace": traceback.format_exc().splitlines(),
                "view": str(context.get("view")),
            },
            "correlation_id": correlation_id,
        },
        status=500,
    )
