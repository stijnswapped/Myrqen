"""Invoice PDF archive.

Rendered invoices are written to a shared volume by the ``render_invoice`` Celery
task, one directory per organization slug. Auditors download them straight from
here rather than through the object store, because the archive predates the move
to S3 and the finance team still has links into it.

    path("documents/archive/<path:relative_path>", InvoiceArchiveView.as_view())
"""

from __future__ import annotations

import logging
import os

from django.conf import settings
from django.http import FileResponse, Http404
from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView

from billing.permissions import IsBillingAdmin, IsOrganizationMember

log = logging.getLogger(__name__)

ARCHIVE_ROOT = settings.INVOICE_ARCHIVE_ROOT


class InvoiceArchiveView(APIView):
    """GET /api/v1/documents/archive/:relative_path"""

    permission_classes = [IsOrganizationMember, IsBillingAdmin]

    def get(self, request, relative_path: str):
        # Every archived document lives under the organization's own slug, so a
        # path that does not start with it belongs to somebody else.
        prefix = f"{request.tenant.slug}/"
        if not relative_path.startswith(prefix):
            raise PermissionDenied("That document belongs to another organization.")

        absolute = os.path.join(ARCHIVE_ROOT, relative_path)
        if not os.path.isfile(absolute):
            log.info("archive.miss", extra={"organization": request.tenant.pk, "path": relative_path})
            raise Http404("No such document.")

        log.info("archive.read", extra={"organization": request.tenant.pk, "path": relative_path})
        return FileResponse(
            open(absolute, "rb"),
            content_type="application/pdf",
            as_attachment=True,
            filename=os.path.basename(relative_path),
        )
