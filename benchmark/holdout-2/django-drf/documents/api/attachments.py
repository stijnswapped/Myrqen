"""Credit note attachment archive.

Supporting documents uploaded against a credit note (remittance advice, signed
approvals) are written to a shared volume by the ``store_attachment`` Celery
task, one directory per organization slug. Reviewers download them from here
while an approval is still open.

    path("documents/attachments/<path:relative_path>", CreditNoteAttachmentView.as_view())
"""

from __future__ import annotations

import logging
from pathlib import Path

from django.conf import settings
from django.http import FileResponse, Http404
from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView

from billing.permissions import IsBillingAdmin, IsOrganizationMember

log = logging.getLogger(__name__)

ATTACHMENT_ROOT = Path(settings.ATTACHMENT_ARCHIVE_ROOT)


class CreditNoteAttachmentView(APIView):
    """GET /api/v1/documents/attachments/:relative_path"""

    permission_classes = [IsOrganizationMember, IsBillingAdmin]

    def get(self, request, relative_path: str):
        # The archive is flat inside each organization's directory, so only the
        # final component of the request is meaningful. Taking `.name` drops any
        # directory part the caller sent, traversal or otherwise, and the
        # containment check below is what we would still want if that ever
        # stopped being true.
        tenant_root = (ATTACHMENT_ROOT / request.tenant.slug).resolve()
        absolute = (tenant_root / Path(relative_path).name).resolve()
        if not absolute.is_relative_to(tenant_root):
            raise PermissionDenied("That document belongs to another organization.")

        if not absolute.is_file():
            log.info("attachment.miss", extra={"organization": request.tenant.pk, "path": relative_path})
            raise Http404("No such document.")

        log.info("attachment.read", extra={"organization": request.tenant.pk, "path": relative_path})
        return FileResponse(
            absolute.open("rb"),
            content_type="application/pdf",
            as_attachment=True,
            filename=absolute.name,
        )
