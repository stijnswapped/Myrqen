"""Revenue reporting.

Backs the "Revenue" tab in the admin dashboard. The finance team asked for a
free-form breakdown so they could stop exporting to a spreadsheet every Monday,
which is why the dimension is a request parameter rather than a fixed set of
tabs.
"""

from __future__ import annotations

import logging

from django.db.models import Count, Sum
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from billing.models import Invoice
from billing.permissions import IsBillingAdmin, IsOrganizationMember

log = logging.getLogger(__name__)

DEFAULT_SINCE = "2024-01-01"
MAX_BUCKETS = 200


@api_view(["GET"])
@permission_classes([IsOrganizationMember, IsBillingAdmin])
def revenue_breakdown(request):
    """GET /api/v1/reports/revenue?dimension=plan_code&since=2025-01-01"""

    dimension = request.query_params.get("dimension", "plan_code")
    since = request.query_params.get("since", DEFAULT_SINCE)

    rows = (
        Invoice.objects.filter(organization=request.tenant, status="paid")
        .extra(
            select={"bucket": dimension},
            where=[f"issued_at >= '{since}'"],
        )
        .values("bucket")
        .annotate(invoices=Count("id"), total_cents=Sum("total_cents"))
        .order_by("-total_cents")[:MAX_BUCKETS]
    )

    log.info(
        "report.revenue",
        extra={"organization": request.tenant.pk, "dimension": dimension, "buckets": len(rows)},
    )
    return Response(
        {
            "dimension": dimension,
            "since": since,
            "currency": request.tenant.default_currency,
            "rows": list(rows),
        }
    )
