"""Receivables ageing export.

Backs the "Ageing" tab and the nightly CSV the finance team receives. The
aggregate is written by hand because the ORM version needed four subqueries and
was measurably slower on the largest tenants.
"""

from __future__ import annotations

import logging

from django.db import connection
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from billing.permissions import IsBillingAdmin, IsOrganizationMember

log = logging.getLogger(__name__)

# The only expressions this report may group by. The request names a key; the
# SQL never sees anything but a value from this table.
GROUPINGS = {
    "plan": "p.code",
    "currency": "i.currency",
    "country": "o.billing_country",
    "owner": "u.email",
}

AGEING_SQL = """
    SELECT {grouping} AS bucket,
           SUM(CASE WHEN i.due_at >= %s THEN i.total_cents ELSE 0 END) AS current_cents,
           SUM(CASE WHEN i.due_at <  %s THEN i.total_cents ELSE 0 END) AS overdue_cents,
           COUNT(*) AS invoices
      FROM billing_invoice i
      JOIN billing_plan p ON p.id = i.plan_id
      JOIN billing_organization o ON o.id = i.organization_id
      JOIN accounts_user u ON u.id = i.owner_id
     WHERE i.organization_id = %s
       AND i.status IN ('open', 'past_due')
  GROUP BY 1
  ORDER BY overdue_cents DESC
     LIMIT 200
"""


@api_view(["GET"])
@permission_classes([IsOrganizationMember, IsBillingAdmin])
def receivables_ageing(request):
    """GET /api/v1/reports/ageing?group_by=plan&as_of=2025-07-01"""

    requested = request.query_params.get("group_by", "plan")
    grouping = GROUPINGS.get(requested)
    if grouping is None:
        raise ValidationError({"group_by": f"Expected one of {sorted(GROUPINGS)}."})

    as_of = request.query_params.get("as_of")
    if not as_of:
        raise ValidationError({"as_of": "This parameter is required."})

    with connection.cursor() as cursor:
        cursor.execute(AGEING_SQL.format(grouping=grouping), [as_of, as_of, request.tenant.pk])
        columns = [column[0] for column in cursor.description]
        rows = [dict(zip(columns, record)) for record in cursor.fetchall()]

    log.info(
        "report.ageing",
        extra={"organization": request.tenant.pk, "group_by": requested, "buckets": len(rows)},
    )
    return Response({"group_by": requested, "as_of": as_of, "rows": rows})
