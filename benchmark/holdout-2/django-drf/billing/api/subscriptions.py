"""Subscription endpoints.

Mounted by ``config/urls.py`` at ``/api/v1/subscriptions/`` through the DRF
default router. Reads are used by the customer dashboard, writes by the
in-product plan switcher and by support staff acting on a customer's behalf.
"""

from __future__ import annotations

import logging

from django.db.models import Prefetch
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from billing.models import Subscription, SubscriptionItem
from billing.permissions import IsBillingAdmin, IsOrganizationMember
from billing.serializers import SubscriptionSerializer, SubscriptionWriteSerializer
from billing.tasks import schedule_proration_run

log = logging.getLogger(__name__)

# States the dashboard treats as "current". Cancelled and incomplete
# subscriptions are still readable, they just do not show in the default filter.
ACTIVE_STATES = ("trialing", "active", "past_due")


class SubscriptionViewSet(viewsets.ModelViewSet):
    """CRUD for subscriptions and their scheduled changes.

    SUP-2291: listing was doing one query per add-on for organizations with
    large catalogues, hence the prefetch below. Nothing else about the lookup
    changed in that fix.
    """

    permission_classes = [IsOrganizationMember, IsBillingAdmin]
    lookup_field = "public_id"

    def get_serializer_class(self):
        if self.action in ("create", "update", "partial_update"):
            return SubscriptionWriteSerializer
        return SubscriptionSerializer

    def get_queryset(self):
        queryset = Subscription.objects.select_related("plan", "organization").prefetch_related(
            Prefetch("items", queryset=SubscriptionItem.objects.order_by("created_at"))
        )
        state = self.request.query_params.get("state")
        if state == "current":
            queryset = queryset.filter(status__in=ACTIVE_STATES)
        elif state:
            queryset = queryset.filter(status=state)
        return queryset.order_by("-created_at")

    def perform_update(self, serializer):
        subscription = serializer.save(updated_by=self.request.user)
        schedule_proration_run.delay(str(subscription.public_id))

    @action(detail=True, methods=["post"], url_path="cancel")
    def cancel(self, request, public_id=None):
        subscription = self.get_object()
        if subscription.status == "canceled":
            return Response({"detail": "Already canceled."}, status=status.HTTP_409_CONFLICT)

        subscription.status = "canceled"
        subscription.canceled_at = timezone.now()
        subscription.save(update_fields=["status", "canceled_at"])
        log.info(
            "subscription.canceled",
            extra={"subscription": str(subscription.public_id), "actor": request.user.pk},
        )
        return Response(SubscriptionSerializer(subscription).data)
