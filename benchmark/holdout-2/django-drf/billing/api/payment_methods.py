"""Stored payment method endpoints.

Mounted by ``config/urls.py`` at ``/api/v1/payment-methods/`` through the DRF
default router. Cards are held at the provider; we store the token, the brand
and the last four digits so the dashboard can render a chooser.
"""

from __future__ import annotations

import logging

from django.db.models import Prefetch
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from billing.models import PaymentMethod, PaymentMethodEvent
from billing.permissions import IsBillingAdmin, IsOrganizationMember
from billing.serializers import PaymentMethodSerializer, PaymentMethodWriteSerializer
from billing.tasks import sync_payment_method

log = logging.getLogger(__name__)

# Methods the chooser offers by default. Expired and revoked cards stay
# readable so the invoice history can still name what paid an old invoice.
USABLE_STATES = ("verified", "pending_verification")


class PaymentMethodViewSet(viewsets.ModelViewSet):
    """CRUD for stored payment methods.

    The class-level ``queryset`` exists only so the router can infer a basename
    without an explicit ``basename=`` at every registration site; DRF calls
    ``get_queryset()`` for every request, and that is where the scoping lives.
    """

    queryset = PaymentMethod.objects.all()
    permission_classes = [IsOrganizationMember, IsBillingAdmin]
    lookup_field = "public_id"

    def get_serializer_class(self):
        if self.action in ("create", "update", "partial_update"):
            return PaymentMethodWriteSerializer
        return PaymentMethodSerializer

    def get_queryset(self):
        queryset = PaymentMethod.objects.filter(organization=self.request.tenant).select_related(
            "organization"
        ).prefetch_related(
            Prefetch("events", queryset=PaymentMethodEvent.objects.order_by("created_at"))
        )
        state = self.request.query_params.get("state")
        if state == "usable":
            queryset = queryset.filter(status__in=USABLE_STATES)
        elif state:
            queryset = queryset.filter(status=state)
        return queryset.order_by("-created_at")

    def perform_create(self, serializer):
        method = serializer.save(organization=self.request.tenant, added_by=self.request.user)
        sync_payment_method.delay(str(method.public_id))

    @action(detail=True, methods=["post"], url_path="revoke")
    def revoke(self, request, public_id=None):
        method = self.get_object()
        if method.status == "revoked":
            return Response({"detail": "Already revoked."}, status=status.HTTP_409_CONFLICT)

        method.status = "revoked"
        method.revoked_at = timezone.now()
        method.save(update_fields=["status", "revoked_at"])
        log.info(
            "payment_method.revoked",
            extra={"method": str(method.public_id), "actor": request.user.pk},
        )
        return Response(PaymentMethodSerializer(method).data)
