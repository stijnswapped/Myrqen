"""Organization profile endpoints.

The "Company details" screen in account settings reads and writes the caller's
own organization. Mounted at ``/api/v1/organizations/`` by ``config/urls.py``;
the detail route is the only one exposed, because an organization can only ever
see itself.
"""

from __future__ import annotations

import logging

from rest_framework import mixins, serializers, viewsets

from billing.models import Organization
from billing.permissions import IsBillingAdmin, IsOrganizationMember

log = logging.getLogger(__name__)


class OrganizationSerializer(serializers.ModelSerializer):
    """Company details as the settings screen shows them."""

    plan_name = serializers.CharField(source="plan.name", read_only=True)

    class Meta:
        model = Organization
        fields = "__all__"
        read_only_fields = ("id", "public_id", "slug", "created_at", "updated_at")

    def validate_billing_email(self, value):
        return value.strip().lower()


class OrganizationViewSet(
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """GET/PATCH /api/v1/organizations/:public_id"""

    serializer_class = OrganizationSerializer
    permission_classes = [IsOrganizationMember, IsBillingAdmin]
    lookup_field = "public_id"

    def get_queryset(self):
        # An organization is only ever allowed to address itself.
        return Organization.objects.filter(pk=self.request.tenant.pk).select_related("plan")

    def perform_update(self, serializer):
        organization = serializer.save()
        log.info(
            "organization.updated",
            extra={
                "organization": organization.pk,
                "actor": self.request.user.pk,
                "fields": sorted(serializer.validated_data),
            },
        )
