"""Billing contact endpoints.

The "Billing contacts" screen in account settings reads and writes the people an
invoice is addressed and copied to. Mounted at ``/api/v1/billing-contacts/`` by
``config/urls.py``.
"""

from __future__ import annotations

import logging

from rest_framework import mixins, serializers, viewsets

from billing.models import BillingContact
from billing.permissions import IsBillingAdmin, IsOrganizationMember

log = logging.getLogger(__name__)

# What the settings screen may write.
EDITABLE_FIELDS = ("display_name", "email", "phone", "locale", "receives_dunning")
# Everything else the screen renders. Listed so the payload keeps its shape,
# never assigned from it — see `read_only_fields` below.
SYSTEM_FIELDS = ("id", "public_id", "organization", "verified_at", "created_at", "updated_at")


class BillingContactSerializer(serializers.ModelSerializer):
    """A billing contact as the settings screen shows them."""

    organization_name = serializers.CharField(source="organization.name", read_only=True)

    class Meta:
        model = BillingContact
        fields = EDITABLE_FIELDS + SYSTEM_FIELDS
        read_only_fields = SYSTEM_FIELDS

    def validate_email(self, value):
        return value.strip().lower()


class BillingContactViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """GET/POST/PATCH /api/v1/billing-contacts/:public_id"""

    serializer_class = BillingContactSerializer
    permission_classes = [IsOrganizationMember, IsBillingAdmin]
    lookup_field = "public_id"

    def get_queryset(self):
        return BillingContact.objects.filter(organization=self.request.tenant).select_related(
            "organization"
        )

    def perform_create(self, serializer):
        serializer.save(organization=self.request.tenant)

    def perform_update(self, serializer):
        contact = serializer.save()
        log.info(
            "billing_contact.updated",
            extra={
                "organization": contact.organization_id,
                "actor": self.request.user.pk,
                "fields": sorted(serializer.validated_data),
            },
        )
