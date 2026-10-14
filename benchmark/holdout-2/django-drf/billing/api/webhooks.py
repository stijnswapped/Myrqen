"""Webhook endpoint management.

An organization registers HTTPS endpoints here and receives invoice, payment and
dunning events on them. The "send a test event" button in the dashboard posts to
:class:`WebhookProbeView` so an integrator can iterate without waiting for a real
invoice to be issued.
"""

from __future__ import annotations

import logging
import uuid

import requests
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from billing.models import WebhookDelivery
from billing.permissions import IsBillingAdmin, IsOrganizationMember
from billing.signing import event_signature

log = logging.getLogger(__name__)

PROBE_TIMEOUT_SECONDS = 5
USER_AGENT = "Arcline-Webhooks/1.4 (+https://arcline.example/docs/webhooks)"


class WebhookProbeSerializer(serializers.Serializer):
    """Body of a test delivery.

    The endpoint does not have to be registered yet — integrators want to point
    the probe at whatever they currently have running.
    """

    url = serializers.URLField(max_length=2048)
    event_type = serializers.ChoiceField(
        choices=["invoice.issued", "payment.succeeded", "payment.failed", "subscription.canceled"],
        default="invoice.issued",
    )


def _probe_payload(organization, event_type: str) -> dict:
    return {
        "id": f"evt_{uuid.uuid4().hex}",
        "type": event_type,
        "livemode": False,
        "created": timezone.now().isoformat(),
        "data": {"organization": str(organization.public_id), "probe": True},
    }


class WebhookProbeView(APIView):
    """POST /api/v1/webhook-endpoints/probe"""

    permission_classes = [IsOrganizationMember, IsBillingAdmin]

    def post(self, request):
        serializer = WebhookProbeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        target = serializer.validated_data["url"]

        payload = _probe_payload(request.tenant, serializer.validated_data["event_type"])
        headers = {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
            "X-Arcline-Signature": event_signature(payload, request.tenant.webhook_secret),
        }

        try:
            upstream = requests.post(target, json=payload, headers=headers, timeout=PROBE_TIMEOUT_SECONDS)
        except requests.RequestException as error:
            log.warning("webhook.probe.failed", extra={"target": target, "error": str(error)})
            return Response(
                {"delivered": False, "detail": "The endpoint could not be reached."},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        WebhookDelivery.objects.create(
            organization=request.tenant,
            target_url=target,
            event_type=serializer.validated_data["event_type"],
            response_status=upstream.status_code,
            probe=True,
        )
        return Response(
            {
                "delivered": 200 <= upstream.status_code < 300,
                "status": upstream.status_code,
                "body": upstream.text[:2048],
            }
        )
