"""Dunning notification endpoints.

An organization registers HTTPS receivers for dunning notices (card expiring,
payment failed, final notice). The "send a test notice" button in the dashboard
posts to :class:`NotificationProbeView`, which replays a fixture notice to a
receiver the organization has already registered and verified.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import uuid
from urllib.parse import urlparse

import requests
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from billing.models import NotificationDelivery, NotificationReceiver
from billing.permissions import IsBillingAdmin, IsOrganizationMember
from billing.signing import event_signature

log = logging.getLogger(__name__)

PROBE_TIMEOUT_SECONDS = 5
USER_AGENT = "Arcline-Notifications/1.4 (+https://arcline.example/docs/dunning)"


class NotificationProbeSerializer(serializers.Serializer):
    """Body of a test notice. The receiver is named, never described."""

    receiver = serializers.UUIDField()
    notice_type = serializers.ChoiceField(
        choices=["card_expiring", "payment_failed", "final_notice"],
        default="payment_failed",
    )


def assert_deliverable(url: str) -> None:
    """Refuse anything that is not a public HTTPS destination.

    Receivers are checked here as well as at registration: a hostname that
    resolved publicly last week can resolve to 169.254.169.254 today, and this
    process can reach the metadata service and the internal admin network.
    """

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValidationError({"receiver": "Only https:// receivers can be used."})
    host = parsed.hostname
    if not host:
        raise ValidationError({"receiver": "The stored URL has no host."})

    try:
        resolved = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
        raise ValidationError({"receiver": f"{host} does not resolve."}) from error

    for *_, sockaddr in resolved:
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global or address.is_multicast:
            raise ValidationError({"receiver": f"{host} resolves to a non-public address."})


def _probe_payload(organization, notice_type: str) -> dict:
    return {
        "id": f"ntc_{uuid.uuid4().hex}",
        "type": notice_type,
        "livemode": False,
        "created": timezone.now().isoformat(),
        "data": {"organization": str(organization.public_id), "probe": True},
    }


class NotificationProbeView(APIView):
    """POST /api/v1/notification-receivers/probe"""

    permission_classes = [IsOrganizationMember, IsBillingAdmin]

    def post(self, request):
        serializer = NotificationProbeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        receiver = get_object_or_404(
            NotificationReceiver,
            public_id=serializer.validated_data["receiver"],
            organization=request.tenant,
            verified_at__isnull=False,
        )
        target = receiver.target_url
        assert_deliverable(target)

        payload = _probe_payload(request.tenant, serializer.validated_data["notice_type"])
        headers = {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
            "X-Arcline-Signature": event_signature(payload, request.tenant.webhook_secret),
        }

        try:
            upstream = requests.post(
                target,
                json=payload,
                headers=headers,
                timeout=PROBE_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
        except requests.RequestException as error:
            log.warning("notification.probe.failed", extra={"receiver": str(receiver.public_id), "error": str(error)})
            return Response(
                {"delivered": False, "detail": "The receiver could not be reached."},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        NotificationDelivery.objects.create(
            organization=request.tenant,
            receiver=receiver,
            notice_type=serializer.validated_data["notice_type"],
            response_status=upstream.status_code,
            probe=True,
        )
        return Response({"delivered": 200 <= upstream.status_code < 300, "status": upstream.status_code})
